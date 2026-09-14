"""Linux setup transactions and actual shell argument/exit-code behavior."""
import os
from pathlib import Path
import subprocess
import sys
import pytest
import linux_setup

pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux setup requires a Linux host')
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "Feathered source ' $ % with spaces"
    root.mkdir()
    for name in ('app.py', 'feathered_cli.py', 'linux_launch.py', 'requirements.txt', 'feathered_app/__init__.py'):
        path = root / name
        path.parent.mkdir(exist_ok=True)
        path.write_text('')
    for name in ('run_cli.sh', 'run_gui.sh'):
        (root / name).write_bytes((ROOT / name).read_bytes())
    return root


@pytest.fixture
def fake_runtime(monkeypatch):
    calls = []
    class Builder:
        def __init__(self, **kwargs):
            assert kwargs == {'with_pip': True}
        def create(self, path):
            (path / 'bin').mkdir(parents=True)
            (path / 'bin/python').write_text('fixture interpreter')
    monkeypatch.setattr(linux_setup.venv, 'EnvBuilder', Builder)
    monkeypatch.setattr(linux_setup.subprocess, 'run', lambda command, **kwargs: calls.append(command))
    return calls


def test_cli_only_installs_without_tk_or_package_index(source, fake_runtime, tmp_path):
    wheelhouse = tmp_path / 'wheels'; wheelhouse.mkdir()
    files = linux_setup.shortcuts(source, tmp_path / 'bin', tmp_path / 'desktop', True)
    runtime = linux_setup.install(source, cli_only=True, wheelhouse=wheelhouse, files=files)
    assert (source / '.venv/current/bin/python').resolve() == runtime
    assert all('tkinter' not in ' '.join(command) for command in fake_runtime)
    pip = next(command for command in fake_runtime if 'pip' in command)
    assert '--no-index' in pip and '--only-binary=:all:' in pip
    assert pip[-2:] == ['--find-links', str(wheelhouse)]
    assert list((tmp_path / 'bin').iterdir()) == [tmp_path / 'bin/feathered']
    assert not (tmp_path / 'desktop').exists()


def test_failed_upgrade_preserves_selected_runtime_and_shortcuts(source, fake_runtime, monkeypatch, tmp_path):
    files = linux_setup.shortcuts(source, tmp_path / 'bin', tmp_path / 'desktop', False)
    original = linux_setup.install(source, cli_only=False, wheelhouse=None, files=files)
    before = {p: p.read_bytes() for p in files}
    assert any('tkinter' in ' '.join(command) for command in fake_runtime)
    def fail(command, **kwargs):
        raise subprocess.CalledProcessError(1, command)
    monkeypatch.setattr(linux_setup.subprocess, 'run', fail)
    with pytest.raises(subprocess.CalledProcessError):
        linux_setup.install(source, cli_only=False, wheelhouse=None, files=files)
    assert (source / '.venv/current/bin/python').resolve() == original
    assert {p: p.read_bytes() for p in files} == before
    assert list((source / '.venv/environments').iterdir()) == [original.parent.parent]
    assert not (source / '.venv/install.lock').exists()


def test_partial_shortcut_publication_rolls_back(source, fake_runtime, monkeypatch, tmp_path):
    files = linux_setup.shortcuts(source, tmp_path / 'bin', tmp_path / 'desktop', False)
    original = linux_setup.atomic_text
    count = 0
    def fail_second(path, text, mode):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError('fixture write failure')
        return original(path, text, mode)
    monkeypatch.setattr(linux_setup, 'atomic_text', fail_second)
    with pytest.raises(OSError, match='fixture write failure'):
        linux_setup.install(source, cli_only=False, wheelhouse=None, files=files)
    assert not any(p.exists() for p in files)
    assert not (source / '.venv/current').exists()
    assert not list((source / '.venv/environments').iterdir())


def test_unmanaged_shortcut_is_not_overwritten(source, fake_runtime, tmp_path):
    path = tmp_path / 'feathered'; path.write_text('existing program')
    with pytest.raises(ValueError, match='not managed'):
        linux_setup.install(source, cli_only=True, wheelhouse=None, files={path: ('new', 0o755)})
    assert path.read_text() == 'existing program'
    assert not fake_runtime


def test_parallel_install_is_rejected(source, fake_runtime):
    with linux_setup.installation_lock(source):
        with pytest.raises(ValueError, match='Another setup'):
            linux_setup.install(source, cli_only=True, wheelhouse=None, files={})
    assert not fake_runtime


@pytest.mark.parametrize('mode', ['cli', 'gui'])
def test_source_launcher_preserves_arguments_cwd_and_status(source, tmp_path, mode):
    # A real child process verifies shell quoting, including spaces and quotes.
    (source / 'linux_launch.py').write_text('''import json,os,sys
print(json.dumps([os.getcwd(),sys.argv[1:]]))
raise SystemExit(4)
''')
    import json
    env = dict(os.environ, FEATHERED_PYTHON=sys.executable)
    args = ['build', '--spec', "local ' spec.json", '--out', 'output $ with % spaces']
    process = subprocess.run(['/bin/sh', str(source / f'run_{mode}.sh'), *args], cwd=tmp_path,
                             env=env, capture_output=True, text=True)
    assert process.returncode == 4, process.stderr
    assert json.loads(process.stdout) == [str(tmp_path), [mode, *args]]


def test_launcher_without_setup_has_actionable_error(source, tmp_path):
    env = dict(os.environ); env.pop('FEATHERED_PYTHON', None)
    process = subprocess.run(['/bin/sh', str(source / 'run_cli.sh'), '--help'], cwd=tmp_path,
                             env=env, capture_output=True, text=True)
    assert process.returncode == 5
    assert 'install_linux.sh' in process.stderr
