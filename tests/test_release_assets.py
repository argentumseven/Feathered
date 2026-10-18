"""Release archives must describe the exact verified version/tag/build."""
import hashlib
import json
from pathlib import Path
import subprocess
from zipfile import ZipFile

import pytest

import prepare_release_assets as assets
from write_source_manifest import build_manifest


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def distribution(root, commit, *, version='1.4.1', mode='release'):
    dist = root / 'dist'
    dist.mkdir(exist_ok=True)
    (dist / 'Feathered.exe').write_bytes(b'controlled packaging fixture')
    verifier = dist / 'gnupg/gpgv.exe'
    verifier.parent.mkdir(exist_ok=True)
    verifier.write_bytes(b'controlled verifier fixture')
    files = [p for p in sorted(dist.rglob('*')) if p.is_file()
             and p.name not in {'SHA256SUMS.txt', 'RELEASE-MANIFEST.json'}]
    rows = [{'path': p.relative_to(dist).as_posix(), 'bytes': p.stat().st_size,
             'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]
    manifest = dist / 'RELEASE-MANIFEST.json'
    manifest.write_text(json.dumps({'schema': 1, 'feathered_version': version,
        'source_commit': commit, 'build_mode': mode, 'files': rows}))
    sums = [f'{row["sha256"]}  {row["path"]}' for row in rows]
    sums.append(f'{hashlib.sha256(manifest.read_bytes()).hexdigest()}  {manifest.name}')
    (dist / 'SHA256SUMS.txt').write_text('\n'.join(sums) + '\n')


@pytest.fixture
def release(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    git(root, 'init', '--quiet')
    git(root, 'config', 'user.name', 'Release Test')
    git(root, 'config', 'user.email', 'release@example.invalid')
    (root / '.gitignore').write_text('dist/\nbuild/\nSOURCE-SHA256.json\n.env\n')
    (root / 'core.py').write_text('FEATHERED_VERSION = "1.4.1"\n')
    (root / 'RELEASE-1.4.1.md').write_text('Release fixture\n')
    git(root, 'add', '.')
    git(root, 'commit', '--quiet', '-m', 'release fixture')
    git(root, 'tag', 'v1.4.1')
    commit = git(root, 'rev-parse', 'HEAD')
    (root / 'SOURCE-SHA256.json').write_text(json.dumps(build_manifest(root)))
    distribution(root, commit)
    return root, commit


def test_release_archives_preserve_complete_distribution_and_source(release):
    root, _ = release
    source, windows, sums = assets.prepare(root, 'v1.4.1')
    prefix = 'Feathered_1.4.1/'
    with ZipFile(source) as archive:
        assert archive.read(prefix + 'core.py') == (root / 'core.py').read_bytes()
        manifest = json.loads(archive.read(prefix + 'SOURCE-SHA256.json'))
        assert set(archive.namelist()) == {prefix + name for name in manifest} | {prefix + 'SOURCE-SHA256.json'}
        assert all(hashlib.sha256(archive.read(prefix + name)).hexdigest() == digest
                   for name, digest in manifest.items())
    with ZipFile(windows) as archive:
        expected = {p.relative_to(root / 'dist').as_posix() for p in (root / 'dist').rglob('*') if p.is_file()}
        assert set(archive.namelist()) == {prefix + name for name in expected}
        assert archive.read(prefix + 'gnupg/gpgv.exe') == b'controlled verifier fixture'
    for line in sums.read_text().splitlines():
        digest, name = line.split('  ', 1)
        assert hashlib.sha256((sums.parent / name).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize('tag', ['v1.4.0', '../1.4.1', 'v1.4.1-preview'])
def test_mismatched_or_unsafe_tag_is_refused(release, tag):
    with pytest.raises(RuntimeError, match='does not match source version'):
        assets.prepare(release[0], tag)


@pytest.mark.parametrize('field,value', [('mode', 'local'), ('commit', '0' * 40), ('version', '1.4.0')])
def test_unsigned_wrong_commit_or_wrong_version_build_is_refused(release, field, value):
    root, commit = release
    kwargs = {'commit': commit, field: value}
    distribution(root, **kwargs)
    with pytest.raises(RuntimeError, match='not a production build'):
        assets.prepare(root, 'v1.4.1')


def test_tampered_distribution_is_refused(release):
    root, _ = release
    (root / 'dist/Feathered.exe').write_bytes(b'changed')
    with pytest.raises(RuntimeError, match='SHA-256'):
        assets.prepare(root, 'v1.4.1')


@pytest.mark.parametrize('name', ['core.py', '.env'])
def test_dirty_or_untracked_source_is_never_published(release, name):
    root, _ = release
    (root / name).write_text('FEATHERED_VERSION = "1.4.1"\n# changed fixture\n')
    with pytest.raises(RuntimeError, match='(modified tracked|untracked) source'):
        assets.prepare(root, 'v1.4.1')


def test_stale_source_manifest_is_refused(release):
    root, _ = release
    (root / 'SOURCE-SHA256.json').write_text('{}')
    with pytest.raises(RuntimeError, match='manifest is stale'):
        assets.prepare(root, 'v1.4.1')


def test_existing_archives_are_preserved(release):
    root, _ = release
    paths = assets.prepare(root, 'v1.4.1')
    original = {p.name: p.read_bytes() for p in paths}
    with pytest.raises(RuntimeError, match='already exists'):
        assets.prepare(root, 'v1.4.1')
    assert {p.name: p.read_bytes() for p in paths} == original


def test_generated_pyinstaller_spec_stays_outside_source_archive(release):
    root, _ = release
    generated = root / 'build/Feathered.spec'
    generated.parent.mkdir()
    generated.write_text('generated build input')
    source, _, _ = assets.prepare(root, 'v1.4.1')
    with ZipFile(source) as archive:
        assert all(not name.endswith('.spec') for name in archive.namelist())


def test_publication_is_after_verified_build_and_only_for_tags():
    import yaml
    root = Path(__file__).resolve().parents[1]
    jobs = yaml.safe_load((root / '.github/workflows/windows-release.yml').read_text())['jobs']
    production = jobs['production-release']
    assert set(production['needs']) == {'windows-source-gate', 'native-conformance', 'static-analysis', 'linux-client'}
    assert production['permissions']['contents'] == 'write'
    steps = production['steps']
    publish = next(i for i, step in enumerate(steps) if step.get('name') == 'Publish verified tag release')
    verify = next(i for i, step in enumerate(steps) if step.get('name') == 'Independently verify signed artifact and release checksums')
    cleanup = next(i for i, step in enumerate(steps) if step.get('name') == 'Remove signing material before third-party upload')
    assert verify < cleanup < publish
    assert steps[publish]['if'] == "startsWith(github.ref, 'refs/tags/v')"
    assert '--verify-tag' in steps[publish]['run']
