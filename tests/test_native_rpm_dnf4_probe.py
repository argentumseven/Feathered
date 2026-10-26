"""Native enterprise DNF4 diagnostic must preserve non-installing evidence."""
from types import SimpleNamespace

import native_rpm_dnf4_probe as live


def test_dnf4_confirmation_aborted_after_full_solve_is_not_package_failure():
    text = 'Dependencies resolved.\nTransaction Summary\nInstall 26 Packages\nOperation aborted.\n'
    assert live.classify_dnf4(1, text) == 'dnf-proposed-no-install'
    assert live.classify_dnf4(1, 'Error: package not found') == 'dnf-no-transaction'
    assert live.classify_dnf4(0, 'Nothing to do') == 'dnf-indeterminate'


def test_dnf4_probe_uses_crb_and_fresh_installroot_without_automatic_yes(monkeypatch, tmp_path):
    seen = []

    def fake_run(argv):
        seen.append(argv)
        if 'repoquery' in argv:
            names = ['cockpit', 'cockpit-system', *(f'example-{n}' for n in range(100))]
            return SimpleNamespace(returncode=0, stdout='\n'.join(names) + '\n', stderr='')
        return SimpleNamespace(returncode=1, stdout='Transaction Summary\nOperation aborted.', stderr='')

    monkeypatch.setattr(live, '_run', fake_run)
    result = live.probe('rocky', '10', ['cockpit'], tmp_path)
    assert result['presets']['cockpit']['status'] == 'dnf-proposed-no-install'
    assert '--enablerepo=crb' in seen[0]
    assert '--assumeno' in seen[1]
    assert '--setopt=reposdir=/etc/yum.repos.d' in seen[1]
    assert any(arg.startswith('--installroot=') for arg in seen[1])
    assert '-y' not in seen[1] and '--assumeyes' not in seen[1]
    assert (tmp_path / 'report.json').is_file()
