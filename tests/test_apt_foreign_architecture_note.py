"""An APT dependency offered only for another architecture says so."""
import apt_core
from core import BuildOptions, Reporter
from test_feather import APT_REPO, deb_pkg


def _note(packages):
    result = apt_core.resolve([("app", None, None)], packages, "amd64", BuildOptions(), Reporter())
    assert len(result.unresolved) == 1
    return next(iter(result.unresolved_notes.values()))


def test_dependency_available_only_for_another_architecture_is_named_as_such():
    note = _note([deb_pkg("app", "1.0", APT_REPO, depends="libfoo"),
                  deb_pkg("libfoo", "1.0", APT_REPO, arch="i386")])

    assert "only for other architecture(s) (i386)" in note
    assert "amd64" in note


def test_wrong_version_in_the_target_architecture_keeps_the_general_note():
    note = _note([deb_pkg("app", "1.0", APT_REPO, depends="libfoo (>= 5)"),
                  deb_pkg("libfoo", "1.0", APT_REPO)])

    assert "none satisfy the requested version/architecture" in note


def test_absent_dependency_keeps_the_absent_note():
    note = _note([deb_pkg("app", "1.0", APT_REPO, depends="libfoo")])

    assert note == "No matching provider in enabled APT repositories"
