from acquisition_model import MirrorLayout
from core import Package, RepoSpec, Reporter
from feathered_app.build_mirror import BuildMirrorMixin


class MirrorHarness(BuildMirrorMixin):
    def __init__(self, repos, layout=MirrorLayout.SEPARATE):
        self.repo_rows = list(repos)
        self._layout = layout

    def _selected_mirror_repositories(self):
        return list(self.repo_rows)

    def _mirror_layout(self):
        return self._layout

    def _is_deb(self):
        return False

    def _is_arch(self):
        return False


def _package(repo):
    return Package(
        "demo", "x86_64", "0", "1", "1", "demo-1-1.x86_64.rpm",
        "sha256", "a" * 64, repo, size=10,
    )


def test_separate_mirror_keeps_successfully_loaded_empty_source():
    base = RepoSpec("Base", "https://example.invalid/base/")
    updates = RepoSpec("Updates", "https://example.invalid/updates/")
    harness = MirrorHarness([base, updates])

    result = harness._mirror_result([_package(base)], Reporter())

    assert len(result.mirror_repository_results) == 2
    assert result.mirror_repository_results[0][1].selected
    assert result.mirror_repository_results[1][1].selected == []
    assert [row["package_count"] for row in result.mirror_repository_summaries] == [1, 0]


def test_unified_mirror_accepts_empty_selected_source():
    base = RepoSpec("Base", "https://example.invalid/base/")
    updates = RepoSpec("Updates", "https://example.invalid/updates/")
    harness = MirrorHarness([base, updates], MirrorLayout.UNIFIED)

    result = harness._mirror_result([_package(base)], Reporter())

    assert len(result.selected) == 1
    assert [row["package_count"] for row in result.mirror_repository_summaries] == [1, 0]
