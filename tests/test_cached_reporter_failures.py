"""Reporting failures must not invalidate verified cached payloads."""
import pytest

import core
from test_bundle_characterization import characterize


@pytest.mark.parametrize('family', ('rpm', 'deb', 'arch'))
@pytest.mark.parametrize('stage', ('verifying', 'reused', 'progress'))
def test_cached_reporting_failure_propagates(tmp_path, monkeypatch, family, stage):
    original_item = core.Reporter.item
    original_progress = core.Reporter.progress

    def item(self, identity, state, **info):
        if state == stage:
            raise RuntimeError('reporting callback failed')
        return original_item(self, identity, state, **info)

    def progress(self, label, value):
        if stage == 'progress' and label.startswith(('RPM ', 'DEB ', 'ALPM ')):
            raise RuntimeError('reporting callback failed')
        return original_progress(self, label, value)

    monkeypatch.setattr(core.Reporter, 'item', item)
    monkeypatch.setattr(core.Reporter, 'progress', progress)
    import artifact_cache
    restores = []
    original_restore = artifact_cache.restore

    def restore(pkg, dest, *args):
        restores.append(dest)
        return original_restore(pkg, dest, *args)

    monkeypatch.setattr(artifact_cache, 'restore', restore)
    from test_bundle_characterization import FAMILIES
    backend = FAMILIES[family][0]
    monkeypatch.setattr(backend, '_copy_or_download', lambda *args: pytest.fail(
        'A reporting failure must not cause a replacement download'))
    with pytest.raises(RuntimeError, match='reporting callback failed'):
        characterize(tmp_path, monkeypatch, family, 'reuse')
    assert len(restores) == 1
