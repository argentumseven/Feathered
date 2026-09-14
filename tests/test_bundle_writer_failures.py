"""Acquisition failures retain their public state and transactional boundary."""
import pytest
import core
from test_bundle_characterization import FAMILIES, characterize


@pytest.mark.parametrize('family', FAMILIES)
@pytest.mark.parametrize('cancelled', (False, True))
def test_transfer_failure_does_not_publish(tmp_path, monkeypatch, family, cancelled):
    failure = core.Cancelled('cancelled') if cancelled else OSError('transfer failed')
    backend = FAMILIES[family][0]
    states = []
    original_item = core.Reporter.item

    def item(self, identity, state, **info):
        states.append(state)
        return original_item(self, identity, state, **info)

    def download(*args):
        raise failure

    monkeypatch.setattr(core.Reporter, 'item', item)
    monkeypatch.setattr(backend, '_copy_or_download', download)
    with pytest.raises(type(failure)) as caught:
        characterize(tmp_path, monkeypatch, family, 'fresh')
    assert caught.value is failure
    assert states[-2:] == ['active', 'pending' if cancelled else 'failed']
    assert not (tmp_path / 'bundle').exists()
    assert not (tmp_path / '.bundle.feathered-building').exists()
