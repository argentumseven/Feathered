"""An input folder cannot bypass the installer's fixed component hashes."""
import pytest

from stage_cached_verifier import COMPONENTS, stage


def test_unpinned_cached_bytes_are_rejected_without_touching_output(tmp_path):
    source = tmp_path / 'untrusted cache'
    source.mkdir()
    for name in COMPONENTS:
        (source / name).write_bytes(b'untrusted executable bytes')
    destination = tmp_path / 'existing output'
    destination.mkdir()
    marker = destination / 'preserve.txt'
    marker.write_bytes(b'existing build')
    with pytest.raises(RuntimeError, match='pinned installer component hashes'):
        stage(source, destination)
    assert list(destination.iterdir()) == [marker]
    assert marker.read_bytes() == b'existing build'
