"""Record edges that payload-only golden fixtures do not exercise."""
import json

import core
from bundle_writer import write_records
from package_family import ARCH


def test_arch_checksums_include_signature_sidecars(tmp_path):
    package = tmp_path / 'demo.pkg.tar.zst'
    signature = tmp_path / 'demo.pkg.tar.zst.sig'
    package.write_bytes(b'package bytes')
    signature.write_bytes(b'signature bytes')
    (tmp_path / 'unrelated.txt').write_text('operator note')
    # Optional records are intentionally retained during additive publication.
    (tmp_path / 'ignored-unresolved.txt').write_text('previous waiver\n')
    payload = {'metadata': {}, 'summary': {'package_count': 1}, 'packages': []}
    write_records(tmp_path, tmp_path, ARCH, payload, [], unresolved=iter(()),
                  ignored_unresolved=[], conflicts=[], skipped_installed=[],
                  installed_satisfied=[], hash_file=core.sha256_file)
    assert (tmp_path / 'SHA256SUMS.txt').read_text() == ''.join(
        f'{core.sha256_file(path)}  {path.name}\n' for path in (package, signature))
    assert (tmp_path / 'manifest.json').read_text() == json.dumps(payload, indent=2)
    assert (tmp_path / 'manifest.txt').read_bytes() == b'\n'
    assert (tmp_path / 'unresolved.txt').read_bytes() == b''
    assert (tmp_path / 'conflicts.txt').read_bytes() == b''
    assert (tmp_path / 'ignored-unresolved.txt').read_text() == 'previous waiver\n'
    assert not (tmp_path / 'skipped-installed.txt').exists()
