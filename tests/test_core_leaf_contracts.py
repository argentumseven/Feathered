"""Compatibility contracts captured before extracting core leaf responsibilities."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import core

GOLDEN = Path(__file__).parent / 'fixtures/core_leaf_contracts.json'
NAMES = [
    'Packages/demo.rpm', 'https://repo.invalid/Packages/DEMO.RPM?token=fixture',
    'C:demo.rpm', r'C:\Windows\demo.rpm', r'..\demo.rpm', '', 'demo.deb',
    'CON.rpm', 'COM1.rpm', 'nul.txt.rpm', 'demo.rpm.', 'demo.rpm ',
    'nested/caf\u00e9.rpm', 'nested/cafe\u0301.rpm', 'space name.rpm',
]
CAPABILITIES = [
    '', '  libfoo.so.1()(64bit) ', 'Python3Dist(Foo_Bar.Baz)',
    'python3.11dist(Foo.Bar[Extra_One, ,Extra.Two])', 'python3dist(foo[])',
    'python3dist(Foo[Bad)', 'python3dist(Foo[Bad])', 'PythonDist(A..__B)',
    'python3dist(Foo) trailing', 'python3dist()', '/usr/bin/Python',
]
DIGEST = 'ab' * 32


def package(identity='demo-1.x86_64', checksum=DIGEST, algorithm='sha256', evidence=None):
    return SimpleNamespace(name='demo', nevra=identity, checksum=checksum,
                           checksum_type=algorithm, verification=evidence)


def snapshots():
    out = {}
    for name in NAMES:
        pkg = SimpleNamespace(name='demo', nevra='demo-1.x86_64', location=name)
        try:
            value = list(core.payload_filenames([pkg], '.rpm').values())
        except Exception as exc:
            value = [type(exc).__name__, str(exc)]
        out['filename:' + name] = value
    for name in CAPABILITIES:
        out['capability:' + name] = [core.canonical_capability_name(name), list(core._index_keys(name))]
    for case, pkg, baseline in [
        ('same', package(), {'demo-1.x86_64': DIGEST.upper()}),
        ('republished', package(checksum='cd' * 32), {'demo-1.x86_64': DIGEST}),
        ('empty', package(), {}),
        ('missing-digest', package(), {'demo-1.x86_64': ''}),
        ('weak', package(algorithm='md5'), {'demo-1.x86_64': DIGEST}),
        ('legacy-bare', package(algorithm=''), {'demo-1.x86_64': DIGEST}),
        ('bad-legacy', package(algorithm='', checksum='not-hex'), {'demo-1.x86_64': 'not-hex'}),
        ('evidence', package(algorithm='md5', evidence=SimpleNamespace(evidence_digest_type='sha256', evidence_digest=DIGEST)), {'demo-1.x86_64': DIGEST}),
        ('primary-before-evidence', package(checksum='cd' * 32, evidence=SimpleNamespace(evidence_digest_type='sha256', evidence_digest=DIGEST)), {'demo-1.x86_64': DIGEST}),
    ]:
        events = []
        reporter = core.Reporter(log=events.append)
        ship, skip = core.split_against_baseline(iter([pkg]), baseline, reporter)
        assert all(item is pkg for item in ship + skip)
        out['baseline:' + case] = [[p.nevra for p in ship], [p.nevra for p in skip], events]
    return out


@pytest.mark.parametrize('key', ['filename:' + name for name in NAMES] +
                         ['capability:' + name for name in CAPABILITIES] +
                         ['baseline:' + name for name in ['same', 'republished', 'empty', 'missing-digest',
                          'weak', 'legacy-bare', 'bad-legacy', 'evidence', 'primary-before-evidence']])
def test_pre_extraction_contract(key):
    assert snapshots()[key] == json.loads(GOLDEN.read_text())[key]


@pytest.mark.parametrize('names', [('Demo.rpm', 'demo.RPM'), ('caf\u00e9.rpm', 'cafe\u0301.rpm')])
def test_filename_collision_cannot_merge_distinct_artifacts(names):
    packages = [SimpleNamespace(name='demo', nevra=f'demo-{i}', location=name) for i, name in enumerate(names)]
    with pytest.raises(RuntimeError, match='filename collision'):
        core.payload_filenames(packages, '.rpm')


def test_equal_package_identity_keeps_distinct_object_keys():
    packages = [SimpleNamespace(name='demo', nevra='demo-1', location='demo.rpm') for _ in range(2)]
    result = core.payload_filenames(packages, '.rpm')
    assert result == {id(pkg): 'demo.rpm' for pkg in packages}


def test_filename_key_patch_is_resolved_at_call_time(monkeypatch):
    seen = []
    def key(name):
        seen.append(name)
        return 'same-destination'
    monkeypatch.setattr(core, '_windows_payload_key', key)
    packages = [SimpleNamespace(name=name, nevra=name, location=name+'.rpm') for name in ('a', 'b')]
    with pytest.raises(RuntimeError, match='filename collision'):
        core.payload_filenames(packages, '.rpm')
    assert seen == ['a.rpm', 'b.rpm']


def test_capability_normalizer_patch_is_resolved_at_call_time(monkeypatch):
    monkeypatch.setattr(core, '_pep503_name', lambda name: 'patched')
    assert core.canonical_capability_name('python3dist(Foo[Bar])') == 'python3dist(patched[patched])'
    monkeypatch.setattr(core, 'canonical_capability_name', lambda name: 'replacement')
    assert core._index_keys('raw') == ('raw', 'replacement')
    assert core.capability_names_equal('a', 'b')


def test_baseline_digest_and_comparator_patches_remain_visible(monkeypatch, tmp_path):
    calls = []
    def strong(algorithm, value):
        calls.append((algorithm, value))
        return ('sha256', 'patched') if value else None
    monkeypatch.setattr(core, 'strong_package_digest', strong)
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps({'packages': [{'package_id':'demo-1.x86_64', 'source_digest_type':'sha256', 'source_digest':'raw'}]}))
    baseline = core.load_baseline(str(path), core.Reporter())
    assert baseline == {'demo-1.x86_64': 'patched'}
    compared = []
    def compare(left, right):
        compared.append((left, right))
        return True
    monkeypatch.setattr(core, 'hmac', SimpleNamespace(compare_digest=compare))
    pkg = package()
    assert core.split_against_baseline([pkg], baseline, core.Reporter()) == ([], [pkg])
    assert calls == [('sha256', 'raw'), ('', ''), ('sha256', DIGEST)]
    assert compared == [('patched', 'patched')]


def test_baseline_manifest_digest_precedence_and_duplicate_keys(tmp_path):
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps({'packages': [
        {'name':'fallback', 'version':'1'},
        {'nevra':'duplicate', 'sha256':'old'},
        {'package_id':'duplicate', 'source_digest_type':'SHA-512', 'source_digest':'SOURCE', 'evidence_digest_type':'sha256', 'evidence_digest':'EVIDENCE', 'sha256':'file'},
        {'package_id':'evidence', 'source_digest_type':'md5', 'source_digest':'weak', 'evidence_digest_type':'sha256', 'evidence_digest':'EVIDENCE'},
        {'package_id':'file-only', 'sha256':DIGEST},
    ]}))
    assert core.load_baseline(str(path), core.Reporter()) == {
        'fallback':'', 'duplicate':'source', 'evidence':'evidence', 'file-only':DIGEST}


def test_baseline_partition_preserves_order_duplicates_and_input_objects():
    same = package(); changed = package(checksum='cd' * 32); missing = package(identity='absent')
    ship, skip = core.split_against_baseline(iter([changed, same, missing, same]), {'demo-1.x86_64':DIGEST}, core.Reporter())
    assert ship == [changed, missing] and skip == [same, same]
    assert ship[0] is changed and skip[0] is skip[1] is same


def test_normalization_and_location_dependency_patches_remain_visible(monkeypatch):
    monkeypatch.setattr(core, 'unicodedata', SimpleNamespace(normalize=lambda form, value: 'Patched. '))
    assert core._windows_payload_key('original') == 'patched'
    monkeypatch.setattr(core, 'posixpath', SimpleNamespace(basename=lambda path: 'chosen.rpm'))
    pkg = SimpleNamespace(location='https://repo.invalid/other.rpm')
    assert core.payload_filenames([pkg], '.rpm') == {id(pkg): 'chosen.rpm'}
    monkeypatch.setattr(core, 're', SimpleNamespace(sub=lambda pattern, replacement, value: 'Hooked'))
    assert core._pep503_name('original') == 'hooked'


def test_capability_pattern_patch_remains_visible(monkeypatch):
    monkeypatch.setattr(core, '_PYDIST_CAP_RE', SimpleNamespace(fullmatch=lambda value: None))
    assert core.canonical_capability_name(' Python3Dist(Foo_Bar) ') == 'Python3Dist(Foo_Bar)'


@pytest.mark.parametrize('name', ['demo.', 'demo ', 'nested/a:b'])
def test_unsuffixed_destination_checks_remain_enforced(name):
    with pytest.raises(RuntimeError, match='not Windows-safe'):
        core.payload_filenames([SimpleNamespace(location=name)], '')


def test_payload_name_fallback_accepts_legacy_minimal_records():
    pkg = SimpleNamespace(location='demo.rpm')
    assert core.payload_filenames([pkg], '.rpm') == {id(pkg): 'demo.rpm'}
