"""The payload cache is bounded, best effort, and removes entries it cannot use.

It used to keep every payload of every build forever, abort a build when the
cache directory was unusable or the disk filled, and retry tampered or
unverifiable entries on every later build. These tests pin the repaired
behaviour; the guards at the end pin what must not change.
"""
import errno
import hashlib
import os
import shutil
import time
from pathlib import Path

import pytest

import artifact_cache
import core
import runtime_limits
from core import BuildOptions, Reporter
from test_feather import APT_REPO, deb_pkg

HOUR = 3600
DAY = 86400


@pytest.fixture(autouse=True)
def _fresh_reports(monkeypatch):
    monkeypatch.setattr(artifact_cache, "_reported", set(), raising=False)


def _limits(monkeypatch, *, bytes_=1_000_000, days=30):
    monkeypatch.setattr(runtime_limits, "PAYLOAD_CACHE_MAX_BYTES", bytes_)
    monkeypatch.setattr(runtime_limits, "PAYLOAD_CACHE_MAX_AGE_DAYS", days)


def _package(tmp_path, name, size=1000, *, seed=None):
    """A package and a verified source file for it."""
    data = hashlib.sha256((seed or name).encode()).digest() * (size // 32 + 1)
    data = data[:size]
    source = tmp_path / f"src-{name}.deb"
    source.write_bytes(data)
    pkg = deb_pkg(name, "1", APT_REPO)
    pkg.checksum = hashlib.sha256(data).hexdigest()
    return pkg, source


def _remember(tmp_path, name, size=1000, **kwargs):
    pkg, source = _package(tmp_path, name, size, **kwargs)
    artifact_cache.remember(pkg, source, tmp_path, Reporter())
    return pkg


def _cache(tmp_path):
    return tmp_path / ".feathered-cache"


def _age(tmp_path, pkg, seconds):
    """Make one package's cache entry (and its payload) look `seconds` old."""
    entry = _cache(tmp_path) / (artifact_cache._key(pkg) + ".json")
    digest = pkg.checksum
    then = time.time() - seconds
    for path in (entry, _cache(tmp_path) / (digest + ".payload")):
        os.utime(path, (then, then))


def _restorable(tmp_path, pkg):
    dest = tmp_path / f"probe-{pkg.name}-{time.monotonic_ns()}.deb"
    artifact_cache.restore(pkg, dest, tmp_path, BuildOptions(), Reporter())
    return dest.exists()


def _prune(tmp_path, packages=(), log=None):
    reporter = Reporter() if log is None else Reporter(log=log.append)
    artifact_cache.prune(tmp_path, packages, reporter)


def _payloads(tmp_path):
    return sorted(p.name for p in _cache(tmp_path).glob("*.payload"))


# --- growth ---------------------------------------------------------------

def test_cache_is_trimmed_to_the_size_limit_oldest_use_first(tmp_path, monkeypatch):
    _limits(monkeypatch, bytes_=2500)
    packages = [_remember(tmp_path, f"p{i}", 1000) for i in range(5)]
    for age, pkg in zip((50, 40, 30, 20, 10), packages):
        _age(tmp_path, pkg, age * 60)

    _prune(tmp_path)

    assert [_restorable(tmp_path, p) for p in packages] == [False, False, False, True, True]
    assert len(_payloads(tmp_path)) == 2


def test_what_this_build_used_is_kept_even_when_it_exceeds_the_limit(tmp_path, monkeypatch):
    _limits(monkeypatch, bytes_=1500)
    older = [_remember(tmp_path, f"old{i}", 1000) for i in range(2)]
    current = [_remember(tmp_path, f"new{i}", 1000) for i in range(3)]
    for pkg in older:
        _age(tmp_path, pkg, DAY)

    _prune(tmp_path, packages=current)

    assert all(_restorable(tmp_path, p) for p in current)
    assert not any(_restorable(tmp_path, p) for p in older)


def test_recent_use_keeps_an_entry_ahead_of_older_untouched_ones(tmp_path, monkeypatch):
    _limits(monkeypatch, bytes_=1500)
    first = _remember(tmp_path, "first", 1000)
    second = _remember(tmp_path, "second", 1000)
    _age(tmp_path, first, 3 * HOUR)
    _age(tmp_path, second, 2 * HOUR)

    assert _restorable(tmp_path, first)  # a restore counts as use
    _prune(tmp_path)

    assert _restorable(tmp_path, first)
    assert not _restorable(tmp_path, second)


def test_entries_expire_by_age_even_under_the_size_limit(tmp_path, monkeypatch):
    _limits(monkeypatch, bytes_=10_000_000, days=30)
    stale = _remember(tmp_path, "stale")
    fresh = _remember(tmp_path, "fresh")
    _age(tmp_path, stale, 31 * DAY)

    _prune(tmp_path)

    assert not _restorable(tmp_path, stale)
    assert _restorable(tmp_path, fresh)


def test_zero_days_means_no_age_limit(tmp_path, monkeypatch):
    _limits(monkeypatch, bytes_=10_000_000, days=0)
    ancient = _remember(tmp_path, "ancient")
    _age(tmp_path, ancient, 900 * DAY)

    _prune(tmp_path)

    assert _restorable(tmp_path, ancient)


def test_a_payload_shared_by_two_entries_survives_until_both_go(tmp_path, monkeypatch):
    _limits(monkeypatch, bytes_=10_000_000, days=30)
    first, source = _package(tmp_path, "mirror-a", seed="same-bytes")
    second = deb_pkg("mirror-b", "1", APT_REPO)
    second.checksum = first.checksum
    artifact_cache.remember(first, source, tmp_path, Reporter())
    artifact_cache.remember(second, source, tmp_path, Reporter())
    _age(tmp_path, first, 31 * DAY)
    entry = _cache(tmp_path) / (artifact_cache._key(second) + ".json")

    _prune(tmp_path)

    assert entry.exists() and len(_payloads(tmp_path)) == 1
    assert _restorable(tmp_path, second)


# --- housekeeping ---------------------------------------------------------

def test_abandoned_files_are_removed_but_recent_ones_and_strangers_are_not(tmp_path, monkeypatch):
    _limits(monkeypatch)
    root = _cache(tmp_path)
    kept = _remember(tmp_path, "kept")
    old = time.time() - 2 * HOUR
    orphan_old = root / ("a" * 64 + ".payload")
    orphan_new = root / ("b" * 64 + ".payload")
    temp_old = root / ".tmp-abandoned"
    temp_legacy = root / "tmpab12cd_9"
    temp_new = root / ".tmp-in-flight"
    stranger = root / "notes.txt"
    for path in (orphan_old, orphan_new, temp_old, temp_legacy, temp_new, stranger):
        path.write_bytes(b"x" * 10)
    for path in (orphan_old, temp_old, temp_legacy):
        os.utime(path, (old, old))

    _prune(tmp_path)

    assert not orphan_old.exists() and not temp_old.exists() and not temp_legacy.exists()
    assert orphan_new.exists() and temp_new.exists()  # another build may be mid-write
    assert stranger.exists()                          # not ours to delete
    assert _restorable(tmp_path, kept)


def test_dangling_and_corrupt_index_entries_are_removed(tmp_path, monkeypatch):
    _limits(monkeypatch)
    root = _cache(tmp_path)
    good = _remember(tmp_path, "good")
    dangling = _remember(tmp_path, "dangling")
    (root / (dangling.checksum + ".payload")).unlink()
    corrupt = root / ("c" * 64 + ".json")
    corrupt.write_text("not json")
    os.utime(corrupt, (time.time() - 2 * HOUR,) * 2)

    _prune(tmp_path)

    assert not (root / (artifact_cache._key(dangling) + ".json")).exists()
    assert not corrupt.exists()
    assert _restorable(tmp_path, good)


def test_pruning_does_not_follow_symlinks_out_of_the_cache(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("symlink creation needs privileges on Windows")
    _limits(monkeypatch, bytes_=1)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "important.payload"
    victim.write_bytes(b"keep me")
    _remember(tmp_path, "one")
    link = _cache(tmp_path) / ("d" * 64 + ".payload")
    link.symlink_to(victim)

    _prune(tmp_path)

    assert victim.read_bytes() == b"keep me" and link.is_symlink()


def test_pruning_refuses_to_work_inside_a_symlinked_cache(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("symlink creation needs privileges on Windows")
    _limits(monkeypatch, bytes_=1)
    target = tmp_path / "elsewhere"
    target.mkdir()
    victim = target / ("e" * 64 + ".payload")
    victim.write_bytes(b"x" * 100)
    os.utime(victim, (time.time() - 2 * HOUR,) * 2)
    _cache(tmp_path).symlink_to(target)
    log = []

    _prune(tmp_path, log=log)

    assert victim.exists()
    assert any("Payload cache not used" in line for line in log)


def test_pruning_never_raises(tmp_path, monkeypatch):
    _limits(monkeypatch)
    _remember(tmp_path, "one")
    monkeypatch.setattr(artifact_cache.os, "scandir", lambda *_: (_ for _ in ()).throw(OSError("denied")))
    log = []

    _prune(tmp_path, log=log)

    assert any("cleanup skipped" in line for line in log)


# --- a cache problem is never a build failure -----------------------------

def test_an_unusable_cache_directory_means_no_cache_not_a_failed_build(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("symlink creation needs privileges on Windows")
    _limits(monkeypatch)
    (tmp_path / "elsewhere").mkdir()
    _cache(tmp_path).symlink_to(tmp_path / "elsewhere")
    log = []
    pkg, source = _package(tmp_path, "one")

    artifact_cache.remember(pkg, source, tmp_path, Reporter(log=log.append))
    artifact_cache.remember(pkg, source, tmp_path, Reporter(log=log.append))
    dest = tmp_path / "restored.deb"
    artifact_cache.restore(pkg, dest, tmp_path, BuildOptions(), Reporter(log=log.append))

    assert not dest.exists()
    assert not list((tmp_path / "elsewhere").iterdir())
    assert sum("Payload cache not used" in line for line in log) == 1  # said once, not per package


def test_a_world_writable_cache_directory_means_no_cache_not_a_failed_build(tmp_path, monkeypatch):
    if os.name == "nt" or not hasattr(os, "geteuid"):
        pytest.skip("POSIX permission checks are not available")
    _limits(monkeypatch)
    _cache(tmp_path).mkdir()
    _cache(tmp_path).chmod(0o777)
    pkg, source = _package(tmp_path, "one")

    artifact_cache.remember(pkg, source, tmp_path, Reporter())

    assert not list(_cache(tmp_path).iterdir())


def test_a_full_disk_while_caching_leaves_no_debris_and_does_not_fail(tmp_path, monkeypatch):
    _limits(monkeypatch)
    real = shutil.copyfile

    def full(src, dst, *args, **kwargs):
        if ".feathered-cache" in str(dst):
            Path(dst).write_bytes(b"partial")
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(src, dst, *args, **kwargs)

    monkeypatch.setattr(artifact_cache.shutil, "copyfile", full)
    pkg, source = _package(tmp_path, "one")

    artifact_cache.remember(pkg, source, tmp_path, Reporter())

    assert list(_cache(tmp_path).iterdir()) == []


def test_the_cache_does_not_take_the_last_of_the_free_space(tmp_path, monkeypatch):
    _limits(monkeypatch)
    free = 100 * 1024 * 1024
    monkeypatch.setattr(artifact_cache.shutil, "disk_usage",
                        lambda _path: shutil._ntuple_diskusage(10 * free, 9 * free, free))
    log = []
    pkg, source = _package(tmp_path, "one", 1000)

    artifact_cache.remember(pkg, source, tmp_path, Reporter(log=log.append))

    assert not _payloads(tmp_path)
    assert any("not enough free space" in line for line in log)


def test_cancellation_is_not_swallowed_by_cache_error_handling(tmp_path, monkeypatch):
    _limits(monkeypatch)
    pkg, source = _package(tmp_path, "one")
    cancelled = core.Reporter(cancel_event=type("Event", (), {"is_set": lambda self: True})())

    with pytest.raises(core.Cancelled):
        artifact_cache.remember(pkg, source, tmp_path, cancelled)


# --- entries that cannot be restored are not retried forever --------------

def test_a_tampered_payload_is_removed_when_found(tmp_path, monkeypatch):
    _limits(monkeypatch)
    pkg = _remember(tmp_path, "one")
    (_cache(tmp_path) / (pkg.checksum + ".payload")).write_bytes(b"changed")

    assert not _restorable(tmp_path, pkg)

    assert list(_cache(tmp_path).iterdir()) == []


def test_an_entry_that_fails_verification_is_not_offered_again(tmp_path, monkeypatch):
    _limits(monkeypatch)
    pkg = _remember(tmp_path, "one")
    entry = _cache(tmp_path) / (artifact_cache._key(pkg) + ".json")
    monkeypatch.setattr(core, "verify_package_artifact",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("signature rejected")))

    assert not _restorable(tmp_path, pkg)

    assert not entry.exists()


@pytest.mark.parametrize("text", ["[]", "{}", '{"sha256": 7}', "null", "\x00"])
def test_a_malformed_index_entry_is_dropped_instead_of_crashing(tmp_path, monkeypatch, text):
    _limits(monkeypatch)
    pkg, _source = _package(tmp_path, "one")
    _cache(tmp_path).mkdir()
    entry = _cache(tmp_path) / (artifact_cache._key(pkg) + ".json")
    entry.write_text(text)

    assert not _restorable(tmp_path, pkg)

    assert not entry.exists()


def test_a_failed_restore_copy_leaves_no_partial_file(tmp_path, monkeypatch):
    _limits(monkeypatch)
    pkg = _remember(tmp_path, "one")
    real = shutil.copyfile

    def partial(src, dst, *args, **kwargs):
        if str(dst).startswith(str(tmp_path / "probe")):
            Path(dst).write_bytes(b"half")
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(src, dst, *args, **kwargs)

    monkeypatch.setattr(artifact_cache.shutil, "copyfile", partial)

    assert not _restorable(tmp_path, pkg)
    assert not list(tmp_path.glob("probe-*"))


# --- the cache can be turned off -----------------------------------------

def test_zero_bytes_turns_the_cache_off_entirely(tmp_path, monkeypatch):
    _limits(monkeypatch, bytes_=0)
    pkg, source = _package(tmp_path, "one")

    artifact_cache.remember(pkg, source, tmp_path, Reporter())
    dest = tmp_path / "restored.deb"
    artifact_cache.restore(pkg, dest, tmp_path, BuildOptions(), Reporter())
    artifact_cache.prune(tmp_path, [pkg], Reporter())

    assert not _cache(tmp_path).exists() and not dest.exists()


def test_environment_variables_set_the_limits(monkeypatch):
    monkeypatch.setenv("FEATHERED_PAYLOAD_CACHE_BYTES", "0")
    monkeypatch.setenv("FEATHERED_PAYLOAD_CACHE_DAYS", "not a number")
    assert runtime_limits.nonnegative_env_int("FEATHERED_PAYLOAD_CACHE_BYTES", 7) == 0
    assert runtime_limits.nonnegative_env_int("FEATHERED_PAYLOAD_CACHE_DAYS", 30) == 30
    monkeypatch.setenv("FEATHERED_PAYLOAD_CACHE_BYTES", "-5")
    assert runtime_limits.nonnegative_env_int("FEATHERED_PAYLOAD_CACHE_BYTES", 7) == 7


# --- through a real build --------------------------------------------------

def _build(tmp_path, number, size, monkeypatch=None):
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    repo = core.RepoSpec("Fixture", source_dir.as_uri() + "/", repo_format="rpm", suite="fixture",
                         allow_unverified_index=True)
    content = hashlib.sha256(str(number).encode()).digest() * (size // 32)
    name = f"demo-{number}.rpm"
    (source_dir / name).write_bytes(content)
    pkg = core.Package("demo", "x86_64", "0", f"1.{number}", "1", name, "sha256",
                       hashlib.sha256(content).hexdigest(), repo, size=len(content))
    result = core.ResolutionResult([pkg], [], [pkg], reasons={pkg.nevra: "requested"})
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    bundle = out / "bundle"
    shutil.rmtree(bundle, ignore_errors=True)
    core.write_bundle(result, bundle, BuildOptions(emit_repository=False), Reporter(),
                      {"distribution": "F", "release": "1", "arch": "x86_64", "package_family": "rpm",
                       "workload": "w", "repositories": [{"name": "F", "url": repo.url}]})
    return out / ".feathered-cache"


def test_repeated_refreshes_do_not_grow_the_cache_without_bound(tmp_path, monkeypatch):
    _limits(monkeypatch, bytes_=250_000)
    sizes = []
    for number in range(1, 13):
        cache = _build(tmp_path, number, 100_000)
        sizes.append(sum(p.stat().st_size for p in cache.iterdir()))

    assert max(sizes) <= 250_000 + 200  # two payloads fit; index entries are tiny
    assert sizes[-1] == sizes[-2]
    assert len(list(cache.glob("*.payload"))) == 2


def test_a_cancelled_or_failed_build_still_leaves_its_downloads_to_resume_from(tmp_path, monkeypatch):
    _limits(monkeypatch, bytes_=1)  # smaller than anything: only "used this build" protection remains
    first = _remember(tmp_path, "downloaded")
    old = _remember(tmp_path, "unrelated")
    _age(tmp_path, old, DAY)

    artifact_cache.prune(tmp_path, [first], Reporter())

    assert _restorable(tmp_path, first)
    assert not _restorable(tmp_path, old)


def test_a_cached_payload_still_restores_and_is_reverified(tmp_path, monkeypatch):
    _limits(monkeypatch)
    pkg, source = _package(tmp_path, "one")
    artifact_cache.remember(pkg, source, tmp_path, Reporter())
    dest = tmp_path / "restored.deb"
    log = []

    artifact_cache.restore(pkg, dest, tmp_path, BuildOptions(), Reporter(log=log.append))

    assert dest.read_bytes() == source.read_bytes()
    assert any("Restored verified payload cache" in line for line in log)
