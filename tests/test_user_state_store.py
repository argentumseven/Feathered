"""Headless persistence contract, including legacy migrations and GUI adapters."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from feathered_app.persistence.store import UserStateStore
from feathered_app.persistence.user_state import PersistenceMixin
from feathered_app.application.sources import SourcesMixin


def _save(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def test_store_has_no_gui_or_app_dependency():
    source = Path(UserStateStore.__module__.replace(".", "/") + ".py")
    source = Path(__file__).resolve().parents[1] / source
    imports = []
    for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            imports.extend(item.name for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    assert not any(name.startswith(("tkinter", "feathered_app.context",
                                     "feathered_app.application", "app")) for name in imports)


def test_atomic_writer_publishes_private_json_without_overwriting_unrelated_temp(tmp_path):
    path = tmp_path / "archive-keyrings.json"
    stale_temp = tmp_path / "archive-keyrings.json.tmp"
    stale_temp.write_text("other writer", encoding="utf-8")
    UserStateStore.write_json(path, {"keyrings": {"archive": "/keys/trusted.gpg"}})
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "keyrings": {"archive": "/keys/trusted.gpg"}
    }
    assert stale_temp.read_text(encoding="utf-8") == "other writer"
    assert list(tmp_path.glob(".archive-keyrings.json.*.tmp")) == []
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_failed_serialization_preserves_previous_document_and_cleans_up(tmp_path):
    path = tmp_path / "state.json"
    _save(path, {"previous": "valid"})
    with pytest.raises(TypeError):
        UserStateStore.write_json(path, {"invalid": object()})
    assert json.loads(path.read_text(encoding="utf-8")) == {"previous": "valid"}
    assert not list(tmp_path.glob(".state.json.*.tmp"))


def test_legacy_directory_rename_is_one_time(tmp_path, monkeypatch):
    if os.name == "nt":
        monkeypatch.setenv("APPDATA", str(tmp_path))
        legacy, current = tmp_path / "Feather", tmp_path / "Feathered"
    elif __import__("sys").platform == "darwin":
        monkeypatch.setenv("HOME", str(tmp_path))
        legacy = tmp_path / "Library" / "Application Support" / "Feather"
        current = legacy.with_name("Feathered")
    else:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        legacy, current = tmp_path / "feather", tmp_path / "feathered"
    _save(legacy / "vendor-signatures.json", {"vendors": {"x": {"keyring": "foo"}}})
    assert UserStateStore.system_root() == current
    assert (current / "vendor-signatures.json").exists()
    assert not legacy.exists()
    if os.name == "posix":
        assert current.stat().st_mode & 0o777 == 0o700


def test_aliases_are_cached_scoped_and_only_written_when_changed(tmp_path):
    writes = []

    def writer(path, payload):
        writes.append((path, json.loads(json.dumps(payload))))

    store = UserStateStore(tmp_path, write_json=writer)
    assert store.aliases() is store.aliases()
    assert store.record_aliases("ubuntu", "deb", [("python", "python3")])
    assert not store.record_aliases("ubuntu", "deb", [("python", "python3")])
    assert store.record_aliases("ubuntu", "rpm", [("python", "python3.12")])
    assert store.aliases_for("ubuntu", "deb") == {"python": "python3"}
    assert store.aliases_for("ubuntu", "rpm") == {"python": "python3.12"}
    assert store.aliases_for("fedora", "rpm") == {}
    assert len(writes) == 2
    assert all(path == tmp_path / "workload-aliases.json" for path, _ in writes)


def test_corrupt_nested_aliases_are_not_allowed_to_break_updates(tmp_path):
    _save(tmp_path / "workload-aliases.json", {"ubuntu": {"deb": "corrupted"}})
    store = UserStateStore(tmp_path)
    assert store.aliases_for("ubuntu", "deb") == {}
    assert store.record_aliases("ubuntu", "deb", [("a", "b")])
    assert store.aliases_for("ubuntu", "deb") == {"a": "b"}


def test_archive_identity_omits_credentials_including_ipv6(tmp_path):
    store = UserStateStore(tmp_path)
    a = SimpleNamespace(url="https://user:secret@[2001:db8::1]:8443/pub/os/x86_64", name="a")
    b = SimpleNamespace(url="https://other:password@[2001:db8::1]:8443/pub/os/x86_64", name="b")
    assert store.archive_identity(a) == store.archive_identity(b)
    assert store.archive_identity(a).startswith("[2001:db8::1]:8443/")
    assert "secret" not in store.archive_identity(a)


def test_keystore_migrates_only_after_successful_atomic_write(tmp_path):
    legacy = tmp_path / "legacy" / "keyrings.json"
    _save(legacy, {"keyrings": {"archive": "/keys/keyring.gpg"}})
    state = tmp_path / "config"
    store = UserStateStore(state)
    assert store.load_keystore(legacy) == {"archive": "/keys/keyring.gpg"}
    assert not legacy.exists()
    assert json.loads((state / "archive-keyrings.json").read_text())["keyrings"] == {
        "archive": "/keys/keyring.gpg"
    }
    # Current user state always takes precedence over leftover legacy state.
    _save(legacy, {"keyrings": {"archive": "/keys/old.gpg"}})
    assert store.load_keystore(legacy)["archive"] == "/keys/keyring.gpg"
    assert legacy.exists()


def test_malformed_keystore_structure_does_not_crash_gui_initialization(tmp_path):
    _save(tmp_path / "archive-keyrings.json", {"keyrings": ["unexpected"]})
    messages = []
    store = UserStateStore(tmp_path, log=messages.append)
    assert store.load_keystore(tmp_path / "absent.json") == {}
    assert any("Keyring store could not be read" in message for message in messages)


def test_failed_keystore_migration_does_not_lose_legacy_file(tmp_path):
    legacy = tmp_path / "keyrings.json"
    _save(legacy, {"keyrings": {"archive": "present"}})
    messages = []

    def failed_writer(_path, _payload):
        raise OSError("read-only")

    store = UserStateStore(tmp_path / "current", write_json=failed_writer, log=messages.append)
    assert store.load_keystore(legacy) == {"archive": "present"}
    assert legacy.exists()
    assert any("Could not migrate" in message for message in messages)


def test_vendor_signature_schema_and_invalid_data(tmp_path):
    store = UserStateStore(tmp_path)
    store.save_vendor_signatures({"example": {"keyring": "/keys/a.gpg", "required": True}})
    assert store.load_vendor_signatures() == {
        "example": {"keyring": "/keys/a.gpg", "required": True}
    }
    _save(tmp_path / "vendor-signatures.json", {"vendors": ["invalid"]})
    assert store.load_vendor_signatures() == {}


def test_legacy_entitlement_paths_migrate_and_missing_files_are_disabled(tmp_path):
    cert = tmp_path / "valid.crt"
    cert.write_text("certificate placeholder", encoding="utf-8")
    legacy = tmp_path / "legacy" / "entitlements.json"
    _save(legacy, {"cert": str(cert), "key": str(tmp_path / "missing.key"),
                   "ca": "", "last_folder": str(tmp_path)})
    messages = []
    store = UserStateStore(tmp_path / "state", log=messages.append)
    result = store.load_entitlements(legacy)
    assert result == {"redhat": {"cert": "", "key": "", "ca": "",
                                "last_folder": str(tmp_path)}}
    assert not legacy.exists()
    assert json.loads((tmp_path / "state" / "vendor-entitlements.json").read_text())["vendors"] == result
    assert any("missing" in message for message in messages)


def test_failed_entitlement_migration_retains_legacy_file(tmp_path):
    legacy = tmp_path / "entitlements.json"
    _save(legacy, {"cert": "", "key": "", "ca": "", "last_folder": "/tmp"})

    def failed_writer(_path, _payload):
        raise OSError("no space")

    store = UserStateStore(tmp_path / "config", write_json=failed_writer)
    assert store.load_entitlements(legacy)["redhat"]["last_folder"] == "/tmp"
    assert legacy.exists()


def test_gui_legacy_adapters_delegate_to_injected_store(tmp_path):
    calls = []
    service = UserStateStore(tmp_path, write_json=lambda path, data: calls.append((path, data)))

    class Host(PersistenceMixin):
        def _log(self, message):
            raise AssertionError(f"unexpected error: {message}")

        def _legacy_program_state_path(self, name):
            return tmp_path / "absent" / name

    host = Host()
    host._user_state_store = service
    host.keystore = {"repo": "key.gpg"}
    host.vendor_signature_profiles = {"repo": {"required": True}}
    host.entitlement_profiles = {"redhat": {"cert": "", "key": "", "ca": ""}}
    host._save_keystore()
    host._save_vendor_signature_profiles()
    SourcesMixin._save_entitlement_paths(host)
    assert [path.name for path, _payload in calls] == [
        "archive-keyrings.json", "vendor-signatures.json", "vendor-entitlements.json"
    ]
    assert service is host._get_user_state_store()
