"""Tk-independent persistence for Feathered's per-user configuration.

The caller supplies a state directory, a logging callback, and optionally an
atomic writer. This module has no dependency on App, its mixins, or tkinter;
its schema and migration behavior can be exercised without a GUI.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from urllib.parse import urlparse


class UserStateStore:
    """Own file IO, format migration, and cached per-user aliases.

    The writer is injectable to preserve legacy embedders' existing
    ``_secure_write_json`` interception points. By default the store uses its
    own atomic, private writer; callers do not need an App to use it.
    """

    def __init__(
        self,
        root: Path,
        *,
        write_json: Callable[[Path, dict[str, Any]], None] | None = None,
        log: Callable[[str], None] | None = None,
        vendor_label: Callable[[str], str] | None = None,
    ) -> None:
        self.root = Path(root)
        self._write = write_json if write_json is not None else self.write_json
        self._log = log if log is not None else (lambda _message: None)
        self._vendor_label = vendor_label if vendor_label is not None else str
        self._aliases: dict[str, Any] | None = None

    @staticmethod
    def system_root() -> Path:
        """Resolve/migrate the OS-specific state directory and protect it."""
        if sys.platform.startswith("win"):
            base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
            root, legacy = base / "Feathered", base / "Feather"
        elif sys.platform == "darwin":
            base = Path.home() / "Library" / "Application Support"
            root, legacy = base / "Feathered", base / "Feather"
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
            root, legacy = base / "feathered", base / "feather"
        if not root.exists() and legacy.is_dir():
            try:
                legacy.rename(root)
            except OSError:
                pass  # Existing behavior: an inaccessible legacy path is not fatal.
        root.mkdir(parents=True, exist_ok=True)
        try:
            root.chmod(0o700)
        except OSError:
            pass
        return root

    @staticmethod
    def write_json(path: Path, payload: dict[str, Any]) -> None:
        """Atomically publish JSON using a unique private temp and fsync."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                fd = -1
                json.dump(payload, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
            dir_fd = -1
            try:
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                dir_fd = os.open(str(path.parent), flags)
                os.fsync(dir_fd)
            except OSError:
                pass  # Some filesystems and Windows cannot sync directories.
            finally:
                if dir_fd >= 0:
                    os.close(dir_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def path(self, filename: str) -> Path:
        return self.root / filename

    @staticmethod
    def archive_identity(repo: Any) -> str:
        """Derive an archive key without ever retaining URL credentials."""
        try:
            parsed = urlparse(repo.url)
            hostname = parsed.hostname
            port = parsed.port
        except (TypeError, ValueError):
            return repo.name
        if hostname:
            host = f"[{hostname}]" if ":" in hostname else hostname
            if port is not None:
                host += f":{port}"
        else:
            host = "local"
        root = (parsed.path or "/").rstrip("/").split("/")
        return f"{host}{'/'.join(root[:3])}"

    def aliases(self) -> dict[str, Any]:
        if self._aliases is None:
            try:
                data = json.loads(self.path("workload-aliases.json").read_text(encoding="utf-8"))
            except Exception:
                data = {}
            self._aliases = data if isinstance(data, dict) else {}
        return self._aliases

    def adopt_aliases(self, cache: dict[str, Any]) -> None:
        """Adopt a preexisting alias cache from a legacy application host."""
        self._aliases = cache

    def aliases_for(self, profile_key: str, family: str) -> dict[str, str]:
        profiles = self.aliases().get(profile_key, {})
        bucket = profiles.get(family, {}) if isinstance(profiles, dict) else {}
        return dict(bucket) if isinstance(bucket, dict) else {}

    def record_aliases(
        self, profile_key: str, family: str, resolutions: Iterable[tuple[str, str]]
    ) -> bool:
        """Record new substitutions; return True iff the store changed."""
        resolutions = tuple(resolutions)
        if not resolutions:
            return False
        store = self.aliases()
        profiles = store.get(profile_key)
        if not isinstance(profiles, dict):
            profiles = {}
            store[profile_key] = profiles
        bucket = profiles.get(family)
        if not isinstance(bucket, dict):
            bucket = {}
            profiles[family] = bucket
        changed = False
        for requested, resolved in resolutions:
            if bucket.get(requested) != resolved:
                bucket[requested] = resolved
                changed = True
        if changed:
            self._write(self.path("workload-aliases.json"), store)
        return changed

    def load_keystore(self, legacy_path: Path) -> dict[str, Any]:
        path = self.path("archive-keyrings.json")
        source = path if path.is_file() else legacy_path if legacy_path.is_file() else None
        if source is None:
            return {}
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
            values = data.get("keyrings", {}) if isinstance(data, dict) else {}
            if not isinstance(values, dict):
                raise ValueError("keyrings must be a dictionary")
        except Exception as exc:
            self._log(f"Keyring store could not be read ({exc}); starting empty.")
            return {}
        if source == legacy_path and values:
            try:
                self.save_keystore(values)
                legacy_path.unlink(missing_ok=True)
                self._log("Migrated remembered archive-keyring references to the per-user Feathered configuration directory.")
            except OSError as exc:
                self._log(f"Could not migrate the legacy keyring reference store: {exc}")
        return values

    def save_keystore(self, keyrings: Mapping[str, Any]) -> None:
        self._write(self.path("archive-keyrings.json"), {"keyrings": dict(keyrings)})

    def load_vendor_signatures(self) -> dict[str, Any]:
        path = self.path("vendor-signatures.json")
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            profiles = data.get("vendors", {}) if isinstance(data, dict) else {}
            return profiles if isinstance(profiles, dict) else {}
        except Exception as exc:
            self._log(f"Vendor keyring reference store could not be read ({exc}); starting empty.")
            return {}

    def save_vendor_signatures(self, profiles: Mapping[str, Any]) -> None:
        # Only operator-selected paths and policy labels, never key material.
        self._write(self.path("vendor-signatures.json"), {"vendors": dict(profiles)})

    def load_entitlements(self, legacy_path: Path) -> dict[str, dict[str, str]] | None:
        """Load and sanitize credential *paths*, optionally migrating old state.

        ``None`` means no usable source was read, so a host may preserve its
        already-initialized in-memory profiles. A migrated legacy file is removed
        only after its replacement has been published successfully.
        """
        path = self.path("vendor-entitlements.json")
        source = path if path.is_file() else legacy_path if legacy_path.is_file() else None
        if source is None:
            return None
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
        except Exception as exc:
            self._log(f"Entitlement reference store could not be read ({exc}); ignoring it.")
            return None
        if isinstance(data, dict) and isinstance(data.get("vendors"), dict):
            profiles = data["vendors"]
        else:
            # Legacy format had one global Red Hat credential tuple.
            profiles = {"redhat": {k: str(data.get(k, "")) for k in
                                    ("cert", "key", "ca", "last_folder")}} if isinstance(data, dict) else {}
        cleaned: dict[str, dict[str, str]] = {}
        for vendor_id, profile in profiles.items():
            if not isinstance(profile, dict):
                continue
            refs = {k: str(profile.get(k, "")) for k in ("cert", "key", "ca", "last_folder")}
            missing = [refs[k] for k in ("cert", "key", "ca") if refs[k] and not Path(refs[k]).is_file()]
            if missing:
                self._log(
                    f"Remembered {self._vendor_label(vendor_id)} entitlement files are no longer present "
                    f"({len(missing)} missing); reconfigure that vendor profile when needed."
                )
                cleaned[vendor_id] = {"cert": "", "key": "", "ca": "",
                                      "last_folder": refs["last_folder"]}
            else:
                cleaned[vendor_id] = refs
        if source == legacy_path:
            try:
                self.save_entitlements(cleaned)
                legacy_path.unlink(missing_ok=True)
                self._log("Migrated entitlement file references to vendor-scoped per-user configuration.")
            except OSError as exc:
                self._log(f"Could not migrate the legacy entitlement reference store: {exc}")
        return cleaned

    def save_entitlements(self, profiles: Mapping[str, Any]) -> None:
        self._write(self.path("vendor-entitlements.json"), {"vendors": dict(profiles)})
