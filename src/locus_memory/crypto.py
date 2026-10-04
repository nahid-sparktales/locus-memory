"""Envelope encryption for one partition.

* Host custody: a :class:`KeyProvider` supplies 256-bit *master* keys by id (Locus
  backs this with the macOS Keychain; the package never touches the Keychain).
* Each partition has random 256-bit data-encryption keys (DEKs) and one HMAC key,
  wrapped (AES-256-GCM) under a master key and stored in ``key_wraps``.
* Records are sealed with AES-256-GCM, random 96-bit nonces, and associated data
  that binds partition, table, record id and security-critical metadata
  (revision, lifecycle, kind, scope hash, DEK id). Moving or relabelling a row
  makes decryption fail.
* Master-key rotation re-wraps DEKs (cheap). DEK rotation re-encrypts rows
  progressively (rows carry their DEK id; see ``admin.py``). A new DEK is wrapped
  under every master key that currently wraps the vault, never only under the
  provider's "current" pointer, so a stale pointer cannot strand it. The HMAC
  key is not rotated in place.
* A missing or wrong key never causes a new key to be generated for an
  existing vault: unlock raises :class:`VaultLocked` when no wrapping master key
  is available (locked provider, key not present) and :class:`WrongKey` when an
  available key fails to authenticate the vault.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import IntegrityError, ValidationError, VaultLocked, WrongKey
from .models import canonical_json

CIPHER_NAME = "AES-256-GCM"
FORMAT_TAG = b"locus-memory/v1"
KEY_BYTES = 32
NONCE_BYTES = 12


@runtime_checkable
class KeyProvider(Protocol):
    """Host-owned master-key custody."""

    def current_key_id(self) -> str:
        """Id of the master key new wraps should use. Raise VaultLocked when locked."""

    def get_key(self, key_id: str) -> bytes:
        """Return the 32-byte key. Raise VaultLocked when locked, KeyError when unknown."""


class StaticKeyProvider:
    """In-memory provider for hosts that already hold key material (and for tests)."""

    def __init__(self, keys: Mapping[str, bytes], current: str | None = None) -> None:
        if not keys:
            raise ValidationError("at least one key is required")
        for key_id, key in keys.items():
            _check_key_id(key_id)
            if len(key) != KEY_BYTES:
                raise ValidationError("master keys must be 256-bit")
        self._keys = dict(keys)
        self._current = current or next(iter(keys))
        if self._current not in self._keys:
            raise ValidationError("the current master key id must be one of the supplied keys")
        self.locked = False

    def current_key_id(self) -> str:
        if self.locked:
            raise VaultLocked("key provider is locked")
        return self._current

    def get_key(self, key_id: str) -> bytes:
        if self.locked:
            raise VaultLocked("key provider is locked")
        return self._keys[key_id]

    def add(self, key_id: str, key: bytes, *, make_current: bool = False) -> None:
        _check_key_id(key_id)
        if len(key) != KEY_BYTES:
            raise ValidationError("master keys must be 256-bit")
        self._keys[key_id] = key
        if make_current:
            self._current = key_id

    def remove(self, key_id: str) -> None:
        self._keys.pop(key_id, None)


class FileKeyProvider:
    """Standalone/CLI custody: ``<dir>/<key_id>.key`` (0600) plus a ``current`` pointer.

    Keys are created only by :meth:`create` (exclusive create, never overwrite).
    """

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)

    def current_key_id(self) -> str:
        try:
            key_id = (self.directory / "current").read_text().strip()
        except OSError as exc:
            raise VaultLocked("no standalone key is configured; run `locus-memory init`") from exc
        _check_key_id(key_id)
        return key_id

    def get_key(self, key_id: str) -> bytes:
        _check_key_id(key_id)
        path = self.directory / f"{key_id}.key"
        try:
            value = path.read_bytes()
        except FileNotFoundError as exc:
            raise KeyError(key_id) from exc
        except OSError as exc:
            raise VaultLocked("the standalone key file is unreadable") from exc
        if len(value) != KEY_BYTES:
            raise WrongKey("the standalone key file is malformed")
        return value

    def create(self, key_id: str | None = None, *, make_current: bool = True) -> str:
        key_id = key_id or "k" + time.strftime("%Y%m%d%H%M%S") + secrets.token_hex(2)
        _check_key_id(key_id)
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass
        path = self.directory / f"{key_id}.key"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise ValidationError("a master key with this id already exists; keys are never overwritten") from exc
        try:
            os.write(fd, secrets.token_bytes(KEY_BYTES))
            os.fsync(fd)
        finally:
            os.close(fd)
        if make_current:
            tmp = self.directory / ".current.tmp"
            tmp.write_text(key_id)
            os.replace(tmp, self.directory / "current")
        return key_id

    def exists(self) -> bool:
        return (self.directory / "current").exists()


def _check_key_id(key_id: str) -> None:
    if not isinstance(key_id, str) or not (1 <= len(key_id) <= 64) or not all(
        ch.isalnum() or ch in "-_." for ch in key_id
    ):
        raise ValidationError("key id must be 1-64 characters of [A-Za-z0-9._-]")


def _hkdf_like(key: bytes, info: bytes) -> bytes:
    return hmac.new(key, FORMAT_TAG + b"|" + info, hashlib.sha256).digest()


class PartitionKeyring:
    """Unlocked key material for one partition database."""

    def __init__(self, partition_id: str, provider: KeyProvider) -> None:
        self.partition_id = partition_id
        self.provider = provider
        self._deks: dict[str, AESGCM] = {}
        self._hmac_key: bytes | None = None
        self.current_dek_id: str | None = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ wrapping
    def _wrap_aad(self, dek_id: str, master_id: str, purpose: str) -> bytes:
        return b"|".join([FORMAT_TAG, b"wrap", self.partition_id.encode(), dek_id.encode(),
                          master_id.encode(), purpose.encode()])

    def _master(self, master_id: str) -> bytes:
        try:
            master = self.provider.get_key(master_id)
        except KeyError as exc:
            raise VaultLocked("the master key is not available from the key provider") from exc
        if not isinstance(master, (bytes, bytearray)) or len(master) != KEY_BYTES:
            raise WrongKey("the key provider returned a malformed master key")
        return bytes(master)

    def _wrap(self, master_id: str, dek_id: str, purpose: str, key: bytes) -> tuple[bytes, bytes]:
        master = self._master(master_id)
        nonce = secrets.token_bytes(NONCE_BYTES)
        return nonce, AESGCM(master).encrypt(nonce, key, self._wrap_aad(dek_id, master_id, purpose))

    def initialize(self, conn: sqlite3.Connection) -> None:
        """Create DEK + HMAC key for a brand-new partition (caller holds a write tx)."""
        existing = conn.execute("SELECT COUNT(*) FROM key_wraps").fetchone()[0]
        if existing:
            raise IntegrityError("refusing to create keys for a vault that already has keys")
        master_id = self.provider.current_key_id()
        now = time.time()
        for purpose in ("data", "hmac"):
            dek_id = ("d" if purpose == "data" else "h") + secrets.token_hex(6)
            key = secrets.token_bytes(KEY_BYTES)
            nonce, wrapped = self._wrap(master_id, dek_id, purpose, key)
            conn.execute(
                "INSERT INTO key_wraps(dek_id, master_key_id, purpose, nonce, wrapped, created_at)"
                " VALUES(?,?,?,?,?,?)", (dek_id, master_id, purpose, nonce, wrapped, now),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
                ("current_dek_id" if purpose == "data" else "hmac_dek_id", dek_id),
            )

    def unlock(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            "SELECT dek_id, master_key_id, purpose, nonce, wrapped FROM key_wraps"
        ).fetchall()
        if not rows:
            raise IntegrityError("vault has no key wraps")
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
        deks: dict[str, AESGCM] = {}
        hmac_key: bytes | None = None
        failed = False  # an available master key did not authenticate its wrap
        for dek_id, master_id, purpose, nonce, wrapped in rows:
            if dek_id in deks or (purpose == "hmac" and hmac_key is not None):
                continue
            try:
                master = self.provider.get_key(master_id)  # VaultLocked propagates
            except KeyError:
                continue  # this wrap's master key is not held by the provider
            try:
                key = AESGCM(bytes(master)).decrypt(
                    bytes(nonce), bytes(wrapped), self._wrap_aad(dek_id, master_id, purpose)
                )
            except (InvalidTag, ValueError):
                failed = True  # another wrap of the same DEK may still open it
                continue
            if purpose == "hmac":
                hmac_key = key
            else:
                deks[dek_id] = AESGCM(key)
        current = meta.get("current_dek_id")
        if hmac_key is None or current not in deks:
            if failed:
                raise WrongKey("the supplied key does not authenticate this vault")
            # Nothing failed to authenticate: the needed master keys are simply unavailable.
            raise VaultLocked("no available master key opens this vault")
        with self._lock:
            self._deks = deks
            self._hmac_key = hmac_key
            self.current_dek_id = current

    @property
    def unlocked(self) -> bool:
        return self._hmac_key is not None

    def has_dek(self, dek_id: str) -> bool:
        return dek_id in self._deks

    def dek_ids(self) -> list[str]:
        return sorted(self._deks)

    def wrapped_master_ids(self, conn: sqlite3.Connection) -> list[str]:
        return [r[0] for r in conn.execute("SELECT DISTINCT master_key_id FROM key_wraps")]

    def _unwrap_all(self, conn: sqlite3.Connection) -> dict[tuple[str, str], bytes]:
        raw: dict[tuple[str, str], bytes] = {}
        for dek_id, master_id, purpose, nonce, wrapped in conn.execute(
            "SELECT dek_id, master_key_id, purpose, nonce, wrapped FROM key_wraps"
        ).fetchall():
            if (dek_id, purpose) in raw:
                continue
            try:
                master = self.provider.get_key(master_id)
            except KeyError:
                continue
            try:
                raw[(dek_id, purpose)] = AESGCM(bytes(master)).decrypt(
                    bytes(nonce), bytes(wrapped), self._wrap_aad(dek_id, master_id, purpose)
                )
            except (InvalidTag, ValueError):
                continue  # rewrap() refuses below if a DEK has no working wrap at all
        return raw

    def rewrap(self, conn: sqlite3.Connection, new_master_id: str, *, drop_old: bool) -> int:
        """Master-key rotation: wrap every DEK under ``new_master_id`` (caller holds write tx).

        The old master key must still be available. ``drop_old`` removes wraps under
        other master keys only after every DEK has a new wrap.
        """
        if not self.unlocked:
            raise VaultLocked("partition is locked")
        _check_key_id(new_master_id)
        self._master(new_master_id)  # the new key must be available before anything changes
        raw = self._unwrap_all(conn)
        needed = {(r[0], r[1]) for r in conn.execute(
            "SELECT DISTINCT dek_id, purpose FROM key_wraps").fetchall()}
        missing = needed - set(raw)
        if missing:
            raise WrongKey("not every data key could be unwrapped; keep the old master key")
        for (dek_id, purpose), key in raw.items():
            nonce, wrapped = self._wrap(new_master_id, dek_id, purpose, key)
            conn.execute(
                "INSERT OR REPLACE INTO key_wraps(dek_id, master_key_id, purpose, nonce, wrapped, created_at)"
                " VALUES(?,?,?,?,?,?)", (dek_id, new_master_id, purpose, nonce, wrapped, time.time()),
            )
        if drop_old:
            conn.execute("DELETE FROM key_wraps WHERE master_key_id <> ?", (new_master_id,))
        raw.clear()
        return len(needed)

    def new_data_key(self, conn: sqlite3.Connection) -> str:
        """DEK rotation step 1: create and make current a new data key (caller holds write tx).

        The new DEK is wrapped under every master key that wraps the current DEK and
        that the provider holds, so it opens exactly like the data it replaces.
        """
        if not self.unlocked or self.current_dek_id is None:
            raise VaultLocked("partition is locked")
        masters = []
        for (master_id,) in conn.execute(
            "SELECT DISTINCT master_key_id FROM key_wraps WHERE dek_id=? ORDER BY master_key_id",
            (self.current_dek_id,),
        ).fetchall():
            try:
                self.provider.get_key(master_id)
            except KeyError:
                continue
            masters.append(master_id)
        if not masters:
            masters = [self.provider.current_key_id()]
        dek_id = "d" + secrets.token_hex(6)
        key = secrets.token_bytes(KEY_BYTES)
        for master_id in masters:
            nonce, wrapped = self._wrap(master_id, dek_id, "data", key)
            conn.execute(
                "INSERT INTO key_wraps(dek_id, master_key_id, purpose, nonce, wrapped, created_at)"
                " VALUES(?,?,?,?,?,?)", (dek_id, master_id, "data", nonce, wrapped, time.time()),
            )
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('current_dek_id', ?)", (dek_id,))
        with self._lock:
            self._deks[dek_id] = AESGCM(key)
            self.current_dek_id = dek_id
        return dek_id

    def retire_data_key(self, conn: sqlite3.Connection, dek_id: str) -> None:
        if dek_id == self.current_dek_id:
            raise ValidationError("cannot retire the current data key")
        conn.execute("DELETE FROM key_wraps WHERE dek_id=? AND purpose='data'", (dek_id,))
        with self._lock:
            self._deks.pop(dek_id, None)

    # ------------------------------------------------------------------ sealing
    def aad(self, table: str, row_id: str, fields: Mapping[str, object]) -> bytes:
        return b"|".join([
            FORMAT_TAG, self.partition_id.encode(), table.encode(), row_id.encode(),
            canonical_json(dict(fields)).encode(),
        ])

    def seal(self, table: str, row_id: str, fields: Mapping[str, object], plaintext: bytes
             ) -> tuple[str, bytes, bytes]:
        if not self.unlocked or self.current_dek_id is None:
            raise VaultLocked("partition is locked")
        dek_id = self.current_dek_id
        aad = self.aad(table, row_id, {**fields, "dek": dek_id})
        nonce = secrets.token_bytes(NONCE_BYTES)
        return dek_id, nonce, self._deks[dek_id].encrypt(nonce, plaintext, aad)

    def open(self, table: str, row_id: str, fields: Mapping[str, object], dek_id: str,
             nonce: bytes, ciphertext: bytes) -> bytes:
        if not self.unlocked:
            raise VaultLocked("partition is locked")
        cipher = self._deks.get(dek_id)
        if cipher is None:
            raise WrongKey("the data key for this record is unavailable")
        try:
            return cipher.decrypt(bytes(nonce), bytes(ciphertext),
                                  self.aad(table, row_id, {**fields, "dek": dek_id}))
        except InvalidTag as exc:
            # Generic on purpose: never echo content or which field mismatched.
            raise IntegrityError("a stored record failed authentication") from exc

    def token(self, purpose: str, value: str) -> str:
        """Keyed, non-reversible token for metadata that must be queryable."""
        if self._hmac_key is None:
            raise VaultLocked("partition is locked")
        return hmac.new(self._hmac_key, f"{purpose}\x00{value}".encode(), hashlib.sha256).hexdigest()[:40]

    def tokens(self, purpose: str, values: Iterable[str]) -> list[str]:
        return [self.token(purpose, value) for value in values]

    def close(self) -> None:
        with self._lock:
            self._deks = {}
            self._hmac_key = None
            self.current_dek_id = None


def derive_subkey(master: bytes, info: str) -> bytes:
    """Deterministic subkey derivation (used by hosts that keep a single master key)."""
    if len(master) != KEY_BYTES:
        raise ValidationError("master key must be 256-bit")
    return _hkdf_like(master, info.encode())
