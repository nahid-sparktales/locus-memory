"""Authenticated ciphertext persistence for the memory-only transcript index."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..crypto import KeyProvider, derive_subkey
from ..errors import IntegrityError, WrongKey


class EncryptedTranscriptCache:
    FORMAT = "locus-transcript-cache/v1"

    @staticmethod
    def is_legacy(path: Path) -> bool:
        if not path.exists():
            return False
        connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "cache_settings" in tables:
                return False
            if "messages_fts" in tables or not tables:
                return True
            raise IntegrityError("unrecognized transcript cache; restore or explicitly remove it")
        finally:
            connection.close()

    def __init__(self, path: Path, keys: KeyProvider, partition: str) -> None:
        if not partition or len(partition) > 512:
            raise ValueError("a bounded partition identity is required")
        self.partition = partition
        # Resolve custody before creating any file.
        key_id = keys.current_key_id()
        self._key = derive_subkey(keys.get_key(key_id), "locus-memory/transcript-cache/v1/" + partition)
        self._cipher = AESGCM(self._key)
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA secure_delete=ON")
        try:
            with self.db:
                self.db.execute("CREATE TABLE IF NOT EXISTS cache_settings(singleton INTEGER PRIMARY KEY, key_id TEXT, proof BLOB)")
                self.db.execute("CREATE TABLE IF NOT EXISTS envelopes(token TEXT PRIMARY KEY, payload BLOB NOT NULL)")
                settings = self.db.execute("SELECT key_id,proof FROM cache_settings WHERE singleton=1").fetchone()
                if settings is None:
                    self.db.execute("INSERT INTO cache_settings VALUES(1,?,?)", (key_id, self._seal("manifest", {"format": self.FORMAT})))
                else:
                    stored_id, proof = settings
                    self._key = derive_subkey(keys.get_key(stored_id), "locus-memory/transcript-cache/v1/" + partition)
                    self._cipher = AESGCM(self._key)
                    if self._open("manifest", proof) != {"format": self.FORMAT}:
                        raise WrongKey("transcript cache manifest failed authentication")
        except BaseException:
            self.db.close()
            raise
        path.chmod(0o600)

    def _token(self, session: str) -> str:
        return hmac.new(self._key, ("session|" + session).encode(), hashlib.sha256).hexdigest()

    def _aad(self, token: str) -> bytes:
        return json.dumps([self.FORMAT, self.partition, token], separators=(",", ":")).encode()

    def _seal(self, token: str, payload: dict) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._cipher.encrypt(nonce, json.dumps(payload, ensure_ascii=False).encode(), self._aad(token))

    def _open(self, token: str, payload: bytes) -> dict:
        try:
            value = json.loads(self._cipher.decrypt(payload[:12], payload[12:], self._aad(token)))
            if not isinstance(value, dict):
                raise ValueError("not a mapping")
            return value
        except (InvalidTag, ValueError, TypeError) as exc:
            raise WrongKey("transcript cache envelope failed authentication") from exc

    def payloads(self) -> list[dict]:
        values = []
        for token, sealed in self.db.execute("SELECT token,payload FROM envelopes").fetchall():
            payload = self._open(token, sealed)
            try:
                sid = payload["session"][0]
                valid = len(payload["session"]) == 6 and self._token(sid) == token
                valid = valid and all(len(m) == 7 and m[1] == sid for m in payload["messages"])
            except (KeyError, TypeError, IndexError):
                valid = False
            if not valid:
                raise IntegrityError("invalid transcript cache envelope structure")
            values.append(payload)
        return values

    def verify(self) -> None:
        self.payloads()

    def store(self, session: str, payload: dict) -> None:
        token = self._token(session)
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO envelopes VALUES(?,?)", (token, self._seal(token, payload)))

    def forget(self, session: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM envelopes WHERE token=?", (self._token(session),))

    def clear(self) -> None:
        with self.db:
            self.db.execute("DELETE FROM envelopes")

    def close(self) -> None:
        self.db.close()
