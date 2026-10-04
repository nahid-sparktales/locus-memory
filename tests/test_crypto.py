"""Envelope encryption: key custody, AAD binding, unlock failure modes, rotation primitives."""
from __future__ import annotations

import os
import secrets
import sqlite3
import stat

import pytest

from locus_memory.crypto import (
    KEY_BYTES,
    FileKeyProvider,
    KeyProvider,
    PartitionKeyring,
    StaticKeyProvider,
    derive_subkey,
)
from locus_memory.errors import IntegrityError, NotFound, ValidationError, VaultLocked, WrongKey
from locus_memory.storage import schema

PID = "p" + "0" * 31


def _store() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("BEGIN")
    schema.migrate(conn, partition_id=PID)
    conn.execute("COMMIT")
    return conn


def _vault(provider, pid: str = PID) -> tuple[sqlite3.Connection, PartitionKeyring]:
    conn = _store() if pid == PID else _store_for(pid)
    ring = PartitionKeyring(pid, provider)
    ring.initialize(conn)
    ring.unlock(conn)
    return conn, ring


def _store_for(pid: str) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", isolation_level=None)
    schema.migrate(conn, partition_id=pid)
    return conn


def _wraps(conn) -> list[tuple]:
    return conn.execute("SELECT dek_id, master_key_id, purpose, nonce, wrapped FROM key_wraps"
                        " ORDER BY dek_id, master_key_id").fetchall()


# ---------------------------------------------------------------------------- providers
def test_static_provider_validation_and_lock():
    with pytest.raises(ValidationError):
        StaticKeyProvider({})
    with pytest.raises(ValidationError):
        StaticKeyProvider({"k1": b"short"})
    with pytest.raises(ValidationError):
        StaticKeyProvider({"k1": secrets.token_bytes(32)}, current="k2")
    with pytest.raises(ValidationError):
        StaticKeyProvider({"bad id!": secrets.token_bytes(32)})
    provider = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    assert isinstance(provider, KeyProvider)
    provider.locked = True
    with pytest.raises(VaultLocked):
        provider.current_key_id()
    with pytest.raises(VaultLocked):
        provider.get_key("k1")


def test_file_provider_creates_private_keys_and_never_overwrites(tmp_path):
    directory = tmp_path / "keys"
    provider = FileKeyProvider(directory)
    assert not provider.exists()
    with pytest.raises(VaultLocked):
        provider.current_key_id()
    key_id = provider.create("k1")
    assert provider.current_key_id() == "k1" and provider.exists()
    key_file = directory / "k1.key"
    original = key_file.read_bytes()
    assert len(original) == KEY_BYTES
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert provider.get_key(key_id) == original
    # Re-creating an existing id is refused and the key material is untouched.
    with pytest.raises(ValidationError):
        provider.create("k1")
    assert key_file.read_bytes() == original
    with pytest.raises(KeyError):
        provider.get_key("k-missing")
    with pytest.raises(ValidationError):
        provider.get_key("../k1")
    second = provider.create(make_current=False)
    assert provider.current_key_id() == "k1" and second != "k1"
    (directory / "bad.key").write_bytes(b"x" * 5)
    with pytest.raises(WrongKey):
        provider.get_key("bad")


def _key_dir_entries(directory) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


def test_file_provider_set_current_validates_the_key_file_and_switches_the_pointer(tmp_path):
    directory = tmp_path / "keys"
    provider = FileKeyProvider(directory)
    provider.create("k1")
    provider.create("k2", make_current=False)
    assert provider.current_key_id() == "k1"
    provider.set_current("k2")
    assert provider.current_key_id() == "k2" and FileKeyProvider(directory).current_key_id() == "k2"
    assert (directory / "current").read_text() == "k2"
    assert stat.S_IMODE((directory / "current").stat().st_mode) == 0o600
    assert _key_dir_entries(directory) == ["current", "k1.key", "k2.key"]  # no temporary file left behind
    provider.set_current("k1")  # switching back is allowed: both keys exist
    assert provider.current_key_id() == "k1"


@pytest.mark.parametrize("content", [b"x" * 5, b"x" * (KEY_BYTES + 1), b""])
def test_file_provider_set_current_refuses_missing_malformed_or_invalid_keys(tmp_path, content):
    directory = tmp_path / "keys"
    provider = FileKeyProvider(directory)
    provider.create("k1")
    (directory / "bad.key").write_bytes(content)
    (directory / "dir.key").mkdir()
    before = _key_dir_entries(directory)
    with pytest.raises(NotFound):
        provider.set_current("k-missing")
    with pytest.raises(ValidationError):
        provider.set_current("bad")
    with pytest.raises(ValidationError):
        provider.set_current("dir")
    for invalid in ("../k1", "", "a" * 65, "k1/../k1"):
        with pytest.raises(ValidationError):
            provider.set_current(invalid)
    # Every refusal leaves the pointer and the directory exactly as they were.
    assert provider.current_key_id() == "k1" and _key_dir_entries(directory) == before
    with pytest.raises(NotFound):
        FileKeyProvider(tmp_path / "no-such-dir").set_current("k1")
    assert not (tmp_path / "no-such-dir").exists()


def test_file_provider_set_current_is_atomic_when_the_replace_fails(tmp_path, monkeypatch):
    directory = tmp_path / "keys"
    provider = FileKeyProvider(directory)
    provider.create("k1")
    provider.create("k2", make_current=False)
    before = _key_dir_entries(directory)

    def failing_replace(src, dst):
        raise OSError("simulated failure")

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(OSError):
        provider.set_current("k2")
    monkeypatch.undo()
    assert provider.current_key_id() == "k1"
    assert _key_dir_entries(directory) == before  # the temporary pointer file was removed


# ---------------------------------------------------------------------------- sealing
def test_seal_open_roundtrip_and_ciphertext_hides_plaintext():
    conn, ring = _vault(StaticKeyProvider({"k1": secrets.token_bytes(32)}))
    plaintext = b"the user prefers tabs"
    dek, nonce, ct = ring.seal("records", "m1", {"lifecycle": "approved"}, plaintext)
    assert dek == ring.current_dek_id and len(nonce) == 12
    assert plaintext not in ct
    assert ring.open("records", "m1", {"lifecycle": "approved"}, dek, nonce, ct) == plaintext


@pytest.mark.parametrize("change", ["table", "row", "field", "extra_field", "nonce", "ciphertext", "dek"])
def test_any_change_to_bound_context_fails_authentication(change):
    conn, ring = _vault(StaticKeyProvider({"k1": secrets.token_bytes(32)}))
    fields = {"lifecycle": "candidate", "revision": 1}
    dek, nonce, ct = ring.seal("records", "m1", fields, b"secret")
    args = {"table": "records", "row_id": "m1", "fields": dict(fields), "dek_id": dek, "nonce": nonce,
            "ciphertext": ct}
    if change == "table":
        args["table"] = "record_revisions"
    elif change == "row":
        args["row_id"] = "m2"
    elif change == "field":
        args["fields"]["lifecycle"] = "approved"
    elif change == "extra_field":
        args["fields"]["scope"] = "x"
    elif change == "nonce":
        args["nonce"] = bytes([nonce[0] ^ 1]) + nonce[1:]
    elif change == "ciphertext":
        args["ciphertext"] = ct[:-1] + bytes([ct[-1] ^ 1])
    if change == "dek":
        with pytest.raises(WrongKey):
            ring.open(args["table"], args["row_id"], args["fields"], "d-unknown", nonce, ct)
        return
    with pytest.raises(IntegrityError) as exc:
        ring.open(args["table"], args["row_id"], args["fields"], args["dek_id"], args["nonce"], args["ciphertext"])
    assert "secret" not in str(exc.value)


def test_ciphertext_is_bound_to_its_partition():
    provider = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    conn, ring = _vault(provider)
    dek, nonce, ct = ring.seal("records", "m1", {}, b"x")
    # Same key material, different partition id: the AAD differs, so it cannot be opened.
    other = PartitionKeyring("p" + "1" * 31, provider)
    other._deks, other._hmac_key, other.current_dek_id = ring._deks, b"h" * 32, ring.current_dek_id
    with pytest.raises(IntegrityError):
        other.open("records", "m1", {}, dek, nonce, ct)


def test_nonces_are_unique():
    conn, ring = _vault(StaticKeyProvider({"k1": secrets.token_bytes(32)}))
    nonces = {ring.seal("t", "r", {}, b"x")[1] for _ in range(2_000)}
    assert len(nonces) == 2_000


def test_tokens_are_keyed_and_purpose_separated():
    provider = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    _, ring = _vault(provider)
    _, ring2 = _vault(provider)  # a different vault has a different HMAC key
    assert ring.token("scope", "p") == ring.token("scope", "p")
    assert ring.token("scope", "p") != ring.token("source", "p")
    assert ring.token("scope", "p") != ring2.token("scope", "p")
    assert len(ring.token("x", "y")) == 40 and "y" not in ring.token("x", "y")
    ring.close()
    with pytest.raises(VaultLocked):
        ring.token("scope", "p")
    with pytest.raises(VaultLocked):
        ring.seal("t", "r", {}, b"x")


# ---------------------------------------------------------------------------- unlock failure modes
def test_initialize_refuses_an_existing_vault():
    conn, ring = _vault(StaticKeyProvider({"k1": secrets.token_bytes(32)}))
    before = _wraps(conn)
    with pytest.raises(IntegrityError):
        ring.initialize(conn)
    assert _wraps(conn) == before


def test_wrong_master_key_bytes_raise_wrong_key():
    conn, _ = _vault(StaticKeyProvider({"k1": secrets.token_bytes(32)}))
    before = _wraps(conn)
    with pytest.raises(WrongKey):
        PartitionKeyring(PID, StaticKeyProvider({"k1": secrets.token_bytes(32)})).unlock(conn)
    assert _wraps(conn) == before


def test_missing_master_key_raises_vault_locked():
    conn, _ = _vault(StaticKeyProvider({"k1": secrets.token_bytes(32)}))
    before = _wraps(conn)
    with pytest.raises(VaultLocked):
        PartitionKeyring(PID, StaticKeyProvider({"k9": secrets.token_bytes(32)})).unlock(conn)
    locked = StaticKeyProvider({"k1": secrets.token_bytes(32)})
    locked.locked = True
    with pytest.raises(VaultLocked):
        PartitionKeyring(PID, locked).unlock(conn)
    assert _wraps(conn) == before


def test_unlock_survives_one_bad_wrap_when_another_wrap_opens_the_keys():
    k1, k2 = secrets.token_bytes(32), secrets.token_bytes(32)
    conn, ring = _vault(StaticKeyProvider({"k1": k1, "k2": k2}))
    ring.rewrap(conn, "k2", drop_old=False)
    # The provider's "k1" is now wrong (e.g. re-issued) but "k2" still opens every key.
    survivor = PartitionKeyring(PID, StaticKeyProvider({"k1": secrets.token_bytes(32), "k2": k2}))
    survivor.unlock(conn)
    assert survivor.current_dek_id == ring.current_dek_id


# ---------------------------------------------------------------------------- rotation primitives
def test_rewrap_moves_every_key_to_the_new_master():
    k1, k2 = secrets.token_bytes(32), secrets.token_bytes(32)
    provider = StaticKeyProvider({"k1": k1, "k2": k2})
    conn, ring = _vault(provider)
    dek, nonce, ct = ring.seal("t", "r", {}, b"payload")
    assert ring.rewrap(conn, "k2", drop_old=True) == 2
    assert ring.wrapped_master_ids(conn) == ["k2"]
    only_new = PartitionKeyring(PID, StaticKeyProvider({"k2": k2}))
    only_new.unlock(conn)
    assert only_new.open("t", "r", {}, dek, nonce, ct) == b"payload"
    with pytest.raises(VaultLocked):
        PartitionKeyring(PID, StaticKeyProvider({"k1": k1})).unlock(conn)


def test_rewrap_to_an_unavailable_master_changes_nothing():
    conn, ring = _vault(StaticKeyProvider({"k1": secrets.token_bytes(32)}))
    before = _wraps(conn)
    with pytest.raises(VaultLocked):
        ring.rewrap(conn, "k-missing", drop_old=True)
    with pytest.raises(ValidationError):
        ring.rewrap(conn, "bad id", drop_old=True)
    assert _wraps(conn) == before


def test_new_data_key_follows_the_vault_masters_not_a_stale_provider_pointer():
    k1, k2 = secrets.token_bytes(32), secrets.token_bytes(32)
    provider = StaticKeyProvider({"k1": k1, "k2": k2}, current="k1")
    conn, ring = _vault(provider)
    ring.rewrap(conn, "k2", drop_old=True)  # host has not moved its "current" pointer yet
    old_dek = ring.current_dek_id
    new_dek = ring.new_data_key(conn)
    assert new_dek != old_dek
    masters = {r[0] for r in conn.execute("SELECT master_key_id FROM key_wraps WHERE dek_id=?", (new_dek,))}
    assert masters == {"k2"}
    # After the host deletes the old master key, the new DEK still opens.
    dek, nonce, ct = ring.seal("t", "r", {}, b"after rotation")
    fresh = PartitionKeyring(PID, StaticKeyProvider({"k2": k2}))
    fresh.unlock(conn)
    assert fresh.current_dek_id == new_dek
    assert fresh.open("t", "r", {}, dek, nonce, ct) == b"after rotation"


def test_old_data_key_stays_usable_until_retired():
    conn, ring = _vault(StaticKeyProvider({"k1": secrets.token_bytes(32)}))
    old = ring.current_dek_id
    sealed = ring.seal("t", "r", {}, b"old row")
    ring.new_data_key(conn)
    assert ring.open("t", "r", {}, *sealed) == b"old row"
    with pytest.raises(ValidationError):
        ring.retire_data_key(conn, ring.current_dek_id)
    ring.retire_data_key(conn, old)
    assert not ring.has_dek(old)
    with pytest.raises(WrongKey):
        ring.open("t", "r", {}, *sealed)


def test_derive_subkey():
    master = secrets.token_bytes(32)
    assert derive_subkey(master, "a") == derive_subkey(master, "a")
    assert derive_subkey(master, "a") != derive_subkey(master, "b")
    assert len(derive_subkey(master, "a")) == 32
    with pytest.raises(ValidationError):
        derive_subkey(b"short", "a")


def test_key_files_are_not_world_readable_even_with_permissive_umask(tmp_path):
    old = os.umask(0)
    try:
        provider = FileKeyProvider(tmp_path / "k")
        provider.create("k1")
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "k" / "k1.key").stat().st_mode) == 0o600
