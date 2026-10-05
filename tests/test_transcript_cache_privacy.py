import json
import sqlite3
from contextlib import contextmanager

import pytest

from locus_memory.crypto import StaticKeyProvider
from locus_memory.errors import WrongKey
from locus_memory.history.transcript_search import (
    TranscriptIndex,
    TranscriptLimits,
    TranscriptSearchError,
    TranscriptSource,
)

KEYS = StaticKeyProvider({"test": b"s" * 32})
CANARY = "canary-nebula-private-person"


def make(tmp_path, *, keys=KEYS, partition="test", upgrade=None):
    source = tmp_path / "source.jsonl"
    if not source.exists():
        source.write_text(json.dumps({"type": "message", "message": {"role": "user", "content": CANARY}}) + "\n")
    return TranscriptIndex(tmp_path / "search.sqlite3", TranscriptSource(lambda: [source], dict, str),
                           TranscriptLimits(1_000_000, 100_000, 100), keys=keys,
                           partition_id=partition, upgrade_lease=upgrade)


def test_encrypted_cache_restart_metadata_and_no_plaintext_artifacts(tmp_path):
    index = make(tmp_path)
    first = index.search(CANARY)["results"]
    assert first
    index.close()
    for path in tmp_path.iterdir():
        if path.name != "source.jsonl":
            assert CANARY.encode() not in path.read_bytes()
            assert b"source" not in path.read_bytes()
    reopened = make(tmp_path)
    assert reopened.search(CANARY)["results"] == first
    assert reopened._connect().execute("PRAGMA database_list").fetchone()[2] == ""
    assert reopened._connect().execute("PRAGMA temp_store").fetchone()[0] == 2
    reopened.close()


@pytest.mark.parametrize("other", ["key", "partition", "swapped-envelope"])
def test_cache_authentication_rejects_wrong_keys_partition_and_relabelled_rows(tmp_path, other):
    index = make(tmp_path)
    index.search(CANARY)
    index.close()
    if other == "swapped-envelope":
        with sqlite3.connect(tmp_path / "search.sqlite3") as db:
            db.execute("UPDATE envelopes SET token=?", ("f" * 64,))
    from locus_memory.errors import IntegrityError
    with pytest.raises((WrongKey, IntegrityError)):
        make(tmp_path, keys=StaticKeyProvider({"test": b"x" * 32}) if other == "key" else KEYS,
             partition="other" if other == "partition" else "test")


def test_legacy_upgrade_requires_lease_and_publishes_verified_encrypted_cache(tmp_path):
    with sqlite3.connect(tmp_path / "search.sqlite3") as db:
        db.execute("CREATE VIRTUAL TABLE messages_fts USING fts5(content)")
        db.execute("INSERT INTO messages_fts VALUES(?)", (CANARY,))
    with pytest.raises(TranscriptSearchError, match="exclusive"):
        make(tmp_path)
    entered = []
    @contextmanager
    def lease():
        entered.append(True)
        yield
    index = make(tmp_path, upgrade=lease)
    assert entered and index.search(CANARY)["results"]
    index.close()
    assert CANARY.encode() not in (tmp_path / "search.sqlite3").read_bytes()
    assert not list(tmp_path.glob("*.encrypted"))


def test_failed_upgrade_preserves_old_index(tmp_path, monkeypatch):
    with sqlite3.connect(tmp_path / "search.sqlite3") as db:
        db.execute("CREATE VIRTUAL TABLE messages_fts USING fts5(content)")
        db.execute("INSERT INTO messages_fts VALUES(?)", (CANARY,))
    from contextlib import nullcontext

    from locus_memory.history.transcript_cache import EncryptedTranscriptCache
    monkeypatch.setattr(EncryptedTranscriptCache, "verify", lambda self: (_ for _ in ()).throw(OSError("failure")))
    with pytest.raises(OSError):
        make(tmp_path, upgrade=nullcontext)
    assert CANARY.encode() in (tmp_path / "search.sqlite3").read_bytes()


def test_deletion_wipes_ciphertexts_and_close_stops_build(tmp_path):
    index = make(tmp_path)
    index.search(CANARY)
    index.delete_all()
    assert index._cache.payloads() == []
    index.close()
    with pytest.raises(TranscriptSearchError):
        index.search(CANARY)
