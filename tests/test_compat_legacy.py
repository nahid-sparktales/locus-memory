"""Characterization of the Locus MemoryVault/ContinuityStore format and the compat extraction.

The fixture under tests/fixtures/locus_legacy was produced by the *real* Locus code
(see make_fixture.py; commit recorded in expected.json). Tests that execute Locus code
directly run only when a Locus checkout is named by LOCUS_SOURCE_DIR (otherwise they skip;
path) and copy its sources to a temp dir first, so the checkout is never written.
"""
from __future__ import annotations

import importlib.util
import json
import math
import os
import shutil
import sys
import types
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from locus_memory.compat.legacy_vault import (
    LegacyContinuityStore,
    LegacyMemoryVault,
    LegacyVaultError,
    LegacyWrongKey,
    legacy_target,
)
from locus_memory.errors import OwnershipFenced

FIXTURE = Path(__file__).parent / "fixtures" / "locus_legacy"
EXPECTED = json.loads((FIXTURE / "expected.json").read_text())
KEY = bytes.fromhex(EXPECTED["key_hex"])
WS = EXPECTED["workspace"]
OTHER = EXPECTED["other_workspace"]
AGENT = EXPECTED["agent_id"]
LOCUS = Path(os.environ["LOCUS_SOURCE_DIR"]) if os.environ.get("LOCUS_SOURCE_DIR") else None
HAVE_LOCUS = LOCUS is not None and (LOCUS / "agent" / "ollama_code" / "memory.py").exists()


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    target = tmp_path / "memory.sqlite3"
    shutil.copy(FIXTURE / "memory.sqlite3", target)
    return target


@pytest.fixture
def locus_modules(tmp_path: Path):
    if not HAVE_LOCUS:
        pytest.skip("set LOCUS_SOURCE_DIR to a Locus checkout to run the host-parity tests")
    sys.dont_write_bytecode = True
    work = tmp_path / "locus_src"
    work.mkdir()
    for name in ("memory.py", "continuity.py"):
        shutil.copy(LOCUS / "agent" / "ollama_code" / name, work / name)
    saved = {k: v for k, v in sys.modules.items() if k == "ollama_code" or k.startswith("ollama_code.")}
    pkg = types.ModuleType("ollama_code")
    pkg.__path__ = [str(work)]
    sys.modules["ollama_code"] = pkg
    paths = types.ModuleType("ollama_code.paths")
    paths.APP_DIR = tmp_path / "app"
    sys.modules["ollama_code.paths"] = paths
    proxy = types.ModuleType("ollama_code.proxy")
    proxy.sanitized_child_environment = lambda: {}
    sys.modules["ollama_code.proxy"] = proxy
    modules = {}
    for name in ("memory", "continuity"):
        spec = importlib.util.spec_from_file_location(f"ollama_code.{name}", work / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        modules[name] = module
    yield modules
    for key in [k for k in sys.modules if k == "ollama_code" or k.startswith("ollama_code.")]:
        del sys.modules[key]
    sys.modules.update(saved)


def test_fixture_records_read_identically(vault_path):
    vault = LegacyMemoryVault(vault_path, key=KEY)
    got = {r["id"]: {"status": r["status"], "scope": r["scope"], "content": r["content"]}
           for r in vault.list(workspace=WS, agent_id=AGENT) + vault.list(workspace=OTHER, scopes=["workspace"])}
    # list() expires due candidates; the fixture candidate is still within its 30-day TTL
    # only if regenerated recently, so compare approved records strictly.
    approved = {k: v for k, v in EXPECTED["memories"].items() if v["status"] == "approved"}
    assert {k: v for k, v in got.items() if v["status"] == "approved"} == approved


def test_aad_and_payload_format(vault_path):
    import sqlite3

    row = sqlite3.connect(vault_path).execute(
        "SELECT id, status, scope, target_hash, revision, nonce, ciphertext FROM memories WHERE id=?",
        (EXPECTED["ids"]["personal"],)).fetchone()
    aad = f"memory-v1|{row[0]}|{row[1]}|{row[2]}|{row[3]}|{row[4]}".encode()
    payload = json.loads(AESGCM(KEY).decrypt(row[5], row[6], aad))
    assert payload["content"] == "Prefer tabs over spaces in Go code."
    assert len(row[5]) == 12 and row[3] == "personal"
    assert payload["feedback"] == {"helpful": 1}
    # Flipping a bound column breaks authentication.
    with pytest.raises(InvalidTag):
        AESGCM(KEY).decrypt(row[5], row[6], aad.replace(b"approved", b"candidate"))


def test_targets_match_host_derivation():
    import hashlib

    assert legacy_target("personal") == "personal"
    assert legacy_target("workspace", workspace=WS) == "workspace:" + hashlib.sha256(
        str(Path(WS).resolve()).encode()).hexdigest()
    assert legacy_target("agent", agent_id=AGENT) == "agent:" + hashlib.sha256(AGENT.encode()).hexdigest()


def test_search_matches_recorded_host_ranking(vault_path):
    vault = LegacyMemoryVault(vault_path, key=KEY)
    assert [r["id"] for r in vault.search("tabs", workspace=WS)] == EXPECTED["search_tabs"]


def test_supersession_from_host_replace_is_preserved(vault_path):
    vault = LegacyMemoryVault(vault_path, key=KEY)
    old = next(r for r in vault.list(workspace=WS) if r["id"] == EXPECTED["ids"]["ws_fact"])
    assert old["stale"] is True and old["superseded_by"] == EXPECTED["ids"]["candidate_approved"]


def test_wrong_key_fails_closed_without_changing_records(vault_path):
    import sqlite3

    def dump() -> list[tuple]:
        con = sqlite3.connect(vault_path)
        try:
            return con.execute("SELECT * FROM memories ORDER BY id").fetchall()
        finally:
            con.close()

    before = dump()
    wrong = LegacyMemoryVault(vault_path, key=b"\x01" * 32)  # construction matches the host contract
    with pytest.raises(LegacyWrongKey, match="could not be decrypted"):
        wrong.list()
    with pytest.raises(LegacyWrongKey):
        wrong.save({"content": "would split the vault", "scope": "personal"})
    # Only the journal-mode header flag may change (as with the host original); no row is touched.
    assert dump() == before and len(before) == len(EXPECTED["memories"])


def test_bad_key_length_rejected(tmp_path):
    with pytest.raises(LegacyVaultError):
        LegacyMemoryVault(tmp_path / "m.sqlite3", key=b"short")


def test_approve_does_not_retarget_across_workspaces(vault_path):
    vault = LegacyMemoryVault(vault_path, key=KEY)
    pending = EXPECTED["ids"]["pending"]
    result = vault.approve(pending, workspace=OTHER)
    assert result["status"] == "approved"
    # Still listed under its own workspace, not moved into OTHER.
    assert pending in {r["id"] for r in vault.list(workspace=WS, scopes=["workspace"])}
    assert pending not in {r["id"] for r in vault.list(workspace=OTHER, scopes=["workspace"])}


def test_enforce_target_blocks_cross_workspace_mutations(vault_path):
    vault = LegacyMemoryVault(vault_path, key=KEY, enforce_target=True)
    target = EXPECTED["ids"]["ws_fact"]
    assert vault.delete(target, workspace=OTHER) is False
    with pytest.raises(LegacyVaultError):
        vault.feedback(target, "helpful", workspace=OTHER)
    with pytest.raises(LegacyVaultError, match="memory candidate not found"):
        vault.approve(EXPECTED["ids"]["pending"], workspace=OTHER)
    assert vault.delete(target, workspace=WS) is True


def test_non_finite_confidence_and_string_tags(tmp_path):
    vault = LegacyMemoryVault(tmp_path / "m.sqlite3", key=KEY)
    with pytest.raises(LegacyVaultError):
        vault.save({"content": "x", "scope": "personal", "confidence": math.nan})
    with pytest.raises(LegacyVaultError):
        vault.save({"content": "x", "scope": "personal", "valid_from": math.inf})
    saved = vault.save({"content": "x", "scope": "personal", "tags": "style"})
    assert saved["tags"] == ["style"]


def test_write_guard_fences_mutations_but_not_reads(vault_path):
    def fence() -> None:
        raise OwnershipFenced("legacy store is no longer authoritative")

    vault = LegacyMemoryVault(vault_path, key=KEY, write_guard=fence)
    assert vault.list(workspace=WS)
    with pytest.raises(OwnershipFenced):
        vault.save({"content": "new", "scope": "personal"})
    with pytest.raises(OwnershipFenced):
        vault.delete(EXPECTED["ids"]["personal"])
    store = LegacyContinuityStore(vault_path, key=KEY, write_guard=fence)
    assert store.list_snapshots(WS)
    with pytest.raises(OwnershipFenced):
        store.save_snapshot(WS, "s2", {"goal": "g"})


def test_legacy_note_import_is_crash_safe_and_preserves_created_at(tmp_path):
    vault = LegacyMemoryVault(tmp_path / "m.sqlite3", key=KEY)
    note = {"id": "n1", "title": "Note", "content": "original", "tags": [], "created_at": 1_500_000_000.0,
            "updated_at": 1_500_000_100.0, "pinned": False, "stale": False}
    memory_id, outcome = vault.import_legacy_note(note, workspace=str(tmp_path))
    assert outcome == "migrated"
    record = vault.list(workspace=str(tmp_path))[0]
    assert record["created_at"] == 1_500_000_000.0
    vault.save({**record, "content": "edited by user"}, memory_id, workspace=str(tmp_path))
    # Crash before the legacy note was deleted => the retry must not clobber the edit.
    again, outcome2 = vault.import_legacy_note(note, workspace=str(tmp_path))
    assert (again, outcome2) == (memory_id, "already_migrated")
    assert vault.list(workspace=str(tmp_path))[0]["content"] == "edited by user"


def test_continuity_fixture_reads(vault_path):
    store = LegacyContinuityStore(vault_path, key=KEY)
    snaps = store.list_snapshots(WS)
    assert snaps and snaps[0]["id"] == EXPECTED["ids"]["snapshot"] and snaps[0]["goal"] == "Add tests"
    obs = store.list_observations(WS)
    assert obs and obs[0]["id"] == EXPECTED["ids"]["observation"] and obs[0]["status"] == "OPEN"


def test_bidirectional_parity_with_real_locus_code(tmp_path, locus_modules):
    mem, cont = locus_modules["memory"], locus_modules["continuity"]
    db = tmp_path / "parity.sqlite3"
    ws = str(tmp_path)
    host = mem.MemoryVault(db, key=KEY)
    a = host.save({"title": "Indent", "content": "Use tabs", "tags": ["style"], "scope": "workspace",
                   "status": "candidate", "kind": "preference"}, workspace=ws)
    pkg = LegacyMemoryVault(db, key=KEY)
    assert pkg.list(workspace=ws)[0]["content"] == "Use tabs"
    pkg.save({"title": "Runner", "content": "Use pytest", "scope": "personal"}, workspace=ws)
    assert sorted(x["content"] for x in host.list(workspace=ws)) == ["Use pytest", "Use tabs"]
    pkg.approve(a["id"], workspace=ws)
    assert [x["status"] for x in host.list(workspace=ws) if x["id"] == a["id"]] == ["approved"]
    host_hits, pkg_hits = host.search("tabs", workspace=ws), pkg.search("tabs", workspace=ws)
    assert [x["id"] for x in host_hits] == [x["id"] for x in pkg_hits]
    assert set(host_hits[0]) == set(pkg_hits[0])
    host_store, pkg_store = cont.ContinuityStore(db, key=KEY), LegacyContinuityStore(db, key=KEY)
    host_store.save_snapshot(ws, "s1", {"goal": "g", "outcome": "o"})
    assert pkg_store.list_snapshots(ws) == host_store.list_snapshots(ws)
    pkg_store.record_observation(ws, {"issue": "i", "suggested_improvement": "s", "principle": "p"})
    assert host_store.list_observations(ws) == pkg_store.list_observations(ws)
    assert mem.format_memory_results(host_hits) == __import__(
        "locus_memory.compat.legacy_vault", fromlist=["x"]).format_memory_results(pkg_hits)


def test_empty_scope_list_returns_nothing_d1(vault_path):
    vault = LegacyMemoryVault(vault_path, key=KEY)
    assert vault.list(workspace=WS, scopes=[]) == []
    assert vault.list(workspace=WS, scopes=None)


def test_feedback_is_compare_and_swap_d23(vault_path, monkeypatch):
    vault = LegacyMemoryVault(vault_path, key=KEY)
    target = EXPECTED["ids"]["personal"]
    original = vault._open_payload

    def racing_open(row):
        payload = original(row)
        # A concurrent writer bumps the revision between feedback's read and write.
        import sqlite3 as _sqlite

        con = _sqlite.connect(vault_path)
        con.execute("UPDATE memories SET revision=revision+0 WHERE id=?", (target,))
        con.commit()
        con.close()
        return payload

    other = LegacyMemoryVault(vault_path, key=KEY)
    current = next(r for r in other.list() if r["id"] == target)
    monkeypatch.setattr(vault, "_open_payload", racing_open)
    vault.feedback(target, "helpful")  # no concurrent change of revision -> succeeds
    monkeypatch.undo()
    # Now a real concurrent save between read and update:
    state = {"done": False}

    def save_in_between(row):
        payload = original(row)
        if not state["done"]:
            state["done"] = True
            other.save({**current, "content": "changed concurrently"}, target)
        return payload

    monkeypatch.setattr(vault, "_open_payload", save_in_between)
    with pytest.raises(LegacyVaultError, match="concurrently"):
        vault.feedback(target, "helpful")
    monkeypatch.undo()
    # Every row still decrypts (the host original could leave this row unreadable).
    assert {r["id"] for r in vault.list()} >= {target}


def test_edit_drops_stale_embedding_d24(tmp_path):
    calls = []

    def embedder(model, host, inputs):
        calls.append(list(inputs))
        return [[1.0, 0.0] if "toronto" in text.lower() else [0.0, 1.0] for text in inputs]

    vault = LegacyMemoryVault(tmp_path / "m.sqlite3", key=KEY, embedder=embedder)
    saved = vault.save({"title": "City", "content": "Lives in Toronto", "scope": "personal"})
    assert vault.search("toronto", embedding_model="fake")
    vault.save({**saved, "content": "Lives in Montreal"}, saved["id"])
    hits = vault.search("toronto", embedding_model="fake")
    assert not hits, "the edited record must not match its old content through a stale vector"


def test_concurrent_first_open_migration_race_d25(tmp_path):
    import sqlite3 as _sqlite
    import threading

    db = tmp_path / "old.sqlite3"
    con = _sqlite.connect(db)
    con.execute("""CREATE TABLE memories (id TEXT PRIMARY KEY, status TEXT NOT NULL, scope TEXT NOT NULL,
        target_hash TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, pinned INTEGER NOT NULL DEFAULT 0,
        stale INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL,
        updated_at REAL NOT NULL, expires_at REAL)""")
    con.commit()
    con.close()
    errors = []

    def open_it():
        try:
            LegacyMemoryVault(db, key=KEY)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=open_it) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_fenced_reads_never_modify_the_store(vault_path):
    import sqlite3 as _sqlite

    def dump():
        con = _sqlite.connect(vault_path)
        try:
            return {t: con.execute(f"SELECT * FROM {t} ORDER BY 1").fetchall()
                    for t in ("memories", "memory_events", "context_snapshots", "skill_observations")}
        finally:
            con.close()

    def fence() -> None:
        raise OwnershipFenced("package is authoritative")

    far_future = 4_000_000_000.0  # every candidate and snapshot is expired at this time
    vault = LegacyMemoryVault(vault_path, key=KEY, write_guard=fence, clock=lambda: far_future,
                              embedder=lambda m, h, xs: [[1.0, 0.0] for _ in xs])
    before = dump()
    listed = vault.list(workspace=WS, agent_id=AGENT)
    assert all(r["status"] != "candidate" for r in listed)  # expired candidates hidden, not deleted
    vault.search("tabs", workspace=WS, embedding_model="fake")
    vault.status(workspace=WS)
    vault.record_event("proposal", "accepted", workspace=WS)
    store = LegacyContinuityStore(vault_path, key=KEY, write_guard=fence, clock=lambda: far_future)
    assert store.list_snapshots(WS) == []  # expired snapshot hidden, not pruned
    assert dump() == before
    with pytest.raises(OwnershipFenced):
        vault.expire_candidates()
