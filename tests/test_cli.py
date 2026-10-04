"""Standalone diagnostic CLI (``locus-memory``): every command end-to-end against a tmp root.

Commands run in-process through ``main(argv)``; one smoke test runs
``python -m locus_memory.cli`` in a subprocess. Every root, key and legacy file lives
under pytest's tmp dirs; nothing touches real app data, keychains or the network.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from conftest import CANARY, access_for, scan_for_plaintext
from foundation_support import count, db_path
from locus_memory.cli import main
from locus_memory.errors import AccessDenied
from locus_memory.models import (
    ForgetPolicy,
    ForgetTarget,
    Operation,
    PartitionRef,
    RememberRequest,
    Scope,
)

FIXTURE = Path(__file__).parent / "fixtures" / "locus_legacy"
EXPECTED = json.loads((FIXTURE / "expected.json").read_text())
GIT = shutil.which("git")


@dataclass
class Run:
    code: int
    data: Any  # parsed JSON document (json mode) or stdout text
    out: str
    err: str


@pytest.fixture
def cli(capsys, root):
    """Run the CLI in-process against the tmp ``root``; JSON mode unless ``json_mode=False``."""

    def run(*args: str, json_mode: bool = True, use_root: Path | None = None) -> Run:
        argv = ["--root", str(use_root or root), *(["--json"] if json_mode else []), *args]
        code = main(argv)
        captured = capsys.readouterr()
        data: Any = captured.out
        if json_mode:
            data = json.loads(captured.out)  # exactly one JSON document
        return Run(code, data, captured.out, captured.err)

    return run


@pytest.fixture
def ready(cli):
    assert cli("init").code == 0
    return cli


def partition_access(**kw):
    return access_for(edition="standalone", **kw)


# ---------------------------------------------------------------------------- init / missing key
def test_init_creates_key_and_vault_and_second_init_is_refused(cli, root):
    first = cli("init")
    assert first.code == 0 and first.data["initialized"] and first.data["key_created"]
    key_files = sorted((root / "keys").glob("*.key"))
    assert len(key_files) == 1
    assert stat.S_IMODE(key_files[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    key_bytes = key_files[0].read_bytes()
    assert key_bytes.hex() not in first.out and first.data["partition_id"] == PartitionRef("standalone", "default").partition_id
    second = cli("init")
    assert second.code == 1 and second.data["error"] == "already_initialized"
    assert sorted((root / "keys").glob("*.key")) == key_files and key_files[0].read_bytes() == key_bytes


def test_commands_without_init_fail_cleanly_and_create_nothing(cli, root):
    for args in (("status",), ("list",), ("remember", "hello"), ("search", "x"), ("forget", "--memory", "m1"),
                 ("history", "search", "x"), ("--admin", "keys", "rotate-data")):
        result = cli(*args)
        assert result.code == 1 and result.data["error"] == "not_initialized", args
        assert "run `locus-memory init`" in result.data["message"]
    assert not root.exists()
    human = cli("status", json_mode=False)
    assert human.code == 1 and "not_initialized" in human.err and human.out == ""


def test_other_profile_needs_its_own_vault_and_explicit_key_reuse(ready, root):
    assert ready("remember", "default profile fact").code == 0
    missing = ready("--profile", "work", "list")
    assert missing.code == 1 and missing.data["error"] == "not_initialized"
    refused = ready("--profile", "work", "init")
    assert refused.code == 1 and refused.data["error"] == "key_exists"
    created = ready("--profile", "work", "init", "--use-existing-key")
    assert created.code == 0 and not created.data["key_created"]
    assert ready("--profile", "work", "list").data["count"] == 0  # partitions never share records
    assert ready("list").data["count"] == 1


def test_init_never_creates_a_key_over_an_existing_vault(ready, root):
    shutil.move(root / "keys", root.parent / "keys-backup")
    status = ready("status")
    assert status.code == 1 and status.data["error"] == "not_initialized"
    refused = ready("init")
    assert refused.code == 1 and refused.data["error"] == "vault_without_key"
    assert not (root / "keys").exists()
    shutil.move(root.parent / "keys-backup", root / "keys")
    assert ready("status").code == 0


# ---------------------------------------------------------------------------- record round trip
def test_remember_list_search_show_explain_correct_pin_round_trip(ready):
    made = ready("remember", "The deploy pipeline uses the staging branch", "--kind", "decision",
                 "--title", "Deploy branch", "--tag", "deploy", "--subject", "deploy", "--predicate", "branch")
    assert made.code == 0
    record = made.data["record"]
    assert record["revision"] == 1 and record["lifecycle"] == "approved" and made.data["receipt"]["status"] == "ok"
    mid = record["id"]

    listed = ready("list")
    assert listed.data["count"] == 1 and listed.data["records"][0]["id"] == mid
    assert "content" not in listed.data["records"][0]  # list shows ids/titles unless --full
    assert ready("list", "--full").data["records"][0]["content"].startswith("The deploy pipeline")

    found = ready("search", "staging")
    assert found.code == 0 and [h["record"]["id"] for h in found.data["hits"]] == [mid]
    assert found.data["hits"][0]["score_kind"] == "rrf"

    shown = ready("show", mid)
    assert shown.data["title"] == "Deploy branch" and shown.data["tags"] == ["deploy"]
    assert shown.data["confidence"]["value"] is None  # unknown stays unknown
    explained = ready("explain", mid)
    assert explained.data["record"]["id"] == mid and len(explained.data["revisions"]) == 1
    assert explained.data["confidence_note"] == "unknown"

    corrected = ready("correct", mid, "--revision", "1", "--content", "The deploy pipeline uses the release branch")
    assert corrected.code == 0 and corrected.data["record"]["revision"] == 2
    stale = ready("correct", mid, "--revision", "1", "--title", "stale write")
    assert stale.code == 1 and stale.data["error"] == "revision_conflict"
    pinned = ready("pin", mid, "--revision", "2")
    assert pinned.data["record"]["retention"]["pinned"] is True and pinned.data["record"]["revision"] == 3
    unpinned = ready("unpin", mid, "--revision", "3")
    assert unpinned.data["record"]["retention"]["pinned"] is False
    # Restart persistence: every invocation above opened and closed its own engine.
    final = ready("show", mid)
    assert final.data["revision"] == 4 and "release branch" in final.data["content"]
    assert [r["change"] for r in ready("explain", mid).data["revisions"]] == ["created", "corrected", "pinned", "unpinned"]


def test_propose_approve_and_reject_candidates(ready):
    proposed = ready("propose", "Tests run with pytest", "--source", "document:README.md", "--rationale", "seen in docs")
    assert proposed.code == 0 and proposed.data["record"]["lifecycle"] == "candidate"
    cid = proposed.data["record"]["id"]
    assert ready("list").data["count"] == 0  # candidates are not approved memory
    assert [r["id"] for r in ready("list", "--lifecycle", "candidate").data["records"]] == [cid]
    approved = ready("approve", cid, "--revision", "1")
    assert approved.code == 0 and approved.data["record"]["lifecycle"] == "approved"

    other = ready("propose", "Lint with flake8", "--source", "document:old-notes.md").data["record"]
    rejected = ready("reject", other["id"], "--revision", "1", "--reason", "we use ruff")
    assert rejected.code == 0 and rejected.data["record"]["lifecycle"] == "rejected"
    assert ready("approve", other["id"], "--revision", "2").data["error"] == "invalid_transition"
    missing_source = ready("propose", "no evidence")
    assert missing_source.code == 1 and missing_source.data["error"] == "usage"
    bad_source = ready("propose", "bad", "--source", "nonsense")
    assert bad_source.code == 1 and bad_source.data["error"] == "usage"


def test_scope_grant_flags_isolate_project_memories(ready):
    made = ready("--project", "p1", "remember", "Project one uses Postgres", "--scope-project", "p1")
    assert made.code == 0
    mid = made.data["record"]["id"]
    assert ready("list").data["count"] == 0
    assert ready("--project", "p2", "list").data["count"] == 0
    assert [r["id"] for r in ready("--project", "p1", "list").data["records"]] == [mid]
    hidden = ready("show", mid)
    assert hidden.code == 1 and hidden.data["error"] == "not_found"  # same as nonexistent
    assert ready("search", "Postgres").data["hits"] == []
    assert ready("--project", "p1", "search", "Postgres").data["hits"][0]["record"]["id"] == mid
    ungranted = ready("remember", "not allowed", "--scope-project", "p3")
    assert ungranted.code == 1 and ungranted.data["error"] == "access_denied"
    assert ready("--project", "p1", "status").data["status"]["counts"] == {"approved": 1}
    assert ready("status").data["status"]["counts"] == {}


# ---------------------------------------------------------------------------- forgetting
def test_forget_previews_by_default_and_forgets_only_with_yes(ready, root):
    mid = ready("remember", "Forget me later").data["record"]["id"]
    before = ready("status").data["status"]
    preview = ready("forget", "--memory", mid)
    assert preview.code == 2 and preview.data["preview"] is True
    assert preview.data["deleted"] == {"memories": 1, "revisions": 1}
    assert ready("show", mid).code == 0  # nothing was deleted
    after_preview = ready("status").data["status"]
    assert after_preview["deletion_generation"] == before["deletion_generation"] == 0
    assert after_preview["generation"] == before["generation"]
    access = partition_access()
    assert count(db_path(root, access), "SELECT COUNT(*) FROM tombstones") == 0
    assert count(db_path(root, access), "SELECT COUNT(*) FROM suppressions") == 0

    done = ready("forget", "--memory", mid, "--yes")
    assert done.code == 0 and done.data["deleted"] == {"memories": 1, "revisions": 1}
    assert done.data["receipt"]["operation"] == "forget" and done.data["deletion_generation"] == 1
    assert ready("show", mid).data["error"] == "not_found"
    assert ready("status").data["status"]["deletion_generation"] == 1
    human = ready("forget", "--memory", mid, json_mode=False)
    assert human.code == 1 and "not_found" in human.err


def test_forget_project_and_profile_targets(ready):
    for text in ("alpha fact", "beta fact"):
        ready("--project", "p1", "remember", text, "--scope-project", "p1")
    ready("remember", "global fact")
    preview = ready("--project", "p1", "forget", "--project", "p1")
    assert preview.code == 2 and preview.data["deleted"]["memories"] == 2
    ungranted = ready("forget", "--project", "p1")
    assert ungranted.code == 1 and ungranted.data["error"] == "access_denied"
    no_admin = ready("forget", "--profile")
    assert no_admin.code == 1 and no_admin.data["error"] == "access_denied"
    profile_preview = ready("--project", "p1", "--admin", "forget", "--profile")
    assert profile_preview.code == 2 and profile_preview.data["deleted"]["memories"] == 3
    assert ready("--project", "p1", "list").data["count"] == 3
    gone = ready("--project", "p1", "forget", "--project", "p1", "--yes")
    assert gone.code == 0 and gone.data["deleted"]["memories"] == 2
    assert [r["title"] for r in ready("--project", "p1", "list").data["records"]] == ["global fact"]


def test_engine_preview_forget_rolls_back_and_matches_the_receipt(make_engine):
    engine = make_engine()
    access = access_for(projects=("p1",))
    ids = [engine.remember(access, RememberRequest(f"note {i}", scope=Scope.of(project="p1"))).record.id
           for i in range(3)]
    ctx = engine.partition_context(access.partition)
    head, generation = ctx.partition.ledger.head(), engine.status(access).generation
    preview = engine.preview_forget(access, ForgetTarget("project", "p1"))
    assert preview["preview"] and preview["deleted"]["memories"] == 3
    assert ctx.partition.ledger.head() == head and engine.status(access).generation == generation
    assert [engine.get(access, i).id for i in ids] == ids
    receipt = engine.forget(access, ForgetTarget("project", "p1"))
    assert receipt.deleted == preview["deleted"] and receipt.retained_by_policy == preview["retained_by_policy"]
    with pytest.raises(AccessDenied):
        engine.preview_forget(access_for(operations=set(Operation) - {Operation.ADMIN}),
                              ForgetTarget("profile", "default"))


def test_engine_profile_preview_keeps_the_provider_usage_buffer(make_engine):
    engine = make_engine()
    access = access_for()
    engine.remember(access, RememberRequest("kept"))
    hub = engine.services(access).providers
    sentinel = object()
    hub._usage_buffer.append(sentinel)
    preview = engine.preview_forget(access, ForgetTarget("profile", "default"), ForgetPolicy())
    assert preview["deleted"]["memories"] == 1
    assert hub._usage_buffer == [sentinel]
    hub._usage_buffer.clear()


# ---------------------------------------------------------------------------- context
def test_context_preview_respects_the_token_allowance(ready):
    for i in range(12):
        ready("remember", f"Preference {i}: " + "always write small focused functions " * 6, "--kind", "preference")
    small = ready("context", "preview", "--tokens", "60")
    assert small.code == 0 and small.data["token_allowance"] == 60
    assert small.data["token_count"] <= 60
    assert any(o["reason"] == "budget" for o in small.data["omissions"])
    large = ready("context", "preview", "--tokens", "4000", "--query", "functions")
    assert large.data["token_count"] <= 4000 and len(large.data["items"]) > len(small.data["items"])
    explained = ready("context", "explain", large.data["receipt_id"])
    assert explained.code == 0
    human = ready("context", "preview", "--tokens", "60", json_mode=False)
    assert human.code == 0 and "/60 tokens" in human.out


# ---------------------------------------------------------------------------- history / episodes / procedures
def test_history_ingest_search_scroll_and_browse(ready, tmp_path):
    events = tmp_path / "events.jsonl"
    lines = [{"event_id": f"e{i}", "session_ref": "sess-1", "sequence": i, "role": role, "text": text,
              "occurred_at": 1_800_000_000 + i}
             for i, (role, text) in enumerate([("user", "How do we run the tests?"),
                                               ("assistant", "Run pytest from the repository root."),
                                               ("user", "Thanks, pytest works.")])]
    events.write_text("\n".join(json.dumps(item) for item in lines) + "\n\n")
    ingested = ready("history", "ingest", "--file", str(events))
    assert ingested.code == 0 and ingested.data["stored"] == 3 and ingested.data["duplicates"] == 0
    assert ready("history", "ingest", "--file", str(events)).data["duplicates"] == 3
    found = ready("history", "search", "pytest")
    assert found.code == 0 and found.data["hits"]
    handle = found.data["hits"][0]["handle"]
    window = ready("history", "scroll", handle, "--before", "1", "--after", "1")
    assert window.code == 0 and window.data["session_ref"] == "sess-1" and window.data["messages"]
    page = ready("history", "browse", "sess-1")
    assert [m["sequence"] for m in page.data["messages"]] == [0, 1, 2]
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"event_id": "x"\n')
    broken = ready("history", "ingest", "--file", str(bad))
    assert broken.code == 1 and broken.data["error"] == "invalid_request" and "line 1" in broken.data["message"]


def test_episode_record_show_and_list(ready, tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"episode_id": "ep-1", "task_ref": "task-1", "attempt_ref": "attempt-1",
                                  "objective": "Add CLI tests", "claimed_outcome": "verified_success",
                                  "verification": ["receipt-1"]}))
    recorded = ready("episode", "record", "--file", str(report))
    assert recorded.code == 0
    # No host verification authority: a claimed success is never taken as evidence.
    assert recorded.data["episode"]["outcome"] != "verified_success"
    assert recorded.data["episode"]["claimed_outcome"] == "verified_success"
    shown = ready("episode", "show", "ep-1")
    assert shown.data["episode_id"] == "ep-1"
    assert ready("episode", "list").data["count"] == 1


def test_procedure_commands(ready, tmp_path):
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps({"name": "run-tests", "purpose": "Run the test suite",
                                 "applicability": "python repositories", "steps": ["run pytest -q"]}))
    nominated = ready("procedure", "nominate", "--file", str(draft))
    assert nominated.code == 0
    pid = nominated.data["procedure"]["procedure_id"]
    assert [p["procedure_id"] for p in ready("procedure", "list").data["procedures"]] == [pid]
    assert ready("procedure", "show", pid).data["procedure_id"] == pid
    evaluated = ready("procedure", "evaluate", pid)
    assert evaluated.code == 3 and evaluated.data["error"] == "unsupported_capability"
    version = nominated.data["procedure"]["version"]
    not_evaluated = ready("procedure", "approve", pid, "--version", str(version))
    assert not_evaluated.code == 1 and not_evaluated.data["error"] == "invalid_transition"
    not_approved = ready("procedure", "export", pid, "--dest", str(tmp_path / "skills"))
    assert not_approved.code == 1
    rejected = ready("procedure", "reject", pid, "--reason", "not needed")
    assert rejected.code == 0 and rejected.data["procedure"]["state"] == "rejected"


# ---------------------------------------------------------------------------- repository
def _git(cwd: Path, *args: str) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"})
    subprocess.run([GIT, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c",
                    "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                    *args], cwd=cwd, env=env, check=True, capture_output=True)


@pytest.mark.skipif(GIT is None, reason="git is required for repository memory")
def test_repo_register_snapshot_status_observations(ready, tmp_path):
    repos = tmp_path / "repos"
    repo = repos / "demo"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("import json\n\nprint(json.dumps({}))\n")
    _git(repo, "init", "-q", ".")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "initial")
    no_root = ready("--repository", "demo", "repo", "register", str(repo), "--id", "demo")
    assert no_root.code == 1 and no_root.data["error"] == "usage"
    allow = ("--allow-root", str(repos))
    registered = ready("--repository", "demo", "repo", "register", str(repo), "--id", "demo", *allow)
    assert registered.code == 0 and registered.data["registered"] is True
    ungranted = ready("repo", "status", "demo", *allow)
    assert ungranted.code == 1
    snap = ready("--repository", "demo", "repo", "snapshot", "demo", *allow)
    assert snap.code == 0, snap.data
    status = ready("--repository", "demo", "repo", "status", "demo", *allow)
    assert status.code == 0
    observations = ready("--repository", "demo", "repo", "observations", "demo", *allow)
    assert observations.code == 0 and observations.data["count"] >= 0


# ---------------------------------------------------------------------------- maintenance / keys
def test_maintain_and_consolidate(ready):
    for _ in range(2):
        ready("remember", "Use ruff for linting")
    assert ready("maintain").code == 0
    run = ready("consolidate")
    assert run.code == 0 and isinstance(run.data, dict)


def test_key_rotation_requires_admin_and_keeps_the_vault_readable(ready, root):
    mid = ready("remember", "survives key rotation").data["record"]["id"]
    denied = ready("keys", "rotate-master")
    assert denied.code == 1 and denied.data["error"] == "access_denied"
    assert len(list((root / "keys").glob("*.key"))) == 1  # no key file was created
    rotated = ready("--admin", "keys", "rotate-master")
    assert rotated.code == 0 and rotated.data["master_key_id"] != rotated.data["previous_master_key_id"]
    assert (root / "keys" / "current").read_text() == rotated.data["master_key_id"]
    assert len(list((root / "keys").glob("*.key"))) == 2  # the CLI never deletes key files
    assert ready("show", mid).data["content"] == "survives key rotation"
    data = ready("keys", "rotate-data", "--admin")  # --admin also accepted after the command
    assert data.code == 0 and data.data["state"] == "complete"
    assert ready("show", mid).code == 0


def test_key_rotation_switches_the_pointer_through_the_key_provider(ready, root, monkeypatch):
    from locus_memory.crypto import FileKeyProvider

    calls = []
    original = FileKeyProvider.set_current
    monkeypatch.setattr(FileKeyProvider, "set_current",
                        lambda self, key_id: (calls.append(key_id), original(self, key_id))[1])
    rotated = ready("--admin", "keys", "rotate-master")
    assert rotated.code == 0 and calls == [rotated.data["master_key_id"]]
    assert (root / "keys" / "current").read_text() == rotated.data["master_key_id"]
    assert sorted(p.name for p in (root / "keys").iterdir() if not p.name.endswith(".key")) == ["current"]

    # A failed pointer switch is reported; the vault (already re-wrapped, old wraps kept) stays readable.
    def refuse(self, key_id):
        raise OSError("simulated failure")

    monkeypatch.setattr(FileKeyProvider, "set_current", refuse)
    failed = ready("--admin", "keys", "rotate-master", "--keep-old")
    assert failed.code == 1 and failed.data["error"] == "io_error"
    assert (root / "keys" / "current").read_text() == rotated.data["master_key_id"]
    monkeypatch.undo()
    assert ready("status").code == 0


def test_only_init_can_create_a_vault_even_without_the_cli_precheck(ready, root, monkeypatch):
    from locus_memory.cli import Session

    monkeypatch.setattr(Session, "require_initialized", lambda self: None)
    typo = PartitionRef("standalone", "defualt").partition_id
    for args in (("--profile", "defualt", "list"), ("--profile", "defualt", "remember", "lost write"),
                 ("--profile", "defualt", "status")):
        result = ready(*args)
        assert result.code == 1 and result.data["error"] == "not_found", args
    assert not (root / typo).exists()
    assert ready("--profile", "defualt", "init", "--use-existing-key").code == 0  # init still creates
    assert (root / typo).is_dir() and ready("--profile", "defualt", "list").data["count"] == 0


# ---------------------------------------------------------------------------- export
def test_export_requires_yes_and_writes_a_private_plaintext_file(ready, root, tmp_path):
    ready("remember", "exported statement")
    out = tmp_path / "out" / "export.json"
    out.parent.mkdir()
    preview = ready("export", "--out", str(out))
    assert preview.code == 2 and preview.data["would_export"] == 1 and not out.exists()
    written = ready("export", "--out", str(out), "--yes")
    assert written.code == 0 and written.data["exported"] == 1 and "PLAINTEXT" in written.err
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    document = json.loads(out.read_text())
    assert document["plaintext"] is True and document["records"][0]["content"] == "exported statement"
    # The file is the engine's export document (plus the CLI's plaintext annotations).
    assert document["format"] == "locus-memory.export" and document["version"] == 1
    assert document["partition_id"] == PartitionRef("standalone", "default").partition_id
    assert document["count"] == 1 and "history" not in document
    assert written.data["format"] == "locus-memory.export"
    again = ready("export", "--out", str(out), "--yes")
    assert again.code == 1 and again.data["error"] == "file_exists"
    inside = ready("export", "--out", str(root / "export.json"), "--yes")
    assert inside.code == 1 and inside.data["error"] == "invalid_request" and not (root / "export.json").exists()
    in_keys = ready("export", "--out", str(root / "keys" / "export.json"), "--yes")
    assert in_keys.code == 1 and in_keys.data["error"] == "invalid_request"
    assert not (root / "keys" / "export.json").exists()


def test_export_is_scope_isolated_and_includes_history_only_when_asked(ready, tmp_path):
    assert ready("--project", "p1", "remember", "p1 statement", "--scope-project", "p1").code == 0
    assert ready("--project", "p2", "remember", "p2 statement", "--scope-project", "p2").code == 0
    events = tmp_path / "events.jsonl"
    events.write_text("\n".join(json.dumps(item) for item in (
        {"event_id": "a0", "session_ref": "sess-p1", "sequence": 0, "role": "user", "text": "p1 line",
         "occurred_at": 1_800_000_000, "scope": {"project": "p1"}},
        {"event_id": "b0", "session_ref": "sess-p2", "sequence": 0, "role": "user", "text": "p2 line",
         "occurred_at": 1_800_000_001, "scope": {"project": "p2"}},
    )) + "\n")
    assert ready("--project", "p1", "--project", "p2", "history", "ingest", "--file", str(events)).data["stored"] == 2

    plain = tmp_path / "plain.json"
    assert ready("--project", "p1", "export", "--out", str(plain), "--yes").code == 0
    document = json.loads(plain.read_text())
    assert [r["content"] for r in document["records"]] == ["p1 statement"]
    assert "history" not in document and "line" not in plain.read_text()

    preview = ready("--project", "p1", "export", "--out", str(tmp_path / "h.json"), "--include-history")
    assert preview.code == 2 and preview.data["would_export_history_sessions"] == 1
    assert not (tmp_path / "h.json").exists()
    written = ready("--project", "p1", "export", "--out", str(tmp_path / "h.json"), "--include-history", "--yes")
    assert written.code == 0 and written.data["exported_history_sessions"] == 1
    assert stat.S_IMODE((tmp_path / "h.json").stat().st_mode) == 0o600
    with_history = json.loads((tmp_path / "h.json").read_text())
    assert [s["session_ref"] for s in with_history["history"]] == ["sess-p1"]
    assert [m["text"] for m in with_history["history"][0]["messages"]] == ["p1 line"]
    text = (tmp_path / "h.json").read_text()
    assert "p2 statement" not in text and "p2 line" not in text and "sess-p2" not in text


# ---------------------------------------------------------------------------- migration
@pytest.fixture
def legacy(tmp_path):
    db = tmp_path / "legacy" / "memory.sqlite3"
    db.parent.mkdir()
    shutil.copy(FIXTURE / "memory.sqlite3", db)
    key_file = tmp_path / "legacy-master.key"
    key_file.write_bytes(bytes.fromhex(EXPECTED["key_hex"]))
    args = ("--legacy-db", str(db), "--key-file", str(key_file),
            "--workspace", f"{EXPECTED['workspace']}=proj-a", "--workspace", f"{EXPECTED['other_workspace']}=proj-b",
            "--agent-id", EXPECTED["agent_id"])
    return db, key_file, args


def test_migrate_inventory_reports_counts_only(cli, root, legacy):
    db, _key_file, args = legacy
    before = db.read_bytes()
    report = cli("migrate", "inventory", *args)
    assert report.code == 0 and report.data["dry_run"] is True
    assert report.data["rows"] == len(EXPECTED["memories"]) and report.data["decrypt_failures"] == 0
    assert report.data["unmapped_scopes"] == {}
    for item in EXPECTED["memories"].values():
        assert item["content"] not in report.out
    assert db.read_bytes() == before and not root.exists()  # read-only; needs no vault


def test_migrate_snapshot_and_full_cutover_flow(cli, root, legacy, tmp_path):
    db, _key_file, args = legacy
    snap = cli("migrate", "snapshot", "--legacy-db", str(db), "--out", str(tmp_path / "snap"))
    assert snap.code == 0 and snap.data["rows"] == len(EXPECTED["memories"])
    for item in EXPECTED["memories"].values():
        assert not scan_for_plaintext(tmp_path / "snap", item["content"])

    grants = ("--project", "proj-a", "--project", "proj-b", "--agent", EXPECTED["agent_id"])
    work = ("--work-dir", str(tmp_path / "work"))
    assert cli(*grants, "--admin", "migrate", "import", *args, *work).data["error"] == "not_initialized"
    assert not root.exists()
    assert cli("init").code == 0
    assert cli(*grants, "migrate", "import", *args, *work).data["error"] == "access_denied"
    assert cli("--admin", "migrate", "state").data["recorded"] is False
    imported = cli(*grants, "--admin", "migrate", "import", *args, *work)
    assert imported.code == 0 and imported.data["state"] == "shadow_prepared"
    fenced = cli("remember", "written during the shadow phase")
    assert fenced.code == 1 and fenced.data["error"] == "ownership_fenced"
    validated = cli(*grants, "--admin", "migrate", "verify", *args, *work, "--query", "pytest")
    assert validated.code == 0 and validated.data["transitioned"] and validated.data["state"] == "validated"
    preview = cli(*grants, "--admin", "migrate", "cutover", *args, *work)
    assert preview.code == 2 and preview.data["state"] == "validated"
    cut = cli(*grants, "--admin", "migrate", "cutover", *args, *work, "--yes")
    assert cut.code == 0 and cut.data["state"] == "package_authoritative"
    state = cli("--admin", "migrate", "state")
    assert state.data["recorded"] and [h["to_state"] for h in state.data["history"]] == [
        "shadow_prepared", "validated", "cutover_in_progress", "package_authoritative"]
    assert cli("remember", "the package owns writes now").code == 0
    personal = EXPECTED["ids"]["personal"]
    assert cli("show", personal).data["content"] == EXPECTED["memories"][personal]["content"]
    readonly = cli(*grants, "--admin", "migrate", "verify", *args, *work)
    assert readonly.code == 0 and readonly.data["transitioned"] is False and readonly.data["verify"]["ok"]
    rollback_preview = cli(*grants, "--admin", "migrate", "rollback", *args, *work)
    assert rollback_preview.code == 2 and rollback_preview.data["plan"]["safe"] is True
    rolled = cli(*grants, "--admin", "migrate", "rollback", *args, *work, "--yes")
    assert rolled.code == 0 and rolled.data["state"] == "legacy_authoritative"
    assert cli("--admin", "migrate", "state").data["ownership"]["state"] == "legacy_authoritative"
    for path in (root, tmp_path / "work"):
        assert not scan_for_plaintext(path, EXPECTED["memories"][personal]["content"])


# ---------------------------------------------------------------------------- errors / output
def test_errors_are_single_json_documents(ready):
    missing = ready("show", "does-not-exist")
    assert missing.code == 1 and set(missing.data) == {"error", "message", "details"}
    usage = ready("list", "--limit", "many")
    assert usage.code == 1 and usage.data["error"] == "usage"
    unknown = ready("frobnicate")
    assert unknown.code == 1 and unknown.data["error"] == "usage"
    no_command = ready()
    assert no_command.code == 1 and no_command.data["error"] == "usage"
    invalid = ready("remember", "   ")
    assert invalid.code == 1 and invalid.data["error"] == "invalid_request"
    secret = ready("remember", "my api key is sk-abcdefghijklmnopqrstuvwxyz0123456789")
    assert secret.code == 1 and secret.data["error"] == "sensitive_content"
    assert "sk-abcdef" not in secret.out


def test_json_flag_after_the_command_and_human_output(ready, capsys):
    ready("remember", "human readable", json_mode=False)
    late = ready("list", "--json", json_mode=False)
    assert late.code == 0 and json.loads(late.out)["count"] == 1
    human = ready("list", json_mode=False)
    assert human.code == 0 and "human readable" in human.out and not human.out.lstrip().startswith("{")
    assert main(["--version"]) == 0
    assert "locus-memory" in capsys.readouterr().out


def test_eval_run_reports_an_unavailable_module(cli, monkeypatch):
    for name in ("locus_memory.evaluation", "locus_memory.evaluation.runner"):
        monkeypatch.setitem(sys.modules, name, None)  # import fails even if imported earlier
    result = cli("eval", "run")
    assert result.code == 3 and result.data == {"error": "unavailable", "message": "evaluation module unavailable",
                                                "details": {}}


def test_eval_run_passes_out_dir_and_repetitions_to_the_benchmark(cli, root, monkeypatch, tmp_path):
    calls: list[tuple[Path, int]] = []

    def run_benchmark(out_dir, *, repetitions=5, seed=7):
        calls.append((Path(out_dir), repetitions))
        return {"passed": True, "runs": [1, 2], "labels": {"scores": "never probabilities"}}

    fake = types.ModuleType("locus_memory.evaluation")
    fake.run_benchmark = run_benchmark
    monkeypatch.setitem(sys.modules, "locus_memory.evaluation", fake)
    result = cli("eval", "run", "--out", str(tmp_path / "eval"), "--repetitions", "2")
    assert result.code == 0 and calls == [(tmp_path / "eval", 2)]
    assert result.data["passed"] is True and result.data["out_dir"] == str(tmp_path / "eval")
    human = cli("eval", "run", "--out", str(tmp_path / "eval2"), json_mode=False)
    assert human.code == 0 and "runs: 2 entries" in human.out and calls[-1][1] == 5
    defaulted = cli("eval", "run")  # out_dir is required by the benchmark: a new temp dir is used
    try:
        assert defaulted.code == 0 and calls[-1][0].is_dir()
        assert _is_within(calls[-1][0], Path(tempfile.gettempdir()))
    finally:
        shutil.rmtree(calls[-1][0], ignore_errors=True)
    inside = cli("eval", "run", "--out", str(root / "eval"))
    assert inside.code == 1 and inside.data["error"] == "invalid_request" and len(calls) == 3


def test_eval_run_exits_1_when_the_benchmark_reports_a_hard_failure(cli, monkeypatch, tmp_path):
    fake = types.ModuleType("locus_memory.evaluation")
    fake.run_benchmark = lambda out_dir, *, repetitions=5: {"passed": False, "failures": ["A seed 1: leak"]}
    monkeypatch.setitem(sys.modules, "locus_memory.evaluation", fake)
    result = cli("eval", "run", "--out", str(tmp_path / "eval"))
    assert result.code == 1 and result.data["passed"] is False and result.data["failures"] == ["A seed 1: leak"]


def test_eval_run_drives_the_real_evaluation_module(cli, root, monkeypatch, tmp_path):
    import functools

    import locus_memory.evaluation as evaluation

    # The real run_benchmark and its real parameter names; only the corpus size and arms are
    # narrowed so the run stays small.
    small = functools.partial(evaluation.run_benchmark, arms=("A", "B"), size="small")
    monkeypatch.setattr(evaluation, "run_benchmark", small)
    out = tmp_path / "eval-out"
    result = cli("eval", "run", "--out", str(out), "--repetitions", "1")
    assert result.code == 0, result.data
    assert result.data["passed"] is True and result.data["out_dir"] == str(out)
    assert result.data["config"]["repetitions"] == 1 and [r["arm"] for r in result.data["runs"]] == ["A", "B"]
    assert {path.name for path in out.iterdir()} == {"manifest.json", "questions.jsonl", "report.md"}
    assert json.loads((out / "manifest.json").read_text())["passed"] is True
    assert not root.exists()  # the benchmark never opens or creates the CLI's vault root


def _is_within(path: Path, base: Path) -> bool:
    real, top = os.path.realpath(path), os.path.realpath(base)
    return os.path.commonpath([real, top]) == top


def test_no_plaintext_canary_in_root_after_cli_writes(ready, root):
    made = ready("remember", f"secret {CANARY}", "--title", f"title {CANARY}", "--pin")
    assert made.code == 0
    assert ready("search", CANARY).data["hits"]
    ready("context", "preview", "--query", CANARY)
    ready("forget", "--memory", made.data["record"]["id"])  # preview only
    assert not scan_for_plaintext(root, CANARY)


def test_subprocess_smoke(tmp_path):
    env = {**os.environ, "LOCUS_MEMORY_HOME": str(tmp_path / "home")}
    base = [sys.executable, "-m", "locus_memory.cli", "--root", str(tmp_path / "cli-root"), "--json"]
    init = subprocess.run([*base, "init"], capture_output=True, text=True, env=env, timeout=120)
    assert init.returncode == 0, init.stderr
    assert json.loads(init.stdout)["initialized"] is True
    status = subprocess.run([*base, "status"], capture_output=True, text=True, env=env, timeout=120)
    assert status.returncode == 0 and json.loads(status.stdout)["status"]["counts"] == {}
    missing = subprocess.run([*base, "--profile", "nope", "list"], capture_output=True, text=True, env=env,
                             timeout=120)
    assert missing.returncode == 1 and json.loads(missing.stdout)["error"] == "not_initialized"
    assert not (tmp_path / "home").exists()  # --root wins over LOCUS_MEMORY_HOME
