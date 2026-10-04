"""Regenerate the disposable legacy-vault fixture using the REAL Locus source (read-only).

Usage:
    LOCUS_SOURCE_DIR=/path/to/locus python tests/fixtures/locus_legacy/make_fixture.py

The Locus modules are copied into a temporary directory before import so nothing
(not even bytecode caches) is written into the Locus checkout. All data is
synthetic; the key is a published test key.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEST_KEY = hashlib.sha256(b"locus-memory synthetic fixture key v1").digest()
WORKSPACE = "/fixture/workspace-a"
OTHER_WORKSPACE = "/fixture/workspace-b"
AGENT = "agent-fixture-1"


def load_locus(source_dir: Path, app_dir: Path):
    sys.dont_write_bytecode = True
    work = Path(tempfile.mkdtemp())
    for name in ("memory.py", "continuity.py", "knowledge.py"):
        shutil.copy(source_dir / "agent" / "ollama_code" / name, work / name)
    pkg = types.ModuleType("ollama_code")
    pkg.__path__ = [str(work)]
    sys.modules["ollama_code"] = pkg
    paths = types.ModuleType("ollama_code.paths")
    paths.APP_DIR = app_dir
    sys.modules["ollama_code.paths"] = paths
    proxy = types.ModuleType("ollama_code.proxy")
    proxy.sanitized_child_environment = lambda: dict(os.environ)
    sys.modules["ollama_code.proxy"] = proxy
    modules = {}
    for name in ("memory", "continuity"):
        spec = importlib.util.spec_from_file_location(f"ollama_code.{name}", work / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        modules[name] = module
    return modules


def main() -> None:
    if not os.environ.get("LOCUS_SOURCE_DIR"):
        raise SystemExit("set LOCUS_SOURCE_DIR to a Locus checkout")
    source = Path(os.environ["LOCUS_SOURCE_DIR"])
    commit = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True,
                            text=True, check=True).stdout.strip()
    tmp = Path(tempfile.mkdtemp())
    mods = load_locus(source, tmp / "app")
    db = tmp / "memory.sqlite3"
    vault = mods["memory"].MemoryVault(db, key=TEST_KEY)
    personal = vault.save({"title": "Indentation", "content": "Prefer tabs over spaces in Go code.",
                           "tags": ["style"], "scope": "personal", "kind": "preference"})
    ws_fact = vault.save({"title": "Test runner", "content": "This project uses pytest.",
                          "tags": ["testing"], "scope": "workspace", "kind": "fact",
                          "source_session_id": "sess-1", "provenance": {"via": "fixture"}},
                         workspace=WORKSPACE)
    candidate = vault.save({"title": "Test runner", "content": "This project uses unittest.",
                            "tags": ["testing"], "scope": "workspace", "status": "candidate",
                            "kind": "fact", "confidence": 0.8, "source_run_id": "run-9"},
                           workspace=WORKSPACE)
    vault.approve(candidate["id"], workspace=WORKSPACE, resolution="replace")
    agent_mem = vault.save({"title": "Agent note", "content": "Agent fixture prefers short answers.",
                            "scope": "agent", "kind": "preference"}, agent_id=AGENT)
    other = vault.save({"title": "Other ws", "content": "Workspace B uses ruff.", "scope": "workspace"},
                       workspace=OTHER_WORKSPACE)
    expired_validity = vault.save({"title": "Old version", "content": "Supports Python 3.8.",
                                   "scope": "workspace", "valid_from": 1_600_000_000,
                                   "valid_until": 1_700_000_000}, workspace=WORKSPACE)
    vault.feedback(agent_mem["id"], "incorrect")
    vault.feedback(personal["id"], "helpful")
    pending = vault.save({"title": "Deploy", "content": "Deploys go through the staging branch.",
                          "scope": "workspace", "status": "candidate", "kind": "decision"},
                         workspace=WORKSPACE)
    vault.record_event("proposal", "accepted", workspace=WORKSPACE, memory_id=pending["id"])
    cont = mods["continuity"].ContinuityStore(db, key=TEST_KEY)
    snap = cont.save_snapshot(WORKSPACE, "sess-1", {"goal": "Add tests", "outcome": "Added 3 tests",
                                                    "pending": "CI", "changed_files": ["a.py"]})
    obs = cont.record_observation(WORKSPACE, {"issue": "slow", "suggested_improvement": "cache",
                                              "principle": "measure first"})
    target = HERE / "memory.sqlite3"
    target.unlink(missing_ok=True)
    src, dst = sqlite3.connect(db), sqlite3.connect(target)
    src.backup(dst)  # consistent single-file copy (no WAL sidecar)
    dst.execute("PRAGMA journal_mode=DELETE")
    src.close()
    dst.close()
    expected = {
        "locus_commit": commit, "key_hex": TEST_KEY.hex(), "workspace": WORKSPACE,
        "other_workspace": OTHER_WORKSPACE, "agent_id": AGENT,
        "memories": {r["id"]: {"status": r["status"], "scope": r["scope"], "content": r["content"]}
                     for r in vault.list(workspace=WORKSPACE, agent_id=AGENT)
                     + vault.list(workspace=OTHER_WORKSPACE, scopes=["workspace"])},
        "ids": {"personal": personal["id"], "ws_fact": ws_fact["id"], "candidate_approved": candidate["id"],
                "agent": agent_mem["id"], "other": other["id"], "expired_validity": expired_validity["id"],
                "pending": pending["id"], "snapshot": snap["id"], "observation": obs["id"]},
        "search_tabs": [r["id"] for r in vault.search("tabs", workspace=WORKSPACE)],
    }
    (HERE / "expected.json").write_text(json.dumps(expected, indent=2, sort_keys=True))
    print("fixture written from Locus", commit)


if __name__ == "__main__":
    main()
