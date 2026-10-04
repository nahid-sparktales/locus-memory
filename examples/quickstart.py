"""Offline quickstart: persist, restart, retrieve, correct, build context, forget.

Run from anywhere after installing the wheel:

    python quickstart.py /tmp/locus-memory-demo

Everything stays in the given directory. A file-based standalone key is created there
for the demo; a host application would supply its own KeyProvider instead.
"""
from __future__ import annotations

import sys
from pathlib import Path

from locus_memory import FileKeyProvider, MemoryEngine
from locus_memory.models import (
    AccessContext,
    Actor,
    ContextRequest,
    Correction,
    ForgetTarget,
    Operation,
    PartitionRef,
    Query,
    RememberRequest,
    Scope,
    ScopeGrants,
)

SECRET_PHRASE = "quickstart-canary-blue-heron"


def main(root: Path) -> int:
    keys = FileKeyProvider(root / "keys")
    if not keys.exists():
        keys.create()
    access = AccessContext(
        principal="demo-user", partition=PartitionRef("standalone", "demo"), actor=Actor.USER,
        grants=ScopeGrants(projects=frozenset({"demo-project"})), operations=frozenset(Operation),
    )

    # 1. Persist.
    with MemoryEngine(root / "data", keys) as engine:
        pref = engine.remember(access, RememberRequest(
            f"Prefers concise answers ({SECRET_PHRASE})", kind="preference", title="Answer style")).record
        fact = engine.remember(access, RememberRequest(
            "The demo project deploys from the staging branch", kind="decision",
            scope=Scope.of(project="demo-project"), title="Deploy branch")).record
        print("remembered:", pref.id, fact.id)

    # 2. Restart and retrieve.
    with MemoryEngine(root / "data", keys) as engine:
        result = engine.search(access, Query(text="deploy branch"))
        print("search status:", result.status.value, "hits:", [h.record.title for h in result.hits])
        assert result.hits and result.hits[0].record.id == fact.id

        # 3. Correct (new revision; cached context is invalidated).
        current = engine.get(access, fact.id)
        corrected = engine.correct(access, fact.id, Correction(
            content="The demo project deploys from the release branch"), expected_revision=current.revision)
        print("corrected to revision", corrected.record.revision)

        # 4. Build a bounded context packet with a receipt.
        packet = engine.build_context(access, ContextRequest(token_allowance=300, query="deploy"))
        print(f"context: {packet.token_count} tokens ({packet.token_count_kind.value}), "
              f"{len(packet.items)} items, receipt {packet.receipt_id}")
        assert "release branch" in packet.text and "staging branch" not in packet.text

        # 5. Forget, with a receipt.
        receipt = engine.forget(access, ForgetTarget("memory", pref.id))
        print("forgot:", receipt.deleted, "generation", receipt.deletion_generation)

    # 6. Restart: the forgotten memory is gone and nothing was left in plaintext.
    with MemoryEngine(root / "data", keys) as engine:
        remaining = [r.id for r in engine.list(access, lifecycles=None)]
        assert pref.id not in remaining and fact.id in remaining
    leaks = [p for p in (root / "data").rglob("*") if p.is_file() and SECRET_PHRASE.encode() in p.read_bytes()]
    print("plaintext leaks on disk:", len(leaks))
    assert not leaks
    print("quickstart OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "./locus-memory-demo")))
