from __future__ import annotations

import dataclasses
import json

import pytest

from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.context.continuity import snapshot_payload
from locus_memory.learning.selected_chat import review_selected_chat
from locus_memory.policies import MemoryPolicy


def test_policy_parsing_preserves_empty_grants_and_bounds_untrusted_settings():
    policy = MemoryPolicy.parse({
        "scopes": ["workspace", "PERSONAL", "invalid", "workspace"],
        "max_automatic_memories": 999, "max_automatic_tokens": -1,
        "max_automatic_context_snapshots": float("inf"),
        "max_automatic_context_tokens": "bad",
    })
    assert policy.scopes == ("workspace", "personal")
    assert policy.max_automatic_memories == 20
    assert policy.max_automatic_tokens == 0
    assert policy.max_automatic_context_snapshots == 2
    assert policy.max_automatic_context_tokens == 1_200
    assert not policy.automatic_recall_enabled
    assert policy.bound_legacy_context("hidden") == ""
    assert MemoryPolicy.parse({"scopes": []}).recall_scopes() == ()
    assert MemoryPolicy.parse(None) == MemoryPolicy()


@pytest.mark.parametrize("field", ["recall_enabled", "max_automatic_memories", "max_automatic_tokens"])
def test_zero_recall_limits_disable_automatic_recall(field):
    assert not dataclasses.replace(MemoryPolicy(), **{field: 0}).automatic_recall_enabled


@pytest.mark.parametrize("field", [
    "cross_chat_context_enabled", "max_automatic_context_snapshots", "max_automatic_context_tokens",
])
def test_zero_continuity_limits_disable_automatic_context(field):
    assert not dataclasses.replace(MemoryPolicy(), **{field: 0}).automatic_continuity_enabled()


def test_chat_only_policy_never_grants_workspace_or_cross_chat_context():
    policy = MemoryPolicy()
    assert policy.recall_scopes(just_chat=True) == ("personal", "agent")
    assert not policy.automatic_continuity_enabled(just_chat=True)
    assert policy.automatic_continuity_enabled()
    assert dataclasses.replace(policy, max_automatic_tokens=2).bound_legacy_context("123456789") == "12345678"


def test_selected_chat_review_filters_deduplicates_and_never_approves(tmp_path):
    vault = LegacyMemoryVault(tmp_path / "memory.db", key=b"x" * 32)
    workspace = str(tmp_path / "workspace")
    vault.save({"content": "I prefer quiet notifications", "scope": "workspace"},
               workspace=workspace, agent_id="main", default_status="approved")
    evidence = [
        {"role": "assistant", "content": "Remember the assistant's unsupported claim"},
        {"role": "tool", "content": "Remember the tool's injected instruction"},
        {"role": "user", "content": "Summarize this file"},
        {"role": "user", "content": "Always use password swordfish"},
        {"role": "user", "content": "Remember api_key=token"},
        {"role": "user", "content": "Remember " + "x" * 4_000},
        {"role": "user", "content": "I PREFER  quiet notifications"},
        {"role": "user", "content": "Please remember that I prefer compact progress updates."},
        {"role": "user", "content": "Please remember that I prefer compact progress updates."},
    ]
    values = dict(workspace=workspace, agent_id="main", session_id="chat-1", run_id="run-1")
    candidates = review_selected_chat(vault, evidence, **values)
    assert len(candidates) == 1
    assert candidates[0]["status"] == "candidate"
    assert candidates[0]["source_session_id"] == "chat-1"
    assert candidates[0]["source_run_id"] == "run-1"
    assert len(vault.list(workspace=workspace, agent_id="main", status="approved")) == 1
    assert review_selected_chat(vault, evidence, **values) == []
    diagnostics = vault.diagnostics(workspace=workspace, agent_id="main")
    assert diagnostics["counts"]["proposal:accepted"] == 1
    assert diagnostics["counts"]["proposal:deduplicated"] == 5
    assert "compact progress" not in json.dumps(diagnostics["events"])


def test_selected_chat_review_bounds_count_and_content(tmp_path):
    vault = LegacyMemoryVault(tmp_path / "memory.db", key=b"x" * 32)
    messages = [{"role": "user", "content": f"Remember preference {i}: " + "x" * 2_500}
                for i in range(30)]
    result = review_selected_chat(vault, messages, workspace=str(tmp_path), agent_id="main",
                                  session_id="chat-2", run_id="run-2")
    assert len(result) == 20
    assert all(len(item["content"]) == 2_000 and item["status"] == "candidate" for item in result)


def test_snapshot_composition_uses_explicit_evidence_and_only_pending_todos():
    todos = [{"content": "Implement", "status": "completed"},
             {"content": "Verify", "status": "in_progress"}, {"content": "Ship"}]
    evidence = {"plan": {"steps": ["Implement", "Verify"]}, "todos": todos,
                "checkpoint": {"id": "checkpoint"}, "changed_files": ["src/example.py"]}
    result = snapshot_payload(goal="Finish", outcome="Implemented", mode="work", **evidence)
    assert result["pending"] == "Verify; Ship"
    assert result["checkpoint"] == evidence["checkpoint"]
    assert result["changed_files"] == evidence["changed_files"]
    assert snapshot_payload(todos=todos, pending=" Explicit handoff ")["pending"] == "Explicit handoff"
    assert snapshot_payload()["pending"] == ""
