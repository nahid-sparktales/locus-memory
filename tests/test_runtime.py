"""Reusable recall lifecycle without a Locus installation, core, environment or keychain."""
from __future__ import annotations

import logging

import pytest

from conftest import access_for, scan_for_plaintext
from locus_memory.compat.legacy_vault import LegacyMemoryVault
from locus_memory.context import CONTEXT_WRAPPER_OPEN
from locus_memory.errors import MemoryEngineError
from locus_memory.models import (
    Actor,
    Correction,
    ForgetTarget,
    MemoryKind,
    Operation,
    RememberRequest,
    Scope,
)
from locus_memory.runtime import LEGACY_RESULTS_HEADER, LegacyRecall, RecallRuntime


@pytest.fixture
def runtimes(tmp_path, keys, clock, user_access):
    opened = []

    def create(**kwargs):
        options = {
            "root": tmp_path / f"runtime-{len(opened)}", "partition": user_access.partition,
            "key_provider": keys, "mode": "enabled", "clock": clock,
            "maintenance_access": access_for(actor=Actor.HOST, operations={Operation.MAINTAIN}),
        }
        options.update(kwargs)
        runtime = RecallRuntime(**options)
        opened.append(runtime)
        return runtime

    yield create
    for runtime in opened:
        runtime.close()


def remember(runtime, access, text="Prefer concise replies", scope=None):
    return runtime.engine.remember(access, RememberRequest(
        content=text, kind=MemoryKind.PREFERENCE, scope=scope or Scope(),
    )).record


def recall(runtime, access, slot, *, include_personal=True):
    return runtime.recall(slot, legacy=lambda: LegacyRecall("legacy text"), build_packet=lambda: runtime.packet(
        access, "preference", max_tokens=2000, max_items=8, include_personal=include_personal,
    ))


def test_disabled_runtime_does_not_open_roots_or_request_keys(runtimes):
    runtime = runtimes(mode="disabled")
    slot = object()
    assert runtime.recall(slot, legacy=lambda: LegacyRecall("legacy only"),
                          build_packet=lambda: pytest.fail("disabled recall compiled a packet")) == "legacy only"
    runtime.session_boundary(slot)
    runtime.scope_change(slot, "changed")
    assert not runtime.root.exists()
    with pytest.raises(MemoryEngineError, match="disabled"):
        _ = runtime.engine


def test_package_ownership_ignores_stale_disabled_flag(runtimes, user_access):
    runtime = runtimes(mode="disabled", initial_state="package_authoritative")
    assert runtime.mode == "enabled"
    remember(runtime, user_access)
    assert "Prefer concise replies" in recall(runtime, user_access, object())
    assert not (runtime.root / "control.sqlite3").exists()


def test_opaque_slots_revalidate_corrections_and_forgetting_independently(runtimes, user_access):
    runtime = runtimes()
    record = remember(runtime, user_access)
    first, second = object(), object()  # no host-specific attributes exist
    one = recall(runtime, user_access, first)
    two = recall(runtime, user_access, second)
    assert one == two and one.count(CONTEXT_WRAPPER_OPEN) == 1
    runtime.engine.correct(user_access, record.id, Correction(content="Prefer detailed replies"), expected_revision=record.revision)
    fresh = runtime.revalidate(first, one)
    assert "Prefer detailed replies" in fresh and "Prefer concise replies" not in fresh
    assert runtime.revalidate(object(), one) is None
    assert runtime.revalidate(first, fresh) is None
    runtime.release_context(second)
    assert runtime.revalidate(second, two) is None
    runtime.engine.forget(user_access, ForgetTarget("memory", record.id))
    assert runtime.revalidate(first, fresh) == ""


def test_personal_scope_can_be_omitted_without_losing_scoped_preferences(runtimes, user_access):
    runtime = runtimes()
    remember(runtime, user_access, "Personal preference should not be injected")
    remember(runtime, user_access, "Project preference for tabs", Scope.of(project="proj-a"))
    result = recall(runtime, user_access, object(), include_personal=False)
    assert "Personal preference" not in result
    assert "Project preference for tabs" in result


def test_shadow_returns_legacy_text_and_content_free_metrics(runtimes, user_access, caplog):
    runtime = runtimes(mode="shadow")
    secret = "canary-never-in-runtime-log"
    record = remember(runtime, user_access, secret)
    caplog.set_level(logging.INFO, logger="locus_memory.runtime")
    result = runtime.recall(object(), legacy=lambda: LegacyRecall("unchanged legacy prompt", (record.id,)),
                            build_packet=lambda: runtime.packet(user_access, "", max_tokens=2000, max_items=8))
    assert result == "unchanged legacy prompt"
    assert runtime.last_shadow["overlap"] == 1
    assert "memory engine shadow:" in caplog.text and secret not in caplog.text
    assert scan_for_plaintext(runtime.root, secret) == []
    assert runtime._pending == {}

    def fail():
        raise MemoryEngineError("simulated error")

    assert runtime.recall(object(), legacy=lambda: LegacyRecall("still legacy"), build_packet=fail) == "still legacy"
    assert runtime.last_shadow is None  # no success from a previous comparison survives


def test_archive_excludes_reasoning_and_memory_injection(runtimes, user_access):
    runtime = runtimes(archive=True)
    ingestion = access_for(actor=Actor.HOST, projects=("proj-a",), operations={Operation.INGEST})
    samples = [
        "Canary archive this committed message",
        "<think>Canary secret hidden reasoning</think>",
        f"{LEGACY_RESULTS_HEADER}\nCanary recalled facts",
        f"{CONTEXT_WRAPPER_OPEN}\nCanary engine injection\n</memory-context>",
    ]
    for index, text in enumerate(samples):
        runtime.archive_text(ingestion, session_ref="session-a", role="user", text=text, event_id=f"event-{index}")
    texts = [hit.message.text for hit in runtime.engine.search_history(user_access, "Canary").hits]
    assert texts == [samples[0]]
    assert scan_for_plaintext(runtime.root, "Canary") == []


def test_archive_requires_opt_in_and_correct_partition(runtimes, user_access):
    runtime = runtimes()
    runtime.archive_text(user_access, session_ref="s1", role="user", text="do not open engine")
    assert runtime._engine is None
    enabled = runtimes(archive=True)
    with pytest.raises(ValueError, match="partition"):
        enabled.archive_text(access_for(profile="other"), session_ref="s1", role="user", text="wrong profile")
    assert enabled._engine is None


def test_maintenance_is_host_scheduled_and_bounded(runtimes, user_access, clock):
    scheduled = []
    runtime = runtimes(schedule=scheduled.append, maintenance_interval_s=60)
    slot = object()
    runtime.session_boundary(slot)
    assert scheduled == [] and runtime._engine is None
    remember(runtime, user_access)
    recall(runtime, user_access, slot)
    runtime.session_boundary(slot)
    assert len(scheduled) == 1 and runtime._pending == {}
    runtime.session_boundary(slot)
    assert len(scheduled) == 1
    scheduled.pop()()
    runtime.session_boundary(slot)
    assert scheduled == []
    clock.advance(61)
    runtime.session_boundary(slot)
    assert len(scheduled) == 1


def test_legacy_sync_revalidates_deletion_without_host_imports(runtimes, tmp_path, user_access):
    source = tmp_path / "legacy.sqlite3"
    key = b"L" * 32
    vault = LegacyMemoryVault(source, key=key)
    row = vault.save({"scope": "personal", "kind": "preference", "content": "Prefer compact answers"})
    runtime = runtimes(
        initial_state="legacy_authoritative", legacy_database=source, legacy_key=lambda: key,
        legacy_access=access_for(actor=Actor.HOST, operations={Operation.ADMIN}),
    )
    slot = object()
    text = recall(runtime, user_access, slot)
    assert "Prefer compact answers" in text
    vault.delete(row["id"])
    assert runtime.revalidate(slot, text) == ""


def test_memory_layer_violation_drops_packet_without_failing_turn(runtimes, user_access):
    def reject(_text):
        raise AssertionError("double layer")

    runtime = runtimes(layer_validator=reject)
    remember(runtime, user_access)
    assert recall(runtime, user_access, object()) == ""
    assert runtime.engine.metrics.snapshot()["counters"]["adapter.layer_violation"]["value"] == 1


def test_archive_with_multiple_project_grants_requires_explicit_scope(runtimes):
    runtime = runtimes(archive=True)
    access = access_for(actor=Actor.HOST, projects=("proj-a", "proj-b"), operations={Operation.INGEST})
    with pytest.raises(ValueError, match="scope is required"):
        runtime.archive_text(access, session_ref="s1", role="user", text="project-specific message")
    assert runtime._engine is None
    runtime.archive_text(access, session_ref="s1", role="user", text="project-specific message",
                         scope=Scope.of(project="proj-b"))
    assert runtime.engine.search_history(access_for(projects=("proj-a",)), "project-specific").hits == ()
    assert len(runtime.engine.search_history(access_for(projects=("proj-b",)), "project-specific").hits) == 1
