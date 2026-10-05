"""Encrypted, content-free host delivery receipts for context inspection.

These records prove only what a host reports submitting, never model attention.
Opaque host identifiers are encrypted with the receipt; no new plaintext index.
"""
from __future__ import annotations

from typing import Any

from .. import policy
from ..errors import AccessDenied, NotFound, ValidationError
from ..models import Operation, Receipt
from .compiler import CONTEXT_RECEIPT_MAX, CONTEXT_RECEIPT_TTL_S, RECEIPT_OPERATION

OPERATION = "context_submission"
STATES = frozenset({"selected", "submitted", "skipped", "failed", "uncertain"})


def _authorize(ctx: Any, access: Any) -> None:
    policy.require(access, Operation.READ)
    if access.partition.partition_id != ctx.partition.partition_id:
        raise AccessDenied("submission belongs to another partition")


def _label(value: str, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise ValidationError(f"{name} must be a bounded opaque identifier")
    return value


def record(ctx: Any, access: Any, *, context_receipt_id: str | None, session_id: str,
           run_id: str, agent_id: str, turn_id: str, attempt_id: str,
           state: str = "selected", reason: str = "", submission_id: str | None = None,
           selected_context_receipt_id: str | None = None) -> dict[str, Any]:
    _authorize(ctx, access)
    if state not in STATES or reason not in {"", "no_eligible_memory", "policy_disabled", "provider_returned",
                                            "provider_failed", "delivery_unknown", "revalidated"}:
        raise ValidationError("invalid submission state or reason")
    identity = {name: _label(value, name) for name, value in (
        ("session_id", session_id), ("run_id", run_id), ("agent_id", agent_id),
        ("turn_id", turn_id), ("attempt_id", attempt_id))}
    p = ctx.partition
    with p.db.write() as conn:
        for identifier in (context_receipt_id, selected_context_receipt_id):
            if not identifier:
                continue
            original = p.load_receipt(conn, identifier)
            if (not original or original.get("operation") != RECEIPT_OPERATION
                    or original.get("details", {}).get("grants_fingerprint") != access.grants.fingerprint()):
                raise NotFound("context receipt not found for this access")
        details = {**identity, "context_receipt_id": context_receipt_id, "state": state, "reason": reason,
                   "selected_context_receipt_id": selected_context_receipt_id,
                   "revalidated": bool(selected_context_receipt_id and selected_context_receipt_id != context_receipt_id),
                   "grants_fingerprint": access.grants.fingerprint()}
        if submission_id:
            previous = p.load_receipt(conn, submission_id)
            if (not previous or previous.get("operation") != OPERATION
                    or any(previous.get("details", {}).get(k) != v for k, v in identity.items())
                    or previous.get("details", {}).get("grants_fingerprint") != access.grants.fingerprint()):
                raise NotFound("submission not found")
            before = previous["details"]["state"]
            transitions = {"selected": STATES, "uncertain": {"uncertain", "submitted", "failed"},
                           "submitted": {"submitted"}, "failed": {"failed"}, "skipped": {"skipped"}}
            if (state not in transitions[before] or previous["details"].get("context_receipt_id") != context_receipt_id
                    or previous["details"].get("selected_context_receipt_id") != selected_context_receipt_id):
                raise ValidationError("a submission cannot change its packet or reverse delivery state")
            receipt = Receipt(receipt_id=submission_id, operation=OPERATION, status=state,
                              created_at=previous["created_at"], partition_id=p.partition_id,
                              generation=p.generation(conn), details=details)
            p.save_receipt(conn, receipt)
        else:
            receipt = p.make_receipt(conn, OPERATION, state, details=details)
        conn.execute("DELETE FROM receipts WHERE operation=? AND created_at<?",
                     (OPERATION, ctx.clock() - CONTEXT_RECEIPT_TTL_S))
        conn.execute("DELETE FROM receipts WHERE id IN (SELECT id FROM receipts WHERE operation=? "
                     "ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET ?)", (OPERATION, CONTEXT_RECEIPT_MAX))
    return {"submission_id": receipt.receipt_id, "created_at": receipt.created_at, **details}


def list_submissions(ctx: Any, access: Any, *, session_id: str, run_id: str, agent_id: str,
                     turn_id: str | None = None) -> list[dict[str, Any]]:
    _authorize(ctx, access)
    result = []
    p = ctx.partition
    with p.db.read() as conn:
        rows = conn.execute("SELECT id FROM receipts WHERE operation=? AND created_at>=? "
                            "ORDER BY created_at,id LIMIT ?",
                            (OPERATION, ctx.clock() - CONTEXT_RECEIPT_TTL_S, CONTEXT_RECEIPT_MAX))
        for row in rows:
            raw = p.load_receipt(conn, row[0])
            details = raw["details"]
            if any(details.get(k) != v for k, v in (
                    ("session_id", session_id), ("run_id", run_id), ("agent_id", agent_id))):
                continue
            if turn_id is not None and details.get("turn_id") != turn_id:
                continue
            # Host authenticates the run identity. Current grants may be narrower
            # than at submission; explanation reauthorizes every individual item.
            result.append({"submission_id": raw["receipt_id"], "created_at": raw["created_at"],
                           **{k: v for k, v in details.items() if k != "grants_fingerprint"}})
    return result
