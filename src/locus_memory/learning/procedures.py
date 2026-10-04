"""Governed procedural learning: nominate -> (host) evaluate -> (human) approve -> export.

Nothing here executes a procedure step. The learner can only *nominate* a draft;
the engine then decides, from data it controls:

* independent evidence - distinct verified-success tasks among the cited episodes
  that the caller may see and that lie inside the procedure's scope. Retries,
  attempts, replays and copies collapse into one unit (same task, or sharing a
  trusted verification receipt). Unknown/failed episodes never count;
* safety - a heuristic screen of every text field for verification bypasses,
  destructive or privileged commands, remote-code piping, credential exfiltration,
  governance edits (AGENTS.md, approval policy, secret exclusions, provider
  settings, evaluation rules) and capability requests broader than the evidence.

Evaluation is delegated to the host's :class:`~locus_memory.host.EvaluationRunner`
with a fixed, allow-listed manifest; approval requires a host-attested reviewer and
is neither authorization to execute nor a capability grant. Export writes a
versioned proposal directory with exclusive-create semantics; the host decides
activation.

Procedure states are kept in the encrypted record payload; the ``procedures`` index
carries only ids, state, version, a keyed name token and timestamps.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import policy, safety
from ..core import check_transition
from ..errors import (
    AccessDenied,
    InvalidTransition,
    ProviderError,
    RevisionConflict,
    SuppressedError,
    UnsupportedCapability,
    ValidationError,
)
from ..models import (
    AccessContext,
    Actor,
    Confidence,
    EpisodeOutcome,
    Lifecycle,
    Links,
    MemoryKind,
    MemoryRecord,
    Operation,
    Procedure,
    ProcedureDraft,
    ProcedureState,
    Receipt,
    Retention,
    Scope,
    ScopeGrants,
    SourceKind,
    SourceRef,
    StatementBasis,
)
from ..services import PartitionContext
from ..storage.partition import new_id, partition_bound
from ..validation import (
    check_finite,
    check_id,
    check_int,
    check_ref,
    check_text,
    normalize_for_fingerprint,
)
from ._common import authorized_by_ids, chunked, existing_ids

MIN_INDEPENDENT_EVIDENCE = 2
MAX_EVIDENCE_EPISODES = 64
MANIFEST_FORMAT = "locus-memory/procedure-manifest/v1"
_TEXT_FIELDS = ("name", "purpose", "applicability", "steps", "preconditions", "expected_outcomes",
                "negative_cases", "known_failures", "requested_capabilities", "rollback")
_LIST_FIELDS = ("steps", "preconditions", "expected_outcomes", "negative_cases", "known_failures",
                "requested_capabilities")
# States from which losing evidence moves a procedure to REVOKED_EVIDENCE.
_REVOCABLE = frozenset({ProcedureState.NOMINATED, ProcedureState.CANDIDATE, ProcedureState.EVALUATING,
                        ProcedureState.EVALUATED, ProcedureState.APPROVED, ProcedureState.EXPORTED})
_REJECTABLE = frozenset({ProcedureState.NOMINATED, ProcedureState.CANDIDATE, ProcedureState.INSUFFICIENT_EVIDENCE,
                         ProcedureState.UNSAFE, ProcedureState.FAILED_EVALUATION, ProcedureState.EVALUATED,
                         ProcedureState.REVOKED_EVIDENCE})
_APPROVAL_LIMITATIONS = (
    "approval does not broaden capabilities: requested capabilities are unchanged and remain subject to host policy",
    "approval is not authorization to execute; the host decides activation and enforcement",
    "the safety screen is heuristic pattern matching, not a proof of safety",
)

# --------------------------------------------------------------------------- safety screen (heuristic)
_SECRET_STORES = (r"(?:\.ssh/|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/credentials|\.netrc\b|\.npmrc\b|\.pypirc\b"
                  r"|\.docker/config\.json|\.kube/config|\bkeychain\b|(?:^|[\s/])\.env\b|private[_ -]?keys?\b"
                  r"|credentials?\.json\b|\.git-credentials\b)")
_GOVERNANCE = (r"(?:AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|copilot-instructions(?:\.md)?"
               r"|approval[ _-]?(?:polic(?:y|ies)|rules?|settings?|gates?|config\w*)"
               r"|secret[ _-]?(?:exclusions?|scann\w*|filters?|allow-?lists?|ignore\w*)|\.gitleaks\w*|\.secretsignore"
               r"|provider[ _-]?(?:settings?|config\w*|keys?|credentials?)"
               r"|eval(?:uation)?[ _-]?(?:rules?|criteria|config\w*|harness|polic(?:y|ies)|thresholds?)"
               r"|memory[ _-]?polic(?:y|ies))")
_EDIT_VERBS = (r"(?:edit\w*|modif\w*|chang\w*|updat\w*|overwrit\w*|rewrit\w*|append\w*|write\s+to|writ\w*\s+into"
               r"|delet\w*|remov\w*|disabl\w*|replac\w*|patch\w*|relax\w*|weaken\w*|loosen\w*|tweak\w*|lower\w*"
               r"|add\w*\s+(?:an?\s+)?(?:exception|entry|rule)s?\s+to)")
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("skip_verification", re.compile(
        r"(?i)\b(?:disabl\w*|skip\w*|bypass\w*|turn(?:ing)?\s+off|ignor\w*|comment\w*\s+out|remov\w*|delet\w*"
        r"|silenc\w*|mut(?:e|ing)|suppress\w*|xfail\w*)\b[^.\n;]{0,40}?\b(?:tests?|test\s+suites?|verification|verif"
        r"(?:y|ier)|checks?|lint\w*|ci|hooks?|pre-commit|type[- ]?check\w*|assertions?|safety|approval)\b")),
    ("skip_verification", re.compile(
        r"(?i)@pytest\.mark\.(?:skip|xfail)\b|\b(?:it|describe|test)\.skip\s*\(|\bunittest\.skip\b|\bHUSKY=0\b"
        r"|\bSKIP_(?:TESTS?|CHECKS?|VERIFY|HOOKS?|CI)\b|\bpytest\b[^\n]*\s(?:--deselect|-p\s+no:)|\|\|\s*true\b"
        r"|--no-(?:tests?|checks?|verification)\b")),
    ("no_verify", re.compile(r"(?i)--no-verify\b|\bgit\s+commit\b[^\n]*\s-[a-zA-Z]*n\b")),
    ("force_push", re.compile(
        r"(?i)\bgit\s+push\b[^\n;&|]*?(?:\s--force(?:-with-lease|-if-includes)?\b|\s-[a-zA-Z]*f\b|\s\+[\w./-]+)"
        r"|\bforce[- ]?push\w*")),
    ("destructive_delete", re.compile(
        r"(?i)\brm\s+(?:-{1,2}[\w-]+\s+)*[\"']?(?:/|/\*|~|~/|~/\*|\$HOME/?\*?|\$\{HOME\}/?\*?)[\"']?(?=$|[\s;&|)])"
        r"|--no-preserve-root\b|\brm\s+(?:-{1,2}[\w-]+\s+)*[\"']?/(?:Users|home|etc|usr|var|System|bin|opt)/?[\"']?"
        r"(?=$|[\s;&|)])")),
    ("world_writable", re.compile(r"(?i)\bchmod\s+(?:-[\w-]+\s+)*(?:0?777|a\+rwx|ugo\+rwx|a=rwx)\b")),
    ("privilege_escalation", re.compile(r"(?i)\bsudo\b|\bdoas\b|\bpkexec\b|\bsu\s+(?:-\s+)?root\b|\bsu\s+-c\b")),
    ("pipe_to_shell", re.compile(
        r"(?i)\b(?:curl|wget)\b[^\n]*?\|\s*(?:sudo\s+)?(?:(?:ba|z|k|da|fi)?sh|python[23]?|perl|ruby|node)\b"
        r"|\b(?:(?:ba|z)?sh|source|\.)\s+(?:-c\s+)?[\"']?[<$]\(\s*(?:curl|wget)\b"
        r"|\b(?:curl|wget)\b[^\n]*?>\s*\S+\s*(?:&&|;)\s*(?:(?:ba|z)?sh|chmod\s+\+x)\b")),
    ("credential_exfiltration", re.compile(
        r"(?i)\b(?:cat|print\w*|echo|less|more|head|tail|cp|copy\w*|scp|rsync|upload\w*|send\w*|post\w*|exfiltrat\w*"
        r"|curl|wget|nc|netcat|base64|mail\w*|paste\w*|leak\w*|share\w*|dump\w*|read\w*|open\w*|zip|tar)\b[^\n]{0,80}?"
        + _SECRET_STORES)),
    ("credential_exfiltration", re.compile(
        r"(?i)\b(?:upload\w*|send\w*|post\w*|exfiltrat\w*|scp|rsync|curl|wget|nc|netcat|mail\w*|paste\w*|leak\w*"
        r"|transmit\w*|forward\w*|share\w*|publish\w*)\b[^\n]{0,80}?\b(?:tokens?|secrets?|passwords?|passwd"
        r"|credentials?|api[_ -]?keys?|access[_ -]?keys?|session\s+cookies?)\b")),
    ("credential_exfiltration", re.compile(
        r"(?i)\b(?:echo|print\w*|cat|log\w*|curl|wget|nc)\b[^\n]{0,60}?\$\{?\w*(?:TOKEN|SECRET|PASSWORD|PASSWD"
        r"|API_?KEY|ACCESS_KEY|PRIVATE_KEY)\w*|\bsecurity\s+find-(?:generic|internet)-password\b"
        r"|\b(?:printenv|env|set)\s*(?:\||>)")),
    ("governance_edit", re.compile(r"(?i)\b" + _EDIT_VERBS + r"\b[^\n]{0,60}?" + _GOVERNANCE)),
    ("governance_edit", re.compile(
        r"(?i)" + _GOVERNANCE + r"[^\n]{0,40}?\b(?:edit\w*|modif\w*|overwrit\w*|rewrit\w*|append\w*|updat\w*"
        r"|chang\w*|relax\w*|disabl\w*)\b|(?:>>?|\btee\b(?:\s+-a)?|\bsed\s+-i\b[^\n]*?)\s*\S*"
        r"(?:AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules)")),
)


def screen_text(field: str, text: str) -> list[str]:
    """Heuristic safety findings (``code@field``) for one text value. Never returns content."""
    found = {f"{code}@{field}" for code, pattern in _PATTERNS if pattern.search(text)}
    scan = safety.scan(text)
    if scan.secrets:
        found.add(f"embedded_secret@{field}")
    if scan.injection:
        found.add(f"instruction_like@{field}")
    return sorted(found)


def screen_draft(draft: ProcedureDraft) -> list[str]:
    findings: set[str] = set()
    for name in _TEXT_FIELDS:
        value = getattr(draft, name)
        if isinstance(value, tuple):
            for index, item in enumerate(value):
                findings.update(screen_text(f"{name}[{index}]", item))
        elif value:
            findings.update(screen_text(name, value))
    return sorted(findings)


def _redact_draft(draft: ProcedureDraft) -> tuple[ProcedureDraft, list[str]]:
    found: set[str] = set()

    def clean(text: str) -> str:
        out, cats = safety.redact_secrets(text)
        found.update(cats)
        return out

    changes: dict[str, Any] = {"purpose": clean(draft.purpose), "applicability": clean(draft.applicability),
                               "rollback": clean(draft.rollback)}
    for name in _LIST_FIELDS:
        changes[name] = tuple(clean(x) for x in getattr(draft, name))
    redacted_name = clean(draft.name)
    if redacted_name != draft.name:
        changes["name"] = "redacted-procedure"
    return dataclasses.replace(draft, **changes), sorted(found)


def _attested_capabilities(attempt: dict[str, Any], task_ref: str) -> set[str] | None:
    """Capabilities the host attested for an attempt (union over its trusted, task-matching
    receipts that carry an attestation); None when none does."""
    found: set[str] | None = None
    for result in attempt.get("verification") or ():
        caps = result.get("capabilities")
        if (result.get("trusted") is not True or result.get("task_ref") not in (None, task_ref)
                or not isinstance(caps, list) or not all(isinstance(c, str) for c in caps)):
            continue
        found = (found or set()) | {c.strip().casefold() for c in caps}
    return found


def _within(inner: Scope, outer: Scope) -> bool:
    """True when every constraint of ``inner`` is also a constraint of ``outer``.

    Anyone authorized for ``outer`` is then authorized for ``inner``, so evidence in
    ``inner`` never leaks to a reader of a procedure scoped to ``outer``.
    """
    outer_pairs = set(outer.constraints)
    return all(pair in outer_pairs for pair in inner.constraints)


def _slug(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip(".-_")[:80]
    slug = re.sub(r"\.{2,}", ".", slug)
    return slug or "procedure"


def _one_line(text: str) -> str:
    return safety.neutralize_markup(" ".join(str(text).split()))


@dataclass
class _Evidence:
    accepted: list[str]
    counted: list[str]
    independent: int
    capabilities: set[str] | None


# --------------------------------------------------------------------------- service
@partition_bound
class ProcedureService:
    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx
        self.p = ctx.partition
        self.records = ctx.records

    # ------------------------------------------------------------------ helpers
    @property
    def now(self) -> float:
        return self.ctx.clock()

    def _name_token(self, name: str) -> str:
        return self.p.token("procedure-name", normalize_for_fingerprint(name))

    def _row(self, conn: sqlite3.Connection, procedure_id: str) -> sqlite3.Row | None:
        return conn.execute("SELECT * FROM procedures WHERE procedure_id=?", (procedure_id,)).fetchone()

    def _load(self, conn: sqlite3.Connection, procedure_id: str) -> MemoryRecord | None:
        row = self._row(conn, procedure_id)
        if row is None:
            return None
        record = self.records.get(conn, row["record_id"])
        if record is None or record.kind != MemoryKind.PROCEDURE or "procedure" not in record.extra:
            return None
        return record

    def _load_visible(self, conn: sqlite3.Connection, access: AccessContext, procedure_id: str) -> MemoryRecord:
        check_id(procedure_id, "procedure_id")
        return policy.require_visible(access, self._load(conn, procedure_id))

    @staticmethod
    def _state(record: MemoryRecord) -> ProcedureState:
        return ProcedureState(record.extra["procedure"]["state"])

    def _to_procedure(self, record: MemoryRecord) -> Procedure:
        s = record.extra["procedure"]
        return Procedure(
            procedure_id=s["procedure_id"], record_id=record.id, version=int(s["version"]),
            state=ProcedureState(s["state"]), draft=ProcedureDraft.from_dict(s["draft"]),
            independent_evidence=int(s["independent_evidence"]),
            evidence_episode_ids=tuple(s["evidence_episode_ids"]), safety_findings=tuple(s["safety_findings"]),
            evaluation_receipts=tuple(s["evaluation_receipts"]),
            state_history=tuple((h[0], float(h[1]), h[2]) for h in s["state_history"]),
            updated_at=record.updated_at,
        )

    @staticmethod
    def _render(draft: ProcedureDraft) -> str:
        lines = [f"Procedure: {draft.name}", f"Purpose: {draft.purpose}", f"Applicability: {draft.applicability}"]
        for label, values in (("Preconditions", draft.preconditions), ("Steps", draft.steps),
                              ("Expected outcomes", draft.expected_outcomes),
                              ("Negative cases", draft.negative_cases), ("Known failures", draft.known_failures),
                              ("Requested capabilities", draft.requested_capabilities)):
            if values:
                lines.append(f"{label}:")
                lines += [f"  {i + 1}. {v}" for i, v in enumerate(values)]
        if draft.rollback:
            lines.append(f"Rollback: {draft.rollback}")
        return safety.neutralize_markup("\n".join(lines))[:32_000]

    def _sources(self, payload: dict[str, Any], actor: Actor) -> tuple[SourceRef, ...]:
        sources = [SourceRef(SourceKind.EPISODE, eid, actor=actor) for eid in payload["evidence_episode_ids"]]
        sources += [SourceRef(SourceKind.EVALUATION_RECEIPT, rid, actor=Actor.HOST)
                    for rid in payload["evaluation_receipts"]]
        return tuple(sources)

    def _index(self, conn: sqlite3.Connection, record: MemoryRecord) -> None:
        s = record.extra["procedure"]
        conn.execute(
            "INSERT OR REPLACE INTO procedures(procedure_id, record_id, state, version, name_token, updated_at)"
            " VALUES(?,?,?,?,?,?)",
            (s["procedure_id"], record.id, s["state"], int(s["version"]), self._name_token(s["draft"]["name"]),
             record.updated_at),
        )
        conn.execute("DELETE FROM procedure_evidence WHERE procedure_id=?", (s["procedure_id"],))
        conn.executemany("INSERT OR IGNORE INTO procedure_evidence(procedure_id, episode_id) VALUES(?,?)",
                         [(s["procedure_id"], eid) for eid in s["evidence_episode_ids"]])

    def _save(self, conn: sqlite3.Connection, record: MemoryRecord, payload: dict[str, Any], *,
              state: ProcedureState, reason: str, change: str, actor: Actor,
              lifecycle: Lifecycle | None = None, links: Links | None = None) -> MemoryRecord:
        """Write a new revision with an updated payload/state (inside the caller's transaction)."""
        now = self.now
        payload = dict(payload)
        if payload["state"] != state.value:
            payload["state_history"] = [*payload["state_history"], [state.value, now, reason[:200]]]
        payload["state"] = state.value
        target = lifecycle or record.lifecycle
        if target != record.lifecycle:
            check_transition(record.lifecycle, target)
        updated = dataclasses.replace(
            record, revision=record.revision + 1, lifecycle=target, updated_at=now,
            sources=self._sources(payload, actor), links=links or record.links,
            extra={**record.extra, "procedure": payload},
        )
        updated = self.ctx.services.core.write_internal(conn, updated, change=change, actor=actor,
                                                         expected=record.revision)
        self._index(conn, updated)
        return updated

    # ------------------------------------------------------------------ evidence
    def _assess(self, conn: sqlite3.Connection, grants: ScopeGrants | None, scope: Scope,
                episode_ids: Iterable[str], exclude: Iterable[str] = ()) -> _Evidence:
        wanted = list(dict.fromkeys(episode_ids))
        excluded = set(exclude)
        if not wanted:
            return _Evidence([], [], 0, None)
        marks = ",".join("?" * len(wanted))
        rows = conn.execute(f"SELECT episode_id, record_id FROM episodes WHERE episode_id IN ({marks})",
                            wanted).fetchall()
        by_record = {r["record_id"]: r["episode_id"] for r in rows}
        if not by_record:
            return _Evidence([], [], 0, None)
        if grants is not None:  # authorization in SQL before anything is decrypted
            records = self.records.authorized(conn, grants, lifecycles=None, kinds=(MemoryKind.EPISODE,),
                                              ids=list(by_record))
        else:
            records = [r for r in (self.records.get(conn, rid) for rid in by_record) if r is not None]
        by_episode = {by_record[r.id]: r for r in records if "episode" in r.extra}
        accepted: list[str] = []
        qualifying: list[tuple[str, dict[str, Any]]] = []
        for eid in wanted:
            record = by_episode.get(eid)
            if record is None or not _within(record.scope, scope):
                continue
            accepted.append(eid)
            state = record.extra["episode"]
            if eid not in excluded and state.get("outcome") == EpisodeOutcome.VERIFIED_SUCCESS.value:
                qualifying.append((eid, state))
        # Independence: union episodes that share a task or any trusted receipt.
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        roots: dict[str, str] = {}
        capabilities: set[str] | None = None
        attested_everywhere = bool(qualifying)
        for eid, state in qualifying:
            latest = state["attempts"][-1]
            nodes = [f"task\x00{state['task_ref']}"]
            nodes += [f"receipt\x00{r['receipt_id']}" for r in latest["verification"] if r.get("trusted")]
            for node in nodes[1:]:
                parent[find(node)] = find(nodes[0])
            roots[eid] = nodes[0]
            # Capability evidence is host-attested only (the verification authority's receipts);
            # the agent's self-reported ``environment`` is never trusted. Every counted episode
            # must be covered, and only capabilities all of them used are allowed.
            caps = _attested_capabilities(latest, state["task_ref"])
            if caps is None:
                attested_everywhere = False
            else:
                capabilities = caps if capabilities is None else capabilities & caps
        if not attested_everywhere:
            capabilities = None
        independent = len({find(node) for node in roots.values()})
        return _Evidence(accepted, [eid for eid, _ in qualifying], independent, capabilities)

    @staticmethod
    def _capability_findings(draft: ProcedureDraft, evidence: _Evidence) -> tuple[list[str], str]:
        if not draft.requested_capabilities:
            return [], "none_requested"
        if evidence.capabilities is None:
            # Fail closed: requested capabilities that no host attestation covers are unverified.
            return ["capability_unverified@requested_capabilities"], "unavailable"
        extra = [c for c in draft.requested_capabilities if c.strip().casefold() not in evidence.capabilities]
        return (["capability_escalation@requested_capabilities"] if extra else []), "checked"

    # ------------------------------------------------------------------ nominate
    def nominate(self, access: AccessContext, draft: ProcedureDraft) -> tuple[Procedure, Receipt]:
        policy.require(access, Operation.PROPOSE)
        if not isinstance(draft, ProcedureDraft) or not isinstance(draft.scope, Scope):
            raise ValidationError("a ProcedureDraft with a Scope is required")
        policy.require_scope(access, draft.scope)
        if len(draft.evidence_episode_ids) > MAX_EVIDENCE_EPISODES:
            raise ValidationError(f"at most {MAX_EVIDENCE_EPISODES} evidence episodes")
        # The model leaves these unchecked: bound them here.
        draft = dataclasses.replace(draft, rollback=check_text(draft.rollback or "", "rollback", max_chars=2_000,
                                                               allow_empty=True))
        if draft.supersedes is not None:
            check_id(draft.supersedes, "supersedes")
        findings = screen_draft(draft)
        draft, redactions = _redact_draft(draft)
        now = self.now
        with self.p.db.write() as conn:
            version, links = 1, Links()
            if draft.supersedes is not None:
                old = self._load_visible(conn, access, draft.supersedes)
                version = int(old.extra["procedure"]["version"]) + 1
                links = Links(supersedes=(old.id,))
            evidence = self._assess(conn, access.grants, draft.scope, draft.evidence_episode_ids)
            cap_findings, cap_check = self._capability_findings(draft, evidence)
            findings = sorted(set(findings) | set(cap_findings))
            if findings:
                state, reason = ProcedureState.UNSAFE, "safety screen rejected the draft"
            elif evidence.independent < MIN_INDEPENDENT_EVIDENCE:
                state, reason = (ProcedureState.INSUFFICIENT_EVIDENCE,
                                 f"{evidence.independent} independent verified task(s); {MIN_INDEPENDENT_EVIDENCE} required")
            else:
                state, reason = ProcedureState.CANDIDATE, f"{evidence.independent} independent verified tasks"
            procedure_id = new_id("pr")
            payload = {
                "procedure_id": procedure_id, "version": version, "state": state.value,
                "draft": draft.to_dict(), "independent_evidence": evidence.independent,
                "evidence_episode_ids": evidence.accepted, "counted_episode_ids": evidence.counted,
                "revoked_evidence_ids": [], "forgotten_evidence": 0, "safety_findings": findings,
                "capability_check": cap_check, "redactions": redactions, "evaluation_receipts": [],
                "evaluations": [], "supersedes_procedure": draft.supersedes, "superseded_by_procedure": None,
                "approved_at": None, "approved_by": None, "exports": [],
                "state_history": [[ProcedureState.NOMINATED.value, now, "draft nominated"],
                                  [state.value, now, reason]],
                "nominated_by": access.actor.value,
            }
            record = MemoryRecord(
                id=new_id("m"), revision=1, kind=MemoryKind.PROCEDURE, lifecycle=Lifecycle.CANDIDATE,
                scope=draft.scope, title=f"Procedure: {draft.name}"[:160], content=self._render(draft),
                tags=("procedure",), basis=StatementBasis.MODEL_INTERPRETATION, confidence=Confidence.unknown(),
                sources=self._sources(payload, access.actor), retention=Retention("durable", None, False),
                links=links, created_at=now, updated_at=now, event_time=now, ingested_at=now,
                reason="procedure nomination", extra={"procedure": payload, "proposer": access.actor.value},
            )
            forgetting = self.ctx.services.forgetting
            blocked = forgetting.blocked_reason(conn, record) if forgetting is not None else None
            if blocked:
                self.p.event(conn, "procedure", "suppressed", "nominate")
                raise SuppressedError(f"procedure refused: {blocked}")
            record = self.ctx.services.core.write_internal(conn, record, change="nominated", actor=access.actor,
                                                           expected=None)
            self._index(conn, record)
            receipt = self.p.make_receipt(
                conn, "nominate_procedure", "ok", record_ids=(record.id,), revisions=(record.revision,),
                details={"procedure_id": procedure_id, "state": state.value, "version": version,
                         "independent_evidence": evidence.independent,
                         "evidence_accepted": len(evidence.accepted),
                         "evidence_not_usable": len(set(draft.evidence_episode_ids)) - len(evidence.accepted),
                         "safety_findings": findings, "capability_check": cap_check, "redactions": redactions},
                limitations=("the safety screen is heuristic pattern matching, not a proof of safety",
                             "independence is judged from task refs and shared host receipts only"),
            )
            self.p.event(conn, "procedure", "nominated", state.value)
        return self._to_procedure(record), receipt

    # ------------------------------------------------------------------ evaluate
    def _manifest(self, record: MemoryRecord) -> dict[str, Any]:
        s = record.extra["procedure"]
        d = s["draft"]
        manifest = {"format": MANIFEST_FORMAT, "procedure_id": s["procedure_id"], "name": d["name"],
                    "version": int(s["version"]), "purpose": d["purpose"], "applicability": d["applicability"],
                    "rollback": d.get("rollback") or "", "evidence_episode_ids": list(s["evidence_episode_ids"])}
        for name in _LIST_FIELDS:
            manifest[name] = list(d.get(name) or ())
        return manifest

    @staticmethod
    def _validate_result(raw: Any) -> dict[str, Any]:
        required = {"passed", "receipt_id", "checks", "negative_cases_checked"}
        optional = {"detail", "duration_s", "issued_at"}
        if not isinstance(raw, dict):
            raise ProviderError("evaluation runner returned a non-object result")
        missing, unknown = required - set(raw), set(raw) - required - optional
        if missing or unknown:
            raise ProviderError("evaluation runner result has an invalid shape",
                                details={"missing": sorted(missing), "unexpected_fields": len(unknown)})
        if not isinstance(raw["passed"], bool) or not isinstance(raw["negative_cases_checked"], bool):
            raise ProviderError("evaluation runner flags must be booleans")
        receipt_id = raw["receipt_id"]
        try:
            check_ref(receipt_id, "evaluation receipt id")
        except ValidationError:
            raise ProviderError("evaluation runner receipt id is invalid") from None
        checks_raw = raw["checks"]
        if not isinstance(checks_raw, (list, tuple)) or len(checks_raw) > 256:
            raise ProviderError("evaluation runner checks must be a bounded list")
        checks = []
        for item in checks_raw:
            if not isinstance(item, dict) or not {"name", "passed"} <= set(item) \
                    or set(item) - {"name", "passed", "required", "detail"}:
                raise ProviderError("evaluation runner check has an invalid shape")
            name, passed = item["name"], item["passed"]
            req, detail = item.get("required", True), item.get("detail", "")
            if (not isinstance(name, str) or not name.strip() or len(name) > 200 or not isinstance(passed, bool)
                    or not isinstance(req, bool) or not isinstance(detail, str) or len(detail) > 2_000):
                raise ProviderError("evaluation runner check has invalid values")
            checks.append({"name": _one_line(name), "passed": passed, "required": req,
                           "detail": safety.redact_secrets(_one_line(detail))[0]})
        if "duration_s" in raw:
            try:
                check_finite(raw["duration_s"], "duration_s", lo=0.0)
            except ValidationError:
                raise ProviderError("evaluation runner duration is invalid") from None
        if raw["passed"] and not checks:
            raise ProviderError("a passing evaluation must report its checks")
        if raw["passed"] and any(c["required"] and not c["passed"] for c in checks):
            raise ProviderError("evaluation runner reported a pass with failed required checks")
        return {"passed": raw["passed"], "receipt_id": receipt_id, "checks": checks,
                "negative_cases_checked": raw["negative_cases_checked"]}

    def evaluate(self, access: AccessContext, procedure_id: str, *, deadline_s: float = 60.0
                 ) -> tuple[Procedure, Receipt]:
        policy.require(access, Operation.MAINTAIN)
        runner = self.ctx.host.evaluation_runner
        if runner is None:
            raise UnsupportedCapability("no host evaluation runner is configured; the engine never executes steps")
        deadline_s = check_finite(deadline_s, "deadline_s", lo=0.001, hi=3_600.0)
        with self.p.db.read() as conn:
            record = self._load_visible(conn, access, procedure_id)
        if self._state(record) != ProcedureState.CANDIDATE:
            raise InvalidTransition(f"cannot evaluate a {self._state(record).value} procedure")
        manifest = self._manifest(record)
        try:
            raw = runner.evaluate(manifest, deadline_s=deadline_s)
        except Exception as exc:  # host code; its failure leaves the procedure unchanged
            raise ProviderError("the evaluation runner failed", details={"runner_error": type(exc).__name__}) from None
        result = self._validate_result(raw)
        draft = ProcedureDraft.from_dict(record.extra["procedure"]["draft"])
        required = [c for c in result["checks"] if c["required"]]
        if not result["passed"]:
            outcome, reason = ProcedureState.FAILED_EVALUATION, "evaluation runner reported failure"
        elif not required:
            outcome, reason = ProcedureState.FAILED_EVALUATION, "evaluation reported no required checks"
        elif draft.negative_cases and not result["negative_cases_checked"]:
            outcome, reason = ProcedureState.FAILED_EVALUATION, "negative cases were not checked"
        else:
            outcome, reason = ProcedureState.EVALUATED, f"{len(required)}/{len(required)} required checks passed"
        with self.p.db.write() as conn:
            current = self._load_visible(conn, access, procedure_id)
            if current.revision != record.revision or self._state(current) != ProcedureState.CANDIDATE:
                raise RevisionConflict("the procedure changed while it was being evaluated")
            payload = dict(current.extra["procedure"])
            payload["evaluation_receipts"] = [*payload["evaluation_receipts"], result["receipt_id"]][-64:]
            payload["evaluations"] = [*payload["evaluations"], {
                "receipt_id": result["receipt_id"], "passed": outcome == ProcedureState.EVALUATED,
                "runner_passed": result["passed"], "checks": result["checks"],
                "negative_cases_checked": result["negative_cases_checked"], "at": self.now, "reason": reason,
            }][-16:]
            updated = self._save(conn, current, payload, state=outcome, reason=reason, change="evaluated",
                                 actor=access.actor)
            receipt = self.p.make_receipt(
                conn, "evaluate_procedure", "ok", record_ids=(updated.id,), revisions=(updated.revision,),
                details={"procedure_id": procedure_id, "state": outcome.value,
                         "evaluation_receipt": result["receipt_id"], "reason": reason},
                limitations=("the engine never executes procedure steps; results are the host runner's",),
            )
        return self._to_procedure(updated), receipt

    # ------------------------------------------------------------------ review
    def approve(self, access: AccessContext, procedure_id: str, *, expected_version: int | None
                ) -> tuple[Procedure, Receipt]:
        policy.require_reviewer(access, self.ctx.host)
        if expected_version is None:
            raise ValidationError("approval requires the expected procedure version")
        check_int(expected_version, "expected_version", lo=1)
        with self.p.db.write() as conn:
            record = self._load_visible(conn, access, procedure_id)
            payload = dict(record.extra["procedure"])
            if int(payload["version"]) != expected_version:
                raise RevisionConflict("the procedure version differs from the reviewed version",
                                       details={"expected_version": expected_version,
                                                "current_version": int(payload["version"])})
            if self._state(record) != ProcedureState.EVALUATED:
                raise InvalidTransition("only an evaluated procedure can be approved")
            scope = Scope.from_dict(payload["draft"].get("scope"))
            evidence = self._assess(conn, None, scope, payload["evidence_episode_ids"],
                                    exclude=payload["revoked_evidence_ids"])
            if evidence.independent < MIN_INDEPENDENT_EVIDENCE:
                raise InvalidTransition("the procedure no longer has enough independent evidence")
            forgetting = self.ctx.services.forgetting
            blocked = forgetting.blocked_reason(conn, record) if forgetting is not None else None
            if blocked:
                raise SuppressedError(f"cannot approve: {blocked}")
            superseded: list[str] = []
            old_id = payload.get("supersedes_procedure")
            if old_id:
                old = self._load(conn, old_id)
                if old is not None and policy.visible(access, old) and \
                        self._state(old) not in (ProcedureState.SUPERSEDED, ProcedureState.REJECTED):
                    old_payload = dict(old.extra["procedure"], superseded_by_procedure=procedure_id)
                    target = Lifecycle.SUPERSEDED if old.lifecycle in (
                        Lifecycle.CANDIDATE, Lifecycle.APPROVED, Lifecycle.STALE) else old.lifecycle
                    self._save(conn, old, old_payload, state=ProcedureState.SUPERSEDED,
                               reason=f"superseded by version {payload['version']}", change="superseded",
                               actor=access.actor, lifecycle=target,
                               links=dataclasses.replace(old.links, superseded_by=record.id))
                    superseded.append(old_id)
            payload.update(approved_at=self.now, approved_by=access.actor.value,
                           independent_evidence=evidence.independent, counted_episode_ids=evidence.counted)
            updated = self._save(conn, record, payload, state=ProcedureState.APPROVED,
                                 reason="approved by host-attested reviewer", change="approved",
                                 actor=access.actor, lifecycle=Lifecycle.APPROVED)
            receipt = self.p.make_receipt(
                conn, "approve_procedure", "ok", record_ids=(updated.id,), revisions=(updated.revision,),
                details={"procedure_id": procedure_id, "version": expected_version, "superseded": superseded,
                         "requested_capabilities_granted": False},
                limitations=_APPROVAL_LIMITATIONS,
            )
            self.p.event(conn, "procedure", "approved")
        return self._to_procedure(updated), receipt

    def reject(self, access: AccessContext, procedure_id: str, reason: str = "") -> tuple[Procedure, Receipt]:
        policy.require_reviewer(access, self.ctx.host)
        if not isinstance(reason, str) or len(reason) > 2_000:
            raise ValidationError("reason must be text of at most 2000 characters")
        with self.p.db.write() as conn:
            record = self._load_visible(conn, access, procedure_id)
            state = self._state(record)
            if state not in _REJECTABLE or record.lifecycle != Lifecycle.CANDIDATE:
                raise InvalidTransition(f"cannot reject a {state.value} procedure")
            payload = dict(record.extra["procedure"], rejection_reason=safety.redact_secrets(reason)[0])
            updated = self._save(conn, record, payload, state=ProcedureState.REJECTED, reason="rejected by reviewer",
                                 change="rejected", actor=access.actor, lifecycle=Lifecycle.REJECTED)
            forgetting = self.ctx.services.forgetting
            if forgetting is not None:  # the same draft is not silently re-nominated
                forgetting.suppress(conn, updated.content, updated.sources)
            receipt = self.p.make_receipt(conn, "reject_procedure", "ok", record_ids=(updated.id,),
                                          revisions=(updated.revision,), details={"procedure_id": procedure_id})
        return self._to_procedure(updated), receipt

    # ------------------------------------------------------------------ reads
    def get(self, access: AccessContext, procedure_id: str) -> Procedure:
        policy.require(access, Operation.READ)
        with self.p.db.read() as conn:
            return self._to_procedure(self._load_visible(conn, access, procedure_id))

    def list(self, access: AccessContext, state: ProcedureState | str | None = None, *, limit: int = 100
             ) -> list[Procedure]:
        policy.require(access, Operation.READ)
        check_int(limit, "limit", lo=1, hi=1000)
        with self.p.db.read() as conn:
            if state is not None:
                ids = [r[0] for r in conn.execute("SELECT record_id FROM procedures WHERE state=?",
                                                  (ProcedureState.parse(state, "state").value,))]
                records = authorized_by_ids(self.records, conn, access.grants, ids,
                                            kinds=(MemoryKind.PROCEDURE,), limit=limit)
            else:
                records = self.records.authorized(conn, access.grants, lifecycles=None,
                                                  kinds=(MemoryKind.PROCEDURE,), limit=limit,
                                                  order="updated_at DESC, id")
        return [self._to_procedure(r) for r in records if "procedure" in r.extra]

    # ------------------------------------------------------------------ evidence revocation
    def revoke_evidence(self, conn_or_access: sqlite3.Connection | AccessContext,
                        episode_id: str | Iterable[str], *, report_to: AccessContext | None = None
                        ) -> dict[str, Any]:
        """Re-assess procedures that cite the given episodes.

        * With a connection (forgetting / internal): episodes that no longer exist are
          dropped from evidence; procedures left with < 2 independent verified tasks
          move to ``revoked_evidence``. Counts cover only procedures ``report_to`` may
          see (all of them when it is None or an admin context).
        * With an access context (host/user): the visible episodes are explicitly
          revoked as evidence for the procedures the caller can see.
        """
        ids = [episode_id] if isinstance(episode_id, str) else list(dict.fromkeys(episode_id))
        if isinstance(conn_or_access, AccessContext):
            access = conn_or_access
            policy.require(access, Operation.MAINTAIN)
            if access.actor not in (Actor.USER, Actor.HOST):
                raise AccessDenied("revoking evidence is a user or host action")
            episodes = self.ctx.services.episodes
            with self.p.db.write() as conn:
                for eid in ids:
                    check_id(eid, "episode id")
                    policy.require_visible(access, episodes.load(conn, eid) if episodes else None)
                counts = self._revoke(conn, ids, explicit=True, access=access, report_to=access)
                receipt = self.p.make_receipt(conn, "revoke_evidence", "ok", details=dict(counts))
            return {**counts, "receipt_id": receipt.receipt_id}
        if not isinstance(conn_or_access, sqlite3.Connection):
            raise ValidationError("revoke_evidence needs a connection or an access context")
        return self._revoke(conn_or_access, ids, explicit=False, access=None, report_to=report_to)

    def _revoke(self, conn: sqlite3.Connection, episode_ids: list[str], *, explicit: bool,
                access: AccessContext | None, report_to: AccessContext | None = None) -> dict[str, int]:
        full_report = report_to is None or Operation.ADMIN in report_to.operations
        counts = {"procedures_revoked": 0, "procedures_evidence_updated": 0}
        if not episode_ids:
            return counts
        procedure_ids: set[str] = set()
        for batch in chunked(dict.fromkeys(episode_ids)):
            procedure_ids.update(r[0] for r in conn.execute(
                f"SELECT DISTINCT procedure_id FROM procedure_evidence WHERE episode_id IN ({','.join('?' * len(batch))})",
                batch))
        for procedure_id in sorted(procedure_ids):
            record = self._load(conn, procedure_id)
            if record is None or (access is not None and not policy.visible(access, record)):
                continue
            payload = dict(record.extra["procedure"])
            evidence_ids = list(payload["evidence_episode_ids"])
            revoked = list(payload.get("revoked_evidence_ids") or [])
            if explicit:
                revoked = list(dict.fromkeys([*revoked, *(e for e in episode_ids if e in evidence_ids)]))
            present = existing_ids(conn, "episodes", "episode_id", evidence_ids)
            forgotten = [e for e in evidence_ids if e not in present]
            remaining = [e for e in evidence_ids if e in present]
            revoked = [e for e in revoked if e in present]
            scope = Scope.from_dict(payload["draft"].get("scope"))
            evidence = self._assess(conn, None, scope, remaining, exclude=revoked)
            state = ProcedureState(payload["state"])
            new_state = state
            if state in _REVOCABLE and evidence.independent < MIN_INDEPENDENT_EVIDENCE:
                new_state = ProcedureState.REVOKED_EVIDENCE
            if (not forgotten and new_state == state and evidence.independent == payload["independent_evidence"]
                    and revoked == payload.get("revoked_evidence_ids", [])):
                continue
            payload.update(evidence_episode_ids=remaining, revoked_evidence_ids=revoked,
                           counted_episode_ids=evidence.counted, independent_evidence=evidence.independent,
                           forgotten_evidence=int(payload.get("forgotten_evidence", 0)) + len(forgotten))
            lifecycle = Lifecycle.STALE if (new_state == ProcedureState.REVOKED_EVIDENCE
                                            and record.lifecycle == Lifecycle.APPROVED) else None
            reason = "evidence forgotten" if forgotten else "evidence revoked"
            updated = self._save(conn, record, payload, state=new_state, reason=reason, change="evidence_revoked",
                                 actor=access.actor if access else Actor.SYSTEM, lifecycle=lifecycle)
            if forgotten:  # earlier revisions still cite forgotten episodes
                conn.execute(
                    "UPDATE record_revisions SET purged=1, dek_id=NULL, nonce=NULL, ciphertext=NULL"
                    " WHERE record_id=? AND revision<?", (updated.id, updated.revision))
            if full_report or policy.visible(report_to, updated):
                counts["procedures_evidence_updated"] += 1
                if new_state != state:
                    counts["procedures_revoked"] += 1
        return {k: v for k, v in counts.items() if v} if not explicit else counts

    # ------------------------------------------------------------------ export
    def _skill_md(self, record: MemoryRecord, manifest: dict[str, Any], slug: str) -> str:
        d = manifest
        description = _one_line(d["purpose"])[:300]
        lines = [
            "---",
            f"name: {json.dumps(slug)}",
            f"description: {json.dumps(description, ensure_ascii=False)}",
            f"version: {int(d['version'])}",
            'status: "proposal"',
            f"source: {json.dumps('locus-memory procedure ' + d['procedure_id'])}",
            "---",
            "",
            f"# {_one_line(d['name'])}",
            "",
            "> Proposal exported from locus-memory after human review. Approval is not authorization",
            "> to execute: the host decides whether and how to activate this skill, and the requested",
            "> capabilities listed below are not granted by this file.",
            "",
            "## Purpose", "", _one_line(d["purpose"]), "",
            "## When to use", "", _one_line(d["applicability"]), "",
        ]
        sections = (("Preconditions", "preconditions", False), ("Steps", "steps", True),
                    ("Expected outcomes", "expected_outcomes", False),
                    ("Do not use when (negative cases)", "negative_cases", False),
                    ("Known failures", "known_failures", False),
                    ("Requested capabilities (not granted)", "requested_capabilities", False))
        for title, key, numbered in sections:
            values = d.get(key) or []
            if not values:
                continue
            lines += [f"## {title}", ""]
            lines += [f"{i + 1}. {_one_line(v)}" if numbered else f"- {_one_line(v)}" for i, v in enumerate(values)]
            lines.append("")
        if d.get("rollback"):
            lines += ["## Rollback", "", _one_line(d["rollback"]), ""]
        prov = d["provenance"]
        lines += ["## Provenance", "",
                  f"- Procedure: `{d['procedure_id']}` version {int(d['version'])}",
                  f"- Independent verified tasks: {int(prov['independent_evidence'])}",
                  f"- Evidence episodes (ids only): {', '.join(d['evidence_episode_ids']) or 'none'}",
                  f"- Evaluation receipts: {', '.join(prov['evaluation_receipts']) or 'none'}", ""]
        return "\n".join(lines)

    @staticmethod
    def _write_exclusive(path: Path, data: str) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

    def export(self, access: AccessContext, procedure_id: str, destination: Path) -> dict[str, Any]:
        policy.require(access, Operation.EXPORT)
        if access.actor not in (Actor.USER, Actor.HOST):
            raise AccessDenied("exporting a procedure is a user or host action")
        with self.p.db.read() as conn:
            record = self._load_visible(conn, access, procedure_id)
        if self._state(record) != ProcedureState.APPROVED:
            raise InvalidTransition("only an approved procedure can be exported")
        payload = record.extra["procedure"]
        version = int(payload["version"])
        manifest = self._manifest(record)
        manifest["provenance"] = {
            "engine": "locus-memory", "procedure_id": payload["procedure_id"], "record_id": record.id,
            "record_revision": record.revision, "nominated_by": payload.get("nominated_by"),
            "approved_at": payload.get("approved_at"), "approved_by": payload.get("approved_by"),
            "independent_evidence": payload["independent_evidence"],
            "evaluation_receipts": list(payload["evaluation_receipts"]), "exported_at": self.now,
            "supersedes_procedure": payload.get("supersedes_procedure"),
            "note": "evidence is referenced by episode id only; transcripts are never exported",
        }
        dest = Path(destination)
        if not dest.is_dir():
            raise ValidationError("the export destination must be an existing directory")
        slug = _slug(payload["draft"]["name"])
        name_dir = dest / slug
        if name_dir.is_symlink():
            raise ValidationError("the export destination contains a symbolic link")
        try:
            name_dir.mkdir(mode=0o700, exist_ok=True)
        except OSError:
            raise ValidationError("the export destination is not usable") from None
        if name_dir.is_symlink() or not name_dir.is_dir():
            raise ValidationError("the export destination is not a directory")
        version_dir = name_dir / f"v{version}"
        try:
            version_dir.mkdir(mode=0o700)  # exclusive: an existing version is never overwritten
        except FileExistsError:
            raise RevisionConflict("this procedure version was already exported to the destination",
                                   details={"reason": "export_exists", "version": version}) from None
        except OSError:
            raise ValidationError("the export destination is not writable") from None
        manifest_path, skill_path = version_dir / "manifest.json", version_dir / "SKILL.md"
        created: list[Path] = []
        try:
            self._write_exclusive(manifest_path, json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False))
            created.append(manifest_path)
            self._write_exclusive(skill_path, self._skill_md(record, manifest, slug))
            created.append(skill_path)
            with self.p.db.write() as conn:
                current = self._load_visible(conn, access, procedure_id)
                if current.revision != record.revision or self._state(current) != ProcedureState.APPROVED:
                    raise RevisionConflict("the procedure changed during export")
                new_payload = dict(current.extra["procedure"])
                new_payload["exports"] = [*new_payload.get("exports", []),
                                          {"version": version, "at": self.now, "directory": str(version_dir)}]
                updated = self._save(conn, current, new_payload, state=ProcedureState.EXPORTED,
                                     reason="exported as a proposal", change="exported", actor=access.actor)
                receipt = self.p.make_receipt(
                    conn, "export_procedure", "ok", record_ids=(updated.id,), revisions=(updated.revision,),
                    details={"procedure_id": procedure_id, "version": version, "directory": str(version_dir)},
                    limitations=("exported files are plaintext outside the encrypted store",
                                 "the host decides activation; export grants no capability"),
                )
        except BaseException:
            for path in created:  # only files this call created exclusively
                try:
                    path.unlink()
                except OSError:
                    pass
            try:
                version_dir.rmdir()
            except OSError:
                pass
            raise
        return {"procedure_id": procedure_id, "version": version, "state": updated.extra["procedure"]["state"],
                "directory": str(version_dir), "manifest": str(manifest_path), "skill": str(skill_path),
                "receipt_id": receipt.receipt_id}

    # ------------------------------------------------------------------ forgetting
    def purge(self, conn: sqlite3.Connection, target_kind: str, target_token: str, forget_policy: Any, *,
              access: AccessContext | None = None) -> dict[str, int]:
        """Drop index rows of purged procedure records; re-assess evidence that is gone.

        Counts include only procedures ``access`` may see (everything for admin/replay).
        """
        full_report = access is None or Operation.ADMIN in access.operations
        counts: dict[str, int] = {}
        gone = [r[0] for r in conn.execute(
            "SELECT procedure_id FROM procedures WHERE record_id NOT IN (SELECT id FROM records)").fetchall()]
        for procedure_id in gone:
            conn.execute("DELETE FROM procedures WHERE procedure_id=?", (procedure_id,))
            conn.execute("DELETE FROM procedure_evidence WHERE procedure_id=?", (procedure_id,))
        if gone and full_report:
            counts["procedure_index_rows"] = len(gone)
        missing = [r[0] for r in conn.execute(
            "SELECT DISTINCT episode_id FROM procedure_evidence"
            " WHERE episode_id NOT IN (SELECT episode_id FROM episodes)").fetchall()]
        if missing:
            for key, value in self._revoke(conn, missing, explicit=False, access=None, report_to=access).items():
                counts[key] = counts.get(key, 0) + value
        return counts


__all__ = ["ProcedureService", "screen_draft", "screen_text", "MANIFEST_FORMAT"]
