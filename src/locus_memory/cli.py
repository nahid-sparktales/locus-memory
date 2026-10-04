"""Standalone diagnostic command line for one local memory profile: ``locus-memory``.

Every invocation opens exactly one partition (``--edition``/``--profile``) under
``--root`` with a file key (``--key-dir``, default ``<root>/keys``) and acts as the
local user: principal ``local-user``, actor ``user``, the scope grants given with
``--project``/``--repository``/... and every operation except ``admin`` (``--admin``
adds it, for administrative commands). The CLI is the host here: it builds that
trusted access context from its own flags and the engine checks every call against
it; nothing read from the store or from input files can widen it.

Safety rules:

* Only ``init`` creates a key, and never when a key or an existing vault is found.
  Every other command fails when the key or the profile's vault is missing; a vault
  is never created implicitly (those commands open the engine with
  ``create_partitions=False``, so the engine itself refuses to create one).
* Destructive or plaintext-producing commands preview by default (exit 2) and act
  only with ``--yes``: ``forget``, ``export``, ``migrate cutover``/``abort``/``rollback``.
  ``export`` writes the engine's ``MemoryEngine.export`` document (records; history
  sessions only with ``--include-history``) to a new 0600 file outside the root and
  key directory.
* Key bytes are never printed. Human output of ``list`` shows ids and titles only;
  content is shown for an explicit ``show``/``explain``/``search``/``context preview``.

Output is human text, or with ``--json`` exactly one JSON document on stdout (warnings
go to stderr). Errors are ``{"error": code, "message": ..., "details": ...}``. Exit
codes: 0 ok, 1 error, 2 preview only (nothing changed), 3 capability unavailable.

Global options go before the command (``locus-memory --project p1 list``); ``--json``
and ``--admin`` are also accepted after it.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib
import inspect
import json
import os
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from . import __version__
from .crypto import FileKeyProvider
from .engine import EXPORT_FORMAT, MemoryEngine
from .errors import (
    IndexUnavailable,
    MemoryEngineError,
    StorageUnavailable,
    UnsupportedCapability,
    ValidationError,
)
from .host import HostCapabilities
from .models import (
    ALL_OPERATIONS,
    API_VERSION,
    AccessContext,
    Actor,
    CandidateProposal,
    ContextRequest,
    Correction,
    EpisodeOutcome,
    EpisodeReport,
    ForgetPolicy,
    ForgetTarget,
    IngestionEvent,
    Lifecycle,
    MemoryKind,
    MemoryRecord,
    Operation,
    PartitionRef,
    ProcedureDraft,
    ProcedureState,
    Query,
    RememberRequest,
    Retention,
    Scope,
    ScopeGrants,
    SourceKind,
    SourceRef,
    to_jsonable,
)
from .storage.partition import Partition

EXIT_OK, EXIT_ERROR, EXIT_PREVIEW, EXIT_UNAVAILABLE = 0, 1, 2, 3
# The store's storage failed (disk full, I/O error, read-only files): not retryable as contention.
EXIT_STORAGE = 4
PRINCIPAL = "local-user"
HOME_ENV = "LOCUS_MEMORY_HOME"
DEFAULT_HOME = "~/.locus-memory"
PLAINTEXT_WARNING = ("WARNING: the export file is PLAINTEXT. Anyone who can read it can read these memories;"
                     " it is outside the encrypted store and later forgetting does not reach it.")

# (dimension, ScopeGrants field) - the order of the grant and --scope-* flags.
GRANT_DIMS = (
    ("project", "projects"), ("repository", "repositories"), ("worktree", "worktrees"),
    ("agent", "agents"), ("team", "teams"), ("session", "sessions"), ("device", "devices"),
    ("legacy_target", "legacy_targets"),
)
# Kinds a user states directly; derived kinds come from their own services.
USER_KINDS = ("preference", "fact", "decision", "constraint", "relationship")
LIFECYCLES = tuple(item.value for item in Lifecycle)


# =========================================================================== plumbing
class CLIError(Exception):
    """A CLI-level failure with a stable error code (never carries record content)."""

    def __init__(self, code: str, message: str, *, exit_code: int = EXIT_ERROR,
                 details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code
        self.details = dict(details or {})


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise CLIError("usage", f"{self.prog}: {message}")


@dataclass
class Outcome:
    data: Any  # the JSON document (models are converted with to_jsonable)
    text: str  # human output
    exit_code: int = EXIT_OK


def _dumps(value: Any) -> str:
    return json.dumps(to_jsonable(value), sort_keys=True, ensure_ascii=False, allow_nan=False, indent=2)


def _resolve_root(value: str | None) -> Path:
    raw = value or os.environ.get(HOME_ENV) or DEFAULT_HOME
    return Path(os.path.abspath(os.path.expanduser(raw)))


def _within(path: Path, base: Path) -> bool:
    real, top = os.path.realpath(path), os.path.realpath(base)
    try:
        return os.path.commonpath([real, top]) == top
    except ValueError:
        return False


def _make_private_dir(path: Path) -> None:
    """Create ``path`` with mode 0700; an existing directory is left as the user set it up."""
    if path.is_dir():
        return
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700)


def _write_private(path: Path, text: str) -> None:
    """Create ``path`` exclusively with mode 0600 (never overwrites, never follows a link)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise CLIError("file_exists", f"refusing to overwrite an existing file: {path}") from None
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(path)  # never leave a partial plaintext file behind
        raise


def _read_json_file(path: str) -> Any:
    try:
        text = sys.stdin.read() if path == "-" else Path(path).expanduser().read_text(encoding="utf-8")
    except FileNotFoundError:
        raise CLIError("not_found", f"file not found: {path}") from None
    except UnicodeDecodeError:
        raise CLIError("invalid_request", f"{path} is not UTF-8 text") from None
    try:
        return json.loads(text)
    except ValueError:
        raise CLIError("invalid_request", f"{path} is not valid JSON") from None


def _text_arg(value: str) -> str:
    """``-`` reads the value from stdin (keeps it out of shell history)."""
    return sys.stdin.read() if value == "-" else value


# =========================================================================== session
class Session:
    """One invocation: one root, one key directory, one partition, one access context."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.root = _resolve_root(args.root)
        self.key_dir = Path(os.path.abspath(os.path.expanduser(args.key_dir))) if args.key_dir \
            else self.root / "keys"
        self.partition = PartitionRef(args.edition, args.profile)
        grants = ScopeGrants(**{field: frozenset(getattr(args, f"grant_{dim}") or ())
                                for dim, field in GRANT_DIMS})
        operations = ALL_OPERATIONS if args.admin else ALL_OPERATIONS - {Operation.ADMIN}
        self.access = AccessContext(principal=PRINCIPAL, partition=self.partition, actor=Actor.USER,
                                    grants=grants, operations=operations, purpose="cli",
                                    issuer="locus-memory-cli")
        self.warnings: list[str] = []
        self._engine: MemoryEngine | None = None
        self._control: Any = None

    @property
    def partition_db(self) -> Path:
        return self.root / self.partition.partition_id / Partition.DB_NAME

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def require_initialized(self) -> None:
        if not FileKeyProvider(self.key_dir).exists():
            raise CLIError("not_initialized",
                           f"no standalone key in {self.key_dir}; run `locus-memory init` first"
                           " (or pass the --key-dir that holds this vault's key)")
        if not self.partition_db.exists():
            raise CLIError("not_initialized",
                           f"profile {self.partition.profile!r} (edition {self.partition.edition!r}) has no"
                           f" vault under {self.root}; run `locus-memory init` for it first")

    def require_admin(self) -> None:
        if Operation.ADMIN not in self.access.operations:
            raise CLIError("access_denied", "this is an administrative command; pass --admin")

    def control(self, *, create: bool):
        """The migration ownership-control file (``<root>/control.sqlite3``), if any."""
        if self._control is None:
            from .migrations.state import OwnershipControl

            if not create and not (self.root / OwnershipControl.FILE).exists():
                return None
            self._control = OwnershipControl(self.root)
        return self._control

    def engine(self, *, allowed_roots: Sequence[str] = (), new_partition: bool = False) -> MemoryEngine:
        if self._engine is None:
            if not new_partition:
                self.require_initialized()
            # Canonical writes are fenced only once a migration has recorded ownership for
            # this partition; a plain standalone vault has no other writer.
            control = self.control(create=False)
            fence = control if control is not None and control.get(self.partition.partition_id).generation else None
            host = HostCapabilities(
                allowed_repository_roots=tuple(Path(os.path.expanduser(p)) for p in allowed_roots),
                ownership=fence,
            )
            # Only ``init`` may create a vault. Every other command opens existing vaults only,
            # so even a check missed above can never turn a mistyped profile into a new vault.
            self._engine = MemoryEngine(self.root, FileKeyProvider(self.key_dir), host=host,
                                        create_partitions=new_partition)
        return self._engine

    def close(self) -> None:
        for closer in (self._engine, self._control):
            if closer is not None:
                with contextlib.suppress(Exception):
                    closer.close()
        self._engine = self._control = None


# =========================================================================== rendering
def _ts(value: float | None) -> str:
    if value is None:
        return "unknown"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def _scope_text(scope: Scope | dict[str, str]) -> str:
    dims = scope.as_dict() if isinstance(scope, Scope) else dict(scope)
    return ", ".join(f"{k}={v}" for k, v in sorted(dims.items())) or "global"


def _counts(values: dict[str, Any] | None) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted((values or {}).items())) or "none"


def _scalar(value: Any) -> str:
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value == [] or value == {}:
        return "none"
    return str(value)


def _render(value: Any, indent: int = 0) -> list[str]:
    """Generic indented key/value rendering of a JSON-compatible value."""
    value = to_jsonable(value)
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{key}:")
                lines += _render(item, indent + 1)
            else:
                lines.append(f"{pad}{key}: {_scalar(item)}")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}-")
                lines += _render(item, indent + 1)
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    else:
        lines.append(pad + _scalar(value))
    return lines or [pad + "none"]


def _render_text(value: Any) -> str:
    return "\n".join(_render(value))


def _record_line(record: MemoryRecord) -> str:
    pin = "[pinned] " if record.pinned else ""
    return (f"{record.id}  r{record.revision}  {record.lifecycle.value:<10}  {record.kind.value:<12}  "
            f"{pin}{record.title}  ({_scope_text(record.scope)})")


def _summary(record: MemoryRecord) -> dict[str, Any]:
    return {"id": record.id, "revision": record.revision, "lifecycle": record.lifecycle.value,
            "kind": record.kind.value, "title": record.title, "scope": record.scope.as_dict(),
            "pinned": record.pinned, "updated_at": record.updated_at}


def _confidence_text(record: MemoryRecord) -> str:
    conf = record.confidence
    if conf.value is None:
        return f"unknown ({conf.method})"
    return f"{conf.value} ({'calibrated' if conf.calibrated else 'uncalibrated - not a probability'}, {conf.method})"


def _record_text(record: MemoryRecord) -> str:
    lines = [
        f"id:          {record.id}",
        f"revision:    {record.revision}",
        f"lifecycle:   {record.lifecycle.value}",
        f"kind:        {record.kind.value}",
        f"scope:       {_scope_text(record.scope)}",
        f"title:       {record.title}",
        f"tags:        {', '.join(record.tags) or 'none'}",
        f"basis:       {record.basis.value}",
        f"confidence:  {_confidence_text(record)}",
        f"pinned:      {'yes' if record.pinned else 'no'}",
        f"created:     {_ts(record.created_at)}",
        f"updated:     {_ts(record.updated_at)}",
        f"sources:     {', '.join(s.identity() for s in record.sources) or 'none'}",
    ]
    if record.subject or record.predicate:
        lines.append(f"subject:     {record.subject or '-'} / {record.predicate or '-'}")
    links = record.links
    for name in ("supersedes", "conflicts_with", "derived_from"):
        if getattr(links, name):
            lines.append(f"{name + ':':<13}{', '.join(getattr(links, name))}")
    if links.superseded_by:
        lines.append(f"superseded by: {links.superseded_by}")
    lines += ["content:", *("  " + line for line in record.content.splitlines() or [""])]
    return "\n".join(lines)


def _write_text(verb: str, result: Any) -> str:
    record, receipt = result.record, result.receipt
    text = f"{verb} {record.id} (revision {record.revision}, {record.lifecycle.value}); receipt {receipt.receipt_id}"
    if receipt.status != "ok":
        text += f" [{receipt.status}]"
    if result.conflicts:
        text += f"\nconflicts with: {', '.join(result.conflicts)}"
    possible = receipt.details.get("possible_conflicts") if isinstance(receipt.details, dict) else None
    if possible:
        text += f"\npossible conflicts (same topic): {', '.join(possible)}"
    return text


def _write_outcome(verb: str, result: Any) -> Outcome:
    return Outcome(result, _write_text(verb, result))


# =========================================================================== helpers
def _scope_from(args: argparse.Namespace) -> Scope:
    return Scope.of(**{dim: getattr(args, f"scope_{dim}", None) for dim, _ in GRANT_DIMS})


def _parse_source(value: str) -> SourceRef:
    kind, sep, ref = value.partition(":")
    if not sep or not kind or not ref:
        raise CLIError("usage", "--source takes KIND:REF (for example document:notes.md)")
    return SourceRef(SourceKind.parse(kind, "source kind"), ref, actor=Actor.USER)


def _lifecycles(values: list[str] | None, default: tuple[Lifecycle, ...] = (Lifecycle.APPROVED,)
                ) -> tuple[Lifecycle, ...] | None:
    if not values:
        return default
    if "all" in values:
        return None
    return tuple(Lifecycle.parse(v, "lifecycle") for v in values)


# =========================================================================== commands: setup
def cmd_init(s: Session, a: argparse.Namespace) -> Outcome:
    keys = FileKeyProvider(s.key_dir)
    if keys.exists():
        if s.partition_db.exists():
            raise CLIError("already_initialized",
                           f"profile {s.partition.profile!r} is already initialized under {s.root};"
                           " keys are never overwritten")
        if not a.use_existing_key:
            raise CLIError("key_exists",
                           f"a standalone key already exists in {s.key_dir}; pass --use-existing-key to add"
                           f" profile {s.partition.profile!r} under it")
        key_id, created = keys.current_key_id(), False
        _make_private_dir(s.root)
    else:
        vaults = sorted(p.name for p in s.root.iterdir() if (p / Partition.DB_NAME).exists()) \
            if s.root.is_dir() else []
        if vaults:
            raise CLIError("vault_without_key",
                           f"{s.root} already holds {len(vaults)} vault(s) but no key was found in {s.key_dir};"
                           " refusing to create a new key over an existing vault. Restore the key or pass"
                           " the --key-dir that holds it.", details={"vaults": len(vaults)})
        _make_private_dir(s.root)
        key_id, created = keys.create(), True
    status = s.engine(new_partition=True).status(s.access)
    data = {
        "initialized": True, "root": str(s.root), "edition": s.partition.edition,
        "profile": s.partition.profile, "partition_id": status.partition_id, "key_dir": str(s.key_dir),
        "key_id": key_id, "key_created": created, "cipher": status.cipher,
        "notes": ["the key file is the only way to open this vault: back it up separately from the vault",
                  "a copy of the key next to a copy of the vault exposes both"],
    }
    text = "\n".join([
        f"initialized profile {s.partition.profile!r} (edition {s.partition.edition!r})",
        f"root:      {s.root}",
        f"partition: {status.partition_id}",
        f"key:       {key_id} in {s.key_dir} ({'created' if created else 'existing'})",
        "note: back up the key separately from the vault; without it the vault cannot be opened.",
    ])
    return Outcome(data, text)


def cmd_status(s: Session, a: argparse.Namespace) -> Outcome:
    engine = s.engine()
    status = engine.status(s.access)
    ownership = engine.ownership_state(s.access)
    data = {"status": status, "root": str(s.root), "edition": s.partition.edition,
            "profile": s.partition.profile, "grants": s.access.grants,
            "admin": Operation.ADMIN in s.access.operations, "ownership": ownership,
            "version": __version__}
    lines = [
        f"locus-memory {__version__} - profile {s.partition.profile!r} (edition {s.partition.edition!r})",
        f"root:                {s.root}",
        f"partition:           {status.partition_id}",
        f"schema / api:        {status.schema_version} / {status.api_version}",
        f"backend / serving:   {status.canonical_backend} / {status.serving_mode}",
        f"records (authorized): {_counts(status.counts)}",
        f"generation:          {status.generation} (deletions: {status.deletion_generation})",
        f"cipher / data key:   {status.cipher} / {status.key_id}",
        f"fts5:                {'available' if status.fts5_available else 'unavailable'}",
    ]
    if ownership is not None:
        lines.append(f"ownership:           {ownership['state']} (writers: {', '.join(ownership['permitted_writers']) or 'none'})")
    lines.append("limitations:")
    lines += [f"  - {item}" for item in status.limitations]
    return Outcome(data, "\n".join(lines))


# =========================================================================== commands: records
def cmd_list(s: Session, a: argparse.Namespace) -> Outcome:
    records = s.engine().list(s.access, lifecycles=_lifecycles(a.lifecycle),
                              kinds=tuple(MemoryKind.parse(k, "kind") for k in a.kind or ()),
                              limit=a.limit, offset=a.offset)
    data = {"records": [r.to_dict() if a.full else _summary(r) for r in records], "count": len(records),
            "limit": a.limit, "offset": a.offset}
    text = "\n".join(_record_line(r) for r in records) or "no memories match (authorized scopes only)"
    return Outcome(data, text)


def cmd_search(s: Session, a: argparse.Namespace) -> Outcome:
    query = Query(text=a.query, limit=a.limit, kinds=tuple(a.kind or ()), lifecycles=_lifecycles(a.lifecycle)
                  or tuple(Lifecycle))
    result = s.engine().search(s.access, query)
    cov = result.coverage
    lines = [f"{len(result.hits)} hit(s) - status {result.status.value}; searched {cov.searched} of"
             f" {'unknown' if cov.total is None else cov.total} authorized record(s)"]
    for hit in result.hits:
        current = "" if hit.current else " [historical]"
        lines.append(f"{hit.rank}. {hit.record.id}  [{hit.score_kind} {hit.score:.4g}]{current}  {hit.record.title}")
        if hit.snippet:
            lines.append(f"   {hit.snippet}")
    for reason in (*cov.missing, *cov.partial_reasons):
        lines.append(f"coverage: {reason}")
    lines.append("note: scores order results; they are not probabilities of truth")
    return Outcome(result, "\n".join(lines))


def cmd_show(s: Session, a: argparse.Namespace) -> Outcome:
    record = s.engine().get(s.access, a.id)
    return Outcome(record, _record_text(record))


def cmd_explain(s: Session, a: argparse.Namespace) -> Outcome:
    info = s.engine().explain(s.access, a.id)
    rec = info["record"]
    lines = [f"{rec['id']}  revision {rec['revision']}  {rec['lifecycle']}  {rec['kind']}  ({_scope_text(rec['scope'])})",
             f"title:      {rec['title']}",
             f"basis:      {info['basis']}",
             f"confidence: {info['confidence_note']}"]
    if info.get("lifecycle_note"):
        lines.append(f"note:       {info['lifecycle_note']}")
    lines.append("sources:")
    lines += [f"  - {src['kind']}:{src['ref']} (actor {src['actor']}{'' if src.get('available', True) else ', unavailable'})"
              for src in info["sources"]] or ["  none"]
    if info.get("sources_unavailable"):
        lines.append(f"  ({info['sources_unavailable']} source(s) not visible to this caller)")
    lines.append("revisions:")
    lines += [f"  r{rev['revision']}  {rev['change']:<12} {rev['lifecycle']:<10} by {rev['actor']}  {_ts(rev['created_at'])}"
              f"{'  [payload purged]' if rev.get('purged') else ''}" for rev in info["revisions"]]
    links = {k: v for k, v in info["links"].items() if v}
    if links:
        lines.append("links:")
        lines += _render(links, 1)
    if info["current_conflicts"]:
        lines.append(f"current conflicts: {', '.join(info['current_conflicts'])}")
    if info["derived_records"]:
        lines.append(f"derived records: {', '.join(info['derived_records'])}")
    lines += ["content:", *("  " + line for line in rec["content"].splitlines() or [""])]
    return Outcome(info, "\n".join(lines))


def cmd_remember(s: Session, a: argparse.Namespace) -> Outcome:
    request = RememberRequest(
        content=_text_arg(a.content), kind=a.kind, scope=_scope_from(a), title=a.title or "",
        tags=tuple(a.tag or ()), subject=a.subject, predicate=a.predicate,
        retention=Retention(pinned=bool(a.pin)), reason=a.reason or "", allow_sensitive=a.allow_sensitive,
    )
    return _write_outcome("remembered", s.engine().remember(s.access, request, idempotency_key=a.idempotency_key))


def cmd_propose(s: Session, a: argparse.Namespace) -> Outcome:
    proposal = CandidateProposal(
        content=_text_arg(a.content), sources=tuple(_parse_source(v) for v in a.source), kind=a.kind,
        scope=_scope_from(a), title=a.title or "", tags=tuple(a.tag or ()), subject=a.subject,
        predicate=a.predicate, rationale=a.rationale or "", proposer="cli",
    )
    result = s.engine().propose(s.access, proposal, idempotency_key=a.idempotency_key)
    outcome = _write_outcome("proposed", result)
    if result.receipt.status == "noop":
        outcome.text += f"\nduplicate of an existing memory: {result.receipt.details.get('duplicate_of')}"
    elif result.record.lifecycle == Lifecycle.CANDIDATE:
        outcome.text += (f"\nreview with: locus-memory approve {result.record.id} --revision {result.record.revision}"
                         f"  (or reject)")
    return outcome


def cmd_approve(s: Session, a: argparse.Namespace) -> Outcome:
    result = s.engine().approve(s.access, a.id, expected_revision=a.revision,
                                resolution="supersede" if a.supersede else "keep_both")
    outcome = _write_outcome("approved", result)
    superseded = result.receipt.details.get("superseded") or []
    if superseded:
        outcome.text += f"\nsuperseded: {', '.join(superseded)}"
    return outcome


def cmd_reject(s: Session, a: argparse.Namespace) -> Outcome:
    return _write_outcome("rejected", s.engine().reject(s.access, a.id, expected_revision=a.revision,
                                                        reason=a.reason or ""))


def cmd_correct(s: Session, a: argparse.Namespace) -> Outcome:
    correction = Correction(content=_text_arg(a.content) if a.content is not None else None, title=a.title,
                            tags=tuple(a.tag) if a.tag is not None else None, reason=a.reason or "",
                            allow_sensitive=a.allow_sensitive)
    return _write_outcome("corrected", s.engine().correct(s.access, a.id, correction, expected_revision=a.revision))


def cmd_pin(s: Session, a: argparse.Namespace) -> Outcome:
    result = s.engine().set_pinned(s.access, a.id, a.pinned, expected_revision=a.revision)
    return _write_outcome("pinned" if a.pinned else "unpinned", result)


# =========================================================================== commands: forgetting
def _forget_target(s: Session, a: argparse.Namespace) -> ForgetTarget:
    if a.target_profile:
        return ForgetTarget("profile", s.partition.profile)
    for kind, value in (("memory", a.memory), ("source", a.source), ("session", a.session),
                        ("project", a.target_project), ("repository", a.target_repository),
                        ("agent", a.target_agent)):
        if value is not None:
            return ForgetTarget(kind, value)
    raise CLIError("usage", "choose what to forget: --memory, --source, --session, --project, --repository,"
                            " --agent or --profile")


def cmd_forget(s: Session, a: argparse.Namespace) -> Outcome:
    target = _forget_target(s, a)
    forget_policy = ForgetPolicy(suppress_relearning=not a.allow_relearning,
                                 delete_source_archive=a.delete_source_archive, include_derived=not a.keep_derived)
    engine = s.engine()
    label = f"{target.kind.value} {target.ref}"
    if not a.yes:
        preview = engine.preview_forget(s.access, target, forget_policy)
        text = "\n".join([
            "PREVIEW ONLY - nothing was deleted.",
            f"forgetting {label} would delete: {_counts(preview['deleted'])}",
            f"retained by policy: {_counts(preview['retained_by_policy'])}",
            f"derived records needing regeneration: {len(preview['regenerate_required'])}",
            f"pending external deletions: {preview['pending_external']}",
            "re-run with --yes to forget.",
        ])
        return Outcome(preview, text, EXIT_PREVIEW)
    receipt = engine.forget(s.access, target, policy=forget_policy, idempotency_key=a.idempotency_key)
    lines = [
        f"forgot {label}: {_counts(receipt.deleted)}",
        f"retained by policy: {_counts(receipt.retained_by_policy)}",
        f"pending external deletions: {len(receipt.pending_external)}",
        f"receipt {receipt.receipt.receipt_id} (deletion generation {receipt.deletion_generation})",
        "limitations:",
        *(f"  - {item}" for item in receipt.receipt.limitations),
    ]
    return Outcome(receipt, "\n".join(lines))


# =========================================================================== commands: context
def cmd_context_preview(s: Session, a: argparse.Namespace) -> Outcome:
    request = ContextRequest(token_allowance=a.tokens, query=a.query or "", include_history=a.include_history)
    packet = s.engine().build_context(s.access, request)
    lines = [f"context receipt {packet.receipt_id}: {packet.token_count}/{packet.token_allowance} tokens"
             f" ({packet.token_count_kind.value}), {len(packet.items)} item(s), {len(packet.omissions)}"
             f" omission(s), status {packet.status.value}"]
    omitted: dict[str, int] = {}
    for omission in packet.omissions:
        omitted[omission.reason] = omitted.get(omission.reason, 0) + 1
    if omitted:
        lines.append(f"omitted: {_counts(omitted)}")
    lines += ["-" * 40, packet.text]
    return Outcome(packet, "\n".join(lines))


def cmd_context_explain(s: Session, a: argparse.Namespace) -> Outcome:
    info = s.engine().explain_context(s.access, a.receipt_id)
    return Outcome(info, _render_text(info))


# =========================================================================== commands: history
def cmd_history_ingest(s: Session, a: argparse.Namespace) -> Outcome:
    from .history.archive import MAX_BATCH_EVENTS

    try:
        text = sys.stdin.read() if a.file == "-" else Path(a.file).expanduser().read_text(encoding="utf-8")
    except FileNotFoundError:
        raise CLIError("not_found", f"file not found: {a.file}") from None
    except UnicodeDecodeError:
        raise CLIError("invalid_request", f"{a.file} is not UTF-8 text") from None
    events: list[IngestionEvent] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            raise CLIError("invalid_request", f"line {lineno} is not valid JSON") from None
        try:
            events.append(IngestionEvent.from_dict(raw))
        except ValidationError as exc:  # messages name fields, never content
            raise ValidationError(f"line {lineno}: {exc}") from None
    history = s.engine().services(s.access).history
    receipts = []
    for start in range(0, len(events), MAX_BATCH_EVENTS):
        receipts += history.ingest_batch(s.access, events[start:start + MAX_BATCH_EVENTS])
    stored = sum(1 for r in receipts if not r.duplicate and not r.skipped_reason)
    duplicates = sum(1 for r in receipts if r.duplicate)
    skipped: dict[str, int] = {}
    for r in receipts:
        if r.skipped_reason:
            skipped[r.skipped_reason] = skipped.get(r.skipped_reason, 0) + 1
    data = {"events": len(events), "stored": stored, "duplicates": duplicates, "skipped": skipped,
            "receipts": receipts}
    text = f"ingested {len(events)} event(s): stored {stored}, duplicates {duplicates}, skipped {_counts(skipped)}"
    return Outcome(data, text)


def _message_lines(messages: Sequence[Any]) -> list[str]:
    return [f"#{m.sequence} {m.role}{' (' + m.tool_name + ')' if m.tool_name else ''}  {_ts(m.occurred_at)}\n"
            + "\n".join("    " + line for line in m.text.splitlines() or [""]) for m in messages]


def _gap_lines(gaps: Sequence[dict[str, Any]]) -> list[str]:
    return [f"gap #{g['from_seq']}-{g['to_seq']}: {g['reason']}" for g in gaps]


def cmd_history_search(s: Session, a: argparse.Namespace) -> Outcome:
    result = s.engine().search_history(s.access, a.query, limit=a.limit, session_ref=a.session)
    lines = [f"{len(result.hits)} hit(s) - status {result.status.value}"]
    for hit in result.hits:
        m = hit.message
        flags = f"  flags: {', '.join(hit.flags)}" if getattr(hit, "flags", ()) else ""
        lines.append(f"{hit.rank}. {hit.handle}  {m.session_ref}#{m.sequence} {m.role}  [{hit.score_kind} {hit.score:.4g}]{flags}")
        lines.append(f"   {hit.snippet}")
    lines.append("note: scores order results; they are not probabilities. Expand with: history scroll HANDLE")
    return Outcome(result, "\n".join(lines))


def cmd_history_scroll(s: Session, a: argparse.Namespace) -> Outcome:
    window = s.engine().scroll_history(s.access, a.handle, before=a.before, after=a.after)
    lines = [f"session {window['session_ref']} around {window['anchor']}"
             f"{' (more before)' if window['has_more_before'] else ''}{' (more after)' if window['has_more_after'] else ''}"]
    lines += _message_lines(window["messages"]) + _gap_lines(window["gaps"])
    return Outcome(window, "\n".join(lines))


def cmd_history_browse(s: Session, a: argparse.Namespace) -> Outcome:
    page = s.engine().browse_history(s.access, a.session, from_seq=a.from_seq, limit=a.limit)
    lines = [f"session {a.session}: {len(page['messages'])} message(s)"
             + (f", next page from {page['next_seq']}" if page["has_more"] else "")]
    lines += _message_lines(page["messages"]) + _gap_lines(page["gaps"])
    return Outcome(page, "\n".join(lines))


# =========================================================================== commands: episodes & procedures
def _episode_text(episode: Any) -> str:
    return "\n".join([
        f"episode {episode.episode_id} (record {episode.record_id}, revision {episode.revision})",
        f"task:      {episode.task_ref}  attempts: {len(episode.attempts)}",
        f"scope:     {_scope_text(episode.scope)}",
        f"outcome:   {episode.outcome.value} (claimed {episode.claimed_outcome.value})",
        f"basis:     {episode.outcome_basis}",
        f"objective: {episode.objective}",
    ])


def cmd_episode_record(s: Session, a: argparse.Namespace) -> Outcome:
    report = EpisodeReport.from_dict(_read_json_file(a.file))
    episode, receipt = s.engine().record_episode(s.access, report)
    return Outcome({"episode": episode, "receipt": receipt},
                   _episode_text(episode) + f"\nreceipt {receipt.receipt_id}")


def cmd_episode_show(s: Session, a: argparse.Namespace) -> Outcome:
    episode = s.engine().get_episode(s.access, a.id)
    return Outcome(episode, _episode_text(episode))


def cmd_episode_list(s: Session, a: argparse.Namespace) -> Outcome:
    episodes = s.engine().list_episodes(s.access, task_ref=a.task, outcome=a.outcome, limit=a.limit)
    text = "\n".join(f"{e.episode_id}  {e.outcome.value:<16}  {e.task_ref}  ({_scope_text(e.scope)})"
                     for e in episodes) or "no episodes (authorized scopes only)"
    return Outcome({"episodes": episodes, "count": len(episodes)}, text)


def _procedure_text(proc: Any) -> str:
    return "\n".join([
        f"procedure {proc.procedure_id} v{proc.version}: {proc.draft.name}",
        f"state:      {proc.state.value}",
        f"evidence:   {proc.independent_evidence} independent episode(s)",
        f"safety:     {', '.join(proc.safety_findings) or 'no findings'}",
        f"purpose:    {proc.draft.purpose}",
    ])


def _procedure_pair(result: tuple[Any, Any]) -> Outcome:
    proc, receipt = result
    return Outcome({"procedure": proc, "receipt": receipt}, _procedure_text(proc) + f"\nreceipt {receipt.receipt_id}")


def cmd_procedure_list(s: Session, a: argparse.Namespace) -> Outcome:
    procs = s.engine().list_procedures(s.access, state=a.state, limit=a.limit)
    text = "\n".join(f"{p.procedure_id}  v{p.version}  {p.state.value:<22}  {p.draft.name}" for p in procs) \
        or "no procedures (authorized scopes only)"
    return Outcome({"procedures": procs, "count": len(procs)}, text)


def cmd_procedure_show(s: Session, a: argparse.Namespace) -> Outcome:
    proc = s.engine().services(s.access).procedures.get(s.access, a.id)
    return Outcome(proc, _procedure_text(proc))


def cmd_procedure_nominate(s: Session, a: argparse.Namespace) -> Outcome:
    draft = ProcedureDraft.from_dict(_read_json_file(a.file))
    return _procedure_pair(s.engine().nominate_procedure(s.access, draft))


def cmd_procedure_evaluate(s: Session, a: argparse.Namespace) -> Outcome:
    # Without a host evaluation runner the engine raises UnsupportedCapability (exit 3):
    # it never executes procedure steps itself.
    return _procedure_pair(s.engine().evaluate_procedure(s.access, a.id))


def cmd_procedure_approve(s: Session, a: argparse.Namespace) -> Outcome:
    return _procedure_pair(s.engine().approve_procedure(s.access, a.id, expected_version=a.version))


def cmd_procedure_reject(s: Session, a: argparse.Namespace) -> Outcome:
    return _procedure_pair(s.engine().reject_procedure(s.access, a.id, a.reason or ""))


def cmd_procedure_export(s: Session, a: argparse.Namespace) -> Outcome:
    dest = Path(os.path.abspath(os.path.expanduser(a.dest)))
    if _within(dest, s.root) or _within(dest, s.key_dir):
        raise CLIError("invalid_request", "export procedures outside the vault root and key directory")
    result = s.engine().export_procedure(s.access, a.id, dest)
    s.warn("note: exported procedure files are plaintext outside the encrypted store; export grants no capability")
    return Outcome(result, _render_text(result))


# =========================================================================== commands: repository
def cmd_repo_register(s: Session, a: argparse.Namespace) -> Outcome:
    result = s.engine(allowed_roots=a.allow_root).register_repository(
        s.access, a.path, repository_id=a.id, exclude_patterns=tuple(a.exclude or ()))
    return Outcome(result, _render_text(result))


def cmd_repo_snapshot(s: Session, a: argparse.Namespace) -> Outcome:
    result = s.engine(allowed_roots=a.allow_root or ()).snapshot_repository(s.access, a.id, max_files=a.max_files)
    return Outcome(result, _render_text(result))


def cmd_repo_status(s: Session, a: argparse.Namespace) -> Outcome:
    result = s.engine(allowed_roots=a.allow_root or ()).repository_status(s.access, a.id)
    return Outcome(result, _render_text(result))


def cmd_repo_observations(s: Session, a: argparse.Namespace) -> Outcome:
    records = s.engine(allowed_roots=a.allow_root or ()).repository_observations(
        s.access, a.id, path=a.path, current_only=not a.all)
    data = {"observations": [r.to_dict() if a.full else _summary(r) for r in records], "count": len(records)}
    return Outcome(data, "\n".join(_record_line(r) for r in records) or "no observations")


# =========================================================================== commands: maintenance
def cmd_maintain(s: Session, a: argparse.Namespace) -> Outcome:
    result = s.engine().maintain(s.access)
    return Outcome(result, _render_text(result))


def cmd_consolidate(s: Session, a: argparse.Namespace) -> Outcome:
    request: dict[str, Any] = {}
    if a.job:
        request["job_id"] = a.job
    else:
        if a.max_records is not None:
            request["max_records"] = a.max_records
        if a.summarize:
            request["summarize"] = True
    result = s.engine().consolidate(s.access, request)
    return Outcome(result, _render_text(result))


def cmd_export(s: Session, a: argparse.Namespace) -> Outcome:
    out = Path(os.path.abspath(os.path.expanduser(a.out)))
    if _within(out, s.root) or _within(out, s.key_dir):
        raise CLIError("invalid_request", "a plaintext export must be written outside the vault root and key directory")
    if os.path.lexists(out):
        raise CLIError("file_exists", f"refusing to overwrite an existing file: {out}")
    # The engine checks the EXPORT operation (and READ for history) against the trusted
    # access context and returns the document; only this command writes it to disk.
    exported = s.engine().export(s.access, include_history=a.include_history)
    records = exported["records"]
    sessions = exported.get("history")
    what = f"{len(records)} authorized record(s)"
    if sessions is not None:
        what += f" and {len(sessions)} authorized history session(s)"
    if not a.yes:
        data = {"preview": True, "would_export": len(records), "out": str(out), "plaintext": True,
                "warning": PLAINTEXT_WARNING}
        if sessions is not None:
            data["would_export_history_sessions"] = len(sessions)
        text = (f"PREVIEW ONLY - nothing was written.\nwould export {what} to {out}"
                f"\n{PLAINTEXT_WARNING}\nre-run with --yes to write the plaintext file (mode 0600).")
        return Outcome(data, text, EXIT_PREVIEW)
    document = {
        **exported, "api_version": API_VERSION, "plaintext": True, "warning": PLAINTEXT_WARNING,
        "edition": s.partition.edition, "profile": s.partition.profile,
        "authorized_grants": s.access.grants, "count": len(records),
    }
    _write_private(out, _dumps(document) + "\n")
    s.warn(PLAINTEXT_WARNING)
    data = {"exported": len(records), "out": str(out), "mode": "0600", "plaintext": True, "format": EXPORT_FORMAT,
            "warning": PLAINTEXT_WARNING}
    if sessions is not None:
        data["exported_history_sessions"] = len(sessions)
    return Outcome(data, f"exported {what} to {out} (mode 0600, PLAINTEXT)")


# =========================================================================== commands: keys
def cmd_keys_rotate_master(s: Session, a: argparse.Namespace) -> Outcome:
    engine = s.engine()
    s.require_admin()
    provider = FileKeyProvider(s.key_dir)
    previous = provider.current_key_id()
    new_id = provider.create(make_current=False)  # the vault is re-wrapped before it becomes current
    receipt = engine.rotate_master_key(s.access, new_id, drop_old=not a.keep_old)
    provider.set_current(new_id)  # validated, atomic pointer switch (only after the re-wrap committed)
    notes = ["key files are never deleted by the CLI; remove the previous key file only after every"
             " profile using this key directory has been rotated and backed up"]
    data = {"receipt": receipt, "master_key_id": new_id, "previous_master_key_id": previous,
            "dropped_old_wraps": not a.keep_old, "notes": notes}
    return Outcome(data, f"re-wrapped {receipt.details.get('wrapped_keys')} key(s) under master key {new_id}"
                         f" (previous {previous}); receipt {receipt.receipt_id}\nnote: {notes[0]}")


def cmd_keys_rotate_data(s: Session, a: argparse.Namespace) -> Outcome:
    engine = s.engine()
    s.require_admin()
    result = engine.rotate_data_key(s.access, batch=a.batch)
    return Outcome(result, _render_text(result))


# =========================================================================== commands: migration
def _legacy_db(path: str) -> Path:
    db = Path(os.path.abspath(os.path.expanduser(path)))
    if not db.is_file():
        raise CLIError("not_found", f"legacy database not found: {db}")
    return db


def _legacy_key(path: str) -> bytes:
    try:
        raw = Path(os.path.expanduser(path)).read_bytes()
    except FileNotFoundError:
        raise CLIError("not_found", f"legacy key file not found: {path}") from None
    if len(raw) == 32:
        return raw
    text = raw.strip()
    if len(text) == 64:
        with contextlib.suppress(UnicodeDecodeError, ValueError):
            return bytes.fromhex(text.decode("ascii"))
    raise CLIError("invalid_request", "the legacy key file must hold the 32 raw key bytes (or 64 hex characters)")


def _legacy_mapping(a: argparse.Namespace):
    from .migrations.legacy import LegacyMapping

    workspaces: dict[str, str] = {}
    for item in a.workspace or ():
        path, sep, project = item.rpartition("=")
        if not sep or not path or not project:
            raise CLIError("usage", "--workspace takes PATH=PROJECT")
        workspaces[path] = project
    mapping = LegacyMapping.from_known(workspaces, list(a.agent_id or ()))
    return mapping, {project: path for path, project in workspaces.items()}


def cmd_migrate_inventory(s: Session, a: argparse.Namespace) -> Outcome:
    from .migrations import legacy

    mapping, _ = _legacy_mapping(a)
    report = legacy.inventory(_legacy_db(a.legacy_db), _legacy_key(a.key_file), mapping)
    return Outcome(report, _render_text(report))


def cmd_migrate_snapshot(s: Session, a: argparse.Namespace) -> Outcome:
    from .migrations import legacy

    manifest = legacy.snapshot(_legacy_db(a.legacy_db), Path(os.path.abspath(os.path.expanduser(a.out))))
    data = {k: v for k, v in manifest.items() if k != "row_fingerprints"}
    data["row_fingerprints"] = len(manifest.get("row_fingerprints") or {})
    data["out"] = str(Path(os.path.abspath(os.path.expanduser(a.out))))
    return Outcome(data, _render_text(data))


def _migrator(s: Session, a: argparse.Namespace):
    from .migrations.cutover import Migrator

    s.require_admin()
    db, key = _legacy_db(a.legacy_db), _legacy_key(a.key_file)
    engine = s.engine()  # the profile must be initialized before anything is recorded for it
    control = s.control(create=True)
    mapping, project_workspaces = _legacy_mapping(a)
    return Migrator(engine, control, s.access, db, key, mapping,
                    work_dir=Path(os.path.abspath(os.path.expanduser(a.work_dir))),
                    project_workspaces=project_workspaces)


def cmd_migrate_import(s: Session, a: argparse.Namespace) -> Outcome:
    result = _migrator(s, a).prepare_shadow()
    return Outcome(result, _render_text(result))


def cmd_migrate_verify(s: Session, a: argparse.Namespace) -> Outcome:
    from .migrations import legacy

    migrator = _migrator(s, a)
    state = migrator.state().state
    if state == "shadow_prepared":  # the protocol's validation step: delta import + verify
        result = {"transitioned": True, **migrator.validate(queries=a.query or None)}
    else:
        result = {"transitioned": False, "state": state,
                  "verify": legacy.verify(migrator.engine, s.access, migrator.legacy_db, migrator.key,
                                          migrator.mapping, queries=a.query or None)}
    ok = result.get("validated", result.get("verify", {}).get("ok"))
    return Outcome(result, _render_text(result), EXIT_OK if ok else EXIT_ERROR)


def cmd_migrate_state(s: Session, a: argparse.Namespace) -> Outcome:
    s.require_admin()
    pid = s.partition.partition_id
    control = s.control(create=False)
    record = control.get(pid) if control is not None else None
    recorded = record is not None and record.generation > 0
    data = {"partition_id": pid, "family": "memories", "recorded": recorded,
            "ownership": record.to_dict() if recorded else None,
            "history": control.history(pid) if recorded else []}
    text = (f"{record.state} (generation {record.generation}; writers: {', '.join(sorted(record.writers)) or 'none'})"
            if recorded else "no migration has been recorded for this profile under this root")
    return Outcome(data, text)


def _abort_interrupted_cutover(s: Session, a: argparse.Namespace, reason: str) -> Outcome:
    from .migrations.cutover import abort_cutover

    s.require_admin()
    control = s.control(create=False)
    if control is None:
        raise CLIError("not_found", "no migration has been recorded for this profile under this root")
    pid = s.partition.partition_id
    state = control.get(pid).state
    if not a.yes:
        data = {"preview": True, "state": state, "action": "abort",
                "effect": "moves an interrupted cutover back to legacy_authoritative (the legacy writer is"
                          " permitted again; no package write was accepted, nothing is lost)"}
        return Outcome(data, f"PREVIEW ONLY - nothing changed.\nstate: {state}\nwould abort: {data['effect']}"
                             "\nre-run with --yes to proceed.", EXIT_PREVIEW)
    try:
        result = abort_cutover(control, pid, reason)
    except MemoryEngineError as exc:
        raise CLIError(exc.code, str(exc)) from None
    return Outcome(result, _render_text(result))


def cmd_migrate_abort(s: Session, a: argparse.Namespace) -> Outcome:
    return _abort_interrupted_cutover(s, a, "operator abort")


def cmd_migrate_cutover(s: Session, a: argparse.Namespace) -> Outcome:
    s.require_admin()
    control = s.control(create=False)
    if (control is not None and control.get(s.partition.partition_id).state == "cutover_in_progress"
            and not Path(os.path.abspath(os.path.expanduser(a.legacy_db))).is_file()):
        # An interrupted cutover cannot be resumed without the legacy file: abort instead of wedging.
        return _abort_interrupted_cutover(s, a, "legacy database missing")
    migrator = _migrator(s, a)
    state = migrator.state().state
    action = "resume" if state == "cutover_in_progress" else "cutover"
    if not a.yes:
        data = {"preview": True, "state": state, "action": action,
                "effect": "fences legacy writers, drains in-flight legacy writes (it holds the legacy file's"
                          " write lock), imports the final delta, verifies, then makes the package the"
                          " authoritative writer (aborts back to legacy on any failure)"}
        return Outcome(data, f"PREVIEW ONLY - nothing changed.\nstate: {state}\nwould {action}: {data['effect']}"
                             "\nre-run with --yes to proceed.", EXIT_PREVIEW)
    result = migrator.resume() if action == "resume" else migrator.cutover(queries=a.query or None)
    return Outcome(result, _render_text(result), EXIT_OK if result.get("state") == "package_authoritative" else EXIT_ERROR)


def cmd_migrate_rollback(s: Session, a: argparse.Namespace) -> Outcome:
    migrator = _migrator(s, a)
    state = migrator.state().state
    action = "resume" if state == "rollback_in_progress" else "rollback"
    if not a.yes:
        plan = migrator.plan_rollback() if state == "package_authoritative" else None
        data = {"preview": True, "state": state, "action": action, "plan": plan,
                "allow_partial": a.allow_partial,
                "effect": "writes representable package records back into the legacy database and makes"
                          " legacy the authoritative writer again"}
        return Outcome(data, "PREVIEW ONLY - nothing changed.\n" + _render_text(data)
                       + "\nre-run with --yes to proceed.", EXIT_PREVIEW)
    result = migrator.resume() if action == "resume" else migrator.rollback(allow_partial=a.allow_partial)
    return Outcome(result, _render_text(result))


# =========================================================================== commands: evaluation
def _benchmark_runner() -> Callable[..., Any]:
    """``locus_memory.evaluation.run_benchmark`` (or its ``runner`` submodule), if installed."""
    for name in ("locus_memory.evaluation", "locus_memory.evaluation.runner"):
        try:
            run = getattr(importlib.import_module(name), "run_benchmark", None)
        except ImportError:
            continue
        if callable(run):
            return run
    raise CLIError("unavailable", "evaluation module unavailable", exit_code=EXIT_UNAVAILABLE)


def _brief(data: Any) -> str:
    """Top-level scalars of a (possibly large) result; nested values are summarized by size."""
    if not isinstance(data, dict):
        return _render_text(data)
    return "\n".join(f"{key}: {_scalar(value)}" if not isinstance(value, (dict, list))
                     else f"{key}: {len(value)} entr{'y' if len(value) == 1 else 'ies'} (see --json)"
                     for key, value in data.items())


def cmd_eval_run(s: Session, a: argparse.Namespace) -> Outcome:
    run = _benchmark_runner()
    try:
        params = dict(inspect.signature(run).parameters)
    except (TypeError, ValueError):
        params = {}
    open_kwargs = not params or any(p.kind == p.VAR_KEYWORD for p in params.values())
    out_name = next((n for n in ("out_dir", "out", "output_dir") if n in params), "out_dir" if open_kwargs else None)
    out_required = out_name in params and params[out_name].default is inspect.Parameter.empty
    kwargs: dict[str, Any] = {}
    out_dir: Path | None = None
    if a.out is not None or out_required:
        if out_name is None:
            raise CLIError("unavailable", "the evaluation module does not accept an output directory",
                           exit_code=EXIT_UNAVAILABLE)
        # Results are synthetic benchmark data; without --out they go to a new temporary directory.
        out_dir = Path(os.path.abspath(os.path.expanduser(a.out))) if a.out is not None \
            else Path(tempfile.mkdtemp(prefix="locus-memory-eval-"))
        if _within(out_dir, s.root) or _within(out_dir, s.key_dir):
            raise CLIError("invalid_request", "write evaluation results outside the vault root and key directory")
        kwargs[out_name] = out_dir
    if a.repetitions is not None:
        if "repetitions" not in params and not open_kwargs:
            raise CLIError("unavailable", "the evaluation module does not accept --repetitions",
                           exit_code=EXIT_UNAVAILABLE)
        kwargs["repetitions"] = a.repetitions
    result = run(**kwargs)
    data = result.to_dict() if callable(getattr(result, "to_dict", None)) else to_jsonable(result)
    if isinstance(data, dict) and out_dir is not None:
        data = {**data, "out_dir": str(out_dir)}
    # A run that violated a hard invariant exits 1, like ``python -m locus_memory.evaluation``.
    failed = isinstance(data, dict) and data.get("passed") is False
    return Outcome(data, _brief(data), EXIT_ERROR if failed else EXIT_OK)


# =========================================================================== parser
def _late_options() -> argparse.ArgumentParser:
    """``--json``/``--admin`` accepted after the command too (merged with the global ones)."""
    late = argparse.ArgumentParser(add_help=False)
    late.add_argument("--json", dest="late_json", action="store_true", default=argparse.SUPPRESS,
                      help="machine-readable output (one JSON document on stdout)")
    late.add_argument("--admin", dest="late_admin", action="store_true", default=argparse.SUPPRESS,
                      help="include the admin operation (administrative commands)")
    return late


def _add_scope_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("record scope (each value must also be granted with the global flag)")
    for dim, _ in GRANT_DIMS:
        flag = dim.replace("_", "-")
        group.add_argument(f"--scope-{flag}", dest=f"scope_{dim}", metavar=dim.upper(),
                           help=f"constrain the record to this {flag}")


def _add_statement_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("content", help="the statement ('-' reads it from stdin)")
    parser.add_argument("--kind", default="fact", choices=USER_KINDS)
    parser.add_argument("--title")
    parser.add_argument("--tag", action="append", help="repeatable")
    parser.add_argument("--subject", help="structured subject (enables conflict detection)")
    parser.add_argument("--predicate", help="structured predicate")
    parser.add_argument("--idempotency-key", help="retrying with the same key returns the first receipt")
    _add_scope_options(parser)


def _add_legacy_options(parser: argparse.ArgumentParser, *, work_dir: bool) -> None:
    parser.add_argument("--legacy-db", required=True, help="path of the Locus memory.sqlite3 (read-only here)")
    parser.add_argument("--key-file", required=True, help="the legacy 32-byte master.key (raw or 64 hex chars)")
    if work_dir:
        parser.add_argument("--work-dir", required=True, help="directory for migration snapshots")
    parser.add_argument("--workspace", action="append", metavar="PATH=PROJECT",
                        help="map a legacy workspace path to a project id (repeatable)")
    parser.add_argument("--agent-id", action="append", help="a known legacy agent id (repeatable)")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="locus-memory",
        description="Diagnostic CLI for one local, encrypted locus-memory profile.",
        epilog="Exit codes: 0 ok, 1 error, 2 preview only (nothing changed), 3 capability unavailable.",
    )
    parser.add_argument("--version", action="version", version=f"locus-memory {__version__}")
    parser.add_argument("--root", help=f"store root (default: ${HOME_ENV}, else {DEFAULT_HOME})")
    parser.add_argument("--profile", default="default", help="profile (security partition) to open")
    parser.add_argument("--edition", default="standalone", help="edition label of the partition")
    parser.add_argument("--key-dir", help="directory of the standalone key (default: <root>/keys)")
    parser.add_argument("--json", action="store_true", help="machine-readable output (one JSON document)")
    parser.add_argument("--admin", action="store_true", help="include the admin operation")
    grants = parser.add_argument_group("scope grants (repeatable; what this invocation may see and use)")
    for dim, _ in GRANT_DIMS:
        flag = dim.replace("_", "-")
        grants.add_argument(f"--{flag}", dest=f"grant_{dim}", action="append", metavar=dim.upper())

    late = _late_options()
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    def leaf(group: Any, name: str, func: Callable[[Session, argparse.Namespace], Outcome], help_text: str
             ) -> argparse.ArgumentParser:
        sub = group.add_parser(name, help=help_text, description=help_text, parents=[late])
        sub.set_defaults(func=func)
        return sub

    def branch(name: str, help_text: str) -> Any:
        sub = commands.add_parser(name, help=help_text, description=help_text)
        return sub.add_subparsers(dest=f"{name}_command", metavar="SUBCOMMAND")

    p = leaf(commands, "init", cmd_init, "create the standalone key (never over an existing one) and the profile vault")
    p.add_argument("--use-existing-key", action="store_true",
                   help="add this profile under the key that already exists in --key-dir")
    leaf(commands, "status", cmd_status, "engine status for the authorized namespace")

    p = leaf(commands, "list", cmd_list, "list memories (ids and titles)")
    p.add_argument("--lifecycle", action="append", choices=(*LIFECYCLES, "all"), help="default: approved")
    p.add_argument("--kind", action="append", choices=tuple(k.value for k in MemoryKind))
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--full", action="store_true", help="include full records in --json output")

    p = leaf(commands, "search", cmd_search, "ranked search over authorized memories")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=8)
    p.add_argument("--kind", action="append", choices=tuple(k.value for k in MemoryKind))
    p.add_argument("--lifecycle", action="append", choices=(*LIFECYCLES, "all"), help="default: approved")

    p = leaf(commands, "show", cmd_show, "show one memory")
    p.add_argument("id")
    p = leaf(commands, "explain", cmd_explain, "provenance, revisions and links of one memory")
    p.add_argument("id")

    p = leaf(commands, "remember", cmd_remember, "store an explicit memory as the user")
    _add_statement_options(p)
    p.add_argument("--pin", action="store_true")
    p.add_argument("--reason")
    p.add_argument("--allow-sensitive", action="store_true",
                   help="you explicitly ask to keep personal information this statement contains")

    p = leaf(commands, "propose", cmd_propose, "propose a candidate memory with evidence")
    _add_statement_options(p)
    p.add_argument("--source", action="append", required=True, metavar="KIND:REF",
                   help="evidence source, e.g. document:notes.md (repeatable)")
    p.add_argument("--rationale")

    p = leaf(commands, "approve", cmd_approve, "approve a candidate")
    p.add_argument("id")
    p.add_argument("--revision", type=int, required=True, help="the revision you reviewed")
    p.add_argument("--supersede", action="store_true", help="supersede conflicting memories")
    p = leaf(commands, "reject", cmd_reject, "reject a candidate")
    p.add_argument("id")
    p.add_argument("--revision", type=int, required=True)
    p.add_argument("--reason")
    p = leaf(commands, "correct", cmd_correct, "correct a memory")
    p.add_argument("id")
    p.add_argument("--revision", type=int, required=True)
    p.add_argument("--content", help="new content ('-' reads stdin)")
    p.add_argument("--title")
    p.add_argument("--tag", action="append", help="replace the tags (repeatable)")
    p.add_argument("--reason")
    p.add_argument("--allow-sensitive", action="store_true")
    for name, pinned in (("pin", True), ("unpin", False)):
        p = leaf(commands, name, cmd_pin, f"{name} a memory")
        p.add_argument("id")
        p.add_argument("--revision", type=int, required=True)
        p.set_defaults(pinned=pinned)

    p = leaf(commands, "forget", cmd_forget, "preview (default) or perform (--yes) an authorized forget")
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--memory", metavar="ID")
    target.add_argument("--source", metavar="KIND:REF", help="a source identity and what was learned from it")
    target.add_argument("--session", metavar="REF")
    target.add_argument("--project", dest="target_project", metavar="P")
    target.add_argument("--repository", dest="target_repository", metavar="R")
    target.add_argument("--agent", dest="target_agent", metavar="A")
    target.add_argument("--profile", dest="target_profile", action="store_true",
                        help="the whole profile (requires --admin)")
    p.add_argument("--yes", action="store_true", help="actually forget (default: preview only, exit 2)")
    p.add_argument("--delete-source-archive", action="store_true", help="also delete archived messages")
    p.add_argument("--keep-derived", action="store_true", help="do not cascade into derived records")
    p.add_argument("--allow-relearning", action="store_true", help="do not suppress relearning")
    p.add_argument("--idempotency-key")

    group = branch("context", "compiled context packets")
    p = leaf(group, "preview", cmd_context_preview, "compile a context packet within a token allowance")
    p.add_argument("--query")
    p.add_argument("--tokens", type=int, default=2000, help="token allowance (default 2000)")
    p.add_argument("--include-history", action="store_true")
    p = leaf(group, "explain", cmd_context_explain, "explain a persisted context receipt")
    p.add_argument("receipt_id")

    group = branch("history", "session history archive")
    p = leaf(group, "ingest", cmd_history_ingest, "archive IngestionEvent objects (one JSON object per line)")
    p.add_argument("--file", required=True, help="events.jsonl ('-' reads stdin)")
    p = leaf(group, "search", cmd_history_search, "lexical search over authorized sessions")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--session-ref", dest="session", help="restrict to one session")
    p = leaf(group, "scroll", cmd_history_scroll, "bounded window around a search hit")
    p.add_argument("handle")
    p.add_argument("--before", type=int, default=5)
    p.add_argument("--after", type=int, default=5)
    p = leaf(group, "browse", cmd_history_browse, "page through one session")
    p.add_argument("session")
    p.add_argument("--from-seq", type=int, default=0)
    p.add_argument("--limit", type=int, default=50)

    group = branch("episode", "task episodes")
    p = leaf(group, "record", cmd_episode_record, "record an EpisodeReport (outcome comes from host verification)")
    p.add_argument("--file", required=True, help="report.json ('-' reads stdin)")
    p = leaf(group, "show", cmd_episode_show, "show one episode")
    p.add_argument("id")
    p = leaf(group, "list", cmd_episode_list, "list episodes")
    p.add_argument("--task")
    p.add_argument("--outcome", choices=tuple(o.value for o in EpisodeOutcome))
    p.add_argument("--limit", type=int, default=50)

    group = branch("repo", "repository memory")
    p = leaf(group, "register", cmd_repo_register, "register a git work tree under an allowed root")
    p.add_argument("path")
    p.add_argument("--id", required=True, help="repository id (grant it with --repository)")
    p.add_argument("--allow-root", action="append", required=True, metavar="PATH",
                   help="host-allowed root for repositories (required; never defaults to home)")
    p.add_argument("--exclude", action="append", help="extra exclusion pattern (repeatable)")
    for name, func, help_text in (("snapshot", cmd_repo_snapshot, "bounded snapshot of a registered repository"),
                                  ("status", cmd_repo_status, "repository status"),
                                  ("observations", cmd_repo_observations, "repository observations")):
        p = leaf(group, name, func, help_text)
        p.add_argument("id")
        p.add_argument("--allow-root", action="append", metavar="PATH", help="host-allowed root (repeatable)")
        if name == "snapshot":
            p.add_argument("--max-files", type=int, default=20_000)
        if name == "observations":
            p.add_argument("--path", help="only observations of this repository path")
            p.add_argument("--all", action="store_true", help="include historical observations")
            p.add_argument("--full", action="store_true", help="include full records in --json output")

    group = branch("procedure", "governed procedural candidates")
    p = leaf(group, "list", cmd_procedure_list, "list procedures")
    p.add_argument("--state", choices=tuple(st.value for st in ProcedureState))
    p.add_argument("--limit", type=int, default=100)
    p = leaf(group, "show", cmd_procedure_show, "show one procedure")
    p.add_argument("id")
    p = leaf(group, "nominate", cmd_procedure_nominate, "nominate a ProcedureDraft")
    p.add_argument("--file", required=True, help="draft.json ('-' reads stdin)")
    p = leaf(group, "evaluate", cmd_procedure_evaluate, "evaluate with the host runner (unsupported standalone)")
    p.add_argument("id")
    p = leaf(group, "approve", cmd_procedure_approve, "approve an evaluated procedure")
    p.add_argument("id")
    p.add_argument("--version", type=int, required=True, help="the procedure version you reviewed")
    p = leaf(group, "reject", cmd_procedure_reject, "reject a procedure")
    p.add_argument("id")
    p.add_argument("--reason")
    p = leaf(group, "export", cmd_procedure_export, "export an approved procedure as a proposal")
    p.add_argument("id")
    p.add_argument("--dest", required=True, help="destination directory (outside the vault)")

    leaf(commands, "maintain", cmd_maintain, "persist due expiries and run bounded maintenance")
    p = leaf(commands, "consolidate", cmd_consolidate, "run or resume a consolidation job")
    p.add_argument("--job", help="resume this job id")
    p.add_argument("--max-records", type=int)
    p.add_argument("--summarize", action="store_true")

    group = branch("migrate", "Locus MemoryVault migration")
    p = leaf(group, "inventory", cmd_migrate_inventory, "read-only legacy inventory (counts only)")
    _add_legacy_options(p, work_dir=False)
    p = leaf(group, "snapshot", cmd_migrate_snapshot, "encrypted legacy snapshot + manifest")
    p.add_argument("--legacy-db", required=True)
    p.add_argument("--out", required=True, help="new snapshot directory")
    p = leaf(group, "import", cmd_migrate_import, "snapshot + shadow import (admin)")
    _add_legacy_options(p, work_dir=True)
    p = leaf(group, "verify", cmd_migrate_verify,
             "validate a shadow import (delta + verify; admin), or verify read-only in any other state;"
             " exits 1 when verification fails")
    _add_legacy_options(p, work_dir=True)
    p.add_argument("--query", action="append", help="compare retrieval for this query (repeatable)")
    leaf(group, "state", cmd_migrate_state, "ownership state of this profile (admin)")
    p = leaf(group, "cutover", cmd_migrate_cutover,
             "make the package authoritative (admin; --yes); exits 1 when it aborts back to legacy")
    _add_legacy_options(p, work_dir=True)
    p.add_argument("--query", action="append")
    p.add_argument("--yes", action="store_true")
    p = leaf(group, "abort", cmd_migrate_abort,
             "abort an interrupted cutover back to legacy_authoritative (admin; --yes)")
    p.add_argument("--yes", action="store_true")
    p = leaf(group, "rollback", cmd_migrate_rollback, "reverse-sync to legacy (admin; --yes)")
    _add_legacy_options(p, work_dir=True)
    p.add_argument("--allow-partial", action="store_true",
                   help="keep unrepresentable records in a read-only package store")
    p.add_argument("--yes", action="store_true")

    p = leaf(commands, "export", cmd_export, "explicit PLAINTEXT export of your authorized records (--yes)")
    p.add_argument("--out", required=True, help="new file outside the vault (written with mode 0600)")
    p.add_argument("--yes", action="store_true", help="write the plaintext file (default: preview, exit 2)")
    p.add_argument("--include-history", action="store_true",
                   help="also export the authorized history sessions and their messages")

    group = branch("keys", "key administration (admin)")
    p = leaf(group, "rotate-master", cmd_keys_rotate_master, "new master key file; re-wrap this profile's keys")
    p.add_argument("--keep-old", action="store_true", help="keep wraps under the previous master key")
    p = leaf(group, "rotate-data", cmd_keys_rotate_data, "start/continue a progressive data-key rotation")
    p.add_argument("--batch", type=int, default=500)

    group = branch("eval", "evaluation benchmark")
    p = leaf(group, "run", cmd_eval_run,
             "run the evaluation benchmark (if the module is installed); exits 1 when a run broke a hard"
             " invariant")
    p.add_argument("--out", help="output directory")
    p.add_argument("--repetitions", type=int)
    return parser


# =========================================================================== entry point
def _fail(code: str, message: str, details: dict[str, Any], exit_code: int, as_json: bool) -> int:
    if as_json:
        print(_dumps({"error": code, "message": message, "details": details}))
    else:
        print(f"error ({code}): {message}", file=sys.stderr)
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    session: Session | None = None
    try:
        parser = build_parser()
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:  # --help / --version
            return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else EXIT_ERROR)
        as_json = bool(args.json or getattr(args, "late_json", False))
        args.admin = bool(args.admin or getattr(args, "late_admin", False))
        func = getattr(args, "func", None)
        if func is None:
            raise CLIError("usage", "a command is required (see locus-memory --help)")
        session = Session(args)
        outcome = func(session, args)
        for warning in session.warnings:
            print(warning, file=sys.stderr)
        if as_json:
            print(_dumps(outcome.data))
        elif outcome.text:
            print(outcome.text)
        return outcome.exit_code
    except CLIError as exc:
        return _fail(exc.code, str(exc), exc.details, exc.exit_code, as_json)
    except MemoryEngineError as exc:
        unavailable = isinstance(exc, (UnsupportedCapability, IndexUnavailable))
        exit_code = EXIT_STORAGE if isinstance(exc, StorageUnavailable) else (
            EXIT_UNAVAILABLE if unavailable else EXIT_ERROR)
        return _fail(exc.code, str(exc), exc.details, exit_code, as_json)
    except KeyboardInterrupt:
        return _fail("interrupted", "interrupted", {}, 130, as_json)
    except OSError as exc:
        where = f": {exc.filename}" if exc.filename else ""
        return _fail("io_error", f"{exc.strerror or type(exc).__name__}{where}", {}, EXIT_ERROR, as_json)
    except Exception as exc:  # never print arbitrary exception text: it could carry content
        return _fail("internal_error", f"unexpected {type(exc).__name__}", {}, EXIT_ERROR, as_json)
    finally:
        if session is not None:
            session.close()


if __name__ == "__main__":
    raise SystemExit(main())
