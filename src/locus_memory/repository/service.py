"""Repository memory: explicit, bounded, read-only observation of registered git work trees.

Registration (``register``) binds a repository id to a work-tree root that must
resolve inside a host-allowed root (never the filesystem root or the home
directory) and be the top level of a git work tree. The stable identity is the
repository id + the encrypted root path + the initial commit hash.

Snapshots (``snapshot``) are explicit and bounded (files, bytes per file, total
bytes, deadline, cancellation). Snapshot identity = HEAD commit + a hash of the
dirty state (``git status --porcelain=v2 -z`` entries for non-excluded paths plus
raw content hashes of modified files) + the work-tree path (+ the exclusion set).
Inventory comes from ``git ls-files -s -z``; unmodified content is read from the
object store (``cat-file``, no filters/textconv), modified content through guarded
no-follow opens beneath the root. Observations are parsed facts, never model
claims: one :class:`MemoryRecord` (kind ``repository_observation``, basis
``observed``, lifecycle ``approved``) per supported file, citing a ``blob_range``
source. Incremental: unchanged blobs reuse their observation; changed, deleted and
renamed paths turn the previous observation ``stale`` (historical, still
searchable); a blob that comes back revives its stale observation; renames are
detected **heuristically** by an identical blob at a new path and keep lineage.
Bounds, cancellation and deadlines record a ``partial`` snapshot - never complete.

Safety: allowed roots and exclusions are enforced on enumeration and on every
direct read (``read_file``, historical blobs, ``history``); excluded files are never
read, hashed by content or parsed and are only ever counted, never named. Paths
with ``..``, absolute paths, NUL and symlinks are refused; symlinks are inventory
entries only. Repository code is never executed (see ``git.py`` for the hardened
git invocation). Everything a repository says - paths, docstrings, commit
subjects, interchange documents - is data: it is encrypted at rest, secret-redacted
and markup-neutralized on the way out, and it can never change access or approve
anything.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .. import policy, safety
from ..errors import (
    AccessDenied,
    IntegrityError,
    InterchangeInvalid,
    MemoryEngineError,
    NotFound,
    ProviderError,
    RepositoryAccessDenied,
    RepositoryConflict,
    RepositoryError,
    ValidationError,
)
from ..host import Deadline
from ..models import (
    AccessContext,
    Actor,
    Confidence,
    Lifecycle,
    Links,
    MemoryKind,
    MemoryRecord,
    Operation,
    Receipt,
    Retention,
    Scope,
    ScopeGrants,
    SourceKind,
    SourceRef,
    StatementBasis,
    Validity,
)
from ..services import PartitionContext
from ..storage import schema
from ..storage.partition import new_id, partition_bound
from ..validation import ID_PATTERN, check_id, check_int
from . import interchange as ix
from . import observations as obs
from . import scanner
from .git import Git, IndexEntry

_HEX = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_KEEP_SNAPSHOTS = 4
_MAX_RECEIPT_IDS = 256
_HARD_MAX_FILES = 200_000
_HARD_MAX_FILE_BYTES = 16 * 1024 * 1024
_HARD_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
_MAX_READ_BYTES = 4 * 1024 * 1024
_MAX_HISTORY = 500
_MAX_HISTORY_PATHS = 200
_PARSE_BATCH_BYTES = 8 * 1024 * 1024
_PARSE_BATCH_BLOBS = 256
# The commit settles entries in bounded write transactions (at most this many entries or this
# much time each, whichever comes first), so a large snapshot never holds the store's write lock
# for long: another writer (a forget) waits at most one batch, far inside its busy budget, and
# the deadline and cancellation are honoured between batches.
_COMMIT_BATCH_ENTRIES = 500
_COMMIT_BATCH_SECONDS = 0.25
_MODE_REGULAR = ("100644", "100755")
_MODE_SYMLINK = "120000"
_MODE_GITLINK = "160000"
_INTERCHANGE_LABEL = f"{ix.FORMAT}/{ix.VERSION}"

LIMITATIONS = (
    "JS/TS imports are extracted with a heuristic regular expression (labelled heuristic)",
    "rename detection is heuristic: an identical blob at a new path while the old path disappeared",
    "languages other than Python, JavaScript and TypeScript are inventoried only (unsupported)",
    "modified work-tree files are hashed as raw bytes; git clean/smudge filters are never run",
    "untracked files are not inventoried; they only contribute their names to the dirty-state hash",
)


@dataclass(frozen=True)
class _Repo:
    row_id: str
    repository_id: str
    scope: Scope
    scope_token: str
    root: str
    common_dir: str
    initial_commit: str
    object_format: str
    exclude_patterns: tuple[str, ...]
    registered_at: float
    current_snapshot: str | None
    payload: dict[str, Any]


@dataclass
class _Entry:
    path: str
    path_token: str
    kind: str  # file | symlink | submodule | other
    mode: str
    blob: str | None
    blob_token: str
    origin: str  # index | worktree
    size: int | None
    language: str
    support: str  # parsed | heuristic | unsupported
    status: str = "pending"
    data: bytes | None = None
    facts: obs.Facts | None = None
    observation_id: str | None = None


def _excluded_observation(excl: scanner.Exclusions, record: MemoryRecord) -> bool:
    extra = record.extra if isinstance(record.extra, dict) else {}
    for key in ("path", "renamed_from"):
        value = extra.get(key)
        if isinstance(value, str) and value and excl.excluded(value):
            return True
    return False


def _chunks(items: list[str], size: int = 500) -> Iterable[list[str]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


@partition_bound
class RepositoryService:
    REPO_TABLE = "repositories"
    SNAP_TABLE = "repo_snapshots"
    FILE_TABLE = "repo_files"

    def __init__(self, ctx: PartitionContext) -> None:
        self.ctx = ctx
        self.p = ctx.partition
        self.records = ctx.records
        # Host-tunable bounds for every git invocation (also overridable by tests).
        self.git_timeout_s = float(getattr(ctx.config, "repository_git_timeout_s", 10.0))
        self.git_executable: str | None = None
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    # ------------------------------------------------------------------ helpers
    def _lock(self, row_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(row_id, threading.Lock())

    def _row_id(self, repository_id: str) -> str:
        return "rp" + self.p.token("repository-id", repository_id)[:32]

    def _path_token(self, row_id: str, path: str) -> str:
        return self.p.token("repo-path", f"{row_id}\x00{path}")

    def _blob_token(self, repository_id: str, blob: str) -> str:
        """Equal to the keyed source token of ``blob_range:<repository_id>:<blob>``."""
        return self.records.source_token(f"{SourceKind.BLOB_RANGE.value}:{repository_id}:{blob}")

    def _git(self, root: str) -> Git:
        return Git(root, timeout_s=self.git_timeout_s, executable=self.git_executable)

    def _allowed_roots(self) -> tuple[Any, ...]:
        return tuple(self.ctx.host.allowed_repository_roots or ())

    def _exclusions(self, repo: _Repo) -> scanner.Exclusions:
        host_extra = scanner.check_patterns(tuple(getattr(self.ctx.host, "repository_exclude_patterns", ()) or ()))
        return scanner.Exclusions(tuple(repo.exclude_patterns) + host_extra)

    @staticmethod
    def _require_any(access: AccessContext, operations: tuple[Operation, ...]) -> None:
        if not any(op in access.operations for op in operations):
            raise AccessDenied("operation not permitted for this caller: requires one of "
                               + ", ".join(op.value for op in operations))

    def _guard_inputs(self, repo: _Repo) -> list[tuple[str, str]]:
        return [(f"scope:{dim}", self.records.scope_value_token(dim, value)) for dim, value in repo.scope.constraints]

    def _visible_clause(self, grants: ScopeGrants, alias: str = "r") -> tuple[str, list[str]]:
        pairs = self.records.allowed_pairs(grants)
        if pairs:
            return (f"NOT EXISTS (SELECT 1 FROM repo_scopes s WHERE s.repo_id={alias}.id AND "
                    f"(s.dim || ':' || s.value_token) NOT IN ({','.join('?' * len(pairs))}))", pairs)
        return f"NOT EXISTS (SELECT 1 FROM repo_scopes s WHERE s.repo_id={alias}.id)", []

    def _records_visible_clause(self, grants: ScopeGrants, alias: str) -> tuple[str, list[str]]:
        pairs = self.records.allowed_pairs(grants)
        if pairs:
            return (f"NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id={alias}.id AND "
                    f"(s.dim || ':' || s.value_token) NOT IN ({','.join('?' * len(pairs))}))", pairs)
        return f"NOT EXISTS (SELECT 1 FROM record_scopes s WHERE s.record_id={alias}.id)", []

    # ------------------------------------------------------------------ registration rows
    def _decode(self, row: sqlite3.Row) -> _Repo:
        payload = self.p.open_json(self.REPO_TABLE, row["id"], {"scope": row["scope_token"]},
                                   row["dek_id"], row["nonce"], row["ciphertext"])
        if not isinstance(payload, dict):
            raise IntegrityError("a stored repository registration is malformed")
        scope = Scope.from_dict(payload.get("scope"))
        if self.records.scope_token(scope) != row["scope_token"] or self._row_id(payload["repository_id"]) != row["id"]:
            raise IntegrityError("repository metadata does not match its authenticated payload")
        return _Repo(
            row_id=row["id"], repository_id=payload["repository_id"], scope=scope,
            scope_token=row["scope_token"], root=payload["root"], common_dir=payload.get("common_dir") or "",
            initial_commit=payload.get("initial_commit") or "", object_format=payload.get("object_format") or "sha1",
            exclude_patterns=tuple(payload.get("exclude_patterns") or ()),
            registered_at=float(payload.get("registered_at") or 0.0),
            current_snapshot=row["current_snapshot"], payload=payload,
        )

    def _load(self, conn: sqlite3.Connection, access: AccessContext, repository_id: str) -> _Repo:
        """Authorized registration (scope filtered in SQL first). Missing == unauthorized."""
        if not isinstance(repository_id, str) or not ID_PATTERN.fullmatch(repository_id):
            raise NotFound("repository not found")
        row_id = self._row_id(repository_id)
        clause, params = self._visible_clause(access.grants)
        row = conn.execute(f"SELECT r.* FROM repositories r WHERE r.id=? AND {clause}",
                           [row_id, *params]).fetchone()
        if row is None:
            raise NotFound("repository not found")
        repo = self._decode(row)
        if repo.repository_id != repository_id or not access.grants.allows(repo.scope):
            raise IntegrityError("authorization index disagrees with repository scope")
        return repo

    def _visible_row(self, conn: sqlite3.Connection, grants: ScopeGrants, row_id: str) -> bool:
        clause, params = self._visible_clause(grants)
        return conn.execute(f"SELECT 1 FROM repositories r WHERE r.id=? AND {clause}",
                            [row_id, *params]).fetchone() is not None

    def _save_repo(self, conn: sqlite3.Connection, row_id: str, scope: Scope, payload: dict[str, Any], *,
                   insert: bool, now: float, current_snapshot: str | None = None) -> None:
        scope_token = self.records.scope_token(scope)
        dek, nonce, ct = self.p.seal_json(self.REPO_TABLE, row_id, {"scope": scope_token}, payload)
        if insert:
            conn.execute(
                "INSERT INTO repositories(id, scope_token, created_at, updated_at, current_snapshot, dek_id,"
                " nonce, ciphertext) VALUES(?,?,?,?,?,?,?,?)",
                (row_id, scope_token, now, now, current_snapshot, dek, nonce, ct))
            conn.executemany(
                "INSERT INTO repo_scopes(repo_id, dim, value_token) VALUES(?,?,?)",
                [(row_id, dim, self.records.scope_value_token(dim, value)) for dim, value in scope.constraints])
        else:
            conn.execute(
                "UPDATE repositories SET updated_at=?, current_snapshot=?, dek_id=?, nonce=?, ciphertext=?"
                " WHERE id=?", (now, current_snapshot, dek, nonce, ct, row_id))

    def _inspect_root(self, real: str) -> tuple[Git, dict[str, Any]]:
        allowed = self._allowed_roots()
        git = self._git(real)
        top = git.toplevel()
        if top is None or os.path.realpath(top) != real or git.is_bare():
            raise RepositoryAccessDenied("the path is not the top level of a git work tree")
        common = git.common_dir()
        if common is None or not scanner.within_allowed(common, allowed):
            raise RepositoryAccessDenied("the repository's git directory is outside the host-allowed roots")
        return git, {"common_dir": common}

    def _open_git(self, repo: _Repo) -> Git:
        """Re-validate a registration against the *current* host policy before any git use."""
        real = scanner.check_root(repo.root, self._allowed_roots())
        if real != repo.root:
            raise RepositoryAccessDenied("the registered root no longer resolves to the same directory")
        git, info = self._inspect_root(real)
        if repo.common_dir and info["common_dir"] != repo.common_dir:
            raise RepositoryAccessDenied("the registered root now points at a different git directory")
        return git

    # ------------------------------------------------------------------ register
    def register(self, access: AccessContext, root: Any, *, repository_id: str, scope: Scope | None = None,
                 exclude_patterns: Iterable[str] = ()) -> dict[str, Any]:
        self._require_any(access, (Operation.WRITE, Operation.ADMIN))
        if access.actor not in (Actor.USER, Actor.HOST):
            raise AccessDenied("only the user or the host can register a repository")
        check_id(repository_id, "repository_id")
        scope = Scope.of(repository=repository_id) if scope is None else Scope.from_dict(scope)
        if scope.get("repository") is None:
            raise ValidationError("a repository scope must include a repository dimension")
        policy.require_scope(access, scope)
        extra = scanner.check_patterns(tuple(exclude_patterns or ()))
        real = scanner.check_root(root, self._allowed_roots())
        git, info = self._inspect_root(real)
        object_format = git.object_format()
        roots = git.root_commits()
        if not roots:
            raise RepositoryError("the repository has no commits yet; commit once before registering it")
        initial_commit = roots[0]
        row_id = self._row_id(repository_id)
        now = self.ctx.clock()
        with self.p.db.write() as conn:
            existing = conn.execute("SELECT * FROM repositories WHERE id=?", (row_id,)).fetchone()
            if existing is not None:
                same = False
                if self._visible_row(conn, access.grants, row_id):
                    repo = self._decode(existing)
                    same = (repo.root == real and repo.initial_commit == initial_commit and repo.scope == scope
                            and tuple(repo.exclude_patterns) == extra)
                if not same:
                    # Identical refusal whether the holder is visible or not.
                    raise RepositoryConflict("this repository id is already registered with a different"
                                             " root, identity, scope or exclusion set")
                receipt = self.p.make_receipt(conn, "repository_register", "noop",
                                              details={"repository_id": repository_id, "idempotent": True})
                return self._registration_view(repo, receipt, registered=False)
            payload = {
                "repository_id": repository_id, "root": real, "scope": scope.as_dict(),
                "common_dir": info["common_dir"], "initial_commit": initial_commit,
                "object_format": object_format, "exclude_patterns": list(extra),
                "registered_at": now, "registered_by": access.actor.value,
                "last_complete_snapshot": None,
            }
            self._save_repo(conn, row_id, scope, payload, insert=True, now=now)
            self.p.bump(conn)
            receipt = self.p.make_receipt(conn, "repository_register", "ok",
                                          details={"repository_id": repository_id})
            self.p.event(conn, "repository_register", "ok")
            repo = self._decode(conn.execute("SELECT * FROM repositories WHERE id=?", (row_id,)).fetchone())
        return self._registration_view(repo, receipt, registered=True)

    @staticmethod
    def _registration_view(repo: _Repo, receipt: Receipt, *, registered: bool) -> dict[str, Any]:
        return {
            "repository_id": repo.repository_id, "registered": registered, "scope": repo.scope.as_dict(),
            "initial_commit": repo.initial_commit, "object_format": repo.object_format,
            "extra_exclusions": len(repo.exclude_patterns), "registered_at": repo.registered_at,
            "receipt_id": receipt.receipt_id,
        }

    # ------------------------------------------------------------------ snapshot
    def snapshot(self, access: AccessContext, repository_id: str, *, max_files: int = 20_000,
                 max_file_bytes: int = 512 * 1024, max_total_bytes: int = 64 * 1024 * 1024,
                 deadline_ms: int | None = None, cancel: Any = None) -> dict[str, Any]:
        self._require_any(access, (Operation.INGEST, Operation.WRITE, Operation.ADMIN))
        check_int(max_files, "max_files", lo=1, hi=_HARD_MAX_FILES)
        check_int(max_file_bytes, "max_file_bytes", lo=1, hi=_HARD_MAX_FILE_BYTES)
        check_int(max_total_bytes, "max_total_bytes", lo=1, hi=_HARD_MAX_TOTAL_BYTES)
        if deadline_ms is not None:
            check_int(deadline_ms, "deadline_ms", lo=1, hi=3_600_000)
        if cancel is not None and not hasattr(cancel, "cancelled"):
            raise ValidationError("cancel must be a CancellationToken")
        deadline = Deadline(deadline_ms)
        with self.p.db.read() as conn:
            repo = self._load(conn, access, repository_id)
        with self._lock(repo.row_id):
            return self._snapshot_locked(access, repository_id, max_files=max_files,
                                         max_file_bytes=max_file_bytes, max_total_bytes=max_total_bytes,
                                         deadline=deadline, cancel=cancel)

    def _stopped(self, deadline: Deadline, cancel: Any) -> str | None:
        if cancel is not None and getattr(cancel, "cancelled", False):
            return "cancelled"
        if deadline.expired:
            return "deadline"
        return None

    def _snapshot_locked(self, access: AccessContext, repository_id: str, *, max_files: int,
                         max_file_bytes: int, max_total_bytes: int, deadline: Deadline,
                         cancel: Any) -> dict[str, Any]:
        with self.p.db.read() as conn:
            repo = self._load(conn, access, repository_id)
            observed_deletion_generation = self.p.deletion_generation(conn)
            # Only observations that can still be reused (approved) or revived (stale) count as known.
            cur_map = {r[0]: (r[1], r[2]) for r in conn.execute(
                "SELECT o.path_token, o.record_id, o.blob_token FROM repo_observations o JOIN records r"
                " ON r.id=o.record_id WHERE o.repo_id=? AND o.current=1 AND r.lifecycle IN ('approved','stale')",
                (repo.row_id,))}
            known_pairs = {(r[0], r[1]) for r in conn.execute(
                "SELECT o.path_token, o.blob_token FROM repo_observations o JOIN records r ON r.id=o.record_id"
                " WHERE o.repo_id=? AND r.lifecycle IN ('approved','stale')", (repo.row_id,))}
            latest_state = None
            if repo.current_snapshot:
                row = conn.execute("SELECT state FROM repo_snapshots WHERE id=?", (repo.current_snapshot,)).fetchone()
                latest_state = row[0] if row else None
        git = self._open_git(repo)
        excl = self._exclusions(repo)
        fmt = repo.object_format
        root = repo.root
        coverage: Counter[str] = Counter()
        reasons: list[str] = []

        # ---- identity: HEAD + dirty-state hash + work-tree path (+ exclusion set)
        head = git.head()
        branch = git.branch()
        status_entries, status_truncated = git.status()
        index_entries, listing_truncated = git.ls_files()
        if status_truncated:
            reasons.append("status_truncated")
        if listing_truncated:
            reasons.append("listing_truncated")
        dirty_items: list[str] = []
        wt_changed: set[str] = set()
        wt_deleted: set[str] = set()
        for st in status_entries:
            raw_path = st.path.rstrip(b"/") if st.kind == "?" else st.path  # untracked directories end in /
            path = scanner.decode_git_path(raw_path)
            if path is None:
                dirty_items.append(f"{st.kind}|invalid|{hashlib.sha256(st.path).hexdigest()}")
                continue
            if excl.excluded(path):
                continue  # never part of identity, never named, never hashed
            if st.kind in ("1", "2"):
                y = st.xy[1:2]
                if y in ("M", "T"):
                    wt_changed.add(path)
                elif y == "D":
                    wt_deleted.add(path)
                dirty_items.append(f"{st.kind}|{st.xy}|{st.head_sha}|{st.index_sha}|{path}")
            elif st.kind == "u":
                dirty_items.append(f"u|{st.xy}|{path}")
            elif st.kind == "?":
                dirty_items.append(f"?|{path}")
        budget_used = 0
        wt_info: dict[str, tuple[str, str | None, int | None, bytes | None]] = {}
        index_modes = {e.path: e.mode for e in index_entries if e.stage == 0}
        for path in sorted(wt_changed):
            if index_modes.get(path.encode("utf-8")) not in _MODE_REGULAR:
                wt_info[path] = ("unreadable", None, None, None)
                dirty_items.append(f"wt|{path}|nonregular")
                continue
            try:
                fd = scanner.open_beneath(root, path)
            except (RepositoryAccessDenied, NotFound, OSError):
                wt_info[path] = ("unreadable", None, None, None)
                dirty_items.append(f"wt|{path}|unreadable")
                continue
            st_info = os.fstat(fd)
            if st_info.st_size > max_file_bytes or budget_used + st_info.st_size > max_total_bytes:
                os.close(fd)
                wt_info[path] = ("too_large", None, int(st_info.st_size), None)
                dirty_items.append(f"wt|{path}|stat|{st_info.st_size}|{st_info.st_mtime_ns}")
                continue
            data, truncated = scanner.read_fd(fd, max_file_bytes)
            if truncated:
                wt_info[path] = ("too_large", None, len(data), None)
                dirty_items.append(f"wt|{path}|stat|{st_info.st_size}|{st_info.st_mtime_ns}")
                continue
            budget_used += len(data)
            blob = scanner.git_blob_id(data, fmt)
            wt_info[path] = ("ok", blob, len(data), data)
            dirty_items.append(f"wt|{path}|{blob}")
        if status_truncated:
            dirty_items.append("status-truncated")
        dirty_hash = hashlib.sha256("\n".join(sorted(dirty_items)).encode("utf-8", "surrogatepass")).hexdigest()
        dirty = bool(dirty_items)
        identity = "\x00".join((repo.row_id, head or "unborn", dirty_hash, root, excl.fingerprint()))
        snapshot_id = "s" + self.p.token("repo-snapshot", identity)[:32]
        if repo.current_snapshot == snapshot_id and latest_state == "complete":
            with self.p.db.read() as conn:
                stored = self._snapshot_payload(conn, repo, snapshot_id)
            if stored is not None:
                return {**self._public_snapshot(stored), "reused": True, "receipt_id": None}

        # ---- inventory (pass 1: the full listing; pass 2: bounded processing)
        present: list[tuple[str, IndexEntry]] = []
        excluded_tokens: set[str] = set()
        seen_unmerged: set[bytes] = set()
        for entry in index_entries:
            if entry.stage != 0:
                if entry.path not in seen_unmerged:
                    seen_unmerged.add(entry.path)
                    coverage["unmerged"] += 1
                continue
            path = scanner.decode_git_path(entry.path)
            if path is None:
                coverage["invalid_paths"] += 1
                continue
            if excl.excluded(path):
                coverage["excluded"] += 1
                excluded_tokens.add(self._path_token(repo.row_id, path))
                continue
            if path in wt_deleted:
                coverage["deleted_in_worktree"] += 1
                continue
            present.append((path, entry))
        inventory_tokens = {self._path_token(repo.row_id, path) for path, _ in present}
        entries: list[_Entry] = []
        stop_reason: str | None = None
        truncated = listing_truncated or status_truncated
        for index, (path, entry) in enumerate(present):
            if index >= max_files:
                truncated = True
                reasons.append("max_files")
                break
            stop_reason = self._stopped(deadline, cancel)
            if stop_reason:
                break
            entries.append(self._make_entry(repo, path, entry, wt_info))
        visited_all = len(entries) == len(present)
        sizes = git.blob_sizes([e.blob for e in entries if e.origin == "index" and e.kind == "file" and e.blob])
        for e in entries:
            if e.origin == "index" and e.kind == "file" and e.blob:
                e.size = sizes.get(e.blob)

        # ---- choose what must be parsed (unchanged blobs reuse their observation)
        deletions_known = visited_all and not listing_truncated and not status_truncated
        deleted_tokens = set(cur_map) - inventory_tokens if deletions_known else set()
        rename_blobs = {cur_map[t][1] for t in deleted_tokens}
        to_read: list[_Entry] = []
        for e in entries:
            if e.kind != "file" or e.blob is None:
                continue
            if e.support == "unsupported":
                e.status = "unsupported"
                continue
            cur = cur_map.get(e.path_token)
            if (cur and cur[1] == e.blob_token) or (e.path_token, e.blob_token) in known_pairs:
                e.status = "known"
                continue
            if e.blob_token in rename_blobs:
                e.status = "rename_candidate"
                continue
            if e.size is None or e.size > max_file_bytes:
                e.status = "too_large"
                continue
            if e.origin == "worktree" and e.data is not None:
                e.status = "to_parse"  # already read (and counted) for the identity hash
                continue
            if budget_used + e.size > max_total_bytes:
                e.status = "budget"
                if "max_total_bytes" not in reasons:
                    reasons.append("max_total_bytes")
                truncated = True
                continue
            budget_used += e.size
            e.status = "to_read"
            to_read.append(e)
        # ---- read (object store, no filters) and parse - outside any transaction
        if stop_reason:
            self._mark_unparsed(entries)
        else:
            stop_reason = self._read_and_parse(git, entries, to_read, deadline, cancel)
        if stop_reason:
            reasons.append(stop_reason)
            deletions_known = False
            deleted_tokens = set()
        state = "partial" if (truncated or stop_reason) else "complete"

        # ---- commit (guarded against concurrent forgetting)
        result = self._commit_snapshot(
            access, repository_id, entries=entries, snapshot_id=snapshot_id, head=head, branch=branch,
            dirty=dirty, state=state, reasons=reasons, truncated=truncated, coverage=coverage,
            deleted_tokens=deleted_tokens, observed_deletion_generation=observed_deletion_generation,
            stop_reason=stop_reason, guard_inputs=self._guard_inputs(repo), excluded_tokens=excluded_tokens,
            deadline=deadline, cancel=cancel)
        return result

    def _make_entry(self, repo: _Repo, path: str, entry: IndexEntry,
                    wt_info: dict[str, tuple[str, str | None, int | None, bytes | None]]) -> _Entry:
        token = self._path_token(repo.row_id, path)
        language, support = scanner.detect_language(path)
        if entry.mode == _MODE_SYMLINK:
            return _Entry(path, token, "symlink", entry.mode, entry.sha, self._blob_token(repo.repository_id, entry.sha),
                          "index", None, "symlink", "unsupported", status="symlink")
        if entry.mode == _MODE_GITLINK:
            return _Entry(path, token, "submodule", entry.mode, entry.sha,
                          self._blob_token(repo.repository_id, entry.sha), "index", None, "submodule",
                          "unsupported", status="submodule")
        if entry.mode not in _MODE_REGULAR:
            return _Entry(path, token, "other", entry.mode, entry.sha, self._blob_token(repo.repository_id, entry.sha),
                          "index", None, language, "unsupported", status="unsupported")
        if path in wt_info:
            state, blob, size, data = wt_info[path]
            if state == "ok" and blob:
                return _Entry(path, token, "file", entry.mode, blob, self._blob_token(repo.repository_id, blob),
                              "worktree", size, language, support, data=data)
            unhashed = self.p.token("repo-unhashed", f"{repo.row_id}\x00{path}\x00{size}")
            return _Entry(path, token, "file", entry.mode, None, unhashed, "worktree", size, language, support,
                          status="too_large" if state == "too_large" else "unreadable")
        return _Entry(path, token, "file", entry.mode, entry.sha, self._blob_token(repo.repository_id, entry.sha),
                      "index", None, language, support)

    def _read_and_parse(self, git: Git, entries: list[_Entry], to_read: list[_Entry], deadline: Deadline,
                        cancel: Any) -> str | None:
        for e in entries:
            if e.status == "to_parse" and e.data is not None:
                stop = self._stopped(deadline, cancel)
                if stop:
                    self._mark_unparsed(entries)
                    return stop
                self._parse_into(e, e.data)
        batch: list[_Entry] = []
        batch_bytes = 0

        def flush() -> None:
            blobs = git.read_blobs([b.blob for b in batch if b.blob], max_total_bytes=batch_bytes)
            for item in batch:
                data = blobs.get(item.blob or "")
                if data is None:
                    item.status = "unreadable"
                else:
                    self._parse_into(item, data)

        for e in to_read:
            stop = self._stopped(deadline, cancel)
            if stop:
                self._mark_unparsed(entries)
                return stop
            batch.append(e)
            batch_bytes += e.size or 0
            if len(batch) >= _PARSE_BATCH_BLOBS or batch_bytes >= _PARSE_BATCH_BYTES:
                flush()
                batch, batch_bytes = [], 0
        if batch:
            stop = self._stopped(deadline, cancel)
            if stop:
                self._mark_unparsed(entries)
                return stop
            flush()
        # The last batch may have used up the deadline: the snapshot is then partial (its commit
        # settles one bounded batch and stops; nothing parsed is lost - it is re-parsed next time).
        return self._stopped(deadline, cancel)

    @staticmethod
    def _mark_unparsed(entries: list[_Entry]) -> None:
        for e in entries:
            if e.status in ("to_read", "to_parse"):
                e.status = "not_parsed_stopped"
                e.data = None

    @staticmethod
    def _parse_into(e: _Entry, data: bytes) -> None:
        outcome = obs.extract(data, e.language, e.support)
        e.status = outcome.status
        e.facts = outcome.facts if outcome.status == "parsed" else None
        e.data = None

    def _commit_snapshot(self, access: AccessContext, repository_id: str, *, entries: list[_Entry],
                         snapshot_id: str, head: str | None, branch: str | None, dirty: bool, state: str,
                         reasons: list[str], truncated: bool, coverage: Counter[str], deleted_tokens: set[str],
                         observed_deletion_generation: int, stop_reason: str | None,
                         guard_inputs: list[tuple[str, str]], excluded_tokens: set[str] | None = None,
                         deadline: Deadline | None = None, cancel: Any = None) -> dict[str, Any]:
        """Settle every entry and record the snapshot, in bounded write transactions.

        Entries are settled in batches (``_COMMIT_BATCH_ENTRIES`` / ``_COMMIT_BATCH_SECONDS``),
        each its own transaction that re-runs the forgetting commit guard and re-reads the
        observation index when anything else wrote meanwhile (a forget can land between
        batches). The deadline and cancellation are checked between batches: a snapshot stopped
        there records what it settled as a ``partial`` snapshot (deletions unknown, so nothing
        is marked deleted; ``last_complete_snapshot`` unchanged) in one short final transaction.
        Observations settled before the stop are reused by the next snapshot.
        """
        counts: Counter[str] = Counter()
        created: list[str] = []
        consumed: set[str] = set()
        settled: list[tuple[_Entry, tuple[Any, ...]]] = []
        known: tuple[Any, ...] | None = None
        seen_generation: int | None = None
        excluded_done = not excluded_tokens
        now = self.ctx.clock()
        index = 0
        stopped: str | None = None
        while True:
            with self.p.db.write() as conn:
                # A forget that landed while this snapshot was reading (or between two of its
                # batches) wins: refuse the derived commit.
                self.ctx.services.forgetting.commit_guard(
                    conn, inputs=guard_inputs, observed_deletion_generation=observed_deletion_generation)
                repo = self._load(conn, access, repository_id)
                if not excluded_done:
                    # Paths excluded since they were observed: their observations go (not just stale).
                    removed = self._purge_excluded(conn, repo, excluded_tokens or set())
                    if removed:
                        counts["observations_excluded_removed"] += removed
                    excluded_done = True
                if known is None or self.p.generation(conn) != seen_generation:
                    known = self._settlement_state(conn, repo, deleted_tokens, consumed)
                cur_map, historical, rename_pool, forgotten_sources = known
                ctx = {"repo": repo, "snapshot_id": snapshot_id, "head": head, "now": now}
                started, done = time.monotonic(), 0
                while index < len(entries) and done < _COMMIT_BATCH_ENTRIES and (
                        done == 0 or time.monotonic() - started < _COMMIT_BATCH_SECONDS):
                    e = entries[index]
                    index += 1
                    done += 1
                    if e.blob is not None and e.blob_token in forgotten_sources:
                        coverage["forgotten_sources"] += 1
                        cur = cur_map.get(e.path_token)
                        if cur and cur[1] != e.blob_token and self._stale(conn, cur[0], "file_modified"):
                            counts["observations_stale"] += 1
                        continue
                    cur = cur_map.get(e.path_token)
                    if e.kind == "file" and e.blob is not None:
                        e.observation_id = self._settle(conn, e, cur, historical, rename_pool, consumed, counts,
                                                        created, ctx)
                    elif cur is not None and self._stale(conn, cur[0], "file_changed"):
                        counts["observations_stale"] += 1
                        counts["modified"] += 1
                    self._count_entry(e, coverage)
                    if e.observation_id and e.status in ("known", "rename_candidate"):
                        e.status = "observed"
                    settled.append((e, self._file_row(snapshot_id, e)))
                if index >= len(entries):
                    return self._finish_snapshot(
                        conn, repo, repository_id, entries=entries, settled=settled, snapshot_id=snapshot_id,
                        head=head, branch=branch, dirty=dirty, state=state, reasons=reasons, truncated=truncated,
                        coverage=coverage, deleted_tokens=deleted_tokens, cur_map=cur_map, consumed=consumed,
                        counts=counts, created=created, now=now, stop_reason=stop_reason)
                seen_generation = self.p.generation(conn)
            stopped = self._stopped(deadline, cancel) if deadline is not None else None
            if stopped:
                break
            self.p.db.yield_to_writers()
        # Stopped between batches: what is left was not settled; deletions are not known.
        for e in entries[index:]:
            e.status = "not_parsed_stopped"
            e.data = None
            e.facts = None
            self._count_entry(e, coverage)
        if stopped not in reasons:
            reasons.append(stopped)
        with self.p.db.write() as conn:
            self.ctx.services.forgetting.commit_guard(
                conn, inputs=guard_inputs, observed_deletion_generation=observed_deletion_generation)
            repo = self._load(conn, access, repository_id)
            return self._finish_snapshot(
                conn, repo, repository_id, entries=entries, settled=settled, snapshot_id=snapshot_id,
                head=head, branch=branch, dirty=dirty, state="partial", reasons=reasons, truncated=truncated,
                coverage=coverage, deleted_tokens=set(), cur_map={}, consumed=consumed, counts=counts,
                created=created, now=now, stop_reason=stopped)

    def _settlement_state(self, conn: sqlite3.Connection, repo: _Repo, deleted_tokens: set[str],
                          consumed: set[str]) -> tuple[dict[str, tuple[str, str]], dict[tuple[str, str], list[str]],
                                                       dict[str, list[str]], set[str]]:
        """The observation index a batch settles against: current observations by path, historical
        ones by (path, blob), the rename pool of deleted paths, and forgotten sources."""
        cur_map = {r[0]: (r[1], r[2]) for r in conn.execute(
            "SELECT path_token, record_id, blob_token FROM repo_observations WHERE repo_id=? AND current=1",
            (repo.row_id,))}
        historical: dict[tuple[str, str], list[str]] = {}
        for r in conn.execute("SELECT path_token, blob_token, record_id FROM repo_observations"
                              " WHERE repo_id=? AND current=0 ORDER BY rowid DESC", (repo.row_id,)):
            historical.setdefault((r[0], r[1]), []).append(r[2])
        rename_pool: dict[str, list[str]] = {}
        for token in sorted(deleted_tokens):
            if token in cur_map and cur_map[token][0] not in consumed:
                rename_pool.setdefault(cur_map[token][1], []).append(cur_map[token][0])
        forgotten_sources = {r[0] for r in conn.execute(
            "SELECT target_token FROM tombstones WHERE target_kind='source'")}
        return cur_map, historical, rename_pool, forgotten_sources

    def _finish_snapshot(self, conn: sqlite3.Connection, repo: _Repo, repository_id: str, *,
                         entries: list[_Entry], settled: list[tuple[_Entry, tuple[Any, ...]]], snapshot_id: str,
                         head: str | None, branch: str | None, dirty: bool, state: str, reasons: list[str],
                         truncated: bool, coverage: Counter[str], deleted_tokens: set[str],
                         cur_map: dict[str, tuple[str, str]], consumed: set[str], counts: Counter[str],
                         created: list[str], now: float, stop_reason: str | None) -> dict[str, Any]:
        """Record the snapshot (inside the caller's write transaction): stale observations of
        deleted paths, the snapshot and file rows, the registration's pointers and the receipt."""
        for token in sorted(deleted_tokens):
            cur = cur_map.get(token)
            if cur is None or cur[0] in consumed:
                continue
            if self._stale(conn, cur[0], "file_deleted"):
                counts["observations_stale"] += 1
                counts["deleted"] += 1
        conn.execute("DELETE FROM repo_snapshots WHERE id=?", (snapshot_id,))
        generation = self.p.bump(conn)
        counts["inventoried"] = len(entries)
        counts["observations_created"] = len(created)
        coverage_view = self._coverage_view(coverage, truncated=truncated, reasons=reasons, state=state)
        payload = {
            "snapshot_id": snapshot_id, "repository_id": repository_id, "state": state, "head": head,
            "branch": branch, "dirty": dirty, "created_at": now, "worktree": repo.root,
            "counts": dict(sorted(counts.items())), "coverage": coverage_view,
        }
        dek, nonce, ct = self.p.seal_json(self.SNAP_TABLE, snapshot_id, {"repo": repo.row_id, "state": state},
                                          payload)
        conn.execute(
            "INSERT INTO repo_snapshots(id, repo_id, created_at, state, index_generation, dek_id, nonce,"
            " ciphertext) VALUES(?,?,?,?,?,?,?,?)",
            (snapshot_id, repo.row_id, now, state, generation, dek, nonce, ct))
        # File rows sealed in an earlier batch are re-sealed if the data key rotated meanwhile.
        current_dek = schema.get_meta(conn, "current_dek_id")
        conn.executemany(
            "INSERT OR REPLACE INTO repo_files(snapshot_id, path_token, blob_token, dek_id, nonce, ciphertext)"
            " VALUES(?,?,?,?,?,?)",
            [row if row[3] == current_dek else self._file_row(snapshot_id, e) for e, row in settled])
        for (old,) in conn.execute(
                "SELECT id FROM repo_snapshots WHERE repo_id=? ORDER BY rowid DESC LIMIT -1 OFFSET ?",
                (repo.row_id, _KEEP_SNAPSHOTS)).fetchall():
            conn.execute("DELETE FROM repo_snapshots WHERE id=?", (old,))
        repo_payload = dict(repo.payload)
        if state == "complete":
            repo_payload["last_complete_snapshot"] = snapshot_id
        repo_payload["latest_snapshot"] = snapshot_id
        self._save_repo(conn, repo.row_id, repo.scope, repo_payload, insert=False, now=now,
                        current_snapshot=snapshot_id)
        receipt = self.p.make_receipt(
            conn, "repository_snapshot", "ok" if state == "complete" else "partial",
            record_ids=tuple(created[:_MAX_RECEIPT_IDS]),
            details={"snapshot_id": snapshot_id, "state": state, "counts": dict(counts),
                     "record_ids_truncated": len(created) > _MAX_RECEIPT_IDS},
            limitations=LIMITATIONS)
        self.p.event(conn, "repository_snapshot", state, stop_reason or "")
        return {**self._public_snapshot(payload), "reused": False, "receipt_id": receipt.receipt_id,
                "generation": receipt.generation}

    def _settle(self, conn: sqlite3.Connection, e: _Entry, cur: tuple[str, str] | None,
                historical: dict[tuple[str, str], list[str]], rename_pool: dict[str, list[str]],
                consumed: set[str], counts: Counter[str], created: list[str], ctx: dict[str, Any]) -> str | None:
        """Bring the observation for one regular file in line with its current blob."""
        if cur is not None and cur[1] == e.blob_token:
            lifecycle = self._lifecycle(conn, cur[0])
            if lifecycle == Lifecycle.APPROVED:
                counts["observations_reused"] += 1
                return cur[0]
            if lifecycle == Lifecycle.STALE and self._revive(conn, cur[0]):
                counts["observations_revived"] += 1
                return cur[0]
            conn.execute("UPDATE repo_observations SET current=0 WHERE record_id=?", (cur[0],))
        elif cur is not None:
            if self._stale(conn, cur[0], "file_modified"):
                counts["observations_stale"] += 1
            counts["modified"] += 1
        if e.support == "unsupported":
            return None  # inventory only; never carries parsed facts
        for record_id in historical.get((e.path_token, e.blob_token), []):
            if self._lifecycle(conn, record_id) == Lifecycle.STALE and self._revive(conn, record_id):
                counts["observations_revived"] += 1
                return record_id
        pool = rename_pool.get(e.blob_token)
        while pool:
            old_id = pool.pop(0)
            old = self.records.get(conn, old_id)
            if old is None or old.lifecycle != Lifecycle.APPROVED:
                continue
            facts = obs.Facts.from_dict(old.extra.get("facts"))
            if facts is None or facts.language != e.language:
                continue  # a rename across languages is re-parsed, never re-labelled
            record = self._create_observation(
                conn, e, facts, ctx, lineage=old.extra.get("lineage_id") or old.id, previous=old.id,
                renamed_from=old.extra.get("path"))
            if record is None:
                counts["suppressed"] += 1
                return None
            created.append(record.id)
            if self._stale(conn, old.id, "file_renamed"):
                counts["observations_stale"] += 1
            consumed.add(old.id)
            counts["renamed"] += 1
            return record.id
        if e.facts is not None:
            record = self._create_observation(conn, e, e.facts, ctx)
            if record is None:
                counts["suppressed"] += 1
                return None
            created.append(record.id)
            return record.id
        if e.status in ("known", "rename_candidate"):
            counts["deferred"] += 1  # state changed concurrently; the next snapshot settles it
        return None

    def _lifecycle(self, conn: sqlite3.Connection, record_id: str) -> Lifecycle | None:
        row = conn.execute("SELECT lifecycle FROM records WHERE id=?", (record_id,)).fetchone()
        return Lifecycle(row[0]) if row else None

    def _stale(self, conn: sqlite3.Connection, record_id: str, reason: str) -> bool:
        conn.execute("UPDATE repo_observations SET current=0 WHERE record_id=?", (record_id,))
        record = self.records.get(conn, record_id)
        if record is None or record.lifecycle != Lifecycle.APPROVED:
            return False
        self.ctx.services.core.transition_internal(conn, record, Lifecycle.STALE, change="stale",
                                                   actor=Actor.SYSTEM, reason=reason)
        return True

    def _revive(self, conn: sqlite3.Connection, record_id: str) -> bool:
        record = self.records.get(conn, record_id)
        if record is None or record.lifecycle != Lifecycle.STALE:
            return False
        if self.ctx.services.forgetting.blocked_reason(conn, record) is not None:
            return False
        self.ctx.services.core.transition_internal(conn, record, Lifecycle.APPROVED, change="reconfirmed",
                                                   actor=Actor.SYSTEM, reason="blob_present_again")
        conn.execute("UPDATE repo_observations SET current=1 WHERE record_id=?", (record_id,))
        return True

    def _create_observation(self, conn: sqlite3.Connection, e: _Entry, facts: obs.Facts, ctx: dict[str, Any], *,
                            lineage: str | None = None, previous: str | None = None,
                            renamed_from: str | None = None) -> MemoryRecord | None:
        repo: _Repo = ctx["repo"]
        now = ctx["now"]
        rendered = obs.render(facts, e.path, origin=e.origin)
        record_id = new_id("m")
        source = SourceRef(
            kind=SourceKind.BLOB_RANGE, ref=f"{repo.repository_id}:{e.blob}", actor=Actor.TOOL,
            locator={"path_token": e.path_token, "commit": ctx["head"], "origin": e.origin,
                     "snapshot": ctx["snapshot_id"]},
            observed_at=now, extraction_version=facts.extraction_version,
        )
        extra: dict[str, Any] = {
            "repository_id": repo.repository_id, "path": e.path, "blob": e.blob, "origin": e.origin,
            "language": facts.language, "support": e.support, "extraction": facts.extraction,
            "facts": facts.to_dict(), "lineage_id": lineage or record_id, "snapshot_id": ctx["snapshot_id"],
            "commit": ctx["head"],
        }
        if previous:
            extra["previous_observation"] = previous
        if renamed_from:
            extra["renamed_from"] = renamed_from
        if rendered.flags:
            extra["flags"] = list(rendered.flags)
        if rendered.redactions:
            extra["redactions"] = list(rendered.redactions)
        record = MemoryRecord(
            id=record_id, revision=1, kind=MemoryKind.REPOSITORY_OBSERVATION, lifecycle=Lifecycle.APPROVED,
            scope=repo.scope, title=rendered.title, content=rendered.content, tags=rendered.tags,
            basis=StatementBasis.OBSERVED,
            confidence=Confidence(None, False, "parsed" if facts.extraction == "ast" else "heuristic"),
            sources=(source,), validity=Validity(source_hashes=((e.path, e.blob or ""),)),
            retention=Retention("durable"), links=Links(), created_at=now, updated_at=now,
            event_time=now, ingested_at=now, reason="", extra=extra,
        )
        if self.ctx.services.forgetting.blocked_reason(conn, record) is not None:
            return None
        self.ctx.services.core.write_internal(conn, record, change="observed", actor=Actor.TOOL, expected=None)
        conn.execute("INSERT INTO repo_observations(record_id, repo_id, path_token, blob_token, current)"
                     " VALUES(?,?,?,?,1)", (record.id, repo.row_id, e.path_token, e.blob_token))
        return record

    def _file_row(self, snapshot_id: str, e: _Entry) -> tuple[Any, ...]:
        payload = {"path": e.path, "blob": e.blob, "origin": e.origin, "kind": e.kind, "mode": e.mode,
                   "size": e.size, "language": e.language, "support": e.support, "status": e.status,
                   "observation_id": e.observation_id}
        dek, nonce, ct = self.p.seal_json(self.FILE_TABLE, f"{snapshot_id}/{e.path_token}",
                                          {"blob": e.blob_token}, payload)
        return (snapshot_id, e.path_token, e.blob_token, dek, nonce, ct)

    @staticmethod
    def _count_entry(e: _Entry, coverage: Counter[str]) -> None:
        mapping = {"symlink": "symlinks", "submodule": "submodules", "unsupported": "unsupported",
                   "too_large": "skipped_size", "budget": "not_parsed_budget", "parse_error": "parse_errors",
                   "no_facts": "no_facts", "unreadable": "unreadable", "not_parsed_stopped": "not_parsed_stopped"}
        if e.status in mapping:
            coverage[mapping[e.status]] += 1
        if e.status == "parsed":
            coverage["parsed"] += 1
            if e.support == "heuristic":
                coverage["heuristic_files"] += 1
        if e.kind == "file":
            coverage["regular_files"] += 1

    @staticmethod
    def _coverage_view(coverage: Counter[str], *, truncated: bool, reasons: list[str], state: str) -> dict[str, Any]:
        keys = ("excluded", "skipped_size", "unsupported", "symlinks", "submodules", "parse_errors", "no_facts",
                "invalid_paths", "unmerged", "deleted_in_worktree", "not_parsed_budget", "not_parsed_stopped",
                "unreadable", "forgotten_sources", "parsed", "heuristic_files", "regular_files")
        view: dict[str, Any] = {k: int(coverage.get(k, 0)) for k in keys}
        view.update({"truncated": bool(truncated), "partial_reasons": list(dict.fromkeys(reasons)),
                     "complete": state == "complete", "notes": list(LIMITATIONS)})
        return view

    @staticmethod
    def _public_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
        return {k: payload.get(k) for k in ("snapshot_id", "repository_id", "state", "head", "branch", "dirty",
                                             "created_at", "counts", "coverage")}

    def _snapshot_payload(self, conn: sqlite3.Connection, repo: _Repo, snapshot_id: str) -> dict[str, Any] | None:
        row = conn.execute("SELECT * FROM repo_snapshots WHERE id=? AND repo_id=?",
                           (snapshot_id, repo.row_id)).fetchone()
        if row is None:
            return None
        return self.p.open_json(self.SNAP_TABLE, row["id"], {"repo": repo.row_id, "state": row["state"]},
                                row["dek_id"], row["nonce"], row["ciphertext"])

    def _file_payloads(self, conn: sqlite3.Connection, snapshot_id: str) -> list[dict[str, Any]]:
        out = []
        for row in conn.execute("SELECT * FROM repo_files WHERE snapshot_id=?", (snapshot_id,)):
            out.append(self.p.open_json(self.FILE_TABLE, f"{snapshot_id}/{row['path_token']}",
                                        {"blob": row["blob_token"]}, row["dek_id"], row["nonce"], row["ciphertext"]))
        return out

    # ------------------------------------------------------------------ reads
    def observations(self, access: AccessContext, repository_id: str, *, path: str | None = None,
                     current_only: bool = True) -> list[MemoryRecord]:
        policy.require(access, Operation.READ)
        if path is not None:
            path = scanner.check_repo_path(path)
        with self.p.db.read() as conn:
            repo = self._load(conn, access, repository_id)
            if path is not None and self._exclusions(repo).excluded(path):
                raise RepositoryAccessDenied("this path is excluded from repository memory")
            return self._observation_records(conn, access, repo, current_only=current_only,
                                             path_token=self._path_token(repo.row_id, path) if path else None)

    def _observation_records(self, conn: sqlite3.Connection, access: AccessContext, repo: _Repo, *,
                             current_only: bool, path_token: str | None = None) -> list[MemoryRecord]:
        sql = "SELECT record_id FROM repo_observations WHERE repo_id=?"
        params: list[Any] = [repo.row_id]
        if current_only:
            sql += " AND current=1"
        if path_token is not None:
            sql += " AND path_token=?"
            params.append(path_token)
        ids = [r[0] for r in conn.execute(sql, params)]
        found: list[MemoryRecord] = []
        for chunk in _chunks(ids):
            found += self.records.authorized(conn, access.grants, ids=chunk,
                                             lifecycles=(Lifecycle.APPROVED,) if current_only else None)
        excl = self._exclusions(repo)
        found = [r for r in found if not _excluded_observation(excl, r)]  # never named, current or stale
        found = self.ctx.services.core.present(conn, access, found)
        return sorted(found, key=lambda r: (str(r.extra.get("path") or ""), r.created_at, r.id))

    def history(self, access: AccessContext, repository_id: str, *, max_commits: int = 50,
                path: str | None = None) -> list[dict[str, Any]]:
        policy.require(access, Operation.READ)
        check_int(max_commits, "max_commits", lo=1, hi=_MAX_HISTORY)
        if path is not None:
            path = scanner.check_repo_path(path)
        with self.p.db.read() as conn:
            repo = self._load(conn, access, repository_id)
        excl = self._exclusions(repo)
        if path is not None and excl.excluded(path):
            raise RepositoryAccessDenied("this path is excluded from repository memory")
        git = self._open_git(repo)
        if git.head() is None:
            return []
        entries, _ = git.log(max_commits=max_commits, path=path)
        out = []
        for entry in entries:
            visible: list[str] = []
            omitted = 0
            for raw in entry.paths:
                decoded = scanner.decode_git_path(raw)
                if decoded is None or excl.excluded(decoded):
                    omitted += 1
                else:
                    visible.append(decoded)
            subject = entry.subject.decode("utf-8", "replace")
            subject = safety.neutralize_markup(safety.redact_secrets(subject)[0])[:300]
            out.append({
                "commit": entry.commit, "author_time": entry.author_time, "subject": subject,
                "paths": visible[:_MAX_HISTORY_PATHS],
                "paths_truncated": entry.paths_truncated or len(visible) > _MAX_HISTORY_PATHS,
                "omitted_paths": omitted,
            })
        return out

    def read_file(self, access: AccessContext, repository_id: str, path: str, *, max_bytes: int = 256 * 1024,
                  commit: str | None = None) -> str:
        """Guarded direct read of a tracked file (or a historical blob). Secret-redacted text."""
        policy.require(access, Operation.READ)
        check_int(max_bytes, "max_bytes", lo=1, hi=_MAX_READ_BYTES)
        path = scanner.check_repo_path(path)
        with self.p.db.read() as conn:
            repo = self._load(conn, access, repository_id)
        if self._exclusions(repo).excluded(path):
            raise RepositoryAccessDenied("this path is excluded from repository memory")
        git = self._open_git(repo)
        if commit is None:
            entry = git.ls_files_entry(path)
            if entry is None:
                raise NotFound("file not found")
            if entry.mode == _MODE_SYMLINK:
                raise RepositoryAccessDenied("symbolic links are repository inventory entries only")
            if entry.mode not in _MODE_REGULAR:
                raise NotFound("file not found")
            data, truncated = scanner.read_beneath(repo.root, path, max_bytes)
        else:
            if not isinstance(commit, str):
                raise ValidationError("commit must be a revision string")
            resolved = git.resolve_commit(commit)
            if resolved is None:
                raise NotFound("commit not found")
            item = git.ls_tree_entry(resolved, path)
            if item is None:
                raise NotFound("file not found at that commit")
            mode, kind, sha = item
            if mode == _MODE_SYMLINK:
                raise RepositoryAccessDenied("symbolic links are repository inventory entries only")
            if kind != "blob" or mode not in _MODE_REGULAR:
                raise NotFound("file not found at that commit")
            size = git.blob_size(sha)
            if size is not None and size > max_bytes:
                raise ValidationError("the file exceeds max_bytes", details={"max_bytes": max_bytes})
            data, truncated = git.read_blob(sha, max_bytes=max_bytes)
        if truncated:
            raise ValidationError("the file exceeds max_bytes", details={"max_bytes": max_bytes})
        if b"\x00" in data:
            raise ValidationError("binary files are not returned as text")
        return safety.redact_secrets(data.decode("utf-8", "replace"))[0]

    def status(self, access: AccessContext, repository_id: str) -> dict[str, Any]:
        policy.require(access, Operation.READ)
        with self.p.db.read() as conn:
            repo = self._load(conn, access, repository_id)
            latest = self._snapshot_payload(conn, repo, repo.current_snapshot) if repo.current_snapshot else None
            clause, params = self._records_visible_clause(access.grants, "r")
            counts = {"current": 0, "historical": 0}
            for current, count in conn.execute(
                    "SELECT o.current, COUNT(*) FROM repo_observations o JOIN records r ON r.id=o.record_id"
                    f" WHERE o.repo_id=? AND {clause} GROUP BY o.current", [repo.row_id, *params]):
                counts["current" if current else "historical"] += int(count)
        try:
            self._open_git(repo)
            availability = "available"
        except RepositoryAccessDenied:
            availability = "not_allowed"
        except (RepositoryError, MemoryEngineError):
            availability = "unavailable"
        excl = self._exclusions(repo)
        return {
            "repository_id": repo.repository_id, "scope": repo.scope.as_dict(),
            "registered_at": repo.registered_at, "initial_commit": repo.initial_commit,
            "object_format": repo.object_format, "root_availability": availability,
            "latest_snapshot": self._public_snapshot(latest) if latest else None,
            "last_complete_snapshot": repo.payload.get("last_complete_snapshot"),
            "observations": counts,
            "exclusions": {"default": len(scanner.DEFAULT_EXCLUSIONS),
                           "extra": len(excl.patterns) - len(scanner.DEFAULT_EXCLUSIONS)},
            "limitations": list(LIMITATIONS),
        }

    # ------------------------------------------------------------------ exclusions on read paths
    def excluded_observations(self, conn: sqlite3.Connection, records: Iterable[MemoryRecord]) -> set[str]:
        """Ids of repository observations whose path (or rename origin) the *current* exclusion
        set - the registration's plus the host's - covers. Read paths (context, search, listing)
        drop them: an exclusion added after ingest must hide what was already observed."""
        cache: dict[str, scanner.Exclusions | None] = {}
        hidden: set[str] = set()
        for record in records:
            if record.kind != MemoryKind.REPOSITORY_OBSERVATION or not isinstance(record.extra, dict):
                continue
            repository_id = record.extra.get("repository_id")
            if not isinstance(repository_id, str) or not ID_PATTERN.fullmatch(repository_id):
                continue
            if repository_id not in cache:
                row = conn.execute("SELECT * FROM repositories WHERE id=?",
                                   (self._row_id(repository_id),)).fetchone()
                cache[repository_id] = self._exclusions(self._decode(row)) if row is not None else None
            excl = cache[repository_id]
            if excl is not None and _excluded_observation(excl, record):
                hidden.add(record.id)
        return hidden

    def _purge_excluded(self, conn: sqlite3.Connection, repo: _Repo, tokens: set[str]) -> int:
        """Remove observations (current and historical) of paths that are now excluded."""
        removed = 0
        for chunk in _chunks(sorted(tokens)):
            ids = [r[0] for r in conn.execute(
                f"SELECT record_id FROM repo_observations WHERE repo_id=? AND path_token IN"
                f" ({','.join('?' * len(chunk))})", [repo.row_id, *chunk])]
            for record_id in ids:
                conn.execute("DELETE FROM repo_observations WHERE record_id=?", (record_id,))
                removed += self.records.purge(conn, record_id).get("memories", 0)
        return removed

    # ------------------------------------------------------------------ evidence + forgetting
    def verify_source(self, conn: sqlite3.Connection, access: AccessContext, source: SourceRef) -> bool | None:
        """COMMIT / BLOB_RANGE ``<repository_id>:<object id>``: True when known in stored snapshots of a
        registered, authorized repository; False when the repository is but the object is not; else None."""
        if source.kind not in (SourceKind.COMMIT, SourceKind.BLOB_RANGE):
            return None
        repository_id, sep, ref = source.ref.partition(":")
        if not sep or not ID_PATTERN.fullmatch(repository_id):
            return None
        row_id = self._row_id(repository_id)
        if not self._visible_row(conn, access.grants, row_id):
            return None  # unregistered and unauthorized look the same
        ref = ref.lower()
        if not _HEX.fullmatch(ref):
            return False
        if source.kind == SourceKind.BLOB_RANGE:
            token = self._blob_token(repository_id, ref)
            if conn.execute("SELECT 1 FROM repo_observations WHERE repo_id=? AND blob_token=? LIMIT 1",
                            (row_id, token)).fetchone():
                return True
            return conn.execute(
                "SELECT 1 FROM repo_files f JOIN repo_snapshots s ON s.id=f.snapshot_id"
                " WHERE s.repo_id=? AND f.blob_token=? LIMIT 1", (row_id, token)).fetchone() is not None
        row = conn.execute("SELECT * FROM repositories WHERE id=?", (row_id,)).fetchone()
        repo = self._decode(row)
        if repo.initial_commit == ref:
            return True
        for snap in conn.execute("SELECT id, state, dek_id, nonce, ciphertext FROM repo_snapshots WHERE repo_id=?",
                                 (row_id,)).fetchall():
            payload = self.p.open_json(self.SNAP_TABLE, snap["id"], {"repo": row_id, "state": snap["state"]},
                                       snap["dek_id"], snap["nonce"], snap["ciphertext"])
            if payload.get("head") == ref:
                return True
        return False

    def reencrypt(self, conn: sqlite3.Connection, old_dek_ids: frozenset[str], limit: int) -> int:
        """Data-key rotation hook (``admin.rotate_data_key``): re-seal registrations, snapshots
        and file inventory rows still under a retiring DEK (same AAD as when sealed)."""
        from ..admin import reencrypt_table

        done = reencrypt_table(conn, self.p, self.REPO_TABLE, key_columns=("id",), row_id=lambda r: r["id"],
                               fields=lambda r: {"scope": r["scope_token"]}, old_dek_ids=old_dek_ids, limit=limit)
        done += reencrypt_table(conn, self.p, self.SNAP_TABLE, key_columns=("id",), row_id=lambda r: r["id"],
                                fields=lambda r: {"repo": r["repo_id"], "state": r["state"]},
                                old_dek_ids=old_dek_ids, limit=limit - done)
        done += reencrypt_table(conn, self.p, self.FILE_TABLE, key_columns=("snapshot_id", "path_token"),
                                row_id=lambda r: f"{r['snapshot_id']}/{r['path_token']}",
                                fields=lambda r: {"blob": r["blob_token"]}, old_dek_ids=old_dek_ids,
                                limit=limit - done)
        return done

    def hidden_registrations_for_scope(self, conn: sqlite3.Connection, access: AccessContext, dim: str,
                                       value_token: str) -> int:
        """Registrations carrying ``dim=value`` that ``access`` may not see (for the forgetting
        service's admin check on broad scope targets; a count for trusted callers only)."""
        clause, params = self._visible_clause(access.grants, "r")
        return int(conn.execute(
            "SELECT COUNT(*) FROM repo_scopes x JOIN repositories r ON r.id=x.repo_id"
            f" WHERE x.dim=? AND x.value_token=? AND NOT ({clause})", [dim, value_token, *params]).fetchone()[0])

    def purge(self, conn: sqlite3.Connection, target_kind: str, target_token: str,
              forget_policy: Any = None, *, access: AccessContext | None = None) -> dict[str, int]:
        """Remove repository rows for a forget target, from the token alone (also on ledger replay).

        Observation records are canonical records: the forgetting service purges them through
        their scopes/sources; their lineage-index rows cascade with them. With a non-admin
        ``access`` (live forgets), reported counts cover only registrations the caller may see;
        everything matching the target is deleted either way.
        """
        reporter = None if access is None or Operation.ADMIN in access.operations else access.grants
        if target_kind == "profile":
            repo_ids = [r[0] for r in conn.execute("SELECT id FROM repositories")]
        elif target_kind.startswith("scope:"):
            dim = target_kind.split(":", 1)[1]
            repo_ids = [r[0] for r in conn.execute(
                "SELECT repo_id FROM repo_scopes WHERE dim=? AND value_token=?", (dim, target_token))]
        elif target_kind == "source":
            if reporter is None:
                shown = None
            else:
                clause, params = self._visible_clause(reporter, "r")
                shown = conn.execute(
                    "SELECT COUNT(*) FROM repo_files f JOIN repo_snapshots sn ON sn.id=f.snapshot_id"
                    f" JOIN repositories r ON r.id=sn.repo_id WHERE f.blob_token=? AND {clause}",
                    [target_token, *params]).fetchone()[0]
            files = conn.execute("DELETE FROM repo_files WHERE blob_token=?", (target_token,)).rowcount
            files = files if shown is None else min(files, int(shown))
            return {"repository_files": files} if files else {}
        else:
            return {}
        visible = set(repo_ids)
        if reporter is not None and repo_ids:
            visible = {r for r in repo_ids if self._visible_row(conn, reporter, r)}
        counts: Counter[str] = Counter()
        for repo_id in repo_ids:
            files = conn.execute(
                "SELECT COUNT(*) FROM repo_files WHERE snapshot_id IN (SELECT id FROM repo_snapshots WHERE repo_id=?)",
                (repo_id,)).fetchone()[0]
            snapshots = conn.execute("DELETE FROM repo_snapshots WHERE repo_id=?", (repo_id,)).rowcount
            conn.execute("DELETE FROM repo_observations WHERE repo_id=?", (repo_id,))
            conn.execute("DELETE FROM repo_scopes WHERE repo_id=?", (repo_id,))
            removed = conn.execute("DELETE FROM repositories WHERE id=?", (repo_id,)).rowcount
            if repo_id in visible:
                counts["repository_files"] += files
                counts["repository_snapshots"] += snapshots
                counts["repositories"] += removed
        with self._locks_guard:
            for repo_id in repo_ids:
                self._locks.pop(repo_id, None)
        return {k: v for k, v in counts.items() if v}

    # ------------------------------------------------------------------ interchange
    def export_interchange(self, access: AccessContext, repository_id: str) -> dict[str, Any]:
        policy.require(access, Operation.EXPORT)
        with self.p.db.read() as conn:
            repo = self._load(conn, access, repository_id)
            snapshot = self._snapshot_payload(conn, repo, repo.current_snapshot) if repo.current_snapshot else None
            files = self._file_payloads(conn, repo.current_snapshot) if snapshot else []
            current = self._observation_records(conn, access, repo, current_only=True)
        excl = self._exclusions(repo)
        records: list[dict[str, Any]] = [{"type": "repository", "repository_id": repo.repository_id,
                                          "object_format": repo.object_format,
                                          "initial_commit": repo.initial_commit or None}]
        if snapshot:
            records.append({"type": "snapshot", "snapshot_id": snapshot["snapshot_id"], "state": snapshot["state"],
                            "head": snapshot.get("head"), "dirty": bool(snapshot.get("dirty")),
                            "created_at": snapshot.get("created_at")})
        for item in sorted(files, key=lambda f: f["path"]):
            if item.get("kind") != "file" or not item.get("blob") or excl.excluded(item["path"]):
                continue
            record = {"type": "file", "path": item["path"], "blob": item["blob"], "size": item.get("size"),
                      "support": item.get("support") or "unsupported"}
            if item.get("language"):
                record["language"] = item["language"]
            records.append(record)
        for record in current:
            path, blob = record.extra.get("path"), record.extra.get("blob")
            if not path or not blob or excl.excluded(path):
                continue
            facts = obs.Facts.from_dict(record.extra.get("facts"))
            extraction = facts.extraction if facts else "tool"
            if facts:
                for symbol in facts.symbols:
                    records.append({"type": "symbol", "path": path, "blob": blob, "name": symbol.name,
                                    "symbol_kind": symbol.kind, "line": symbol.line, "extraction": extraction})
                for imported in facts.imports:
                    item = {"type": "import", "path": path, "blob": blob, "module": imported.module,
                            "extraction": extraction}
                    if imported.names:
                        item["names"] = list(imported.names)
                    records.append(item)
            records.append({"type": "observation", "path": path, "blob": blob, "text": record.content,
                            "extraction": extraction, "language": record.extra.get("language") or "unknown"})
        from .. import __version__

        document = ix.new_document(
            repository_id=repo.repository_id, hash_algorithm=repo.object_format,
            producer={"name": "locus-memory", "version": __version__, "kind": "observer"},
            records=records, generated_at=self.ctx.clock())
        return ix.validate_document(document, exclusions=excl)

    def import_interchange(self, access: AccessContext, document: Any) -> Receipt:
        """Import an untrusted interchange document. Observations and summaries become *candidates*."""
        policy.require(access, Operation.PROPOSE)
        raw = ix.load_document(document)
        repository_id = raw.get("repository_id")
        if not isinstance(repository_id, str) or not ID_PATTERN.fullmatch(repository_id):
            raise InterchangeInvalid("interchange document rejected: repository_id is invalid")
        with self.p.db.read() as conn:
            repo = self._load(conn, access, repository_id)
        doc = ix.validate_document(raw, exclusions=self._exclusions(repo))
        if doc["hash_algorithm"] != repo.object_format:
            raise InterchangeInvalid("interchange document rejected: hash algorithm does not match the repository")
        producer = doc["producer"]
        counts: Counter[str] = Counter()
        created: list[str] = []
        with self.p.db.write() as conn:
            repo = self._load(conn, access, repository_id)
            now = self.ctx.clock()
            for record in doc["records"]:
                kind = record["type"]
                if kind == "repository":
                    if record.get("initial_commit") and repo.initial_commit and \
                            record["initial_commit"] != repo.initial_commit:
                        raise InterchangeInvalid("interchange document rejected: it describes a different repository")
                    continue
                if kind == "snapshot":
                    counts["snapshots_described"] += 1
                    continue
                if kind in ("file", "symbol", "import"):
                    known = self._pair_known(conn, repo, record["path"], record["blob"])
                    counts[f"{kind}s_{'verified' if known else 'unverified'}"] += 1
                    continue
                if kind == "observation":
                    pairs = [(record["path"], record["blob"])]
                    made = self._import_candidate(
                        conn, access, repo, kind=MemoryKind.REPOSITORY_OBSERVATION,
                        basis=StatementBasis.SOURCE_ATTRIBUTED, text=record["text"], title=None, pairs=pairs,
                        producer=producer, model=None, now=now, counts=counts)
                else:  # summary
                    made = self._import_candidate(
                        conn, access, repo, kind=MemoryKind.SUMMARY, basis=StatementBasis.MODEL_INTERPRETATION,
                        text=record["text"], title=record.get("title"),
                        pairs=[(p, b) for p, b in record["source_hashes"]], producer=producer,
                        model=record["model"], now=now, counts=counts, summary_producer=record["producer"])
                if made:
                    created.append(made)
            if created:
                self.p.bump(conn)
            receipt = self.p.make_receipt(
                conn, "repository_import", "ok" if created else "noop",
                record_ids=tuple(created[:_MAX_RECEIPT_IDS]),
                details={"repository_id": repository_id, "candidates_created": len(created),
                         "counts": dict(sorted(counts.items())), "producer": producer.get("name"),
                         "record_ids_truncated": len(created) > _MAX_RECEIPT_IDS},
                limitations=(
                    "imported observations and summaries are unapproved candidates; review is required",
                    "file, symbol and import records are verified against stored snapshots but not stored",
                    "summaries are model output (basis model_interpretation); confidence is unknown",
                ))
            self.p.event(conn, "repository_import", "ok" if created else "noop")
        return receipt

    def import_from_provider(self, access: AccessContext, provider: Any, repository_id: str, *,
                             since_snapshot: str | None = None) -> Receipt:
        """Pull a document from an optional deep producer and import it (as untrusted data)."""
        if not isinstance(provider, ix.RepositoryIntelligenceProvider):
            raise ValidationError("provider must implement RepositoryIntelligenceProvider")
        check_id(repository_id, "repository_id")
        try:
            provider.describe()
            document = provider.export(repository_id, since_snapshot)
        except MemoryEngineError:
            raise
        except Exception as exc:  # provider failures never leak their message (it may hold content)
            raise ProviderError("the repository intelligence provider failed") from exc
        raw = ix.load_document(document)
        if raw.get("repository_id") != repository_id:
            raise InterchangeInvalid("interchange document rejected: it describes a different repository")
        return self.import_interchange(access, raw)

    def _pair_known(self, conn: sqlite3.Connection, repo: _Repo, path: str, blob: str) -> bool:
        path_token = self._path_token(repo.row_id, path)
        blob_token = self._blob_token(repo.repository_id, blob)
        if conn.execute("SELECT 1 FROM repo_observations WHERE repo_id=? AND path_token=? AND blob_token=?"
                        " LIMIT 1", (repo.row_id, path_token, blob_token)).fetchone():
            return True
        return conn.execute(
            "SELECT 1 FROM repo_files f JOIN repo_snapshots s ON s.id=f.snapshot_id"
            " WHERE s.repo_id=? AND f.path_token=? AND f.blob_token=? LIMIT 1",
            (repo.row_id, path_token, blob_token)).fetchone() is not None

    def _import_candidate(self, conn: sqlite3.Connection, access: AccessContext, repo: _Repo, *,
                          kind: MemoryKind, basis: StatementBasis, text: str, title: str | None,
                          pairs: list[tuple[str, str]], producer: dict[str, Any], model: str | None, now: float,
                          counts: Counter[str], summary_producer: str | None = None) -> str | None:
        label = "summaries" if kind == MemoryKind.SUMMARY else "observations"
        if not all(self._pair_known(conn, repo, path, blob) for path, blob in pairs):
            counts[f"{label}_rejected_unverified"] += 1
            return None
        scan = safety.scan(text)
        if scan.sensitive:
            counts[f"{label}_rejected_sensitive"] += 1
            return None
        text, redactions = safety.redact_secrets(text)
        text = safety.neutralize_markup(text)
        shown_title = safety.neutralize_markup(safety.redact_secrets(title or text[:60])[0])[:160]
        cited: dict[str, SourceRef] = {}
        for path, blob in pairs:  # one citation per blob (identical blobs share a source identity)
            cited.setdefault(blob, SourceRef(
                kind=SourceKind.BLOB_RANGE, ref=f"{repo.repository_id}:{blob}", actor=Actor.PROVIDER,
                locator={"path_token": self._path_token(repo.row_id, path)}, observed_at=now,
                extraction_version=_INTERCHANGE_LABEL))
        sources = tuple(cited.values())
        extra: dict[str, Any] = {
            "proposer": f"interchange:{producer.get('name')}", "producer": producer.get("name"),
            "producer_kind": producer.get("kind"), "producer_version": producer.get("version"),
            "imported_via": _INTERCHANGE_LABEL, "repository_id": repo.repository_id,
        }
        if model:
            extra["model"] = model
        if summary_producer:
            extra["summary_producer"] = summary_producer
        if scan.injection:
            extra["flags"] = ["instruction_like"]
        if redactions:
            extra["redactions"] = list(redactions)
        record = MemoryRecord(
            id=new_id("m"), revision=1, kind=kind, lifecycle=Lifecycle.CANDIDATE, scope=repo.scope,
            title=shown_title, content=text, tags=("repository", "imported"), basis=basis,
            confidence=Confidence(None, False, "model_uncalibrated" if model else "unknown"),
            sources=sources, validity=Validity(source_hashes=tuple(pairs)),
            retention=Retention("durable", now + self.ctx.config.candidate_ttl_seconds, False),
            links=Links(), created_at=now, updated_at=now, event_time=None, ingested_at=now,
            reason=f"imported from {producer.get('name')}"[:2000], extra=extra,
        )
        if self.ctx.services.forgetting.blocked_reason(conn, record) is not None:
            counts[f"{label}_suppressed"] += 1
            return None
        duplicate = conn.execute(
            "SELECT 1 FROM records WHERE content_token=? AND scope_token=? AND lifecycle IN ('candidate','approved')"
            " LIMIT 1", (self.records.content_token(record.content), self.records.scope_token(record.scope)),
        ).fetchone()
        if duplicate is not None:
            counts[f"{label}_duplicates"] += 1
            return None
        self.ctx.services.core.write_internal(conn, record, change="proposed", actor=access.actor, expected=None)
        counts[f"{label}_imported_as_candidates"] += 1
        return record.id
