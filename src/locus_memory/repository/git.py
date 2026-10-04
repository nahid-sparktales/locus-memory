"""Hardened, bounded, read-only git invocation for repository memory.

Every call made through :class:`Git`:

* runs the git executable from an argv list (never a shell) with ``cwd`` = the
  registered work-tree root;
* gets a scrubbed environment built from scratch - no ``GIT_DIR`` /
  ``GIT_WORK_TREE`` / ``GIT_INDEX_FILE`` / ``GIT_EXEC_PATH`` / trace / config
  injection is inherited - with ``GIT_TERMINAL_PROMPT=0``,
  ``GIT_CONFIG_NOSYSTEM=1``, ``GIT_CONFIG_GLOBAL=/dev/null``,
  ``GIT_OPTIONAL_LOCKS=0`` (read commands never rewrite the index), ``LC_ALL=C``,
  literal pathspecs, no replace objects and a discovery ceiling at the root's parent;
* passes command-line configuration that disables every program a repository's own
  configuration could make git run during read-only commands: fsmonitor hooks,
  hooks, external diff, pager, credential helpers, transports, signature
  verification - plus per-repository neutralization of *filter drivers*
  (``filter.<name>.clean/smudge/process``), which ``git status`` would otherwise
  execute for stat-dirty files;
* is bounded in time (default 10 s; the whole process group is killed) and in
  output bytes (output beyond the bound is dropped and the result is flagged
  ``truncated`` - never silently cut).

Only plumbing/read commands are used. Nothing here fetches, pulls, clones, checks
out, writes the index or touches a remote. Errors are typed and never carry git's
own output, which may contain paths.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass

from ..errors import GitCommandError, GitTimeout, RepositoryError

DEFAULT_TIMEOUT_S = 10.0
DEFAULT_MAX_OUTPUT = 32 * 1024 * 1024
_MAX_STDERR = 16 * 1024
_MAX_FILTER_DRIVERS = 64

# Command-line configuration applied to every invocation (it overrides repository config).
SAFE_CONFIG: tuple[tuple[str, str], ...] = (
    ("core.fsmonitor", "false"),
    ("core.hooksPath", "/dev/null"),
    ("diff.external", ""),
    ("core.pager", "cat"),
    ("protocol.allow", "never"),
    ("credential.helper", ""),
    ("core.attributesFile", "/dev/null"),
    ("core.excludesFile", "/dev/null"),
    ("core.untrackedCache", "false"),
    ("core.sshCommand", ""),
    ("log.showSignature", "false"),
    ("i18n.logOutputEncoding", "UTF-8"),
    ("color.ui", "false"),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
)

_HEX = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REV = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/~^-]{0,199}")  # first char alnum: never an option


def _base_argv() -> list[str]:
    argv: list[str] = []
    for key, value in SAFE_CONFIG:
        argv += ["-c", f"{key}={value}"]
    argv.append("--no-pager")
    return argv


@dataclass(frozen=True)
class GitResult:
    stdout: bytes
    returncode: int
    truncated: bool
    stderr_class: str = ""  # content-free classification of stderr


@dataclass(frozen=True)
class IndexEntry:
    mode: str
    sha: str
    stage: int
    path: bytes


@dataclass(frozen=True)
class StatusEntry:
    kind: str  # "1" ordinary, "2" rename/copy, "u" unmerged, "?" untracked, "!" ignored
    xy: str
    path: bytes
    head_sha: str = ""
    index_sha: str = ""


@dataclass(frozen=True)
class LogEntry:
    commit: str
    author_time: int
    subject: bytes
    paths: tuple[bytes, ...]
    paths_truncated: bool = False


def _classify_stderr(err: bytes) -> str:
    text = err.decode("utf-8", "replace").lower()
    if "not a git repository" in text:
        return "not_a_repository"
    if "dubious ownership" in text or "safe.directory" in text:
        return "unsafe_ownership"
    if "bad object" in text or "not a valid object" in text or "unknown revision" in text:
        return "unknown_object"
    if "does not have any commits" in text or "bad default revision" in text:
        return "no_commits"
    return "failed" if text.strip() else ""


class Git:
    """One registered work tree. Construct per operation; cheap (no process is started)."""

    def __init__(self, root: str, *, timeout_s: float = DEFAULT_TIMEOUT_S,
                 max_output_bytes: int = DEFAULT_MAX_OUTPUT, executable: str | None = None) -> None:
        self.root = root
        self.timeout_s = float(timeout_s)
        self.max_output_bytes = int(max_output_bytes)
        exe = executable or shutil.which("git")
        if not exe:
            raise RepositoryError("git is not available on this host")
        self.executable = exe
        self._driver_overrides: list[str] | None = None

    # ------------------------------------------------------------------ process
    def env(self) -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/nonexistent"),
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "GIT_ADVICE": "0",
            "GIT_CEILING_DIRECTORIES": os.path.dirname(self.root.rstrip(os.sep)) or os.sep,
        }
        tmp = os.environ.get("TMPDIR")
        if tmp:
            env["TMPDIR"] = tmp
        return env

    def argv(self, args: Sequence[str]) -> list[str]:
        return [self.executable, *_base_argv(), *(self._driver_overrides or ()), *args]

    def run(self, args: Sequence[str], *, input: bytes | None = None, timeout_s: float | None = None,
            max_output_bytes: int | None = None, ok: tuple[int, ...] = (0,)) -> GitResult:
        """Run ``git <safe config> <args>``; raises :class:`GitCommandError` on other exit codes."""
        if self._driver_overrides is None and args and args[0] != "config":
            self._driver_overrides = self._filter_driver_overrides()
        timeout = self.timeout_s if timeout_s is None else float(timeout_s)
        cap = self.max_output_bytes if max_output_bytes is None else int(max_output_bytes)
        result = _execute(self.argv(args), self.root, self.env(), input, timeout, cap)
        subcommand = args[0] if args else ""
        if result.returncode == -9999:
            raise GitTimeout(f"git {subcommand} exceeded its time bound", details={"subcommand": subcommand})
        if not result.truncated and result.returncode not in ok:
            raise GitCommandError(f"git {subcommand} failed",
                                  details={"subcommand": subcommand, "returncode": result.returncode,
                                           "reason": result.stderr_class or "failed"})
        return result

    def _filter_driver_overrides(self) -> list[str]:
        """``-c filter.<name>.{clean,smudge,process}=`` for every driver in repository config.

        An empty command is a no-op in git's convert machinery; ``required=false`` keeps a
        neutralized required filter from aborting the command. Driver names git's ``-c``
        syntax cannot express are refused rather than left active.
        """
        self._driver_overrides = []  # the probe itself runs without overrides
        try:
            result = self.run(["config", "-z", "--get-regexp", r"^filter\."], ok=(0, 1),
                              max_output_bytes=1024 * 1024)
        except BaseException:
            self._driver_overrides = None  # fail closed: nothing runs until the probe succeeds
            raise
        if result.truncated:
            self._driver_overrides = None
            raise RepositoryError("repository configuration is too large to inspect safely")
        names: set[str] = set()
        for item in result.stdout.split(b"\0"):
            key = item.split(b"\n", 1)[0].decode("utf-8", "surrogateescape")
            if not key.startswith("filter.") or key.count(".") < 2:
                continue
            names.add(key[len("filter."):key.rfind(".")])
        if len(names) > _MAX_FILTER_DRIVERS:
            self._driver_overrides = None
            raise RepositoryError("repository configuration defines too many filter drivers")
        overrides: list[str] = []
        for name in sorted(names):
            try:
                name.encode("utf-8")
                expressible = bool(name) and not any(ch in name for ch in "=\n\r\0")
            except UnicodeEncodeError:
                expressible = False
            if not expressible:
                self._driver_overrides = None
                raise RepositoryError("repository configuration defines a filter driver that cannot be"
                                      " neutralized safely")
            for var, value in (("clean", ""), ("smudge", ""), ("process", ""), ("required", "false")):
                overrides += ["-c", f"filter.{name}.{var}={value}"]
        return overrides

    # ------------------------------------------------------------------ identity
    def _line(self, args: Sequence[str], ok: tuple[int, ...] = (0,)) -> str | None:
        result = self.run(args, ok=ok, max_output_bytes=64 * 1024)
        if result.returncode != 0 or result.truncated:
            return None
        text = result.stdout.decode("utf-8", "surrogateescape").rstrip("\n")
        return text or None

    def toplevel(self) -> str | None:
        try:
            return self._line(["rev-parse", "--show-toplevel"], ok=(0, 128))
        except GitCommandError:
            return None

    def is_bare(self) -> bool:
        return self._line(["rev-parse", "--is-bare-repository"], ok=(0, 128)) == "true"

    def common_dir(self) -> str | None:
        value = self._line(["rev-parse", "--git-common-dir"], ok=(0, 128))
        if value is None:
            return None
        return os.path.realpath(os.path.join(self.root, value))

    def git_dir(self) -> str | None:
        value = self._line(["rev-parse", "--git-dir"], ok=(0, 128))
        if value is None:
            return None
        return os.path.realpath(os.path.join(self.root, value))

    def object_format(self) -> str:
        try:
            value = self._line(["rev-parse", "--show-object-format"], ok=(0,))
        except GitCommandError:
            value = None  # git < 2.27 only supports sha1
        return "sha256" if value == "sha256" else "sha1"

    def head(self) -> str | None:
        value = self._line(["rev-parse", "--verify", "-q", "HEAD^{commit}"], ok=(0, 1, 128))
        return value if value and _HEX.fullmatch(value) else None

    def branch(self) -> str | None:
        return self._line(["symbolic-ref", "-q", "--short", "HEAD"], ok=(0, 1, 128))

    def root_commits(self) -> list[str]:
        result = self.run(["rev-list", "--max-parents=0", "HEAD"], ok=(0, 128), max_output_bytes=64 * 1024)
        if result.returncode != 0:
            return []
        return sorted(line for line in result.stdout.decode("ascii", "replace").split()
                      if _HEX.fullmatch(line))

    def resolve_commit(self, rev: str) -> str | None:
        if not _REV.fullmatch(rev) or ".." in rev:
            return None
        value = self._line(["rev-parse", "--verify", "-q", f"{rev}^{{commit}}"], ok=(0, 1, 128))
        return value if value and _HEX.fullmatch(value) else None

    # ------------------------------------------------------------------ inventory
    def status(self) -> tuple[list[StatusEntry], bool]:
        result = self.run(["status", "--porcelain=v2", "-z", "--no-renames", "--ignore-submodules=all",
                           "--untracked-files=normal"])
        return parse_status(result.stdout, result.truncated), result.truncated

    def ls_files(self) -> tuple[list[IndexEntry], bool]:
        result = self.run(["ls-files", "-s", "-z"])
        return parse_ls_files(result.stdout, result.truncated), result.truncated

    def ls_files_entry(self, path: str) -> IndexEntry | None:
        result = self.run(["ls-files", "-s", "-z", "--", path], max_output_bytes=4 * 1024 * 1024)
        wanted = path.encode("utf-8", "surrogateescape")
        for entry in parse_ls_files(result.stdout, result.truncated):
            if entry.path == wanted and entry.stage == 0:
                return entry
        return None

    def ls_tree_entry(self, commit: str, path: str) -> tuple[str, str, str] | None:
        if not _HEX.fullmatch(commit):
            return None
        result = self.run(["ls-tree", "-z", commit, "--", path], ok=(0, 128), max_output_bytes=1024 * 1024)
        if result.returncode != 0:
            return None
        wanted = path.encode("utf-8", "surrogateescape")
        for item in result.stdout.split(b"\0"):
            meta, sep, name = item.partition(b"\t")
            if not sep or name != wanted:
                continue
            parts = meta.decode("ascii", "replace").split(" ")
            if len(parts) == 3 and _HEX.fullmatch(parts[2]):
                return parts[0], parts[1], parts[2]
        return None

    def blob_sizes(self, shas: Sequence[str]) -> dict[str, int]:
        """Object sizes for blob ids via one ``cat-file --batch-check`` call."""
        wanted = [s for s in dict.fromkeys(shas) if _HEX.fullmatch(s)]
        if not wanted:
            return {}
        result = self.run(["cat-file", "--batch-check"], input=("\n".join(wanted) + "\n").encode(),
                          max_output_bytes=max(1024 * 1024, 128 * len(wanted)))
        sizes: dict[str, int] = {}
        for line in result.stdout.decode("ascii", "replace").splitlines():
            parts = line.split(" ")
            if len(parts) == 3 and parts[1] == "blob" and parts[2].isdigit():
                sizes[parts[0]] = int(parts[2])
        return sizes

    def read_blobs(self, shas: Sequence[str], *, max_total_bytes: int) -> dict[str, bytes]:
        """Raw blob contents (no filters, no textconv) via ``cat-file --batch``.

        Blobs that do not fit in ``max_total_bytes`` are simply absent from the result.
        """
        wanted = [s for s in dict.fromkeys(shas) if _HEX.fullmatch(s)]
        if not wanted:
            return {}
        cap = max_total_bytes + 128 * len(wanted)
        result = self.run(["cat-file", "--batch"], input=("\n".join(wanted) + "\n").encode(),
                          max_output_bytes=cap)
        return parse_batch(result.stdout)

    def blob_size(self, sha: str) -> int | None:
        return self.blob_sizes([sha]).get(sha)

    def read_blob(self, sha: str, *, max_bytes: int) -> tuple[bytes, bool]:
        if not _HEX.fullmatch(sha):
            raise GitCommandError("invalid object id")
        result = self.run(["cat-file", "blob", sha], max_output_bytes=max_bytes)
        return result.stdout, result.truncated

    # ------------------------------------------------------------------ history
    def log(self, *, max_commits: int, path: str | None = None, max_output_bytes: int = 4 * 1024 * 1024
            ) -> tuple[list[LogEntry], bool]:
        # A per-call random marker separates records, so a hostile commit subject cannot forge one.
        nonce = secrets.token_hex(8)
        marker = f"\x1eLOCUS{nonce}\x1f".encode()
        fmt = f"%x1eLOCUS{nonce}%x1f%H%x1f%at%x1f%s"
        args = ["log", "--no-ext-diff", "--no-textconv", "--no-color", "--no-show-signature",
                "--no-renames", "--name-only", "-z", "--encoding=UTF-8", f"--max-count={int(max_commits)}",
                f"--format={fmt}", "HEAD", "--"]
        if path is not None:
            args.append(path)
        result = self.run(args, max_output_bytes=max_output_bytes)
        return parse_log(result.stdout, marker, result.truncated), result.truncated


# ---------------------------------------------------------------------- parsing
def parse_status(out: bytes, truncated: bool = False) -> list[StatusEntry]:
    records = out.split(b"\0")
    if truncated and records:
        records = records[:-1]  # the last record may be cut
    entries: list[StatusEntry] = []
    skip_next = False
    for rec in records:
        if skip_next:
            skip_next = False
            continue
        if not rec:
            continue
        kind = rec[:1].decode("ascii", "replace")
        if kind == "1":
            parts = rec.split(b" ", 8)
            if len(parts) == 9:
                entries.append(StatusEntry("1", parts[1].decode("ascii", "replace"), parts[8],
                                           parts[6].decode("ascii", "replace"), parts[7].decode("ascii", "replace")))
        elif kind == "2":
            parts = rec.split(b" ", 9)
            if len(parts) == 10:
                entries.append(StatusEntry("2", parts[1].decode("ascii", "replace"), parts[9],
                                           parts[6].decode("ascii", "replace"), parts[7].decode("ascii", "replace")))
            skip_next = True  # the original path follows as its own NUL-terminated field
        elif kind == "u":
            parts = rec.split(b" ", 10)
            if len(parts) == 11:
                entries.append(StatusEntry("u", parts[1].decode("ascii", "replace"), parts[10]))
        elif kind in ("?", "!"):
            entries.append(StatusEntry(kind, kind * 2, rec[2:]))
    return entries


def parse_ls_files(out: bytes, truncated: bool = False) -> list[IndexEntry]:
    records = out.split(b"\0")
    if truncated and records:
        records = records[:-1]
    entries: list[IndexEntry] = []
    for rec in records:
        meta, sep, path = rec.partition(b"\t")
        if not sep:
            continue
        parts = meta.decode("ascii", "replace").split(" ")
        if len(parts) != 3 or not _HEX.fullmatch(parts[1]) or not parts[2].isdigit():
            continue
        entries.append(IndexEntry(parts[0], parts[1], int(parts[2]), path))
    return entries


def parse_batch(out: bytes) -> dict[str, bytes]:
    blobs: dict[str, bytes] = {}
    pos = 0
    total = len(out)
    while pos < total:
        newline = out.find(b"\n", pos)
        if newline < 0:
            break
        header = out[pos:newline].decode("ascii", "replace").split(" ")
        pos = newline + 1
        if len(header) == 2 and header[1] == "missing":
            continue
        if len(header) != 3 or not header[2].isdigit():
            break
        size = int(header[2])
        if pos + size > total:
            break  # truncated object: not returned
        if header[1] == "blob":
            blobs[header[0]] = out[pos:pos + size]
        pos += size + 1  # contents are followed by a newline
    return blobs


def parse_log(out: bytes, marker: bytes, truncated: bool = False) -> list[LogEntry]:
    chunks = out.split(marker)[1:]
    entries: list[LogEntry] = []
    for index, chunk in enumerate(chunks):
        last = index == len(chunks) - 1
        header, _, rest = chunk.partition(b"\0")
        parts = header.split(b"\x1f", 2)
        if len(parts) != 3:
            continue
        commit = parts[0].decode("ascii", "replace")
        if not _HEX.fullmatch(commit) or not parts[1].isdigit():
            continue
        names = [p for p in rest.lstrip(b"\n").split(b"\0") if p]
        cut = truncated and last
        if cut and names:
            names = names[:-1]
        entries.append(LogEntry(commit, int(parts[1]), parts[2], tuple(names), paths_truncated=cut))
    return entries


# ---------------------------------------------------------------------- execution
def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, AttributeError):
        try:
            proc.kill()
        except OSError:
            pass


def _execute(argv: list[str], cwd: str, env: dict[str, str], stdin_data: bytes | None,
             timeout_s: float, max_out: int) -> GitResult:
    """Run one process with bounded time and output. returncode -9999 means timed out."""
    try:
        proc = subprocess.Popen(
            argv, cwd=cwd, env=env, close_fds=True, start_new_session=True,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise RepositoryError("git could not be started") from exc
    out = bytearray()
    err = bytearray()
    state = {"truncated": False}

    def pump_out() -> None:
        fd = proc.stdout.fileno()  # type: ignore[union-attr]
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            room = max_out - len(out)
            if len(chunk) > room:
                out.extend(chunk[:max(room, 0)])
                state["truncated"] = True
                _kill_group(proc)
                return
            out.extend(chunk)

    def pump_err() -> None:
        fd = proc.stderr.fileno()  # type: ignore[union-attr]
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            if len(err) < _MAX_STDERR:
                err.extend(chunk[:_MAX_STDERR - len(err)])

    def feed() -> None:
        try:
            proc.stdin.write(stdin_data)  # type: ignore[union-attr,arg-type]
        except (BrokenPipeError, OSError, ValueError):
            pass
        finally:
            try:
                proc.stdin.close()  # type: ignore[union-attr]
            except (BrokenPipeError, OSError, ValueError):
                pass

    threads = [threading.Thread(target=pump_out, daemon=True), threading.Thread(target=pump_err, daemon=True)]
    if stdin_data is not None:
        threads.append(threading.Thread(target=feed, daemon=True))
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        proc.wait(timeout=max(timeout_s, 0.001))
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
        proc.wait()
    # Pipes may stay open if a descendant inherited them; never wait on them unboundedly.
    deadline = time.monotonic() + 2.0
    for thread in threads:
        thread.join(timeout=max(deadline - time.monotonic(), 0.0))
    if any(thread.is_alive() for thread in threads):
        _kill_group(proc)
        for thread in threads:
            thread.join(timeout=1.0)
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()  # type: ignore[union-attr]
        except OSError:
            pass
    if timed_out:
        return GitResult(b"", -9999, False, "timeout")
    return GitResult(bytes(out), proc.returncode, state["truncated"], _classify_stderr(bytes(err)))
