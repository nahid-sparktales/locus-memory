"""Path safety, exclusions, root checks and guarded reads for repository memory.

Rules enforced here (used by enumeration *and* by every direct read, including
historical blobs):

* Repository paths are relative, ``/``-separated, without empty, ``.`` or ``..``
  components, NUL/control characters, backslashes or drive letters.
* Exclusions match any path component (or path prefix) case-insensitively; an
  excluded file is never read, hashed by content or parsed, and is never named in
  any output - only counted.
* Work-tree reads open each component relative to the previous one with
  ``O_NOFOLLOW``: a symlink anywhere on the path is refused, never followed, so a
  read can never leave the registered root. Symlinks are inventory entries only.
* Roots must resolve (``realpath``) inside a host-allowed root, and are never the
  filesystem root, the user's home directory or an ancestor of it.

Nothing here executes repository content.
"""
from __future__ import annotations

import errno
import fnmatch
import hashlib
import os
import stat
import unicodedata
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from ..errors import NotFound, RepositoryAccessDenied, RepositoryError, ValidationError

DEFAULT_EXCLUSIONS: tuple[str, ...] = (
    # Environment and credential files.
    ".env", ".env.*", "*.env", ".envrc", ".pgpass", ".netrc", ".npmrc", ".pypirc",
    ".git-credentials", ".htpasswd",
    # Keys and keystores.
    "id_rsa*", "id_ed25519*", "id_dsa*", "id_ecdsa*", "*.ppk",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", "*.jks", "*.kdbx",
    # Anything that names itself a secret or credential.
    "credentials*", "*secret*",
    # Infrastructure state and variables.
    "*.tfvars", "*.tfvars.json", "terraform.tfstate*",
    # Directories.
    ".aws/", ".ssh/", ".gnupg/", ".git/",
)
MAX_EXTRA_PATTERNS = 128
MAX_PATTERN_CHARS = 256
MAX_PATH_CHARS = 4096


def _denied(message: str = "this repository path is not allowed") -> RepositoryAccessDenied:
    return RepositoryAccessDenied(message)


# ---------------------------------------------------------------------- patterns
def check_patterns(patterns: Any) -> tuple[str, ...]:
    """Validate extra exclusion patterns (they can only add exclusions)."""
    if patterns is None:
        return ()
    if isinstance(patterns, str) or not isinstance(patterns, (list, tuple, set, frozenset)):
        raise ValidationError("exclude patterns must be a list of strings")
    out: list[str] = []
    for item in patterns:
        if not isinstance(item, str) or not item.strip():
            raise ValidationError("exclude patterns must be non-empty strings")
        item = item.strip()
        if len(item) > MAX_PATTERN_CHARS or any(unicodedata.category(ch).startswith("C") for ch in item):
            raise ValidationError("an exclude pattern is too long or contains control characters")
        out.append(item)
    if len(out) > MAX_EXTRA_PATTERNS:
        raise ValidationError(f"at most {MAX_EXTRA_PATTERNS} extra exclude patterns are allowed")
    return tuple(sorted(set(out)))


class Exclusions:
    """Default + configured exclusion patterns (case-insensitive)."""

    def __init__(self, extra: Iterable[str] = ()) -> None:
        extra = check_patterns(tuple(extra))
        self.extra = extra
        self.patterns = tuple(DEFAULT_EXCLUSIONS) + tuple(p for p in extra if p not in DEFAULT_EXCLUSIONS)
        self._component: list[str] = []
        self._dirs: list[str] = []
        self._paths: list[str] = []
        for raw in self.patterns:
            pattern = raw.lower().lstrip("/")
            if pattern.endswith("/"):
                body = pattern.rstrip("/")
                (self._paths if "/" in body else self._dirs).append(body)
            elif "/" in pattern:
                self._paths.append(pattern)
            else:
                self._component.append(pattern)

    def fingerprint(self) -> str:
        return hashlib.sha256("\n".join(sorted(self.patterns)).encode()).hexdigest()

    def excluded(self, path: str) -> bool:
        parts = path.lower().split("/")
        for part in parts:
            for pattern in self._component:
                if fnmatch.fnmatchcase(part, pattern):
                    return True
            for pattern in self._dirs:
                if fnmatch.fnmatchcase(part, pattern):
                    return True
        if self._paths:
            for end in range(1, len(parts) + 1):
                prefix = "/".join(parts[:end])
                for pattern in self._paths:
                    if fnmatch.fnmatchcase(prefix, pattern):
                        return True
        return False


# ---------------------------------------------------------------------- paths
def check_repo_path(path: Any) -> str:
    """Validate a repository-relative path; RepositoryAccessDenied on anything unsafe."""
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_CHARS:
        raise _denied()
    if "\x00" in path or "\\" in path:
        raise _denied()
    if path.startswith("/") or (len(path) >= 2 and path[1] == ":" and path[0].isalpha()):
        raise _denied()
    # Control, format (bidi overrides, zero-width), surrogate and private-use characters.
    if any(unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co") for ch in path):
        raise _denied()
    for part in path.split("/"):
        if part in ("", ".", ".."):
            raise _denied()
    return path


def decode_git_path(raw: bytes) -> str | None:
    """A git index/tree path as text, or None when it is not valid UTF-8 or not a safe path."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        return check_repo_path(text)
    except RepositoryAccessDenied:
        return None


# ---------------------------------------------------------------------- roots
def _within(child: str, parent: str) -> bool:
    if parent == os.sep:
        return child.startswith(os.sep)
    return child == parent or child.startswith(parent.rstrip(os.sep) + os.sep)


def resolve_allowed_roots(allowed: Sequence[Any]) -> list[str]:
    out = []
    for item in allowed or ():
        try:
            out.append(os.path.realpath(os.fspath(item)))
        except (TypeError, ValueError):
            continue
    return out


def check_root(root: Any, allowed_roots: Sequence[Any]) -> str:
    """Resolve ``root`` and verify it may be registered/read. Runs no git command."""
    allowed = resolve_allowed_roots(allowed_roots)
    if not allowed:
        raise RepositoryAccessDenied("repository memory disabled: the host allows no repository roots")
    try:
        raw = os.fspath(root)
    except TypeError as exc:
        raise ValidationError("repository root must be a path") from exc
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValidationError("repository root must be a path")
    real = os.path.realpath(os.path.abspath(raw))
    if os.path.dirname(real) == real:
        raise RepositoryAccessDenied("the filesystem root cannot be registered as a repository")
    home = os.path.realpath(os.path.expanduser("~"))
    if home and home != os.sep and _within(home, real):
        raise RepositoryAccessDenied("the home directory (or a directory containing it) cannot be registered")
    if not any(_within(real, base) for base in allowed):
        raise RepositoryAccessDenied("the repository root is outside the host-allowed roots")
    if not os.path.isdir(real):
        raise RepositoryError("the repository root is not an available directory")
    return real


def within_allowed(path: str, allowed_roots: Sequence[Any]) -> bool:
    return any(_within(path, base) for base in resolve_allowed_roots(allowed_roots))


# ---------------------------------------------------------------------- guarded reads
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _component_error(dir_fd: int, name: str, exc: OSError) -> Exception:
    try:
        st = os.lstat(name, dir_fd=dir_fd)
    except OSError:
        return NotFound("file not found")
    if stat.S_ISLNK(st.st_mode):
        return _denied("symbolic links are repository inventory entries only and are never followed")
    if exc.errno in (errno.ENOTDIR, errno.ENOENT):
        return NotFound("file not found")
    return _denied()


def open_beneath(root: str, rel: str) -> int:
    """Open ``root/rel`` read-only without following any symlink; returns a regular-file fd."""
    rel = check_repo_path(rel)
    if not (_O_NOFOLLOW and _O_DIRECTORY and os.open in os.supports_dir_fd):
        raise RepositoryError("this platform cannot open repository files without following symlinks")
    parts = rel.split("/")
    try:  # the root itself must not have been swapped for a symlink since it was validated
        dir_fd = os.open(root, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC)
    except OSError as exc:
        raise _denied("the repository root is not available as a directory") from exc
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dir_fd)
            except OSError as exc:
                raise _component_error(dir_fd, part, exc) from None
            os.close(dir_fd)
            dir_fd = next_fd
        try:
            fd = os.open(parts[-1], os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC, dir_fd=dir_fd)
        except OSError as exc:
            raise _component_error(dir_fd, parts[-1], exc) from None
    finally:
        os.close(dir_fd)
    try:
        st = os.fstat(fd)
    except OSError:
        os.close(fd)
        raise NotFound("file not found") from None
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise _denied("only regular files can be read")
    return fd


def read_fd(fd: int, max_bytes: int) -> tuple[bytes, bool]:
    """Read at most ``max_bytes``; returns (data, truncated). Closes ``fd``."""
    chunks: list[bytes] = []
    total = 0
    try:
        while total <= max_bytes:
            chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        return data[:max_bytes], True
    return data, False


def read_beneath(root: str, rel: str, max_bytes: int) -> tuple[bytes, bool]:
    return read_fd(open_beneath(root, rel), max_bytes)


def hash_beneath(root: str, rel: str, object_format: str, *, max_bytes: int) -> tuple[str, int] | None:
    """Git blob id of a work-tree file (raw bytes, no filters) streamed up to ``max_bytes``."""
    fd = open_beneath(root, rel)
    try:
        size = os.fstat(fd).st_size
        if size > max_bytes:
            return None
        digest = hashlib.sha256() if object_format == "sha256" else hashlib.sha1()
        digest.update(b"blob %d\0" % size)
        read = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            read += len(chunk)
            digest.update(chunk)
        if read != size:
            return None  # changed while reading
        return digest.hexdigest(), size
    finally:
        os.close(fd)


def git_blob_id(data: bytes, object_format: str) -> str:
    """Object id git assigns to ``data`` as a blob (raw content; filters are not applied)."""
    digest = hashlib.sha256() if object_format == "sha256" else hashlib.sha1()
    digest.update(b"blob %d\0" % len(data))
    digest.update(data)
    return digest.hexdigest()


# ---------------------------------------------------------------------- languages
_LANGUAGES = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift",
    ".rb": "ruby", ".php": "php", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".cs": "csharp", ".m": "objective-c", ".mm": "objective-c",
    ".scala": "scala", ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".lua": "lua",
    ".r": "r", ".sql": "sql", ".md": "markdown", ".rst": "restructuredtext", ".txt": "text",
    ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".ini": "ini", ".cfg": "ini",
    ".xml": "xml", ".html": "html", ".htm": "html", ".css": "css", ".scss": "scss", ".vue": "vue",
    ".svelte": "svelte", ".proto": "protobuf", ".graphql": "graphql", ".dart": "dart",
    ".ex": "elixir", ".exs": "elixir", ".erl": "erlang", ".hs": "haskell", ".clj": "clojure",
    ".pl": "perl", ".ps1": "powershell", ".tf": "terraform", ".nix": "nix", ".zig": "zig",
}
_NAMED = {"dockerfile": "dockerfile", "makefile": "make", "gemfile": "ruby", "rakefile": "ruby",
          "cmakelists.txt": "cmake", "jenkinsfile": "groovy"}
PARSED_LANGUAGES = frozenset({"python"})
HEURISTIC_LANGUAGES = frozenset({"javascript", "typescript"})


def detect_language(path: str) -> tuple[str, str]:
    """(language, support) where support is ``parsed`` | ``heuristic`` | ``unsupported``."""
    name = Path(path).name.lower()
    language = _NAMED.get(name) or _LANGUAGES.get(os.path.splitext(name)[1], "unknown")
    if language in PARSED_LANGUAGES:
        return language, "parsed"
    if language in HEURISTIC_LANGUAGES:
        return language, "heuristic"
    return language, "unsupported"
