"""Typed errors. Every public failure is one of these; messages never contain record content.

This module deliberately defines no ``__all__`` and imports nothing: ``from .errors import *``
exports every public class, including ones appended at the end of the file later.
"""


class MemoryEngineError(Exception):
    """Base class for all locus_memory errors."""

    code = "memory_error"

    def __init__(self, message: str = "", *, details: dict | None = None) -> None:
        super().__init__(message or self.code)
        self.details = dict(details or {})

    def to_dict(self) -> dict:
        return {"error": self.code, "message": str(self), "details": self.details}


class ValidationError(MemoryEngineError):
    code = "invalid_request"


class AccessDenied(MemoryEngineError):
    """The trusted access context does not permit the operation or target.

    Raised identically for "exists but unauthorized" and "does not exist" when a
    distinction would reveal another scope's contents.
    """

    code = "access_denied"


class NotFound(MemoryEngineError):
    code = "not_found"


class VaultLocked(MemoryEngineError):
    """No key is available (host keychain locked or key provider unavailable)."""

    code = "vault_locked"


class WrongKey(MemoryEngineError):
    """A key is available but does not authenticate this vault."""

    code = "wrong_key"


class IntegrityError(MemoryEngineError):
    """Authenticated decryption or a structural integrity check failed."""

    code = "integrity_error"


class RevisionConflict(MemoryEngineError):
    code = "revision_conflict"


class IdempotencyConflict(MemoryEngineError):
    """The same idempotency key was reused for a different request."""

    code = "idempotency_conflict"


class InvalidTransition(MemoryEngineError):
    code = "invalid_transition"


class Contention(MemoryEngineError):
    """The store stayed busy beyond the bounded wait."""

    code = "contention"


class IndexUnavailable(MemoryEngineError):
    code = "index_unavailable"


class UnsupportedCapability(MemoryEngineError):
    code = "unsupported_capability"


class ConsentRequired(MemoryEngineError):
    code = "consent_required"


class ProviderError(MemoryEngineError):
    code = "provider_error"


class Cancelled(MemoryEngineError):
    code = "cancelled"


class DeadlineExceeded(MemoryEngineError):
    code = "deadline_exceeded"


class StaleDerivation(MemoryEngineError):
    """A derived write observed state that a later deletion/correction invalidated."""

    code = "stale_derivation"


class SensitiveContent(MemoryEngineError):
    code = "sensitive_content"


class ReconciliationRequired(MemoryEngineError):
    """The store is older than the newest known deletion state; it must be reconciled first."""

    code = "reconciliation_required"


class OwnershipFenced(MemoryEngineError):
    """A writer attempted a write while it is not the authoritative owner."""

    code = "ownership_fenced"


class MigrationError(MemoryEngineError):
    code = "migration_error"


class RepositoryAccessDenied(AccessDenied):
    code = "repository_access_denied"


class SuppressedError(MemoryEngineError):
    """A write was refused because a forget, rejection or correction suppresses it."""

    code = "suppressed"


class RepositoryError(MemoryEngineError):
    """A repository-memory operation failed (not a work tree, unavailable root, git failure)."""

    code = "repository_error"


class RepositoryConflict(RepositoryError):
    """A repository id is already registered with a different root, identity or scope."""

    code = "repository_conflict"


class GitCommandError(RepositoryError):
    """A bounded, read-only git command failed. Never carries git's output (it may name paths)."""

    code = "git_error"


class GitTimeout(GitCommandError):
    """A git command exceeded its time bound and was killed."""

    code = "git_timeout"


class InterchangeInvalid(ValidationError):
    """A repository interchange document failed strict validation."""

    code = "interchange_invalid"
