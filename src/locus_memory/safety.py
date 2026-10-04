"""Defense-in-depth content checks.

These are *not* the primary injection defence (that is the separation of data
from authority: memory is rendered as quoted data and can never change access,
tools, budgets or verification). They catch obvious secrets before persistence
and flag instruction-like text so hosts can display it as suspicious.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("password_assignment", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?[^\s'\"]{6,}")),
    ("connection_string", re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]{3,}@[^\s]+")),
    ("bearer", re.compile(r"(?i)\bauthorization:\s*bearer\s+[A-Za-z0-9._~+/=-]{16,}")),
)

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bignore (?:all |any )?(?:previous|prior|above) (?:instructions|rules)"),
    re.compile(r"(?i)\b(?:you are now|act as|new instructions|system prompt)\b"),
    re.compile(r"(?i)\b(?:disable|skip|bypass|turn off) (?:the )?(?:tests?|verification|checks?|safety|approval)"),
    re.compile(r"(?i)\b(?:grant|give) (?:yourself|the agent) (?:access|permission)"),
    re.compile(r"(?i)</?(?:system|assistant|tool|memory|instructions?)>"),
    re.compile(r"(?i)\brun (?:this|the following) (?:command|script)\b.*(?:curl|wget).*\|\s*(?:sh|bash)"),
)

# Categories that must never be inferred and persisted automatically.
_SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("health", re.compile(r"(?i)\b(?:diagnos(?:ed|is)|medication|therapy|disorder|pregnan\w*|hiv|cancer)\b")),
    ("government_id", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("payment_card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("sexuality_religion_politics", re.compile(r"(?i)\b(?:sexual orientation|religio(?:n|us) belief|political affiliation)\b")),
)


@dataclass(frozen=True)
class ScanResult:
    secrets: tuple[str, ...]
    injection: bool
    sensitive: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return not self.secrets and not self.injection and not self.sensitive


def scan(text: str) -> ScanResult:
    secrets = tuple(sorted({name for name, pattern in _SECRET_PATTERNS if pattern.search(text)}))
    injection = any(pattern.search(text) for pattern in _INJECTION_PATTERNS)
    sensitive = tuple(sorted({name for name, pattern in _SENSITIVE_PATTERNS if pattern.search(text)}))
    return ScanResult(secrets, injection, sensitive)


def redact_secrets(text: str) -> tuple[str, tuple[str, ...]]:
    found: list[str] = []
    out = text
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(out):
            found.append(name)
            out = pattern.sub(f"[REDACTED:{name}]", out)
    return out, tuple(sorted(set(found)))


_WRAPPER = re.compile(r"(?i)<\s*/?\s*(memory|memory-context|system|assistant|user|tool|instructions?)\b[^>]*>")


def neutralize_markup(text: str) -> str:
    """Prevent stored text from closing or opening the host's prompt wrappers."""
    return _WRAPPER.sub(lambda m: m.group(0).replace("<", "‹").replace(">", "›"), text)
