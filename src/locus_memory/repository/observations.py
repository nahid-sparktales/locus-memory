"""Fact extraction from repository files - parsing only, never executing.

* Python: :func:`ast.parse` (compiles to a syntax tree; no code runs, no imports are
  resolved). Extracted: imports (anywhere in the module), top-level classes and
  functions, and the first line of the module docstring. ``extraction = "ast"``.
* JavaScript / TypeScript: import specifiers via regular expressions
  (``import ... from``, side-effect ``import '...'``, ``export ... from``,
  ``require(...)``, dynamic ``import(...)``). This is a **heuristic**: it can miss
  imports and can match text inside comments or strings. ``extraction = "heuristic"``.
* Every other language: inventory only (``support = "unsupported"``), no facts.

Facts are observations of file content, not model claims. File content is untrusted
data: docstrings and specifiers are secret-redacted and markup-neutralized before
they are rendered into memory text, and instruction-like text is flagged.
"""
from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field
from typing import Any

from .. import safety

PYTHON_EXTRACTION = "python-ast/1"
JS_EXTRACTION = "js-ts-import-regex/1"
MAX_IMPORTS = 200
MAX_SYMBOLS = 300
MAX_NAME_CHARS = 200
MAX_DOCSTRING_CHARS = 300
MAX_SPECIFIER_CHARS = 300

_SYMBOL_KINDS = ("class", "function", "async_function")
_JS_PATTERNS = (
    re.compile(r"""\bfrom\s*(['"])([^'"\r\n]{1,300})\1"""),
    re.compile(r"""\bimport\s*(['"])([^'"\r\n]{1,300})\1"""),
    re.compile(r"""\b(?:require|import)\s*\(\s*(['"])([^'"\r\n]{1,300})\1\s*\)"""),
)
_PRINTABLE = re.compile(r"[^\x20-\x7e -￿]")


@dataclass(frozen=True)
class ImportFact:
    module: str
    names: tuple[str, ...] = ()


@dataclass(frozen=True)
class SymbolFact:
    name: str
    kind: str  # class | function | async_function
    line: int | None = None


@dataclass(frozen=True)
class Facts:
    language: str
    extraction: str  # "ast" | "heuristic"
    extraction_version: str
    docstring: str | None = None
    imports: tuple[ImportFact, ...] = ()
    symbols: tuple[SymbolFact, ...] = ()
    truncated: bool = False
    extra_counts: dict[str, int] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not self.docstring and not self.imports and not self.symbols

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language, "extraction": self.extraction,
            "extraction_version": self.extraction_version, "docstring": self.docstring,
            "imports": [{"module": i.module, "names": list(i.names)} for i in self.imports],
            "symbols": [{"name": s.name, "kind": s.kind, "line": s.line} for s in self.symbols],
            "truncated": self.truncated,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> Facts | None:
        if not isinstance(raw, dict):
            return None
        try:
            return cls(
                language=str(raw["language"]), extraction=str(raw["extraction"]),
                extraction_version=str(raw.get("extraction_version") or ""),
                docstring=raw.get("docstring"),
                imports=tuple(ImportFact(str(i["module"]), tuple(str(n) for n in i.get("names") or ()))
                              for i in raw.get("imports") or ()),
                symbols=tuple(SymbolFact(str(s["name"]), str(s["kind"]), s.get("line"))
                              for s in raw.get("symbols") or ()),
                truncated=bool(raw.get("truncated")),
            )
        except (KeyError, TypeError, ValueError):
            return None


@dataclass(frozen=True)
class ParseOutcome:
    facts: Facts | None
    status: str  # parsed | no_facts | parse_error | unsupported


def _clean(text: str, limit: int) -> str:
    text = _PRINTABLE.sub(" ", text).strip()
    return text[:limit]


# ---------------------------------------------------------------------- python
def parse_python(data: bytes, language: str = "python") -> ParseOutcome:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(data, mode="exec")
    except (SyntaxError, ValueError, RecursionError, MemoryError, UnicodeDecodeError, OverflowError):
        return ParseOutcome(None, "parse_error")
    truncated = False
    docstring = None
    try:
        raw_doc = ast.get_docstring(tree, clean=True)
    except (TypeError, ValueError):
        raw_doc = None
    if raw_doc:
        first = raw_doc.strip().splitlines()[0] if raw_doc.strip() else ""
        docstring = _clean(first, MAX_DOCSTRING_CHARS) or None
    imports: list[ImportFact] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    try:
        nodes = list(ast.walk(tree))
    except RecursionError:
        return ParseOutcome(None, "parse_error")
    for node in nodes:
        fact = None
        if isinstance(node, ast.Import):
            for alias in node.names:
                fact = ImportFact(_clean(alias.name, MAX_NAME_CHARS))
                if fact.module and (fact.module, ()) not in seen:
                    seen.add((fact.module, ()))
                    imports.append(fact)
            continue
        if isinstance(node, ast.ImportFrom):
            module = "." * int(node.level or 0) + (node.module or "")
            names = tuple(_clean(a.name, MAX_NAME_CHARS) for a in node.names)[:32]
            fact = ImportFact(_clean(module, MAX_NAME_CHARS), names)
            key = (fact.module, fact.names)
            if fact.module and key not in seen:
                seen.add(key)
                imports.append(fact)
    if len(imports) > MAX_IMPORTS:
        imports, truncated = imports[:MAX_IMPORTS], True
    symbols: list[SymbolFact] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            symbols.append(SymbolFact(_clean(node.name, MAX_NAME_CHARS), "class", node.lineno))
        elif isinstance(node, ast.AsyncFunctionDef):
            symbols.append(SymbolFact(_clean(node.name, MAX_NAME_CHARS), "async_function", node.lineno))
        elif isinstance(node, ast.FunctionDef):
            symbols.append(SymbolFact(_clean(node.name, MAX_NAME_CHARS), "function", node.lineno))
    if len(symbols) > MAX_SYMBOLS:
        symbols, truncated = symbols[:MAX_SYMBOLS], True
    facts = Facts(language, "ast", PYTHON_EXTRACTION, docstring, tuple(imports), tuple(symbols), truncated)
    return ParseOutcome(facts, "no_facts" if facts.empty else "parsed")


# ---------------------------------------------------------------------- javascript / typescript
def parse_js_imports(data: bytes, language: str) -> ParseOutcome:
    """HEURISTIC regex extraction of import specifiers (see module docstring)."""
    text = data.decode("utf-8", "replace")
    found: dict[str, None] = {}
    for pattern in _JS_PATTERNS:
        for match in pattern.finditer(text):
            spec = _clean(match.group(2), MAX_SPECIFIER_CHARS)
            if spec:
                found.setdefault(spec)
            if len(found) > MAX_IMPORTS:
                break
    specs = list(found)
    truncated = len(specs) > MAX_IMPORTS
    facts = Facts(language, "heuristic", JS_EXTRACTION, None,
                  tuple(ImportFact(s) for s in sorted(specs[:MAX_IMPORTS])), (), truncated)
    return ParseOutcome(facts, "no_facts" if facts.empty else "parsed")


def extract(data: bytes, language: str, support: str) -> ParseOutcome:
    if support == "parsed" and language == "python":
        return parse_python(data, language)
    if support == "heuristic":
        return parse_js_imports(data, language)
    return ParseOutcome(None, "unsupported")


# ---------------------------------------------------------------------- rendering
_KIND_LABEL = {"class": "class", "function": "def", "async_function": "async def"}
_LANGUAGE_LABEL = {"python": "Python", "javascript": "JavaScript", "typescript": "TypeScript"}


@dataclass(frozen=True)
class Rendered:
    title: str
    content: str
    tags: tuple[str, ...]
    flags: tuple[str, ...]
    redactions: tuple[str, ...]


def render(facts: Facts, path: str, *, origin: str) -> Rendered:
    """Memory text for one file's facts. Content is quoted data, never instructions."""
    label = _LANGUAGE_LABEL.get(facts.language, facts.language)
    if facts.extraction == "ast":
        method = f"parsed with the {label} syntax tree (no code was executed)"
    else:
        method = (f"{label} import specifiers extracted with a HEURISTIC regular expression;"
                  " may be incomplete or include false matches")
    lines = [f"Repository observation ({method}).", f"File: {path}"]
    if origin == "worktree":
        lines.append("Content: uncommitted working-tree version.")
    if facts.docstring:
        lines.append(f"Docstring (first line): {facts.docstring}")
    if facts.imports:
        rendered = []
        for item in facts.imports:
            if item.names:
                rendered.append(f"from {item.module} import {', '.join(item.names)}")
            else:
                rendered.append(item.module)
        lines.append(f"Imports ({len(facts.imports)}): " + "; ".join(rendered))
    if facts.symbols:
        rendered = [f"{_KIND_LABEL.get(s.kind, s.kind)} {s.name}" + (f" (line {s.line})" if s.line else "")
                    for s in facts.symbols]
        lines.append(f"Top-level definitions ({len(facts.symbols)}): " + ", ".join(rendered))
    if facts.truncated:
        lines.append("Note: lists were truncated at their bounds.")
    content = "\n".join(lines)
    if len(content) > 30_000:
        content = content[:30_000] + "\n[truncated]"
    content, redactions = safety.redact_secrets(content)
    scan = safety.scan(content)
    content = safety.neutralize_markup(content)
    title = safety.neutralize_markup(safety.redact_secrets(f"{label} file {path}")[0])[:160]
    tags = ("repository", facts.language, "heuristic" if facts.extraction == "heuristic" else "parsed")
    flags = ("instruction_like",) if scan.injection else ()
    return Rendered(title, content, tags, flags, redactions)
