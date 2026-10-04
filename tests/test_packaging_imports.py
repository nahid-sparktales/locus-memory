"""Packaging hygiene: importing the package has no side effects, pulls in no host/network stacks."""
from __future__ import annotations

import importlib.metadata
import importlib.resources
import json
import os
import re
import socket
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import locus_memory
from conftest import access_for
from locus_memory.models import (
    CandidateProposal,
    ForgetTarget,
    RememberRequest,
    Scope,
    SourceKind,
    SourceRef,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ("ollama_code", "fastapi", "langgraph", "agent_dispatcher", "requests", "httpx", "urllib3",
             "aiohttp", "starlette", "uvicorn", "pydantic", "numpy", "keyring")
NETWORK_CLIENTS = ("http.client", "urllib.request", "ssl", "ftplib", "smtplib", "xmlrpc.client")
ALLOWED_THIRD_PARTY = ("locus_memory", "cryptography", "_cffi_backend", "cffi", "_openssl", "_rust")

PROBE = textwrap.dedent("""
    import json, sys
    before = set(sys.modules)
    {body}
    print(json.dumps({{"modules": sorted(sys.modules), "new": sorted(set(sys.modules) - before)}}))
""")


def _isolated(tmp_path: Path, body: str, *flags: str) -> dict:
    home, cwd, tmp = tmp_path / "home", tmp_path / "cwd", tmp_path / "tmp"
    for d in (home, cwd, tmp):
        d.mkdir()
    env = {"HOME": str(home), "TMPDIR": str(tmp), "PATH": os.environ.get("PATH", ""),
           "XDG_CONFIG_HOME": str(home / ".config"), "XDG_DATA_HOME": str(home / ".local/share"),
           "XDG_CACHE_HOME": str(home / ".cache"), "LANG": "C.UTF-8"}
    result = subprocess.run([sys.executable, "-I", "-B", *flags, "-c", PROBE.format(body=body)],
                            cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    for d in (home, cwd, tmp):
        assert list(d.rglob("*")) == [], f"files created in {d.name}"
    return json.loads(result.stdout.strip().splitlines()[-1])


def _top_level(modules: list[str]) -> set[str]:
    return {m.split(".")[0] for m in modules}


def test_import_is_side_effect_free_and_pulls_in_no_host_or_network_stack(tmp_path):
    out = _isolated(tmp_path, "import locus_memory\nassert locus_memory.__version__", "-W", "error")
    modules = set(out["modules"])
    for name in FORBIDDEN:
        assert not any(m == name or m.startswith(name + ".") for m in modules), name
    for name in NETWORK_CLIENTS:
        assert name not in modules, name
    # Only what ``import locus_memory`` added (interpreter/venv start-up modules are excluded).
    third_party = _top_level(out["new"]) - set(sys.stdlib_module_names) - set(sys.builtin_module_names)
    assert {m for m in third_party if not m.startswith(ALLOWED_THIRD_PARTY)} == set()
    assert "locus_memory" in third_party


def test_importing_every_submodule_stays_local(tmp_path):
    body = textwrap.dedent("""
        import importlib, pkgutil, locus_memory
        for info in pkgutil.walk_packages(locus_memory.__path__, "locus_memory."):
            importlib.import_module(info.name)
    """)
    out = _isolated(tmp_path, body)
    for name in FORBIDDEN:
        assert not any(m == name or m.startswith(name + ".") for m in out["modules"]), name
    assert "locus_memory.engine" in out["modules"] and "locus_memory.admin" in out["modules"]


def test_constructing_and_closing_an_engine_creates_nothing(tmp_path):
    body = textwrap.dedent(f"""
        import secrets
        from locus_memory import MemoryEngine, StaticKeyProvider
        MemoryEngine({str(tmp_path / "home" / "root")!r}, StaticKeyProvider({{"k1": secrets.token_bytes(32)}})).close()
    """)
    _isolated(tmp_path, body)


def test_an_open_existing_only_engine_creates_nothing_for_a_missing_vault(tmp_path):
    # _isolated asserts that HOME (which holds the root), the cwd and TMPDIR stay empty.
    body = textwrap.dedent(f"""
        import secrets
        from locus_memory import MemoryEngine, StaticKeyProvider
        from locus_memory.errors import NotFound
        from locus_memory.models import AccessContext, Operation, PartitionRef
        engine = MemoryEngine({str(tmp_path / "home" / "root")!r},
                              StaticKeyProvider({{"k1": secrets.token_bytes(32)}}), create_partitions=False)
        access = AccessContext(principal="p", partition=PartitionRef("standalone", "default"),
                               operations=frozenset(Operation))
        for call in (engine.status, engine.export, engine.list):
            try:
                call(access)
            except NotFound:
                continue
            raise SystemExit("an open-existing-only engine served a vault that does not exist")
        engine.close()
    """)
    _isolated(tmp_path, body)


def test_core_flows_never_touch_the_network(engine, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("network access attempted")

    for name in ("create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    access = access_for(projects=("proj-a",))
    record = engine.remember(access, RememberRequest(content="offline", scope=Scope.of(project="proj-a"))).record
    candidate = engine.propose(access, CandidateProposal(content="offline candidate", scope=Scope.of(project="proj-a"),
                                                         sources=(SourceRef(SourceKind.DOCUMENT, "d"),))).record
    engine.approve(access, candidate.id, expected_revision=1)
    engine.explain(access, record.id)
    engine.status(access)
    assert engine.export(access, include_history=True)["records"]
    engine.forget(access, ForgetTarget("memory", record.id))
    engine.rotate_data_key(access)


def test_distribution_metadata_matches_the_package():
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text()
    version = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE).group(1)
    assert locus_memory.__version__ == version
    try:
        assert importlib.metadata.version("locus-memory") == version
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover - running from a source tree
        pytest.skip("package metadata not installed")
    requires = importlib.metadata.requires("locus-memory") or []
    runtime = [r for r in requires if "extra ==" not in r]
    assert [re.split(r"[<>=!~ ;]", r)[0] for r in runtime] == ["cryptography"]
    assert (importlib.resources.files("locus_memory") / "py.typed").is_file()


def test_public_names_resolve():
    for name in locus_memory.__all__:
        assert getattr(locus_memory, name) is not None, name
