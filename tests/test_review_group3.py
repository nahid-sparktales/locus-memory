"""Review group 3 regressions.

exclusion-unicode-casefold-bypass: repository secret-file exclusions compared
``str.lower()`` forms, so names a case-insensitive filesystem treats as the same file
(APFS: ``ſecrets.py`` with U+017F LONG S *is* ``secrets.py``) got past ``*secret*``,
``credentials*``, ``id_rsa*`` and ``.ssh/``; their contents were read, parsed, stored
as observations and returned to agents. Every repository here is a disposable git repo
under pytest's tmp_path, built with a git helper that ignores the developer's own git
configuration.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import access_for, scan_for_plaintext
from locus_memory.errors import InterchangeInvalid, RepositoryAccessDenied
from locus_memory.host import HostCapabilities
from locus_memory.models import Actor, Operation
from locus_memory.repository import interchange as ix
from locus_memory.repository import scanner

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git is required for repository memory tests")

LONG_S = "ſ"  # LATIN SMALL LETTER LONG S: case-folds to "s"
KELVIN = "K"  # KELVIN SIGN: case-folds to "k"
DOTLESS_I = "ı"  # upper-cases to "I" (equal to "i" on NTFS / exFAT)
SECRET = "hunter2-PROD-PASSWORD-xyz"


# ---------------------------------------------------------------------- helpers
def _git(cwd: Path, *args: str) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"})
    return subprocess.run(
        [GIT, "-c", "user.name=Test User", "-c", "user.email=test@example.invalid",
         "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
         *args],
        cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout


def _make_repo(path: Path, files: dict[str, str]) -> Path:
    path.mkdir(parents=True)
    _git(path, "init", "-q", ".")
    for name, text in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "initial")
    return path


def _allowed(tmp_path: Path) -> Path:
    path = tmp_path / "allowed"
    path.mkdir()
    return path


def _engine(make_engine, clock, allowed: Path):
    return make_engine(host=HostCapabilities(clock=clock, allowed_repository_roots=(allowed,)))


def _user():
    return access_for(repositories=("r1",), projects=("proj-a",))


def _agent_reader():
    return access_for(actor=Actor.AGENT, repositories=("r1",), projects=("proj-a",), operations={Operation.READ})


def _current_paths(eng, access) -> list[str]:
    return [r.extra.get("path") for r in eng.repository_observations(access, "r1")]


def _folds_long_s(directory: Path) -> bool:
    """True when the filesystem treats U+017F as "s" (case-insensitive APFS does)."""
    probe = directory / "probe-secrets.py"
    probe.write_text("x")
    try:
        return (directory / f"probe-{LONG_S}ecrets.py").exists()
    finally:
        probe.unlink()


# ---------------------------------------------------------------------- matcher
@pytest.mark.parametrize("alias", [
    f"{LONG_S}ecrets.py",                # *secret*
    f"config/{LONG_S}ecret.yaml",        # *secret*
    f"credential{LONG_S}.json",          # credentials*
    f"credent{DOTLESS_I}als.json",       # credentials*
    f"id_r{LONG_S}a",                    # id_rsa*
    f".{LONG_S}{LONG_S}h/config",        # .ssh/
    f"keys/prod.{KELVIN}ey",             # *.key
    f"deploy/.aw{LONG_S}/config",        # .aws/
    "ｓｅｃｒｅｔｓ.txt",  # fullwidth "secrets": *secret* (compatibility form)
    "secrets.py",                        # control: plain spelling
    "SECRETS.PY",                        # control: ASCII case
])
def test_case_folding_aliases_of_secret_names_are_excluded(alias):
    assert scanner.Exclusions().excluded(alias) is True


@pytest.mark.parametrize("path", [
    "app.py", "README.md", "src/main.py", "straße.py", "café/menu.py", f"docs/{DOTLESS_I}ntro.md",
    "src/Ｗidget.py",
])
def test_ordinary_names_stay_included(path):
    assert scanner.Exclusions().excluded(path) is False


def test_configured_patterns_match_across_case_folding_and_normalization():
    excl = scanner.Exclusions(["café/", f"{LONG_S}taging/*.yaml", "ma?e.txt"])
    assert excl.excluded("café/menu.txt")  # NFD path, NFC pattern: one directory on APFS
    assert excl.excluded("CAFÉ/menu.txt")
    assert excl.excluded("staging/prod.yaml") and excl.excluded(f"{LONG_S}TAGING/prod.YAML")
    # Never narrower than the plain lower-case comparison: "?" still matches the single "ß".
    assert excl.excluded("maße.txt")
    assert not excl.excluded("cafe/menu.txt") and not excl.excluded("staging/readme.md")


def test_interchange_rejects_a_case_folding_alias_of_a_secret_path():
    doc = ix.new_document(
        repository_id="r1", hash_algorithm="sha1", producer={"name": "t", "kind": "tool"},
        records=[{"type": "repository", "repository_id": "r1", "object_format": "sha1"},
                 {"type": "file", "path": f"config/{LONG_S}ecrets.yaml", "blob": "a" * 40}])
    with pytest.raises(InterchangeInvalid, match="excluded"):
        ix.validate_document(doc)


# ---------------------------------------------------------------------- end to end
@needs_git
def test_alias_named_secret_file_is_never_read_stored_or_returned(tmp_path, make_engine, clock, root):
    alias = f"{LONG_S}ecrets.py"
    allowed = _allowed(tmp_path)
    repo = _make_repo(allowed / "r1", {"app.py": "import os\n", alias: f'"""prod db: {SECRET}"""\nDB = "x"\n'})
    eng = _engine(make_engine, clock, allowed)
    user, agent = _user(), _agent_reader()
    eng.register_repository(user, repo, repository_id="r1")
    result = eng.snapshot_repository(user, "r1")
    assert result["coverage"]["excluded"] == 1
    observations = eng.repository_observations(user, "r1", current_only=False)
    assert [r.extra.get("path") for r in observations] == ["app.py"]
    assert not any(SECRET in (r.content or "") or alias in (r.content or "") for r in observations)
    for access in (agent, user):
        with pytest.raises(RepositoryAccessDenied, match="excluded"):
            eng.read_repository_file(access, "r1", alias)
        with pytest.raises(RepositoryAccessDenied, match="excluded"):
            eng.repository_observations(access, "r1", path=alias)
    history = eng.repository_history(user, "r1")
    assert history[0]["paths"] == ["app.py"] and history[0]["omitted_paths"] == 1
    exported = json.dumps(eng.export_repository_interchange(user, "r1"), ensure_ascii=False)
    assert alias not in exported and SECRET not in exported
    assert scan_for_plaintext(root, SECRET) == []


@needs_git
def test_snapshot_taken_under_the_old_matcher_is_not_reused(tmp_path, make_engine, clock, monkeypatch):
    alias = f"{LONG_S}ecrets.py"
    allowed = _allowed(tmp_path)
    repo = _make_repo(allowed / "r1", {"app.py": "import os\n", alias: f'"""prod db: {SECRET}"""\n'})
    eng = _engine(make_engine, clock, allowed)
    user = _user()
    eng.register_repository(user, repo, repository_id="r1")
    with monkeypatch.context() as legacy:  # the pre-fix matcher and fingerprint
        legacy.setattr(scanner, "fold_name", str.lower)
        legacy.setattr(scanner.Exclusions, "fingerprint",
                       lambda self: hashlib.sha256("\n".join(sorted(self.patterns)).encode()).hexdigest())
        before = eng.snapshot_repository(user, "r1")
        assert before["coverage"]["excluded"] == 0
        assert _current_paths(eng, user) == ["app.py", alias]
    after = eng.snapshot_repository(user, "r1")
    assert after["reused"] is False and after["snapshot_id"] != before["snapshot_id"]
    assert after["coverage"]["excluded"] == 1
    assert _current_paths(eng, user) == ["app.py"]
    with pytest.raises(RepositoryAccessDenied, match="excluded"):
        eng.read_repository_file(_agent_reader(), "r1", alias)


@needs_git
def test_secret_written_through_an_apfs_case_folding_alias_is_excluded(tmp_path, make_engine, clock):
    """The reported scenario: the index tracks ``ſecrets.py``; the user writes ``secrets.py``."""
    allowed = _allowed(tmp_path)
    if not _folds_long_s(allowed):
        pytest.skip("the filesystem does not fold U+017F to 's' (not case-insensitive APFS)")
    alias = f"{LONG_S}ecrets.py"
    repo = _make_repo(allowed / "r1", {"app.py": "import os\n", alias: '"""placeholder"""\n'})
    (repo / "secrets.py").write_text(f'"""prod db: {SECRET}"""\nDB = "x"\n')
    assert SECRET in (repo / alias).read_text()  # the write landed in the tracked alias file
    eng = _engine(make_engine, clock, allowed)
    user = _user()
    eng.register_repository(user, repo, repository_id="r1")
    result = eng.snapshot_repository(user, "r1")
    assert result["coverage"]["excluded"] == 1
    observations = eng.repository_observations(user, "r1", current_only=False)
    assert [r.extra.get("path") for r in observations] == ["app.py"]
    assert not any(SECRET in (r.content or "") for r in observations)
    for path in (alias, "secrets.py"):
        with pytest.raises(RepositoryAccessDenied, match="excluded"):
            eng.read_repository_file(_agent_reader(), "r1", path)
