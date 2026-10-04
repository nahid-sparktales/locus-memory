#!/bin/bash
# Build the wheel, then install it into clean virtualenvs OUTSIDE the checkout (offline,
# from a local wheelhouse) for every supported interpreter and run the quickstart and
# CLI smoke tests from an empty working directory.
#
#   scripts/verify_wheel.sh <work-dir> <python> [<python> ...]
#
# The wheelhouse needs the cryptography wheel for each interpreter; populate it once
# with:  pip download --only-binary=:all: cryptography -d <work-dir>/wheelhouse --python-version X.Y
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:?work dir}"; shift
mkdir -p "$WORK/dist" "$WORK/wheelhouse"
rm -f "$WORK"/dist/locus_memory-*.whl
"$REPO/.venv/bin/python" -m pip wheel --no-deps --no-build-isolation -w "$WORK/dist" "$REPO" >/dev/null
WHEEL="$(ls "$WORK"/dist/locus_memory-*.whl)"
echo "wheel: $WHEEL"
shasum -a 256 "$WHEEL"
for PY in "$@"; do
  VER="$("$PY" -c 'import sys;print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  ENV="$WORK/venv-$VER"
  rm -rf "$ENV"
  "$PY" -m venv "$ENV"
  "$ENV/bin/python" -m pip install -q --no-index --find-links "$WORK/wheelhouse" "$WHEEL"
  RUN="$(mktemp -d "$WORK/run-$VER.XXXX")"
  cp "$REPO/examples/quickstart.py" "$RUN/"
  (
    cd "$RUN"
    # Prove the import does not come from the checkout and pulls in no host packages.
    "$ENV/bin/python" - <<'PY'
import sys, locus_memory, pathlib
assert "locus-memory/src" not in locus_memory.__file__, locus_memory.__file__
before = set(sys.modules)
import locus_memory.cli  # noqa: F401
forbidden = {m for m in sys.modules if m.split(".")[0] in {"ollama_code", "langgraph", "langgraph_workflow", "fastapi", "requests", "httpx"}}
assert not forbidden, forbidden
print("import ok from", pathlib.Path(locus_memory.__file__).parent, "python", sys.version.split()[0])
PY
    HOME="$RUN/home" "$ENV/bin/python" quickstart.py "$RUN/demo"
    "$ENV/bin/locus-memory" --help >/dev/null
    "$ENV/bin/locus-memory" --root "$RUN/cli" --json init >/dev/null
    "$ENV/bin/locus-memory" --root "$RUN/cli" --json remember "wheel smoke memory" >/dev/null
    "$ENV/bin/locus-memory" --root "$RUN/cli" --json search "wheel smoke" | "$ENV/bin/python" -c 'import json,sys;d=json.load(sys.stdin);assert d["hits"],d;print("cli search ok")'
  )
  echo "python $VER: OK"
done
