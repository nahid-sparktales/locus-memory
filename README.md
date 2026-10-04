# locus-memory

A local-first, encrypted, scope-enforcing memory engine, extracted from Locus. It is an
in-process Python library (Python >= 3.10). Its only runtime dependency is `cryptography`.

* **Authorization comes from the host.** Every engine call takes a trusted `AccessContext` that
  the host builds from its own authenticated state: principal, partition, actor, scope grants
  and allowed operations. Nothing read from the store, from a transcript or from a model can
  widen it.
* **Encrypted at rest.** Records are sealed with AES-256-GCM under per-partition data keys,
  and those keys are wrapped under host-supplied master keys. See `src/locus_memory/crypto.py`.
  The package never reads a keychain and never generates a new key over an existing vault.
* **No side effects on import.** Importing does no I/O and uses no network. A partition's
  database is opened when the first operation for that partition arrives.

## Install from a checkout

```bash
pip install -e .           # library and the `locus-memory` command
pip install -e '.[dev]'    # adds pytest and ruff
```

## Library use

```python
import secrets
from locus_memory import MemoryEngine, StaticKeyProvider
from locus_memory.models import (AccessContext, Operation, PartitionRef, RememberRequest, Scope,
                                 ScopeGrants)

keys = StaticKeyProvider({"k1": secrets.token_bytes(32)})  # the host holds the master key
access = AccessContext(principal="user-1", partition=PartitionRef("standalone", "default"),
                       grants=ScopeGrants(projects=frozenset({"proj-a"})),
                       operations=frozenset({Operation.READ, Operation.WRITE}))
with MemoryEngine("/path/to/store", keys) as engine:
    engine.remember(access, RememberRequest(content="Use tabs in Makefiles",
                                            scope=Scope.of(project="proj-a")))
    result = engine.search(access, "makefiles")
```

`MemoryEngine` (`src/locus_memory/engine.py`) is the only public entry point. It covers
memory records and review, ranked search, context packets within a token allowance, the
session history archive, episodes and procedures, repository observations, forgetting, and
key rotation.

## Command line

`locus-memory` (or `python -m locus_memory.cli`) is a diagnostic CLI for one local profile.
It uses a file key under `--root` (default `$LOCUS_MEMORY_HOME`, else `~/.locus-memory`).

```bash
locus-memory --root ./store init
locus-memory --root ./store --project p1 remember "Use tabs in Makefiles" --scope-project p1
locus-memory --root ./store --project p1 search makefiles
locus-memory --root ./store --project p1 forget --project p1        # preview only (exit 2)
locus-memory --help
```

`forget`, `export` and the migration cutover and rollback commands only preview unless you pass
`--yes`. Exit codes: 0 ok, 1 error, 2 preview only (nothing changed), 3 capability unavailable.

## Evaluation

The package includes an offline benchmark that runs over a synthetic corpus. It uses no
network, no model and no real user data.

```bash
python -m locus_memory.evaluation --out /tmp/eval-smoke --repetitions 1 --size small
locus-memory eval run --out /tmp/eval-run --repetitions 1
```

Scores are rates and counts over synthetic questions. They are never probabilities. The design,
the rollout criteria and the measured results are in [docs/evaluation.md](docs/evaluation.md).

## Documentation

* [docs/locus-compatibility.md](docs/locus-compatibility.md): an audit of Locus's current memory
  behavior, including formats and defects.
* [docs/ownership-and-extraction.md](docs/ownership-and-extraction.md): who owns each memory
  responsibility, and the extraction plan.
* [docs/evaluation.md](docs/evaluation.md) and [evals/README.md](evals/README.md): the benchmark.

## Development

```bash
python -m pytest
ruff check src tests
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
