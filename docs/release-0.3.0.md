# 0.3.0 implementation and validation record

Status: release verification resumed on 2026-10-05 at the user's explicit request,
including publication of the dependency required by Locus 4.0.0. This supersedes
the 2026-10-04 pause for RAM usage. Existing canonical profiles and the completed
cutover are untouched. The record below separates package checks from host application
and live-model checks; historical quality measurements are retained.

## Release verification

All stores used by this run are disposable synthetic fixtures. No private memory,
model credential, live provider request or production migration is part of these checks.
The visual-guide PDF and original production-campaign report retain their October 4
pre-release snapshot; this Markdown record supplies the current validation state.

- CPython 3.14.6 initial full suite: 1,588 passed, one optional source-parity skip,
  two failures. The existing paraphrase test exposed an imperative `Keep` wrongly
  classified as an entity; it is now in the instruction vocabulary. The other
  failure was stale editable-package version metadata during the release bump.
- Final installed 0.3.0 wheel, CPython 3.14.6: **46 focused tests passed** covering
  evidence admission, package metadata/import boundaries, recall runtime, submission
  receipts and encrypted transcript caches.
- Final installed 0.3.0 wheel, CPython 3.10.22: **1,590 passed, one optional source-parity
  skip**, in 262.12 seconds. The source-parity fixture requires a historical Locus export.
- Final wheel on both interpreters: all 75 submodules import in isolated processes;
  standalone CLI init/remember/search and the complete quickstart pass, including
  restart, correction, forget and encrypted-store plaintext-canary checks.
- Locus host tests against the final installed wheel: **218 passed**, including
  memory scopes, review routes, migration isolation, restore recovery, native signed-helper
  checkpoint parsing and runtime packaging probes. The Locus application build and its
  broader suites are tracked by that repository's 4.0.0 release.
- Frozen held-out production policy, five seeds 20303030–20303034: all hard gates
  pass; recall@5 0.9737–1.0, abstention accuracy 1.0, false abstention 0.0, and zero
  scope, future-evidence, deletion, corrected-history or plaintext leaks. Policy
  source hashes were recorded before evaluation and checked against the exact wheel.
  [Full synthetic results](../evals/results/2026-10-05-release-0.3.0/heldout.json).
- `ruff check src tests` and staged `gitleaks git --staged --redact` pass.

The exact wheel is `locus_memory-0.3.0-py3-none-any.whl`, SHA-256
`aafdbdf72b04aa2e83589cf0b88f1f9c8493b6ab9e97b65b6deac6dd5802d4b6`.
Two builds were byte-identical using CPython 3.14.6, setuptools 84.0.0, wheel 0.48.0
and `SOURCE_DATE_EPOCH=1791196800`. The wheel includes Apache-2.0 license/notice,
the typed marker and interchange schema. Its only runtime dependency remains
`cryptography>=42`; Python >=3.10 remains supported.

```sh
SOURCE_DATE_EPOCH=1791196800 .venv/bin/python -m pip wheel --no-deps \
  --no-build-isolation --wheel-dir /tmp/locus-memory-030-release/dist .
.venv/bin/python -m pytest tests/test_evidence_policy.py tests/test_packaging_imports.py \
  tests/test_runtime.py tests/test_context_submissions.py tests/test_transcript_cache_privacy.py
.venv310/bin/python -m pytest
.venv/bin/python -m locus_memory.evaluation.production --seed 20303030 \
  --repetitions 5 --out evals/results/2026-10-05-release-0.3.0/heldout.json
```

The test environments install the exact wheel with `--no-deps`, replacing editable
installs, before the final checks. Locus packaging now probes the newly required
cache/submission APIs and imports the actual backend before producing runtime archives.
No live agent-task campaign or semantic embedding-quality comparison was rerun for this
release. The previous 2/6 versus 2/6 task result remains the only measured live result;
no task-quality improvement is claimed. Keyword retrieval remains the default.

## Implemented ownership boundary

The package owns record behavior, scopes, current-evidence selection, encrypted receipt
references, vectors, episodes/procedures, transcript cache envelopes, ledger reconciliation,
bootstrap and migration. Constructors accept injected HostCapabilities without replacing
authoritative ownership fences. Locus owns authenticated identity, provider calls, task
verification, approved suite execution, Swift review UI and signed Keychain custody.

- Inspector: a Memory action on turns/runs; selected/final-submitted/failed/uncertain states,
  agent and attempt identity, scoped current content, changed revision labels, token budget,
  omissions, revalidation changes and semantic fallback. Receipts are encrypted references
  and reasons, retained for 30 days / 5,000 receipts. “Submitted to model” is a delivery claim,
  not a claim that the model used the information.
- Retrieval: current model-facing history excludes corrected evidence; historical browsing
  is explicit. Preferences do not establish factual answerability. Qualifier/entity guards
  and relevance order avoid staging/production substitutions. The original benchmark and
  baseline results are preserved.
- Agents: native Codex opt-in defaults false; existing scopes and search/proposal policy
  remain authoritative. Memory travels as delimited reference data outside trusted developer
  instructions. Provider context is rebuilt when memory changes; transmitted content cannot
  be retracted. Helper proposals resolve retained host-owned attempts and remain candidates.
- Embeddings: host-owned Ollama adapter, explicitly selected installed model, loopback only,
  no proxy/redirect/model pull, bounded requests, digest/dimension/preprocessing identity,
  encrypted vectors, maintenance indexing, lexical fallback. Keyword retrieval stays the
  supported default until the semantic acceptance threshold is demonstrated.
- Learning: terminal task evidence is captured within the owning agent/workspace. The host
  resolves TaskStateStore receipts against task identity, revision, check hashes and input
  fingerprints; user acceptance or assistant prose cannot create verified success. Stable
  logical episodes prevent resumes from counting as independent successes. Procedures need
  two independent episodes, a human-approved version-bound fixed suite with negative cases,
  disposable worktrees, successful execution and human approval. Approval does not install
  or execute instructions. Invalidated/forgotten evidence revokes dependent eligibility.
- Privacy: persistent saved-chat cache uses AES-256-GCM session envelopes and RAM FTS.
  Profile-exclusive upgrades verify rebuilt encrypted cache before removing the old index.
  Raw transcript JSONL files are unchanged, and historical copies cannot be forensically
  erased. macOS restore checkpoints use the signed LocusMemoryGuard login-Keychain helper.
  Other hosts retain injectable mirrors and explicitly report unavailable protection;
  enrolled profiles cannot silently downgrade. Missing custody can be recovered offline only
  with authenticated checkpoint evidence and explicit acknowledgment of lost deletion history.
  Unknown or corrupt high-water marks must be restored; the guard does not invent history.

## Evidence completed before tests were deferred

These are focused runs of intermediate code, not certification of the final working tree:

- Package privacy/regressions: 87 passed; capability constructor wiring: 3 passed.
- Host privacy/search/isolation: 20 passed. A signed native helper smoke test used a disposable
  Keychain account; monotonic updates and fork/CAS rejection passed, then the account was removed.
- Package context/submissions: 87 passed; host native/adapter: 97 passed.
- Host local embeddings: 21 passed; budget/paired smoke harness: 5 passed.
- Host task-learning authority/cancellation: 9 passed; bootstrap/reusable checks: 18 passed.
- Full package CPython 3.14 and 3.10.22 suites and the full host suite were interrupted.
  A host route-contract failure from new API routes was identified; the route fixture was
  updated afterward and has not been rerun. The interruption also caused pytest teardown noise.
- At that point, later retrieval, recovery, UI and learning integration changes remained untested; current checks are recorded above.

The original offline evaluation remains in `evals/results/`. New measurements live separately
in [production-initial](../evals/results/2026-10-04-production-initial/README.md).
Calibration on three seeds was perfect on its generated corpus. Five held-out seeds showed
recall@5 0.947–1.0 and abstention 1.0, but false abstention reached 0.0263, so the nonregression
gate was not met. Subsequent lexical normalization and task-prompt admission fixes are covered by the current checks above.

A small local `qwen3.6:27b` campaign completed 12 requests: six synthetic JSON artifact tasks
with and without memory. Both arms passed 2/6. Source inspection suggests the pre-fix lexical
filter could withhold relevant context when artifact-format words diluted its overlap rule.
The initial artifact lacks selection diagnostics and output JSON, so that cause is an
inference rather than a recorded per-case finding. This records a failure of the tested configuration to help;
it does not establish that memory cannot help, or measure broad coding-agent outcomes.
Usage: 1,099 tokens, $0. No installed embedding model was selected, so semantic quality gains
have not been measured. Remaining campaign allowance: 248,901 tokens and $10, subject to
pre-request reservations and verified pricing. Small samples are not a broad quality claim.

Task-outcome grading follows the principle of checking actual environment state rather than
assistant claims from [Anthropic's agent evaluation guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents).

## Validation and release sequence

Run stages **serially**, keeping local models unloaded during test suites and builds:

1. Focused regressions for final inspector, scope changes, ambiguous delivery, helper promotion,
   verified learning, immutable suite bindings, cancellation and Keychain recovery.
2. Complete package suites on 3.14 and 3.10.22, then the host suite. Resolve failures before
   proceeding. Do not run the three suites concurrently.
3. Fresh held-out retrieval run with the policy frozen first. Require abstention ≥0.75 and no
   false-abstention regression; zero scope/deletion/corrected-history leaks.
4. Paired real agent tasks (`memory_comparison=true`) from identical fixed workspace snapshots, model settings and checks;
   learning disabled. Set `memory_campaign_token_limit=248901` for this campaign continuation
   after the initial 1,099 tokens. Reuse the same persistent campaign owner across retries. Unknown-priced
   billable routes must be skipped. Native routes without enforceable pre-request output caps
   are ineligible for a strict bounded campaign; ordinary native memory is unaffected. Record incomplete campaigns without claiming improvement.
5. Optional semantic comparison only with an explicitly installed/selected embedding model.
   Require ≥5 percentage-point recall@5 gain, no precision/abstention regression and ≤5-second
   recall deadline; otherwise retain keyword-only as the supported default.
6. Focused Swift tests, signed Release build/audit, and disposable fresh/existing-profile smoke.
   Restore tests must cover database-only, ledger-only, combined/fork restores and custody loss.
7. Only after acceptance: bump package metadata to 0.3.0, build/rebuild the wheel, verify isolated
   imports and deterministic bytes, compute SHA-256, publish the exact release asset, and update
   Locus's `requirements-runtime.in`, `requirements-runtime.lock`, `agent/pyproject.toml`, dependency
   provenance and bundling audit version/hash together. Build/audit the app against that exact wheel.
8. Public distribution of Locus stays in its normal application release process. Do not repeat
   the existing canonical cutover or mutate real profiles during recovery tests.
