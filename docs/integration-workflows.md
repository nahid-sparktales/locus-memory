# Workflows and Agent Dispatcher: optional consumers and producers

langgraph-workflow and Agent Dispatcher are optional. Neither is needed to install or run
`locus-memory`, and the package imports neither (R1.3, R1.5): `tests/test_packaging_imports.py`
fails if importing the package pulls in `langgraph` or `agent_dispatcher`, and
`scripts/verify_wheel.sh` checks the installed wheel for `langgraph` and `langgraph_workflow`.

This document records what the two projects do today, a recommended contract for connecting them to
memory through Locus, and what is not implemented. **No integration between `locus-memory` and either
project exists.** Everything under "recommended contract" is a proposal.

Sources (read-only audits; nothing in either repository was modified):

| Repository | Path | Commit | Notes |
|---|---|---|---|
| langgraph-workflow | `/Users/nahid/Documents/langgraph-workflow` | `52799242a53d80ed067797d0cbb6e1c83363214e` (package 0.4.1) | |
| Agent Dispatcher | `/Users/nahid/Documents/agent-skills` | `d68446fe33c4e2162c1eb4d4d15bb663a3040888` | 2 uncommitted user edits: `decision/redact.py`, `tests/test_retrieval_security.py` |

The audit results are summarized in [locus-compatibility.md](locus-compatibility.md) §15 (Dispatcher),
§16 (langgraph-workflow) and §19.5, and in [ownership-and-extraction.md](ownership-and-extraction.md)
§3.8, §4.4 and §5. Paths in §2 and §3 below are relative to the repository being described. The Locus
side of the contract is in [integration-locus.md](integration-locus.md); the repository-intelligence
format is in [repository-interchange.md](repository-interchange.md).

---

## 1. At a glance

| | langgraph-workflow | Agent Dispatcher |
|---|---|---|
| Role toward memory | consumer (jobs could receive recalled memory); possible producer of candidates and episodes from verified outcomes | producer (repository intelligence, task experience, procedural learning) |
| Memory API today | none: the host port has no memory method or capability | no importable API; CLI `--json` outputs and its own context packet |
| How it meets Locus | shipped Locus plugin (MCP stdio server); in-process reference adapter `LocusHost` (harness only, not shipped) | bundled into Locus as `agent/ollama_code/builtin_skills/agent-dispatcher`; Locus reads the in-workspace `.agent-dispatcher/project-map.json` |
| Its own storage | checkpoint sidecar and plugin job ledger (SQLite) | `~/.cache/agent-dispatcher/...` (SQLite and JSON) |
| Encryption at rest | optional host cipher for checkpoint blobs; the plugin passes none | none |
| Integration with `locus-memory` | none | none; no exporter exists |

---

## 2. langgraph-workflow today

### 2.1 Host port

`src/langgraph_workflow/ports.py` defines `WorkflowHost`, the only host port, with nine methods:
`capabilities`, `admit`, `revalidate`, `execute`, `lookup`, `cancel`, `verify`, `authorize_decision`,
`publish`. The capability set `CAPABILITIES` is `jobs.read`, `jobs.write`, `verify`, `decisions`,
`events`, `cancel`. There is no memory method and no memory capability; the module docstring says the
host "remains authoritative for ... memory". Graphs compile with a checkpointer only and no LangGraph
`BaseStore` (`executor.WorkflowExecutor`). The project lists "scoped memory view / memory candidates" as
deferred (`docs/implementation-status.md`, `docs/locus-integration-map.md`).

### 2.2 Two integration modes, and where memory reaches jobs

* **Plugin mode (shipped).** An MCP stdio server (`mcp_server.build_server`) launched by Locus's MCP
  manager. The Locus agent carries out each job in an ordinary chat turn and reports back through the
  `workflow_report` tool; `agent_host.AgentHost` hands each operation out once. Because jobs are
  ordinary chat turns, whatever recall path Locus uses for chat applies to them: the legacy recall, or
  the Stage-2 adapter in `shadow`/`enabled` mode. This follows from reading the call path; it was not
  tested with the plugin.
* **In-process reference adapter (harness only).** `integrations/locus/adapter_reference.LocusHost` runs
  read jobs through `TeamOrchestrator.run_read_job` (a langgraph-workflow patch to Locus that is not
  upstream but still applies to `b332e455`), write jobs through `AgentCore.run_turn`, verification
  through `TaskVerifier`, and publishes `workflow_event` rows into Locus's `RunStore`. **It never
  computes or injects memory**: the reader profile has no `_memory_context` and `AgentCore` is built
  without `configure_agent(memory_context=...)` (`integrations/locus/harness.py`). In-process jobs
  therefore run without approved memory, unlike native Locus team members.

### 2.3 Checkpoints and stored state

* `checkpoints.CheckpointStore` is a SQLite WAL sidecar (LangGraph `SqliteSaver` tables plus
  `lgw_attempts`, `lgw_leases`, `lgw_controls`, `lgw_decisions`), file mode 0600 in a 0700 directory.
  The host chooses its location: in-process `<Locus profile>/langgraph-workflow/checkpoints.sqlite3`,
  plugin `<PLUGIN_DATA>/workspaces/<key>/checkpoints.sqlite3`.
* Checkpoint state holds the frozen request (goal, checks, plan, drawn definition), the admission, and
  every job receipt including its output; `LocusHost` keeps an output summary of up to 2,000 characters.
* `checkpoints.StrictEncryptedSerializer` encrypts checkpoint and pending-write blobs with a
  host-injected LangGraph `CipherProtocol` and fails closed on unencrypted blobs. **The plugin constructs
  `WorkflowExecutor` with no cipher**, so its checkpoints are plaintext. Even with a cipher, thread ids,
  checkpoint metadata, channel names and the `lgw_*` tables stay plaintext by design.
* `agent_host.AgentHost` keeps job specs, agent-reported results, workspace hashes, events and claim
  tokens in `<PLUGIN_DATA>/workspaces/<key>/agent-host.sqlite3`. It has **no encryption option**, its file
  mode follows the umask, and its rows are never pruned. `workspaces.json` (absolute paths) is also
  written with default permissions.
* The plugin prunes terminal attempts older than `keep_finished_days` (default 30) through
  `CheckpointStore.prune` when it first opens a workspace's executor, but attempts marked
  `blocked:<reason>` never match the terminal list and are kept.

### 2.4 Replay and identity

* `state.spec` builds `operation_id = f"{attempt_id}/{key}"`. Keys are deterministic per node (for
  example `inspect`, `plan`, `implement-<plan digest>`, `repair-<n>`, `review-<n>`,
  `investigate-<i>-<digest>`, `synthesize`, and `<node_id>-<visit>` for drawn workflows).
* `state.Runtime.run_job` looks an operation up with `host.lookup` before submitting it, marks a
  fingerprint mismatch `uncertain/operation_conflict`, resubmits only `admitted`, `running`,
  `budget_exhausted` or `busy` operations, and counts only new operations, so replay cannot double count.
* Decision ids are deterministic on re-entry; `lgw_decisions` records each response digest once and
  rejects a different answer as `duplicate_decision`.
* Plugin attempt ids are `lgw-<12 hex>-<10 hex>` and double as run and task ids. `LocusHost` job ids are
  `'{operation_id}#{input_fingerprint}'`. The package's identifier regex is
  `^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,159}$` with `..` rejected (`contracts.py`).

### 2.5 Events and usage

Events use the schema `langgraph-workflow.event/1` (`events.make_event`), with
`event_id = sha256(json([attempt_id, kind, operation_id, key]))[:32]`. Redaction replaces secret-shaped
keys and values, truncates strings at 2,000 characters and keeps at most 64 items to depth 6. It does
not know about memory content. In plugin mode, events stay in `agent-host.sqlite3` and never reach
Locus's `RunStore`. Usage reported by the executor is never authoritative; Locus's usage ledgers are.

### 2.6 Gaps the audit recorded

* `LocusHost` cannot run drawn (custom) workflows: `RESPONSE_CONTRACT` and `ROLE` have no `task` key.
* The compatibility record covers package 0.1.0 against Locus `5ac5b5b1`, not 0.4.1 against
  `b332e455`; the Locus integration suite was not re-run.
* `langsmith` is imported directly by `executor.py` but not declared.
* An unrelated, reverted Locus-native LangGraph runtime left `~/.ollama-code/langgraph/runs.sqlite`
  and `workflows/`. Migration tooling must not confuse it with the langgraph-workflow sidecar.

---

## 3. Agent Dispatcher today

### 3.1 Packaging and contracts

There is no importable package. Each module loads its siblings with `exec(compile(source))` into a
private namespace (for example `repository_intelligence._sibling`). The stable consumer contracts are
the CLI `--json` outputs and the context packet (`schema_version` 1, built in `context.select_context`)
with optional `repository_intelligence`, `memory` and `learning` sections.

### 3.2 Stores

All under `~/.cache/agent-dispatcher/` (or `$XDG_CACHE_HOME`): per-repository
`state-v1/<sha256({path,dev,ino})>/` holds `repository-index.sqlite`, `experience.sqlite`,
`learning.sqlite`, `repository-memory.json`, `memory-semantic.json` and `working-memory/*.json`; a global
learning profile lives under `learning-v1/`; an HMAC-signed parser cache under `parser-v1/`.

* No store is encrypted at rest. Protection is owner-only directories, 0600 single-link files, and an
  HMAC on the parser cache only. Deletion is logical.
* `repo_store.IndexStore` and `repo_store.ExperienceStore` share one `SCHEMA = 1`. A mismatch says
  "rebuild it", but experience data cannot be rebuilt, and no migrations exist.
* On the audited machine only `working-memory` and the project map and graph JSON were present (by
  name). No experience, learning or index database existed, so there was no live Dispatcher data to
  migrate there.

### 3.3 Exports

* `repository_intelligence.export` writes `{document: "repository-intelligence-export", note, generated,
  coverage, snapshot, counts, inferences[]}`. It has **no schema version**, contains summary data only,
  carries no record bodies or content hashes, and is never read back.
* `learning.export_generation` writes a versioned (`schema_version` 1) frozen library of the active
  generation's revision records; `learning.import_generation` re-validates and re-derives each revision
  and never carries approvals across.
* `learning.export_patch` writes a unified diff for review.
* **Nothing exports** experience events, corrections, episodic or semantic stores, working memory,
  index records (files, symbols, edges, commits) or learning observations
  ([locus-compatibility.md §15.4](locus-compatibility.md)).

### 3.4 Relation to Locus

Locus bundles a copy of Dispatcher as a built-in skill and reads the in-workspace project map through
`dispatcher_runtime.py` (store 28 in ownership §4.2). The Stage-2 adapter's history archive skips
`_dispatcher_control` messages ([integration-locus.md §3.2](integration-locus.md)). Dispatcher's stores
sit outside Locus's `APP_DIR` and outside any Locus erase path.

### 3.5 Risks that matter for memory

From compatibility §15.5 (CONFIRMED items were reproduced on scratch copies):

* CONFIRMED: credential-named paths (`.env`, `secrets.yaml`) are stored **by name** in experience
  records; `experience.build_event` filters with `_safe_path` only, not `context._skip`.
* CONFIRMED: `repository_memory.load_store` falls back to an **in-project**
  `.agent-dispatcher/repository-memory.json` when no private state exists, so a cloned repository can
  ship forged memory hits.
* Redaction gaps (`DB_PASSWORD = "..."`, `client_secret: "..."`, JSON `"api_key": "..."`); the
  uncommitted `decision/redact.py` edit narrows redaction further.
* Policy and package digests hash Dispatcher **source bytes**, so moving or reformatting the code
  invalidates every index, episodic store and learned revision.
* Approval identity is a free-text label plus uid.

---

## 4. Recommended contract (proposal)

### 4.1 One memory authority

* Locus's memory adapter is the only memory authority. Workflows and Dispatcher never construct a
  `MemoryEngine` on Locus's engine root, never open its files, and never hold its keys. They reach memory
  only through host calls that build a trusted `AccessContext` from Locus state (R7.1, R18.7).
* Neither project keeps a second store of approved memory. LangGraph checkpoints, the plugin job ledger,
  and Dispatcher's experience, episodic and semantic stores are execution state or derived retrieval
  hints, never approved memory, and are never injected under the `## Approved memory` layer.
* Identity (private) mode, Ask mode and the per-message memory policy are applied by Locus before any
  workflow job asks for memory. The langgraph-workflow integration map already says workflows must refuse
  identity sessions.

### 4.2 Recall for workflow jobs

* **Plugin mode** needs no new call: jobs run as chat turns and get whatever the chat recall path gives.
* **In-process mode** needs a production `LocusHost` that, per job, asks the same adapter used for chat
  for a packet (`MemoryEngine.build_context` with the policy-derived `ContextRequest`) for the job's agent
  (`JobSpec.assignee` or the reader profile; an open question in the audit), sets it as the reader's
  memory context, and calls `MemoryEngine.revalidate_context` immediately before the model call, as the
  Stage-2 adapter does for solo turns.
* Whether read-only research jobs get workspace-scoped memory, and which query to use (`goal`,
  `instruction` or both), are open host decisions.

### 4.3 Checkpoints stay execution state

* A checkpoint may record that memory was used, by `ContextPacket.receipt_id`; the host can explain it
  later with `MemoryEngine.explain_context`. It should not record the packet text.
* Memory ids and memory text must never enter LangGraph `configurable`, checkpoint metadata or the
  `lgw_*` tables, which are plaintext even with a cipher.
* A resumed attempt must not reuse a packet restored from checkpoint state. After a resume from
  checkpoint state the host must build a new packet under the *current* access context, so a memory
  forgotten or corrected since the checkpoint is not served (R9.5, R18.6). Revalidation is not an
  option there: `MemoryEngine.revalidate_context` needs the full `ContextPacket`
  (`context.compiler.ContextCompiler.revalidate` checks the packet text against its snapshot hash), and
  no API rebuilds a packet from a `receipt_id`. A checkpoint that keeps only the receipt id therefore
  cannot be revalidated after a process restart.
* Revalidation applies only to a packet the host still holds in memory, which is what the Stage-2
  adapter does between recall and the model call (`MemoryAdapter.revalidate_before_use`). It then
  filters or recompiles under the current access context, also across an engine restart while the
  host keeps the packet object (tests:
  `tests/test_context.py::test_revalidate_without_known_request_filters_after_restart`,
  `::test_forged_packet_is_revalidated_without_crash_or_leak`).

### 4.4 Stable idempotency keys for replayed nodes

A replayed node must produce the same memory write, not a second one. The package already provides
idempotent entry points; the proposal is to derive their keys from langgraph-workflow's deterministic
identifiers:

| Package call | Idempotency mechanism (implemented) | Proposed key for a replayed node | Tests |
|---|---|---|---|
| `MemoryEngine.propose`, `MemoryEngine.remember` | `idempotency_key=`: stored as a keyed token bound to the caller's principal and actor; the same key with a different request raises `IdempotencyConflict`; replay after the record was forgotten raises `NotFound` | derived from `operation_id` plus a purpose label, e.g. `<operation_id>/propose/<n>` | `tests/test_core.py::test_idempotent_remember_replays_without_a_second_record`, `::test_replay_of_a_forgotten_or_out_of_scope_record_is_not_found`, `tests/test_concurrency.py::test_replayed_idempotent_remember_across_processes_yields_one_record` |
| `MemoryEngine.forget` | `idempotency_key=`, also bound to the caller's grants. `forget` refuses `AGENT` actors ("forgetting is a user or host action"), so this applies only to forgets the host or the user issues, never to one a workflow job issues as an agent | as above | `tests/test_review_group1.py::test_forget_idempotency_replay_requires_authorization_and_is_caller_bound` |
| `MemoryEngine.ingest_event` | idempotency by `(session_ref, event_id)`: an identical re-ingest is a duplicate with no state change. "Identical" is the fingerprint in `history.archive._fingerprint_payload`: `sequence`, `occurred_at`, `role`, `text`, `scope`, `tool_name`, `attachments` and the two injection/summary flags. The same `event_id` with any of these changed, or a `sequence` already used by another event of the session, raises `IdempotencyConflict`. `HistoryArchive._ingest_one` also binds a session to the scope of its first event and raises `AccessDenied` for a later event under another scope. Requires `INGEST` | `event_id` from the workflow `event_id`; `session_ref` from `attempt_id`. That alone is not replay-safe (see below) | `tests/test_history.py::test_identical_reingest_is_duplicate_without_state_change`, `::test_same_event_id_with_different_content_conflicts` |
| `MemoryEngine.record_episode` | `EpisodeReport.episode_id` is the logical episode; re-reporting the same `attempt_ref` adds no attempt; a resumed attempt adds a revision; the same attempt under another episode id raises `IdempotencyConflict`. Requires `WRITE` or `INGEST` (`EpisodeService._require_report_permission`) and a scope the caller is granted, which an episode id cannot later change | `episode_id` from the attempt; `task_ref` from the task; `attempt_ref` from `attempt_id` | `tests/test_learning.py::test_resumed_attempt_updates_the_same_episode_and_is_not_double_counted`, `::test_same_attempt_under_a_different_episode_id_is_rejected`, `::test_episode_permissions_and_scope_bounds` |

Replay safety for `ingest_event` needs more than stable ids. langgraph-workflow's `WorkflowEvent`
(`events.make_event`) carries a stable `event_id` but neither a per-attempt sequence nor a timestamp. A
replayed node that reuses the `event_id` but takes a new `sequence`, or an `occurred_at` read from the
clock at replay time, raises `IdempotencyConflict` instead of being treated as a duplicate. The host must
therefore:

* derive `sequence` deterministically, for example from the event's position within the attempt;
* take `occurred_at` from a stored record of the event, never from the clock at (re)ingest time;
* produce the same `text`, `role`, `tool_name`, `attachments` and `scope` on every replay;
* always ingest a given `attempt_id` session under one scope.

Identifier fit, checked against both regexes:

* langgraph-workflow identifiers (`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,159}$`, no `..`) are a subset of the
  package's `validation.REF_PATTERN` (`[A-Za-z0-9_.:@/+=-]{1,256}`, no `..`). Attempt ids and operation
  ids can therefore be used as `task_ref`, `attempt_ref`, `session_ref` and `VerificationRef.receipt_id`
  as they are.
* `LocusHost` job ids contain `#`, which `REF_PATTERN` rejects; use the `operation_id` instead.
* `episode_id` uses the stricter `validation.ID_PATTERN` (`[A-Za-z0-9_-]{1,128}`). Plugin attempt ids
  match it; operation ids (they contain `/`) do not and would need a digest.

### 4.5 Outcomes become proposals or episodes; episodes are injectable

* Workflow outcomes may enter memory only as `propose` candidates (operation `PROPOSE`; the Stage-2
  adapter's `tool` purpose uses actor `AGENT`) or as `record_episode` reports. Workflow outcomes never
  create approved *memories* by bypassing review: approval needs `APPROVE` and an actor in
  `HostCapabilities.approval_actors` (`policy.require_reviewer`), and explicit `remember` needs actor
  `USER` or `HOST` (`policy.require_author`).
* Episodes are different. `learning.episodes.EpisodeService.record` stores each episode as a
  `MemoryRecord` with `kind=EPISODE` and `lifecycle=APPROVED`: a factual record of the attempt whose
  outcome the engine derives (below), not reviewed by anyone
  (`tests/test_learning.py::test_claimed_done_without_receipts_is_unknown` asserts the lifecycle).
  `context.compiler._governed` admits an episode that carries its engine payload, and both
  `models.DEFAULT_SLICES` and the Stage-2 adapter's `_SLICES` include an `episodes` slice, so by
  reading the code a recorded episode can be injected into hot context with no human review (with the
  Stage-2 adapter in `enabled` mode, inside the `## Approved memory` layer). No test
  injects a recorded episode; `tests/test_review_group1.py::test_context_never_injects_ungoverned_procedures_or_forged_episodes`
  covers only the forged case. Only the episode's lesson candidates stay unapproved
  (`tests/test_learning.py::test_lessons_become_unapproved_candidates_linked_to_the_episode`).
* Recording needs only `WRITE` or `INGEST` (`EpisodeService._require_report_permission`), and an
  `AGENT` actor that holds `INGEST` can record one
  (`tests/test_learning.py::test_episode_permissions_and_scope_bounds`). The Stage-2 `tool` purpose
  (`{READ, PROPOSE}`) cannot record episodes. The Stage-2 `ingest` purpose (`HOST`, `{INGEST}`) can, but
  without `PROPOSE` every lesson is skipped as `propose_not_permitted`. While ownership stays
  `legacy_authoritative` (all of Stage 2), `MemoryEngine.record_episode` is fenced whatever the purpose
  (`MemoryEngine._fence`; `tests/test_review_group1.py::test_canonical_record_writes_are_fenced_beyond_the_core_api`),
  so this matters from Stage 3 on. The host must decide whether workflow episodes are recorded at all,
  and under which purpose, before any are recorded.
* A success outcome is never taken from the claim: `verified_success` requires every referenced
  receipt to resolve as trusted through `HostCapabilities.verification`, plus the further conditions
  in `learning.episodes.derive_outcome` (the receipts name this task or no task, carry at least one required
  check, all of which pass, and do not already back another attempt or episode;
  `tests/test_learning.py::test_claimed_done_without_receipts_is_unknown`). A failure is also derived
  when a trusted receipt reports a failed required check. Claimed negative outcomes (`failure`,
  `partial`, `cancelled`, `interrupted`) are recorded as reported, with no verification; anything else is
  `unknown`. langgraph-workflow's verification receipts (from `LocusHost.verify`, which uses Locus's
  `TaskVerifier`) are the natural `VerificationRef`s; `AgentHost`'s self-checked file and JSON checks are
  agent-side and should not be attested as trusted.
* Candidate inputs the audit identified: `AttemptStatus.result` (`status`, `blocker`, `plan_digest`,
  `verification`, `evidence[]`, `jobs{}`) and research synthesis claims with their sources.

### 4.6 Plaintext checkpoint risk: required cipher and scrubbing

If recalled memory reaches a workflow job, it can be echoed into a job output and persisted in
plaintext: in checkpoint state without a cipher, and in `agent-host.sqlite3` in every case. A forget in
`locus-memory` cannot reach those copies; `ForgetReceipt.pending_external` covers queued provider
deletions only (R17.7). Before memory is delivered to workflow jobs, the host must:

1. **Encrypt checkpoints.** Inject a LangGraph `CipherProtocol` into `WorkflowExecutor` with a key from
   Locus custody (for example a subkey derived with `crypto.derive_subkey` under a label distinct from
   `locus-memory/engine/v1`), and set `require_encryption=True`. `locus-memory` does not ship a
   `CipherProtocol` adapter; the sidecar's type-tag format belongs to LangGraph.
2. **Scrub or withhold for the plugin job ledger.** `agent-host.sqlite3` has no encryption option. Either
   keep memory text out of job specs and results that the plugin stores (pass receipt ids, not packet
   text), or do not deliver memory in plugin mode until the ledger is encrypted. Also fix its file mode.
3. **Bound retention.** Prune `AgentHost` rows and `blocked:*` attempts, which today are kept forever.
4. **Cascade erasure.** Include the checkpoint sidecar and the plugin ledger in the host's erase
   cascade, so forgetting memory or a session also removes workflow copies (or reports that it cannot).

### 4.7 Agent Dispatcher as a producer

* Repository intelligence enters `locus-memory` only as a `locus-memory.repository-interchange` v1
  document, pulled through `repository.interchange.RepositoryIntelligenceProvider`. It is untrusted data:
  observations and summaries become unapproved candidates, and file, symbol and import records are only
  checked against stored snapshots. See [repository-interchange.md](repository-interchange.md),
  including a proposed mapping from Dispatcher stores.
* Procedural learning: Dispatcher's `learning.export_generation` documents could, in a future
  integration, become `MemoryEngine.nominate_procedure` drafts. They would then go through the package's
  own evaluation (through a host `EvaluationRunner`) and explicit approval; approvals would not carry
  over, as `learning.import_generation` already enforces. Not implemented.
* Experience records have no exporter and no interchange record type (see
  [repository-interchange.md §9](repository-interchange.md)). The credential-path defect must be fixed
  before any such export.
* Dispatcher's own `memory` packet section is a retrieval hint inside Dispatcher's packet. If Locus shows
  it, it must not be labelled approved memory.

### 4.8 History archive

Whether `locus-memory`'s history archive should index `workflow_event` rows (in-process mode) is an
open decision. In plugin mode those events never reach Locus. If they are archived, they go through
`ingest_event` like any other host event, with the keys and the replay rules in §4.4.

---

## 5. What is not implemented

* No langgraph-workflow `WorkflowHost` memory method or capability, and no production `LocusHost` that
  recalls memory per job.
* No checkpoint cipher wired by Locus or the plugin; no encryption for `agent-host.sqlite3`.
* No candidate or episode ingestion from workflow outcomes.
* No indexing of `workflow_event` rows by the history archive.
* No Agent Dispatcher exporter of any kind for `locus-memory`; no real `RepositoryIntelligenceProvider`
  implementation (only the test stand-in `repository.interchange.SyntheticRepositoryProducer`).
* No import of Dispatcher experience, episodic, semantic, working-memory or learning stores.
* No tests that run either project against `locus-memory`. The idempotency, revalidation and episode
  tests cited above exercise the package alone.
