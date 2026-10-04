# Requirements (extracted from the implementation specification)

Numbered, terse restatement of the governing specification ("Claude implementation prompt:
Locus Memory and staged extraction from Locus"), used as the backbone of
`docs/requirements-checklist.md`. Section numbers follow the specification.

## §0 Scope and execution
- R0.1 Default scope: standalone package, migration tooling on disposable fixtures, integration preparation.
- R0.2 A Locus checkout is inspection-only unless explicitly included in the implementation scope; otherwise produce an exact host-side handoff.
- R0.3 No publishing, pushing, remote repos, real-data migration or paid services without separate authorization; local reviewable changes and disposable data only.
- R0.4 Build working software (complete vertical slices, tested), not only designs or interfaces.

## §1 End-state architecture
- R1.1 One-way dependency: Locus app -> thin adapter -> locus_memory -> local encrypted persistence + optional injected providers.
- R1.2 In-process library + diagnostic CLI by default; no mandatory daemon, HTTP server, port, Docker, Redis, Postgres, hosted vector DB or cloud account.
- R1.3 Core imports without Locus, ollama_code, Swift, Agent Dispatcher, LangGraph or provider SDKs.
- R1.4 Host integration code lives in Locus; portable contracts live in locus-memory.
- R1.5 langgraph-workflow and Agent Dispatcher are optional consumers/producers via explicit contracts; not required to install the engine.

## §2 Ownership
- R2.1 Ownership matrix created before implementation and maintained through extraction (responsibility, present owner, final owner, boundary).
- R2.2 "All memory parts out" = all reusable memory-domain implementation; UI, auth, chat server, live workflow execution stay in Locus.
- R2.3 Host chat/task records may stay authoritative application records; the engine owns the searchable memory archive/projection; document relationship and deletion semantics; no second session lifecycle.
- R2.4 Thin adapter only translates schemas, derives trusted scope, provides capabilities, routes calls, renders results; no second ranker, DB, consolidation engine or lifecycle rules.

## §3 Audit
- R3.1 Inspect actual repositories (Locus paths listed in spec, plus context assembly, user-memory actions, candidate approval, key management, app-data isolation, skill observations, provider usage, native models, recovery logic).
- R3.2 Revalidate the earlier baseline (encrypted MemoryVault, scopes, statuses, provenance); characterize the legacy migration path (run twice? safe?).
- R3.3 Deliver docs/locus-compatibility.md (commits, symbols, call sites, tests, runtime versions, existing/reuse/extend/new/unknown).
- R3.4 Deliver docs/ownership-and-extraction.md (responsibility, present owner, final owner, temporary bridge, migration prerequisite, bridge-removal criterion).
- R3.5 Deliver a requirements-to-tests checklist.
- R3.6 Record actual Python minimum and bundled interpreter; do not raise Locus's runtime requirement; do not assume optional SQLite capabilities.

## §4 Extract before replace
- R4.1 Characterize existing behaviour with disposable legacy fixtures and tests first.
- R4.2 Extract/improve existing generic code rather than unrelated rewrites; preserve licenses/attribution.
- R4.3 Preserve compatible record formats and stable IDs; code extraction and physical data migration are separate operations.
- R4.4 Temporary facades must delegate (no second complete implementation); every bridge has an exit criterion and delegation tests.
- R4.5 No undocumented access to private host tables; legacy readers use an audited, versioned schema contract or host export.

## §5 Memory model
- R5.1 Model independently: security boundary, scope (user-global, project, repository/worktree, agent, team, session, device), kind (preference, fact, decision, repository observation, episode, procedure), storage role (canonical, source archive, derived index, context receipt), lifecycle (candidate, approved, rejected, stale, superseded, expired, forgotten).
- R5.2 Scope constraints intersect; "global" is global within an authorized profile; team participation does not grant members' private memories.
- R5.3 User memory: explicit durable preferences/facts incl. corrections; never infer and persist sensitive personal information automatically.
- R5.4 Profile-global memory with device/environment restrictions; generalizing project knowledge to global needs review or narrow policy.
- R5.5 Project memory: decisions, conventions, constraints, limitations, applicable versions.
- R5.6 Repository memory: source-backed observations; current validity separate from historical truth.
- R5.7 Episodic memory incl. failed/partial/cancelled/interrupted attempts with verification evidence and uncertainty.
- R5.8 Procedural memory: proposals with applicability, evidence, evaluation, versions, explicit promotion.
- R5.9 Session history is searchable evidence, not approved facts.
- R5.10 Agent identity and authoritative instructions stay host-managed; no auto-rewritten SOUL.md/USER.md/MEMORY.md.

## §6 Public API and receipts
- R6.1 Typed, validated, versioned models (access context, scopes, records, revisions, sources, queries, results, episodes, procedures, ingestion events, context packets, receipts).
- R6.2 Operations covering get/search/remember/propose/approve/reject/correct/forget/ingest_event/record_episode/build_context/consolidate/explain/explain_context/status.
- R6.3 Records carry stable opaque IDs, schema/revision versions, scope, timestamps (event and ingestion), content, lifecycle, retention, provenance, validity, conflict/supersession links, deletion generations.
- R6.4 Sources reference real messages, user actions, commits/blobs/ranges, task attempts or verification receipts; preserve extraction version, actor, evidence fingerprints, availability; reject fabricated or unauthorized cross-scope evidence.
- R6.5 Unknown confidence stays unknown; model confidence labelled uncalibrated; relevance, confidence and authorization are separate.
- R6.6 Validate identifiers, sizes, timestamps, finite numbers, versions, provider output; optimistic revision checks; typed errors (access denied, locked vault, revision conflict, unavailable index, unsupported capability, partial coverage).
- R6.7 Every write returns a receipt; every context operation returns an inspectable receipt; no remembered/deleted claim before success.

## §7 Authorization and untrusted memory
- R7.1 Host constructs trusted access context; model-supplied ids grant nothing.
- R7.2 Enforce scope in get, search, scroll, explain, export, write, update, approve, consolidate, delete, provider calls, context construction — before content reaches ranking, snippets, model requests, logs or counts; revalidate on concurrent permission change.
- R7.3 No global-corpus-then-filter; isolate security domains; no cross-profile statistics; document residual metadata/timing limits.
- R7.4 Transcripts, repository files, provider outputs, generated memories are untrusted; cannot gain system authority, enable tools, change budgets/access, or waive verification.
- R7.5 Bounded validation, secret scanning, suspicious-content handling as defense in depth.
- R7.6 Never auto-rewrite AGENTS.md, protected skills, approval policy, secret exclusions, provider settings, evaluation rules; stored procedures are not authorization.

## §8 Storage and secure search
- R8.1 Preserve existing encryption guarantees; host keeps OS key custody; package holds generic record crypto via injected capabilities.
- R8.2 Established AEAD; versioned key IDs; nonce handling; authenticated binding of identity/security metadata; wrong-key behaviour; rotation; recovery; legacy decryptability until migration verified; never silently generate a new key over an existing locked vault.
- R8.3 Transactional writes, durable migrations, optimistic concurrency, bounded contention, explicit open/close/hydration; import has no side effects (no scanning, migration or network).
- R8.4 No plaintext search sidecar on disk; FTS5 only as authorized bounded in-memory projections (or a verified page-encrypted backend); never fall back to plaintext.
- R8.5 Bound memory/hydration/fan-out; expose coverage/readiness; resumable hydration; incomplete historical search names missing coverage; no rebuild-every-turn, no silent omission.
- R8.6 No plaintext copies via SQLite config, temp storage, debug tools, logs, exports, vector caches, migration files; canary tests across DB, journal/WAL, temp, cache, logs.
- R8.7 State realistic guarantees (not a compromised process, swap, stolen key, all backups; no promise of perfect zeroization/SSD erasure).

## §9 Hot memory
- R9.1 Compiled view of authorized approved records; not a writable store.
- R9.2 Stable user/profile slices plus task-relevant project/repository/agent/episodic context; tunable caps (500/800 tokens); host supplies total allowance; slices compete.
- R9.3 Count wrappers, labels, sources, metadata; accept tokenizer callback; label estimates; empty/irrelevant memory costs ~nothing.
- R9.4 Return selected IDs/revisions, sources, reasons, conflicts, omissions, token counts/estimates, coverage, costs, snapshot hash; deterministic ordering.
- R9.5 Corrections, forgetting, revocation and stale sources override cached snapshots before the next model call; replay never overrides current access/deletion.
- R9.6 Optional previews; no auto plaintext USER.md/MEMORY.md mirrors.

## §10 Session history
- R10.1 Idempotent ingestion: stable IDs, roles, timestamps, deterministic order, host refs, durable cursors.
- R10.2 Search, browse, bounded scroll; exact retained text and boundaries; summaries/chunks derived; expose redaction, retention gaps, missing attachments, partial coverage.
- R10.3 Locus mode consumes authorized events/exports; no scraping app-data dirs; no second chat lifecycle.
- R10.4 Retain only permitted user-visible conversation and allowed tool evidence; no hidden reasoning, credentials, env dumps, default attachments; attachment references keep access constraints.
- R10.5 Archive retention separate from extraction, injection and sync; injected memory and generated summaries never re-ingested as user evidence.

## §11 Retrieval
- R11.1 Offline path: trusted scope -> authorized namespace + structured lookup -> lexical -> dedup/validity/conflict -> optional semantic within policy -> diversity selection -> bounded packet with evidence and coverage.
- R11.2 Phrases, text, exact IDs, dates, paths, identifiers, message/session refs, no-result; preserve identifier/path structure.
- R11.3 Parameterized SQL plus deliberate FTS query parsing/escaping; bounded input/complexity; tests for punctuation, Unicode, empty, adversarial.
- R11.4 BM25 lower-is-better; scores are not probabilities; documented rank fusion.
- R11.5 Deduplicate archive/summary/approved duplicates; track selected, injected, cited, verified-useful separately.
- R11.6 Bounded escalation via inspectable signals; no mandatory embeddings/rerank/external account.
- R11.7 Expansion handles; cancellation, deadlines, limits, partial status; "insufficient evidence" is valid.

## §12 Provenance, correction, consolidation, decay
- R12.1 Explicit transitions preserving legacy semantics; candidates never in normal hot context.
- R12.2 Separate observed facts, source-attributed statements, model interpretations, hypotheses; quotes are not user facts; model confidence never authorizes approval.
- R12.3 Conflicts by subject/predicate/scope/applicability/evidence/explicit correction; ambiguous conflicts stay visible; corrections invalidate derived context immediately.
- R12.4 Pinned = preferred retention/selection, not truth; durable preferences do not expire from disuse; repository facts invalidate by content/version; transient observations may expire by time.
- R12.5 Bounded consolidation (dedup, summarize, suggest merges/supersession) with provenance and reversible revisions; never turn weak statements into an approved strong claim.
- R12.6 Retrieval frequency/restatement never inflates confidence; explanations expose sources and transformation history under normal access rules.

## §13 Repository memory
- R13.1 Offline baseline + versioned interchange contract; explicit registration, stable identity, commit/worktree snapshot identity, tracked inventory, hashes, symbol/import observations, bounded read-only git history; parsed facts separate from summaries; label unsupported/partial.
- R13.2 Dirty files, branches, worktrees, renames, deletions, moves, incremental invalidation; summaries keep source hashes and stop being current when sources change.
- R13.3 Allowed roots and exclusions on enumeration and direct reads incl. historical blobs and deleted secret files; reject traversal/symlink escape; default secret exclusions; never index home or execute repo code.
- R13.4 Git without shell, external diff/textconv, network fetch or unbounded output; bounded commits/bytes/sizes/time.
- R13.5 Inspect Agent Dispatcher exports before claiming compatibility; versioned records or injected RepositoryIntelligenceProvider; no private DB copy; provisional schema + synthetic tests where no exporter exists; explicit resumable cancellable budgeted deep ingestion.

## §14 Episodes
- R14.1 Structured episode fields (ids, objective, scope/env/snapshot, approach, artifacts, verification receipts, outcome enum, failure modes, uncertainties, lessons, usage, context receipts).
- R14.2 "Done" is not verified success; only trusted host evidence establishes it; resumed attempts update the same logical episode.
- R14.3 Record failures/interruptions; preserve applicability.
- R14.4 Structured outcomes first; LLM extraction only proposes; event boundaries, watermarks, coalescing.
- R14.5 Model calls use host account/egress/cost/cancellation controls; no silent subagents; never consume verification budget.

## §15 Procedural learning
- R15.1 Lifecycle: independent evidence -> scoped candidate -> dedup + safety validation -> evaluation via authorized runner -> receipt -> explicit approval -> versioned export -> host activation/rollback.
- R15.2 Candidate fields: purpose, applicability, preconditions, steps, expected outcomes, negative cases, evidence, failures, capabilities, version, rollback.
- R15.3 Count independent tasks, not copies/retries/summaries/replays.
- R15.4 Proposal-only by default; never execute candidate commands; evaluator/approval/verification outside learner control.
- R15.5 States: rejected, failed-evaluation, insufficient-evidence, superseded, revoked-evidence; procedures cannot broaden permissions, disable tests or carry past authorization.
- R15.6 Portable manifests; never overwrite SKILL.md; no edits to Dispatcher roles/global instructions.

## §16 Providers and maintenance
- R16.1 Separate storage, enrichment, extraction, governance; working local provider; injectable contracts for semantic search, embeddings, reranking, extraction, external services.
- R16.2 Capability negotiation; explicit failure or policy degradation, never fake success; deterministic fakes labelled as such.
- R16.3 No external service by default; consent names provider, scope, data classes, transcript/source egress; outages never switch accounts or broaden sharing.
- R16.4 Deadlines, bounded retries, cancellation, rate limits, circuit breaking, usage receipts, idempotency, deletion reconciliation; unknown cost != zero; providers never approve or resurrect.
- R16.5 Version embeddings (model, dims, preprocessing, index generation); reject incompatible vectors; validate before persistence.
- R16.6 Host schedules maintenance; engine performs bounded resumable cancellable units; no own background agent or cron.

## §17 Forgetting
- R17.1 Forget memories, sources/sessions, projects/repositories, agents, profiles with explicit receipts (completed, retained by policy, pending external, limitations).
- R17.2 Deleting a memory vs its source transcript distinguished; source-linked suppression; no promise of arbitrary paraphrase suppression.
- R17.3 Track derivations through summaries, indexes, embeddings, caches, episodes, procedural evidence, pending jobs, exports, provider replicas; mixed-source summaries removed or regenerated.
- R17.4 Tombstones/deletion generations with commit-time rechecks; late replies, replay, reindex, migration retry, restart, restored context receipts tested.
- R17.5 Backup restore reconciles with the newest deletion ledger/generation before serving; ledger protected from rollback with the snapshot or explicit reconciliation; document lost-ledger limitation.
- R17.6 Audit/revision history keeps no forgotten payloads; minimal redacted receipts; plaintext export only by explicit action.
- R17.7 No claims about prompts already sent, external copies, or all backups.

## §18 Locus integration (when authorized)
- R18.1 One narrow adapter consuming a pinned package via the real dependency/bundling mechanism; no copied source or sibling path at runtime.
- R18.2 Map host boundaries: before model call, explicit remember/correct/forget, committed message, task/attempt boundary, repository change, session/maintenance boundary, scope/consent change.
- R18.3 Preserve routes, native models, memory actions, approval, edition/profile isolation, recovery.
- R18.4 No double injection; account for wrappers without reducing instructions, output reserve or verification.
- R18.5 Per-app-instance dependency injection; multi-instance tests share nothing.
- R18.6 Locus keeps live sessions/Task Capsules; memory never resets allowances, changes task identity or marks incomplete work verified; reauthorize references at resume.
- R18.7 langgraph-workflow uses the same host contract; checkpoints stay execution state; stable idempotency keys for replayed nodes; no LangGraph dependency in the package.

## §19 Rollout controls
- R19.1 Two dimensions: serving/learning mode (disabled|shadow|enabled) and canonical backend (legacy|package with migration state).
- R19.2 Disabled: no ingestion/maintenance/extraction/provider calls/injection; behaviour unchanged.
- R19.3 Shadow: compare without changing prompts or canonical memory; derived writes explicit, isolated, redacted, bounded.
- R19.4 Enabled: inject through host budget/governance; learning, retention, sync, activation separately controlled.
- R19.5 After package is canonical, disabling injection never moves writes back to legacy or hides data; reverting ownership needs the migration protocol.
- R19.6 Permission/consent/key failures fail closed; optional retrieval failures omit with a visible reason; required canonical writes report failure, never silently fall back; "unavailable" != "nothing found".

## §20 Migration, cutover, rollback, retirement
- R20.1 Tools tested on disposable copies; no real migration as a side effect.
- R20.2 Durable state machine with authoritative owner, permitted writers, crash recovery, allowed rollback per state.
- R20.3 Inventory all stores/paths; map IDs, scopes, statuses, provenance, revisions, validity, pin/stale, deletions; classify unsupported fields; never approve candidates.
- R20.4 Dry-run report; encrypted consistent snapshot + manifest; idempotent resumable import; decrypt-and-behaviour verification; interruption tests at every boundary.
- R20.5 Cutover via write quiescence + drain + durable ownership generation fencing; reads/writes redirected together; no "exactly-once" dual-write claims; one canonical owner per record type/partition.
- R20.6 Rollback before cutover leaves original usable; after cutover preserves new records, corrections, tombstones; refuse destructive rollback when unrepresentable; safe read-only recovery path; bounded retention of recovery artifacts.
- R20.7 Retirement criteria: all reads/writes on the selected backend; characterization/route/approval/scope/deletion/recovery tests pass; migration/restart/rollback evidence; no untracked writer, private-table dependency or duplicate context path; shims owned with removal conditions.
- R20.8 Final ownership matrix with no reusable memory algorithm left in Locus outside shims; dependency tests and explicit inventory.

## §21 Native controls, CLI, observability
- R21.1 Preserve/extend native presentation; show scope, state, provenance, revisions, conflicts, sources; previews of hot context and reasons; backend/migration state; coverage; consent; receipts; no other-profile counts.
- R21.2 CLI: init/status, scoped list/search/show/explain, remember/propose/approve/reject/correct, context preview, history search/scroll, episodes, repository index status, procedures, migration dry-run, explicit export/forget, evaluation; JSON plus human output; destructive ops need explicit targets and previews/receipts; no unguarded search-all/approve-all-profiles.
- R21.3 Measure stage latency, coverage, token overhead, index/storage growth, provider calls/cost, candidate outcomes, errors, pending deletions; redacted logs; label measured/estimated/unavailable.

## §22 Evaluation
- R22.1 Offline chronological benchmark on synthetic/licensed fixtures; no private chats.
- R22.2 Multi-session dependencies, corrections, missing evidence, distractors, stale repo facts, failed attempts, interruptions, deletion; strict chronology (no future leakage).
- R22.3 Arms A–F; matched settings; isolated state between arms/repetitions; state preserved within a sequence; separate index warming from learning.
- R22.4 Report recall/precision/rank, attribution, abstention, distracting/stale retrieval, scope leakage, correction/deletion propagation, budget compliance, overhead; separately task correctness and verification coverage.
- R22.5 Include cold ingestion, hydration, warm retrieval, maintenance, extraction, execution costs; cumulative/amortized; record versions, corpus, config, hardware, raw manifests.
- R22.6 Procedural evaluation: false promotion, negative cases, independent evidence, rollback.
- R22.7 Repeated runs with uncertainty; pre-defined rollout criteria; no borrowed performance claims; no paid/live runs without opt-in.

## §23 Mandatory regression coverage
- R23.1 For each critical feature: direct acceptance, nearest failure, highest-risk neighbor; dedicated compatibility assertions.
- R23.2 Areas: persistence, encryption canaries, scope, lifecycle, concurrency, retrieval, context, injection, repository, episodes, procedures, providers, forgetting, cutover, rollback, host compatibility, packaging, extraction.
- R23.3 Disposable data and synthetic canaries only; state which native/real-host tests could not run; fake-host passing is not real integration.

## §24 Layout, packaging, documentation
- R24.1 Adapt layout to existing code; no empty abstractions.
- R24.2 License and notices; no Hermes code/assets.
- R24.3 Build a wheel, install in a clean environment outside the checkout; offline quickstart persists, restarts, retrieves, corrects, forgets; test declared Python support.
- R24.4 Locus consumes a pinned, immutable, integrity-verified artifact via its real lock/bundling; distinguish local wheel from release; no floating git deps, runtime downloads, home paths or copied trees.
- R24.5 Document contracts, storage locations, init/key requirements, feature controls, exact commands, guarantees/limitations and implemented/experimental/contract-only/deferred status; no advertising fake-only integrations.

## §25 Milestones and gates
- R25.1 Milestones 1–5 for the package; Gate A requires the standalone offline path tested; without authorized host writes, stop at Gate A with a full handoff and report later milestones as not executed.
- R25.2 Maintain progress and test evidence in the repository for later sessions.

## §26 Completion report
- R26.1 Report implemented milestones and ownership model; inspected repos/commits; public contracts; feature classification; exact commands; tests run/not run; measurements; migration status and guarantees; remaining bridges; next host-side handoff; no unearned claims.
