# Initial production policy measurements — validation deferred

These synthetic measurements were collected before the user asked to stop testing
because of RAM usage. They describe the initial `conservative-v1` implementation,
not the subsequently edited working tree. Original benchmark arms and historical
results were not modified.

- Calibration: three corpora, seeds 20261004–20261006, 48 questions each. Recall@5
  1.0, abstention accuracy 1.0, false abstention 0, no scope/deletion/correction leaks.
- Held out: five corpora, seeds 20272020–20272024. Recall@5 0.947–1.0, abstention
  accuracy 1.0, false abstention 0–0.0263. The false-abstention acceptance gate did
  **not** pass: the policy missed a commit-message-style paraphrase.
- Actual local model task outcomes: qwen3.6:27b, six synthetic artifact tasks,
  paired memory on/off, identical initial files and model settings, deterministic
  checks of result.json. Both arms passed 2/6. All twelve calls completed using
  1,099 total tokens and zero provider cost. This is **not a demonstrated gain**.
  Source inspection suggests the initial lexical admission policy could discard
  relevant memory for imperative requests containing artifact-format instructions.
  The initial artifact did not preserve selection diagnostics or output JSON, so
  that causal explanation cannot be established from its recorded results alone.
- These findings prompted a small plural-normalization and topic-anchor admission
  change (`conservative-v2-pending-validation`). No further tests or model calls
  were run after the user's stop request. It needs fresh held-out evaluation;
  the results above must not be presented as validation of that change.
- No installed embedding model was selected. Semantic relevance improvement is
  unmeasured, so keyword retrieval remains the default.
- The qwen3.6:27b model used by this campaign was explicitly unloaded after the
  user's request. No real user memory/profile or working checkout was used.

The paired campaign is a bounded artifact-task harness, not a complete multi-step
Locus agent benchmark. Its findings must not be generalized to overall agent quality.

For example, the retention task asked for the approved Vega retention policy in
`result.json`; its supplied synthetic memory said "Vega data retention is 17 days."
The frozen expected artifact was `{"retention_days":17}`. Both arms failed the
check. Format words in the task could dilute the initial lexical overlap rule,
but the original result cannot show whether this case's memory was omitted.
Future synthetic results retain selected IDs, coverage/omission reasons, receipt
references, and bounded expected/actual JSON to make this inspectable.

Resume commands after the user requests testing:

```sh
python -m locus_memory.evaluation.production --seed 20303030 --repetitions 5 --out /tmp/production-fresh-heldout.json
python -m ollama_code.memory_evaluation --model qwen3.6:27b --out /tmp/memory-paired-v2.json
```

A new paired invocation must use the remaining aggregate campaign budget: the
first invocation already consumed 1,099 of the approved 250,000 tokens. The Python
API accepts a shared `CampaignBudget`; the CLI starts a new campaign and should
not be used to represent continuation of this campaign's remaining allowance.

The working-tree Locus evaluation suite now accepts `memory_comparison: true`.
It replays one immutable baseline per case for both arms and all repetitions,
records `memory_arm` on real agent-task results, uses the saved agent identity,
disables learning/proposals, and grades through the existing task verifier.
The campaign's persistent UsageLedger owner is `memory-campaign:<suite-id>`;
all tracked worker, helper, compaction and rubric-review calls share its $10 /
250,000-token reservation limits. Unknown billing rates prevent dispatch.
`memory_campaign_token_limit` can lower the bound (for example, to 248901 to
account for the smoke campaign above). Re-running the same suite does not reset
its allowance.

Native subscription transports presently cannot enforce a hard output-token
cap. Their strict campaign calls are refused at `tracked_native` before dispatch;
ordinary native application turns are unaffected. Full multi-step agent suites,
new paired-mode tests, semantic settings API/UI, and post-stop transport/admission
changes remain **unexecuted** pending the user's request to resume testing.
Paired suite completion events now include actual arm totals, graded/skipped counts,
campaign usage, and explicit completeness/reasons. Admission refusals are persisted
at the tracked model boundary, including unknown pricing, unbounded native output,
and exhausted reservations; these are skipped/incomplete rather than quality ties.
