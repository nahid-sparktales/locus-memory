"""Markdown rendering of a benchmark manifest (numbers only come from the manifest)."""
from __future__ import annotations

from typing import Any

from .arms import F_NOT_EXECUTED, FAKE_EMBEDDING_LABEL


def _fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _ci(summary: dict[str, Any], digits: int = 3) -> str:
    if not summary or summary.get("mean") is None:
        return "n/a"
    mean = _fmt(summary["mean"], digits)
    if summary.get("ci95_low") is None:
        return mean
    return f"{mean} [{_fmt(summary['ci95_low'], digits)}, {_fmt(summary['ci95_high'], digits)}]"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(out)


def _observed(value: Any) -> str:
    if isinstance(value, dict):
        return "; ".join(f"{k}: {_fmt(v)}" for k, v in value.items()) or "n/a"
    return _fmt(value)


def render_report(manifest: dict[str, Any]) -> str:
    agg = manifest["aggregate"]
    arms = list(manifest["arms"])
    config = manifest["config"]
    versions = manifest["versions"]
    hardware = manifest["hardware"]
    lines: list[str] = []
    add = lines.append
    add("# locus-memory cumulative-usefulness benchmark (synthetic, offline)")
    add("")
    add(f"Run created {manifest['created_at']}; {config['repetitions']} repetitions (seeds "
        f"{', '.join(str(s) for s in manifest['seeds'])}); corpus size `{config['size']}`; arms "
        f"{', '.join(arms)}; runtime {manifest['runtime_s']} s.")
    add("")
    add("**Small synthetic fixtures are not proof of production gains.** Every number below comes from a"
        " generated corpus of two fictional profiles and three fictional projects; it checks behaviour and"
        " invariants of this engine on that corpus, nothing more.")
    add("")
    add(f"Overall: **{'all hard invariants held' if manifest['passed'] else 'HARD INVARIANT FAILURES'}**"
        + ("" if manifest["passed"] else " - " + "; ".join(manifest["failures"][:10])))
    add("")
    add("## Setup")
    add("")
    corpus = manifest["corpora"][0]
    add(f"* Corpus per repetition: {corpus['events']} events, {corpus['questions']} questions"
        f" ({corpus['abstention_questions']} expect abstention), {corpus['keys']} ground-truth statements,"
        f" {corpus['days']} simulated days. Hashes: "
        + ", ".join(f"`{c['seed']}:{c['hash'][:12]}`" for c in manifest["corpora"]) + ".")
    add(f"* Context: token allowance {config['token_allowance']} (engine estimator, no host tokenizer);"
        f" history hits per question k={config['history_k']}; fake embedding dimensions"
        f" {config['embedding_dimensions']}.")
    add(f"* Versions: locus_memory {versions['locus_memory']}, Python {versions['python']}"
        f" ({versions['python_implementation']}), SQLite {versions['sqlite']}, cryptography"
        f" {versions['cryptography']}, {versions['git'] or 'git unavailable'}, FTS5 {versions['fts5_available']}.")
    add(f"* Hardware: {hardware['platform']}; machine {hardware['machine']}; CPUs {hardware['cpu_count']}.")
    add("")
    add("## Arms")
    add("")
    rows = [[name, desc] for name, desc in manifest["arms"].items()]
    rows += [[name, desc] for name, desc in manifest["arms_not_executed"].items()]
    add(_table(["arm", "configuration"], rows))
    add("")
    if "E" in arms:
        add(f"Arm E uses `FakeEmbeddingProvider`: **{FAKE_EMBEDDING_LABEL}**. Its numbers only show that the"
            " semantic path runs inside the same safety gates.")
        add("")
    add("## Rollout criteria (defined before the run in docs/evaluation.md)")
    add("")
    rows = [[c["id"], c["arms"], c["text"], _observed(c["observed"]),
             {True: "met", False: "**NOT met**", None: "n/a"}[c["met"]]] for c in manifest["criteria"]]
    add(_table(["id", "arms", "criterion", "observed", "result"], rows))
    add("")
    add("## Retrieval quality (mean [95% t-interval] over repetitions)")
    add("")
    quality = [("recall@5", "recall@5"), ("recall@10", "recall@10"), ("recall_all", "recall (all units)"),
               ("precision@5", "precision@5"), ("mrr", "MRR"), ("multi_session_complete", "multi-session complete"),
               ("abstention_accuracy", "abstention accuracy"), ("false_abstention_rate", "false abstention"),
               ("distracting_rate", "distracting/stale unit rate"), ("stale_rate", "stale+superseded unit rate"),
               ("extractive_proxy", "extractive proxy (verbatim answer present)")]
    rows = [[label] + [_ci(agg[a][m]) for a in arms] for m, label in quality]
    add(_table(["metric"] + arms, rows))
    add("")
    add("Evidence list = context-packet items (packet order) interleaved round-robin with history hits (rank"
        " order). Ranking metrics use answerable questions; abstention uses missing-evidence, deleted,"
        " cross-scope and cross-profile questions (retrieval-level: no candidate answer surfaced).")
    add("")
    add("## Safety and invariants (totals per run; mean [CI] over repetitions)")
    add("")
    safety = [("scope_leakage_count", "scope leakage units"), ("future_units", "future units"),
              ("deletion_failures", "forgotten units retrieved"),
              ("deletion_probe_pass_rate", "deletion probes passed"),
              ("correction_failures_context", "superseded units in context"),
              ("correction_failures_history", "superseded units in history hits"),
              ("correction_probe_pass_rate", "correction probes passed"),
              ("budget_compliance", "budget compliance"), ("plaintext_hits", "plaintext hits on disk"),
              ("attribution_correct_rate", "source attribution correct"),
              ("unattributed_units", "unattributed units"), ("warm_inconsistencies", "warm/cold result mismatches")]
    rows = [[label] + [_ci(agg[a][m]) for a in arms] for m, label in safety]
    add(_table(["check"] + arms, rows))
    add("")
    add("## By question category (recall_all, or abstention accuracy for abstention categories; mean over runs)")
    add("")
    categories = sorted({c for a in arms for c in manifest["by_category"][a]})
    rows = [[c] + [_fmt(manifest["by_category"][a].get(c, {}).get("mean")) for a in arms] for c in categories]
    add(_table(["category"] + arms, rows))
    add("")
    if manifest["paired"]:
        add("## Paired differences (same corpus per seed; mean [95% t-interval])")
        add("")
        metrics = ["recall@5", "recall_all", "mrr", "abstention_accuracy", "distracting_rate"]
        rows = [[pair] + [_ci(values[m]) for m in metrics] for pair, values in manifest["paired"].items()]
        add(_table(["pair"] + metrics, rows))
        add("")
    add("## Cost, latency and storage (wall clock on the machine above; mean [CI] over repetitions)")
    add("")
    cost = [("context_ms_p50", "context build p50 ms (cold)"), ("context_ms_p95", "context build p95 ms (cold)"),
            ("context_warm_ms_p50", "context build p50 ms (warm repeat)"),
            ("history_ms_p50", "history search p50 ms (cold)"), ("history_ms_p95", "history search p95 ms (cold)"),
            ("history_warm_ms_p50", "history search p50 ms (warm repeat)"),
            ("ingest_ms_total", "ingestion total ms (cold, all events)"),
            ("maintenance_ms_total", "maintenance total ms"),
            ("engine_construct_ms", "engine construction ms (partitions open lazily)"),
            ("cold_open_first_context_ms", "first context after reopen ms (open + unlock + index warming; sum of"
             " one probe per profile)"),
            ("cold_open_first_history_ms", "first history search after reopen ms (archive hydration; sum of"
             " one probe per profile)"),
            ("cold_open_warm_context_ms", "second context after reopen ms (warm; sum of one probe per profile)"),
            ("projection_build_p95_ms", "memory projection build p95 ms (engine timer)"),
            ("history_search_engine_p95_ms", "history search incl. hydration p95 ms (engine timer)"),
            ("cumulative_cost_ms", "cumulative serving cost ms"),
            ("amortized_cost_ms_per_question", "amortized cost ms / question"),
            ("packet_tokens_mean", "context packet tokens (mean)"),
            ("overhead_tokens_mean", "context overhead tokens (mean, packet + history)"),
            ("overhead_tokens_max", "context overhead tokens (max)"),
            ("storage_bytes_final", "bytes on disk (final, after close)"), ("storage_bytes_per_event", "bytes per corpus event")]
    rows = [[label] + [_ci(agg[a][m], 1) for a in arms] for m, label in cost]
    add(_table(["measure"] + arms, rows))
    add("")
    growth = manifest.get("growth_by_day") or {}
    days = sorted({g["day"] for a in arms for g in growth.get(a, [])})
    shown = [d for d in days if d in (days[0], days[len(days) // 2], days[-1])] if days else []
    if shown:
        add("Growth over simulated days (mean over runs; database + deletion-ledger bytes excluding the SQLite"
            " -wal/-shm journals, which the open engine has not yet checkpointed / cumulative serving cost ms):")
        add("")
        rows = []
        for a in arms:
            by_day = {g["day"]: g for g in growth.get(a, [])}
            rows.append([a] + [f"{_fmt(by_day[d]['storage_bytes_main'], 0)} B / "
                               f"{_fmt(by_day[d]['cumulative_cost_ms'], 1)} ms" if d in by_day else "n/a"
                               for d in shown])
        add(_table(["arm"] + [f"end of day {d}" for d in shown], rows))
        add("")
    add("Cumulative serving cost = ingestion + maintenance + cold context builds + cold history searches"
        " (warm repeats excluded). Token counts are the engine's conservative estimate"
        " (characters / 3.5 x 1.15), not a model tokenizer. Provider cost is zero: no external provider is"
        " called; arm E's embeddings are local fakes.")
    add("")
    add("## Not measured")
    add("")
    add(f"* Evidence-backed task correctness: {manifest['not_measured']['evidence_backed_task_correctness']}")
    add(f"* Arm F: {F_NOT_EXECUTED}.")
    add("")
    add("Raw per-run metrics are in `manifest.json`; per-question rows in `questions.jsonl`.")
    add("")
    return "\n".join(lines)
