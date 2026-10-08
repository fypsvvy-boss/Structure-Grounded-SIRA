"""Module 4 -- assembling one evaluation into a results file and its tables.

:func:`evaluate` is the whole harness in one call: qrels and runs in, a
single JSON-serialisable ``results`` dict out, holding quality (RQ2), cost
and efficiency (RQ3), the enrichment audit (RQ4), every validation issue
found on the way, and the provenance needed to say exactly what was
measured. :func:`render_markdown` turns that dict into tables;
``scripts/run_eval.py`` is a thin CLI over the two.

Provenance carried into every results file (README, Reproducibility):
the evaluation's config hash, the ATT&CK release the ontology was built
from, the git commit, the benchmark manifest (split seed and fraction), and
for every run its full Module 3 manifest -- which holds that run's own
config hash, settings, index manifest, and the model and prompt version
behind the enriched index. Anything that cannot be established is recorded
as ``null`` with a ``provenance_missing`` warning, never filled in.

Not scored: multi-document synthesis (CSC / TAP / MLA). See
:mod:`sira_cti.eval.cticonnect`; the results file says so under
``"blocked"`` instead of carrying a number for it.
"""

from __future__ import annotations

import itertools
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from ..common.repro import config_hash, load_config
from ..common.schemas import read_jsonl
from . import audit as audit_mod
from . import cost as cost_mod
from . import metrics as metrics_mod
from .cticonnect import BLOCKED_SYNTHESIS, read_metadata, read_qrels
from .runs import ERROR, WARNING, Issue, check_consistency, errors, read_run, sidecar

RESULTS_SCHEMA = "sira-cti-eval/1"

SYNTHESIS_BLOCK_DETAIL = (
    "CSC / TAP / MLA are judged free-text answers over vendor reports. Those reports are not in the "
    "retrieval index (corpus_kb holds cve/cwe/capec/mitre only), so there is no gold document to score "
    "against, and 'entity/answer coverage' has no agreed definition. No metric is computed for these "
    "tasks until the team defines one."
)


# -- provenance -----------------------------------------------------------------------


def git_commit(repo_dir: str | Path = ".") -> Optional[str]:
    """The checked-out commit, or ``None`` outside a git checkout."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(repo_dir), capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None if out.returncode == 0 else None


def detect_attack_version(bundle_paths: Iterable[str | Path]) -> list[str]:
    """ATT&CK release(s) named by the STIX bundles' ``x-mitre-collection`` objects.

    ``data/README.md`` pins the ontology to one tagged release and asks for
    it to be recorded with every result; this reads it from the files the
    graph was actually built from rather than trusting a comment.
    """
    versions: set[str] = set()
    for path in bundle_paths:
        path = Path(path)
        if not path.exists():
            continue
        bundle = json.loads(path.read_text(encoding="utf-8"))
        for obj in bundle.get("objects", []):
            if obj.get("type") == "x-mitre-collection" and obj.get("x_mitre_version"):
                versions.add(str(obj["x_mitre_version"]))
    return sorted(versions)


def _attack_provenance(stated: Optional[str], cfg: Mapping[str, Any]) -> dict[str, Any]:
    if stated:
        return {"value": stated, "source": "stated"}
    paths = (cfg.get("graph") or {}).get("attack_path") or []
    detected = detect_attack_version([paths] if isinstance(paths, str) else paths)
    if detected:
        return {"value": detected[0] if len(detected) == 1 else detected, "source": "stix_bundle"}
    return {"value": None, "source": "unknown"}


def _run_provenance(run, costs_path: Optional[Path]) -> dict[str, Any]:
    manifest = run.manifest or {}
    settings = manifest.get("settings") if isinstance(manifest.get("settings"), dict) else {}
    index = manifest.get("index_manifest") if isinstance(manifest.get("index_manifest"), dict) else {}
    return {
        "run_path": run.path,
        "costs_path": str(costs_path) if costs_path else None,
        "config_hash": manifest.get("config_hash"),
        # For the agent this is the LLM; for the hybrid baseline, the encoder.
        "model": settings.get("model"),
        "index_kind": index.get("kind"),
        "index_config_hash": index.get("config_hash"),
        "corpus_enrichment_model": index.get("enrichment_model"),
        "corpus_enrichment_prompt_version": index.get("enrichment_prompt_version"),
        "query_enrichment_path": manifest.get("enrichment_path"),
        "manifest": run.manifest,
    }


def _enrichment_provenance(path: str | Path) -> dict[str, Any]:
    manifest_path = sidecar(path, ".manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else None
    models = sorted({rec.model for rec in read_jsonl(path) if rec.model})
    return {
        "path": str(path),
        "models": models,
        "prompt_version": (manifest or {}).get("prompt_version"),
        "config_hash": (manifest or {}).get("config_hash"),
        "manifest": manifest,
    }


# -- the harness ----------------------------------------------------------------------


def evaluate(
    *,
    qrels_path: str | Path,
    run_paths: Sequence[str | Path],
    config_path: str | Path,
    metadata_path: Optional[str | Path] = None,
    known_doc_ids: Optional[Iterable[str]] = None,
    corpus_enrichment_paths: Sequence[str | Path] = (),
    query_enrichment_paths: Sequence[str | Path] = (),
    attack_version: Optional[str] = None,
    baseline: Optional[str] = None,
    n_bootstrap: int = 1000,
    n_randomisation: int = 10000,
    alpha: float = 0.05,
    seed: Optional[int] = None,
    repo_dir: str | Path = ".",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Score ``run_paths`` against ``qrels_path``. Returns ``(results, per_query_rows)``.

    ``metadata_path`` defaults to ``metadata.jsonl`` beside the qrels (where
    :func:`~sira_cti.eval.cticonnect.write_benchmark` puts it); without it
    there is no task/category breakdown. ``known_doc_ids`` turns on the
    check that every retrieved doc id exists in the corpus. ``seed`` and the
    metric list default to ``eval.seed`` / ``eval.metrics`` in the config.

    ``results["status"]`` is ``"errors"`` if any error-severity issue was
    found; the numbers are still computed so they can be inspected, and it
    is the caller's decision whether to publish them.
    """
    qrels_path, config_path = Path(qrels_path), Path(config_path)
    cfg = load_config(config_path)
    eval_cfg = cfg.get("eval") or {}
    seed = eval_cfg.get("seed", 42) if seed is None else seed
    metric_list = metrics_mod.metric_names(eval_cfg.get("metrics"))
    the_hash = config_hash(config_path)
    issues: list[Issue] = []

    qrels = read_qrels(qrels_path)
    if metadata_path is None and (qrels_path.parent / "metadata.jsonl").exists():
        metadata_path = qrels_path.parent / "metadata.jsonl"
    metadata = read_metadata(metadata_path) if metadata_path is not None else {}
    if not metadata:
        issues.append(Issue(WARNING, "no_metadata", "no metadata file -- results are not broken down by task/category"))
    groupings = {"task": metrics_mod.group_of(metadata, "task"), "category": metrics_mod.group_of(metadata, "category")}

    bench_manifest_path = qrels_path.parent / "manifest.json"
    bench_manifest = None
    if bench_manifest_path.exists():
        candidate = json.loads(bench_manifest_path.read_text(encoding="utf-8"))
        bench_manifest = candidate if candidate.get("kind") == "cticonnect_eval" else None
    if bench_manifest is None:
        issues.append(Issue(WARNING, "provenance_missing", "no benchmark manifest beside the qrels (split seed unknown)"))

    known_docs = set(known_doc_ids) if known_doc_ids is not None else None
    if known_docs is None:
        issues.append(Issue(WARNING, "doc_ids_unchecked", "no corpus given -- retrieved doc ids were not validated"))

    runs = [read_run(p, known_query_ids=qrels.keys(), known_doc_ids=known_docs) for p in run_paths]
    for run in runs:
        issues.extend(run.issues)
    issues.extend(check_consistency(runs, config_hash=the_hash))

    attack = _attack_provenance(attack_version, cfg)
    if attack["value"] is None:
        issues.append(Issue(WARNING, "provenance_missing", "ATT&CK version unknown: pass --attack-version or fetch data/raw/attack"))

    systems: dict[str, Any] = {}
    per_query_by_system: dict[str, metrics_mod.PerQuery] = {}
    run_provenance: dict[str, Any] = {}
    per_query_rows: list[dict[str, Any]] = []

    for run in runs:
        name = run.system or Path(run.path).name
        if name in systems:
            continue  # duplicate_system is already an error; score the first file only
        per_query = metrics_mod.per_query_metrics(run.doc_rankings(), qrels, metric_list)
        per_query_by_system[name] = per_query
        scored = sorted(per_query)

        quality = metrics_mod.summarise(
            per_query, groupings=groupings if metadata else None, metrics=metric_list,
            n_resamples=n_bootstrap, alpha=alpha, seed=seed,
        )

        costs, cost_issues = cost_mod.read_costs_for_run(run.path)
        issues.extend(cost_issues)
        costs_path = sidecar(run.path, ".costs.jsonl") if costs is not None else None
        cost_summary = efficiency = None
        if costs is not None:
            cost_summary = cost_mod.summarise_costs(costs, query_ids=scored)
            if cost_summary["missing"]:
                issues.append(Issue(
                    WARNING, "cost_rows_missing",
                    f"{len(cost_summary['missing'])} scored question(s) have no cost row", str(costs_path),
                ))
            means = {m: quality["overall"][m]["mean"] for m in metric_list}
            efficiency = cost_mod.efficiency(means, cost_summary)

        systems[name] = {
            "coverage": {
                "questions_scored": len(scored),
                "missing_from_run": sum(1 for q in scored if q not in run.rankings),
                "extra_in_run": len(run.query_ids - qrels.keys()),
            },
            "quality": quality,
            "cost": cost_summary,
            "efficiency": efficiency,
        }
        prov = _run_provenance(run, costs_path)
        run_provenance[name] = prov
        if prov["config_hash"] is None:
            issues.append(Issue(WARNING, "provenance_missing", f"{name}: no config hash for this run", run.path))

        for q in scored:
            row = {"query_id": q, "system": name, **{k: metadata.get(q, {}).get(k) for k in ("task", "category", "split")}}
            row.update(per_query[q])
            per_query_rows.append(row)

    names = list(systems)
    if baseline is not None and baseline not in systems:
        issues.append(Issue(ERROR, "unknown_baseline", f"--baseline {baseline!r} is not one of {names}"))
        baseline = None
    pairs = [(n, baseline) for n in names if n != baseline] if baseline else list(itertools.combinations(names, 2))
    comparisons = [
        {"a": a, "b": b, "metric": metric, **stats}
        for a, b in pairs
        for metric, stats in metrics_mod.compare(
            per_query_by_system[a], per_query_by_system[b],
            metrics=metric_list, n_resamples=n_randomisation, seed=seed,
        ).items()
    ]

    n_scored = max((s["coverage"]["questions_scored"] for s in systems.values()), default=0)
    offline_costs = []
    for path in corpus_enrichment_paths:
        offline = cost_mod.offline_enrichment_cost(path)
        if n_scored:
            offline["amortised"] = cost_mod.amortise(offline, n_scored)
        offline_costs.append(offline)

    audits = {
        "corpus": [audit_mod.audit_file(p) for p in corpus_enrichment_paths],
        "query": [audit_mod.audit_file(p) for p in query_enrichment_paths],
    }

    blocked_by_task = (bench_manifest or {}).get("blocked_by_task")
    results = {
        "schema": RESULTS_SCHEMA,
        "status": "errors" if errors(issues) else "ok",
        "provenance": {
            "created_at": time.time(),
            "git_commit": git_commit(repo_dir),
            "config_path": str(config_path),
            "config_hash": the_hash,
            "attack_version": attack,
            "eval": {
                "metrics": list(metric_list), "seed": seed, "alpha": alpha,
                "bootstrap_resamples": n_bootstrap, "randomisation_resamples": n_randomisation,
            },
            "benchmark": {
                "qrels_path": str(qrels_path),
                "metadata_path": str(metadata_path) if metadata_path is not None else None,
                "manifest": bench_manifest,
            },
            "runs": run_provenance,
            "enrichment": {
                "corpus": [_enrichment_provenance(p) for p in corpus_enrichment_paths],
                "query": [_enrichment_provenance(p) for p in query_enrichment_paths],
            },
        },
        "benchmark": {
            "questions_in_qrels": len(qrels),
            "questions_scored": n_scored,
        },
        "systems": systems,
        "comparisons": comparisons,
        "offline_costs": offline_costs,
        "audit": audits,
        "blocked": {
            "multi_doc_synthesis": {
                "status": "blocked",
                "reason": BLOCKED_SYNTHESIS,
                "detail": SYNTHESIS_BLOCK_DETAIL,
                "blocked_questions_by_task": blocked_by_task,
            }
        },
        "issues": [i.to_dict() for i in issues],
        "caveats": {"cost": list(cost_mod.CAVEATS), "audit": list(audit_mod.CAVEATS)},
    }
    return results, per_query_rows


# -- rendering ------------------------------------------------------------------------


def _num(value: Any, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _table(header: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return lines + [""]


def _with_ci(cell: Mapping[str, Any]) -> str:
    if cell["mean"] is None:
        return "n/a"
    return f"{cell['mean']:.4f} [{_num(cell['ci_low'])}, {_num(cell['ci_high'])}]"


def _audit_rows(label: str, table: Mapping[str, Any]) -> list[list[Any]]:
    rows = []
    for key, c in table.items():
        s = c["structural"]
        rows.append([
            f"{label}: {key}" if key else label, c.get("records", ""), c["proposed"], c["accepted"], _num(c["total_rejection_rate"]),
            s["proposed"], s["graph_rejected"], s["corpus_stats_rejected"], s["other_rejected"],
            _num(s["structural_rejection_rate"]), _num(s["graph_rejection_rate"]),
        ])
    return rows


def render_markdown(results: Mapping[str, Any]) -> str:
    """The results dict as Markdown tables. Reads only ``results`` -- no recomputation."""
    prov = results["provenance"]
    metric_list = prov["eval"]["metrics"]
    systems = results["systems"]
    out: list[str] = ["# SIRA-CTI evaluation results", ""]

    if results["status"] != "ok":
        out += ["> **These results carry validation errors (see Issues). Do not report them as they stand.**", ""]

    out += ["## Provenance", ""]
    bench = prov["benchmark"]["manifest"] or {}
    out += _table(["Item", "Value"], [
        ["Config hash", prov["config_hash"]],
        ["Git commit", _num(prov["git_commit"])],
        ["ATT&CK version", f"{_num(prov['attack_version']['value'])} ({prov['attack_version']['source']})"],
        ["Qrels", prov["benchmark"]["qrels_path"]],
        ["Split seed / dev fraction", f"{_num(bench.get('seed'))} / {_num(bench.get('dev_fraction'))}"],
        ["Questions scored", results["benchmark"]["questions_scored"]],
        ["Seed (bootstrap, randomisation)", prov["eval"]["seed"]],
        ["Resamples (bootstrap / randomisation)", f"{prov['eval']['bootstrap_resamples']} / {prov['eval']['randomisation_resamples']}"],
    ])
    out += _table(
        ["System", "Run config hash", "Model", "Index", "Corpus-enrichment model", "Corpus prompt version", "Run file"],
        [[name, _num(p["config_hash"]), _num(p["model"]), _num(p["index_kind"]), _num(p["corpus_enrichment_model"]),
          _num(p["corpus_enrichment_prompt_version"]), p["run_path"]] for name, p in prov["runs"].items()],
    )
    for side in ("corpus", "query"):
        for e in prov["enrichment"][side]:
            out += [f"- {side}-side enrichment `{e['path']}`: models {', '.join(e['models']) or 'n/a'}, "
                    f"prompt version {_num(e['prompt_version'])}, config hash {_num(e['config_hash'])}"]
    out += [""]

    alpha_pct = round((1 - prov["eval"]["alpha"]) * 100)
    out += ["## Retrieval quality", "", f"Mean over questions, with a {alpha_pct}% bootstrap confidence interval.", ""]
    out += _table(
        ["System", "n", *metric_list],
        [[name, s["quality"]["overall"]["n"], *(_with_ci(s["quality"]["overall"][m]) for m in metric_list)]
         for name, s in systems.items()],
    )
    for grouping in ("category", "task"):
        key = f"by_{grouping}"
        if not any(key in s["quality"] for s in systems.values()):
            continue
        out += [f"### By {grouping}", ""]
        out += _table(
            ["System", grouping.capitalize(), "n", *metric_list],
            [[name, group, cell["n"], *(_num(cell[m]["mean"]) for m in metric_list)]
             for name, s in systems.items() for group, cell in s["quality"].get(key, {}).items()],
        )

    out += ["## Cost per question (online)", "", "Mean / median / p95 over the scored questions.", ""]

    def triple(d: Mapping[str, Any], digits: int = 1) -> str:
        return " / ".join(_num(d[k], digits) for k in ("mean", "median", "p95"))

    out += _table(
        ["System", "n", "LLM calls", "Prompt tokens", "Completion tokens", "Total tokens",
         "LLM latency (ms)", "Retrieval calls", "Retrieval (ms)", "Total (ms)"],
        [[name, s["cost"]["n"], triple(s["cost"]["llm_calls"], 2), triple(s["cost"]["prompt_tokens"]),
          triple(s["cost"]["completion_tokens"]), triple(s["cost"]["total_tokens"]), triple(s["cost"]["llm_latency_ms"]),
          triple(s["cost"]["retrieval_calls"], 2), triple(s["cost"]["retrieval_ms"]), triple(s["cost"]["total_ms"])]
         if s["cost"] else [name, "no cost file", *[""] * 8] for name, s in systems.items()],
    )

    out += ["## Quality per unit of cost", "", "`n/a` where the denominator is zero (a system that makes no LLM call).", ""]
    out += _table(
        ["System", "Metric", "Per LLM call", "Per 1k tokens", "Per second"],
        [[name, m, _num(e["per_llm_call"]), _num(e["per_1k_tokens"]), _num(e["per_second"])]
         for name, s in systems.items() if s["efficiency"] for m, e in s["efficiency"].items()],
    )

    if results["comparisons"]:
        out += ["## Paired randomisation tests", "",
                "Two-sided, on per-question scores; mean difference is A minus B. Not corrected for multiple comparisons.", ""]
        out += _table(
            ["A", "B", "Metric", "Mean diff", "p", "Method", "n"],
            [[c["a"], c["b"], c["metric"], _num(c["mean_diff"]), _num(c["p_value"]), c["method"], c["n"]]
             for c in results["comparisons"]],
        )

    if results["offline_costs"]:
        out += ["## Offline cost: corpus-side enrichment", "",
                "Paid once per corpus. **Not included in any per-question figure above.**", ""]
        out += _table(
            ["Enrichment file", "Records", "Failed (no record)", "Models", "LLM calls", "Total tokens",
             "LLM latency (ms)", "Tokens per record (mean)", "Amortised tokens / question"],
            [[o["path"], o["records"], o["failed_without_record"], ", ".join(o["models"]) or "n/a",
              _num(o["llm_calls"]["total"]), _num(o["total_tokens"]["total"]), _num(o["llm_latency_ms"]["total"]),
              _num(o["total_tokens"]["mean"], 1), _num((o.get("amortised") or {}).get("total_tokens"), 1)]
             for o in results["offline_costs"]],
        )

    for side in ("corpus", "query"):
        for a in results["audit"][side]:
            out += [f"## Enrichment audit ({side}-side): `{a['path']}`", "",
                    "Graph rejections are identifiers the ontology refused; corpus-statistics rejections "
                    "(too_common, not_in_index) passed the graph. The two rates are not interchangeable.", ""]
            out += _table(
                ["Slice", "Records", "Proposed", "Accepted", "Total rej. rate", "Structural proposed",
                 "Graph rejected", "Corpus-stats rejected", "Other rejected", "Structural rej. rate", "Graph rej. rate"],
                _audit_rows("all", {"": a}) + _audit_rows("source", a["by_source"])
                + _audit_rows("model", a["by_model"]) + _audit_rows("catalogue", a["by_catalogue"]),
            )
            out += _table(["Reject reason", "Terms"], a["rejected_by_reason"].items())

    out += ["## Not scored", ""]
    for name, b in results["blocked"].items():
        counts = b["blocked_questions_by_task"]
        out += [f"- **{name}** -- {b['status']} (`{b['reason']}`). {b['detail']}"
                + (f" Questions set aside: {counts}." if counts else "")]
    out += [""]

    out += ["## Issues", ""]
    if results["issues"]:
        out += _table(["Severity", "Code", "Where", "Detail"],
                      [[i["severity"], i["code"], i["where"], i["message"]] for i in results["issues"]])
    else:
        out += ["None.", ""]

    out += ["## Caveats", ""]
    out += [f"- {c}" for side in ("cost", "audit") for c in results["caveats"][side]]
    return "\n".join(out) + "\n"


def write_results(results: Mapping[str, Any], per_query_rows: Iterable[Mapping[str, Any]], out_dir: str | Path) -> dict[str, Path]:
    """``results.json``, ``results.md`` and ``per_query.jsonl`` under ``out_dir``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"json": out_dir / "results.json", "markdown": out_dir / "results.md", "per_query": out_dir / "per_query.jsonl"}
    paths["json"].write_text(json.dumps(results, indent=2), encoding="utf-8")
    paths["markdown"].write_text(render_markdown(results), encoding="utf-8")
    with paths["per_query"].open("w", encoding="utf-8") as fh:
        for row in per_query_rows:
            fh.write(json.dumps(row) + "\n")
    return paths
