#!/usr/bin/env python3
"""Module 4 — prepare the CTIConnect benchmark, and score retrieval runs against it.

Two steps, kept explicit like the index build:

    # 1. CTIConnect QA rows -> query files (Module 3's format), qrels, dev/test split
    python scripts/run_eval.py prepare --output-dir runs/benchmark

    # ... Module 3 produces runs from runs/benchmark/queries.<split>.jsonl ...

    # 2. Score them
    python scripts/run_eval.py score \\
        --qrels runs/benchmark/qrels.test.trec \\
        --run runs/sira.trec --run runs/bm25.trec --run runs/agent.trec \\
        --corpus-enrichment indexes/enrichment/corpus.jsonl \\
        --output-dir runs/results/test

``score`` reads, for every ``--run``, the run file plus the
``<run>.costs.jsonl`` and ``<run>.manifest.json`` Module 3's runner writes
beside it. It writes ``results.json``, ``results.md`` and
``per_query.jsonl``. It exits non-zero, and writes nothing, if a run fails
validation — pass ``--allow-errors`` to write the results anyway, marked as
carrying errors.

Tune on ``dev``, report ``test``: the split is fixed by ``prepare`` (seed:
``--seed``, default ``eval.seed``) before any system is run.

Multi-document synthesis (CSC/TAP/MLA) is not scored — how to score it is
undecided. ``prepare`` sets those questions aside in ``blocked.jsonl`` and
``score`` reports them as blocked.

No model is called and nothing is fetched: both steps only read local files.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import config_hash, load_config
from sira_cti.eval import evaluate, load_qa, write_benchmark, write_results
from sira_cti.index import load_corpus


def _corpus_doc_ids(cfg: dict, kb_dir: Optional[str]) -> Optional[set[str]]:
    """Doc ids of the corpus the index is built from, or ``None`` if it is not on disk."""
    corpus_cfg = cfg.get("corpus") or {}
    kb = Path(kb_dir or corpus_cfg.get("kb_dir", ""))
    kinds = corpus_cfg.get("kinds") or []
    if not kb.is_dir() or not all((kb / f"{kind}.jsonl").exists() for kind in kinds):
        return None
    return {doc.doc_id for doc in load_corpus(kb, kinds)}


def cmd_prepare(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    qa_dir = Path(args.qa_dir)
    if not qa_dir.is_dir():
        print(f"CTIConnect QA directory not found at {qa_dir} -- see data/README.md for fetch steps.")
        return 1

    seed = args.seed if args.seed is not None else cfg["eval"]["seed"]
    doc_ids = _corpus_doc_ids(cfg, args.kb_dir)
    bench = load_qa(qa_dir)
    manifest = write_benchmark(
        bench, args.output_dir, seed=seed, dev_fraction=args.dev_fraction,
        qa_dir=qa_dir, config_hash=config_hash(args.config), known_doc_ids=doc_ids,
    )

    q = manifest["questions"]
    print(f"Benchmark -> {args.output_dir}  (seed={seed}, dev_fraction={args.dev_fraction})")
    print(f"  scoreable questions: {q['all']}  (dev {q['dev']}, test {q['test']})")
    for task, n in manifest["questions_by_task"]["all"].items():
        print(f"    {task}: {n}")
    print(f"  blocked (not scored): {manifest['blocked']}  {manifest['blocked_by_reason'] or ''}")
    if doc_ids is None:
        print("  corpus not found -- gold ids were not checked against it")
    elif manifest["gold_not_in_corpus"]:
        print(f"  {len(manifest['gold_not_in_corpus'])} gold id(s) name no document in the corpus (kept in the qrels):")
        for row in manifest["gold_not_in_corpus"][:10]:
            print(f"    {row['id']}: {row['gold_id']}")
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    for path in [args.qrels, *args.run, *args.corpus_enrichment, *args.query_enrichment]:
        if not Path(path).exists():
            print(f"Not found: {path}")
            return 1

    results, per_query = evaluate(
        qrels_path=args.qrels,
        run_paths=args.run,
        config_path=args.config,
        metadata_path=args.metadata,
        known_doc_ids=_corpus_doc_ids(cfg, args.kb_dir),
        corpus_enrichment_paths=args.corpus_enrichment,
        query_enrichment_paths=args.query_enrichment,
        attack_version=args.attack_version,
        baseline=args.baseline,
        n_bootstrap=args.bootstrap,
        n_randomisation=args.randomisation,
        seed=args.seed,
    )

    for issue in results["issues"]:
        print(f"  [{issue['severity']}] {issue['code']}: {issue['message']}" + (f"  ({issue['where']})" if issue["where"] else ""))

    if results["status"] != "ok" and not args.allow_errors:
        print("\nValidation errors -- nothing written. Fix the inputs, or pass --allow-errors to write marked results.")
        return 1

    paths = write_results(results, per_query, args.output_dir)
    metrics = results["provenance"]["eval"]["metrics"]
    print(f"\n{results['benchmark']['questions_scored']} questions scored  (config {results['provenance']['config_hash']})")
    for name, system in results["systems"].items():
        overall = system["quality"]["overall"]
        cells = "  ".join(f"{m}={overall[m]['mean']:.4f}" for m in metrics if overall[m]["mean"] is not None)
        print(f"  {name}: {cells}")
    print("  multi_doc_synthesis: blocked (scoring undefined)")
    print(f"\nResults -> {paths['json']}, {paths['markdown']}, {paths['per_query']}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare", help="CTIConnect QA rows -> query files, qrels, dev/test split")
    prepare.add_argument("--config", default="configs/default.yaml")
    prepare.add_argument("--qa-dir", default="data/CTIConnect/data", help="CTIConnect's data/ directory")
    prepare.add_argument("--output-dir", required=True)
    prepare.add_argument("--seed", type=int, default=None, help="split seed (default: eval.seed)")
    prepare.add_argument("--dev-fraction", type=float, default=0.2, help="share of each task held out for tuning")
    prepare.add_argument("--kb-dir", default=None, help="override corpus.kb_dir (used to check gold ids exist)")
    prepare.set_defaults(func=cmd_prepare)

    score = sub.add_parser("score", help="score TREC runs against qrels")
    score.add_argument("--config", default="configs/default.yaml")
    score.add_argument("--qrels", required=True)
    score.add_argument("--run", action="append", required=True, help="a TREC run file; repeat for each system")
    score.add_argument("--output-dir", required=True)
    score.add_argument("--metadata", default=None, help="defaults to metadata.jsonl beside the qrels")
    score.add_argument("--corpus-enrichment", action="append", default=[], help="corpus-side enrichment JSONL: offline cost + audit")
    score.add_argument("--query-enrichment", action="append", default=[], help="query-side enrichment JSONL: audit")
    score.add_argument("--baseline", default=None, help="compare every other system against this one (default: all pairs)")
    score.add_argument("--attack-version", default=None, help="ATT&CK release, e.g. v17.1 (default: read from the STIX bundles)")
    score.add_argument("--kb-dir", default=None, help="override corpus.kb_dir (used to check retrieved doc ids exist)")
    score.add_argument("--seed", type=int, default=None, help="bootstrap/randomisation seed (default: eval.seed)")
    score.add_argument("--bootstrap", type=int, default=1000, help="bootstrap resamples")
    score.add_argument("--randomisation", type=int, default=10000, help="randomisation-test resamples")
    score.add_argument("--allow-errors", action="store_true", help="write results even if a run fails validation")
    score.set_defaults(func=cmd_score)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
