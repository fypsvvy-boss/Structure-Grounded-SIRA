#!/usr/bin/env python3
"""Module 1, part A — run corpus-side enrichment over the CTI corpus.

Requires the base index to already exist (``scripts/build_index.py --stage
base``): the too_common filter reads document frequency from it, which is
exactly the two-pass ordering this project's design docs call for --
base index -> DF stats -> enrichment -> enriched index -- made explicit here
rather than silently assumed.

    python scripts/enrich_corpus.py --config configs/default.yaml
    python scripts/enrich_corpus.py --limit 5 --dry-run   # cheap iteration
    python scripts/enrich_corpus.py --limit 50            # a real small slice

Resumable: re-running with the same ``--output`` skips documents already in
that file and only retries ones that previously failed to parse.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import OllamaClient, config_hash, load_config
from sira_cti.enrichment.corpus_side import run_corpus_enrichment, summarize
from sira_cti.graph import OntologyGraph
from sira_cti.index import LuceneDFLookup, load_corpus


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--output", default=None, help="defaults to config's index.enrichment_path")
    parser.add_argument("--limit", type=int, default=None, help="cap total documents (cheap iteration)")
    parser.add_argument("--concurrency", type=int, default=None, help="override config's enrichment.concurrency")
    parser.add_argument("--dry-run", action="store_true", help="run the pipeline but write nothing to disk")
    args = parser.parse_args()

    cfg = load_config(args.config)
    output_path = Path(args.output) if args.output else Path(cfg["index"]["enrichment_path"])

    base_dir = Path(cfg["index"]["base_dir"])
    if not (base_dir / "manifest.json").exists():
        print(f"Base index not found at {base_dir} -- build it first:")
        print("  python scripts/build_index.py --stage base --config " + args.config)
        return 1

    graph_cfg = cfg["graph"]
    missing = [
        p for p in (*_as_list(graph_cfg["attack_path"]), graph_cfg["cwe_path"], graph_cfg["capec_path"])
        if not Path(p).exists()
    ]
    if missing:
        print("Missing ontology source files -- see data/README.md for fetch steps:")
        for p in missing:
            print(f"  {p}")
        return 1

    graph = OntologyGraph.from_files(
        attack_path=graph_cfg["attack_path"],
        cwe_path=graph_cfg["cwe_path"],
        capec_path=graph_cfg["capec_path"],
        domains=graph_cfg.get("domains"),
    )
    df_lookup = LuceneDFLookup(base_dir)

    llm_cfg = cfg["llm"]
    if llm_cfg["backend"] != "ollama":
        print(f"llm.backend={llm_cfg['backend']!r} is not supported yet (only 'ollama').")
        return 1

    def client_factory():
        return OllamaClient(
            model=llm_cfg["model"], host=llm_cfg.get("host"),
            temperature=llm_cfg.get("temperature", 0.0), max_retries=llm_cfg.get("max_retries", 2),
        )

    corpus_cfg = cfg["corpus"]
    enrich_cfg = cfg["enrichment"]
    docs = load_corpus(corpus_cfg["kb_dir"], corpus_cfg["kinds"], limit=args.limit)

    print(f"Enriching -> {output_path}  (model={llm_cfg['model']}, dry_run={args.dry_run})")
    summary = run_corpus_enrichment(
        docs,
        client_factory=client_factory,
        graph=graph,
        df_lookup=df_lookup,
        output_path=output_path,
        max_terms=enrich_cfg["max_terms_per_doc"],
        df_max_ratio=enrich_cfg["df_max_ratio"],
        allow_deprecated=graph_cfg.get("allow_deprecated", False),
        revoked_policy=graph_cfg.get("revoked_policy", "reject"),
        concurrency=args.concurrency if args.concurrency is not None else enrich_cfg.get("concurrency", 1),
        prompt_version=enrich_cfg.get("corpus_prompt_version", "corpus-v1"),
        config_hash=config_hash(args.config),
        corpus_kinds=list(corpus_cfg["kinds"]),
        dry_run=args.dry_run,
    )

    print(
        f"\n{summary.total_docs} docs total, {summary.already_done} already done, "
        f"{summary.processed} processed, {summary.failed} failed, {summary.elapsed_s:.1f}s"
    )
    if summary.failures:
        print("Failures:")
        for doc_id, error in summary.failures[:10]:
            print(f"  {doc_id}: {error}")

    if not args.dry_run and output_path.exists():
        stats = summarize(output_path)
        print("\nAccept/reject summary (cumulative, whole file):")
        print(f"  accepted: {stats['accepted']}")
        print(f"  rejected: {stats['rejected']}")
        for reason, n in sorted(stats["rejected_by_reason"].items()):
            print(f"    {reason}: {n}")
        print(f"  repaired: {stats['repaired']}")
        rate = stats["staleness_rate"]
        print(f"  staleness_rate: {rate:.3f}" if rate is not None else "  staleness_rate: n/a")

    return 0


def _as_list(value):
    return [value] if isinstance(value, str) else list(value)


if __name__ == "__main__":
    raise SystemExit(main())
