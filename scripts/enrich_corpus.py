#!/usr/bin/env python3
"""Module 1, part A — run corpus-side enrichment over the CTI corpus.

Requires the base index to already exist (``scripts/build_index.py --stage
base``): the too_common filter reads document frequency from it, which is
exactly the two-pass ordering this project's design docs call for --
base index -> DF stats -> enrichment -> enriched index -- made explicit here
rather than silently assumed.

    python scripts/enrich_corpus.py --config configs/default.yaml
    python scripts/enrich_corpus.py --limit 5 --dry-run   # cheap iteration
    python scripts/enrich_corpus.py --per-kind 10 --output indexes/enrichment/corpus_stratified.jsonl

``--limit N`` takes the first N documents in load order, which for corpus_kb
means CVEs only until N passes 3,011 -- fine for smoke-testing, useless for any
claim about CWE/CAPEC/ATT&CK. ``--per-kind N`` takes a seeded random N from
each document type instead (seed: ``--seed``, default ``eval.seed``).

Resumable: re-running with the same ``--output`` skips documents already in
that file and only retries ones that previously failed to parse. Give a
sampled run its own ``--output`` -- resuming a different sample into the same
file mixes two populations.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import OllamaClient, config_hash, load_config
from sira_cti.enrichment.corpus_side import run_corpus_enrichment, summarize, summarize_by_source
from sira_cti.enrichment.prompts.corpus_side import PROMPT_VERSION, REPLY_SCHEMA
from sira_cti.graph import OntologyGraph
from sira_cti.index import LuceneDFLookup, load_corpus, sample_corpus


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--output", default=None, help="defaults to config's index.enrichment_path")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--limit", type=int, default=None, help="first N documents in load order (CVE-only below 3,011)")
    selection.add_argument("--per-kind", type=int, default=None, help="seeded random N documents from each type")
    parser.add_argument("--seed", type=int, default=None, help="sampling seed for --per-kind (default: eval.seed)")
    parser.add_argument("--concurrency", type=int, default=None, help="override config's enrichment.concurrency")
    parser.add_argument("--model", default=None, help="override config's llm.model (recorded in the manifest)")
    parser.add_argument(
        "--no-name-check",
        action="store_true",
        help="disable the name-ID consistency stage (reproduces corpus-v3 adjudication)",
    )
    parser.add_argument(
        "--name-overlap",
        type=float,
        default=None,
        help="override enrichment.name_match_min_overlap (0.0-1.0)",
    )
    parser.add_argument(
        "--name-scorer", choices=["v1", "v2", "v3"], default=None,
        help="override enrichment.name_scorer",
    )
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

    model = args.model or llm_cfg["model"]

    corpus_cfg = cfg["corpus"]
    enrich_cfg = cfg["enrichment"]

    # enrichment.max_new_tokens used to be read by nothing at all: the cap sat
    # in the config file while every reply was generated unbounded. It now
    # reaches Ollama as options.num_predict via the wrapper.
    max_new_tokens = enrich_cfg.get("max_new_tokens")

    # enrichment.json_mode: "schema" | "json" | "off". Only "schema" pins the
    # reply *shape*; plain "json" is valid-JSON-only and made qwen2.5:14b
    # answer with one object instead of an array (see REPLY_SCHEMA).
    json_mode_cfg = str(enrich_cfg.get("json_mode", "off")).lower()
    if json_mode_cfg not in {"schema", "json", "off", "true", "false"}:
        print(f"enrichment.json_mode={json_mode_cfg!r} must be one of: schema, json, off")
        return 1
    json_schema = REPLY_SCHEMA if json_mode_cfg == "schema" else None
    json_mode = json_mode_cfg in {"json", "true"}

    def client_factory():
        return OllamaClient(
            model=model, host=llm_cfg.get("host"),
            temperature=llm_cfg.get("temperature", 0.0), max_retries=llm_cfg.get("max_retries", 2),
            max_new_tokens=max_new_tokens, json_mode=json_mode, json_schema=json_schema,
        )

    if args.no_name_check:
        name_overlap = None
    elif args.name_overlap is not None:
        name_overlap = args.name_overlap
    else:
        name_overlap = enrich_cfg.get("name_match_min_overlap")
    if args.per_kind is not None:
        seed = args.seed if args.seed is not None else cfg["eval"]["seed"]
        docs = sample_corpus(corpus_cfg["kb_dir"], corpus_cfg["kinds"], per_kind=args.per_kind, seed=seed)
        sampling = {"method": "per_kind", "per_kind": args.per_kind, "seed": seed}
    else:
        docs = load_corpus(corpus_cfg["kb_dir"], corpus_cfg["kinds"], limit=args.limit)
        sampling = {"method": "prefix", "limit": args.limit}

    print(
        f"Enriching -> {output_path}  (model={model}, dry_run={args.dry_run})\n"
        f"  prompt={PROMPT_VERSION}  name_check="
        + ("off" if name_overlap is None else f"overlap>={name_overlap}")
        + f"  max_new_tokens={max_new_tokens}  decoding={json_mode_cfg}"
    )
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
        name_match_min_overlap=name_overlap,
        name_scorer=args.name_scorer or enrich_cfg.get("name_scorer", "v1"),
        name_match_min_jaccard=float(enrich_cfg.get("name_match_min_jaccard", 0.6)),
        json_retries=int(enrich_cfg.get("json_retries", 0)),
        record_json_failures=bool(enrich_cfg.get("record_json_failures", False)),
        max_new_tokens=max_new_tokens,
        json_mode=json_mode_cfg,
        concurrency=args.concurrency if args.concurrency is not None else enrich_cfg.get("concurrency", 1),
        prompt_version=PROMPT_VERSION,
        config_hash=config_hash(args.config),
        corpus_kinds=list(corpus_cfg["kinds"]),
        sampling=sampling,
        dry_run=args.dry_run,
    )

    print(
        f"\n{summary.total_docs} docs total, {summary.already_done} already done, "
        f"{summary.processed} processed, {summary.failed} failed, "
        f"{summary.json_failures} unparseable, {summary.elapsed_s:.1f}s"
    )
    if summary.json_failures:
        print(
            "  (unparseable replies are written as reject_reason=llm_json_error; "
            f"the raw text is in {output_path.name}.raw_failures.jsonl)"
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

        print("\nBy source document type:")
        for source, s in sorted(summarize_by_source(output_path).items()):
            print(f"  {source}: {s['docs']} docs, {s['proposed']} proposed, {s['accepted']} accepted")
            print(f"    rejected: {s['rejected_by_reason'] or '{}'}")
            print(f"    structural proposed by catalogue: {s['structural_proposed_by_namespace'] or '{}'}")
            print(f"    structural accepted by catalogue: {s['structural_accepted_by_namespace'] or '{}'}")

    return 0


def _as_list(value):
    return [value] if isinstance(value, str) else list(value)


if __name__ == "__main__":
    raise SystemExit(main())
