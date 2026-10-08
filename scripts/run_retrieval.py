#!/usr/bin/env python3
"""Module 3 — run one retrieval system over a query file and write a TREC run.

    python scripts/run_retrieval.py --system sira --queries q.jsonl \\
        --enrichment indexes/enrichment/queries.jsonl --output runs/sira.trec
    python scripts/run_retrieval.py --system plain_bm25 --queries q.jsonl --output runs/bm25.trec
    python scripts/run_retrieval.py --system hybrid     --queries q.jsonl --output runs/hybrid.trec
    python scripts/run_retrieval.py --system agent      --queries q.jsonl --output runs/agent.trec

Ablations of ``--system sira`` (README, Evaluation > Ablations):

    --no-grounding           also admit terms the ontology graph rejected (1)
    --no-corpus-enrichment   search the base index, contents only        (2)
    --budget N               extra sub-queries for synthesis questions   (3)
    --w X                    expansion weight                            (4)

``--queries`` is JSONL, one question per line: ``{"id": ..., "query": ...}``.
A multi-document synthesis question may add ``"sub_queries": [{"id": ...,
"query": ...}, ...]`` -- written up front by query-side enrichment, never
from retrieved results. ``--enrichment`` is the query-side enrichment JSONL
(Module 2); each record's ``doc_id`` is the id of the question or sub-query
it belongs to. Without it, ``sira`` has no expansion half.

Writes three files: the run itself, ``<output>.costs.jsonl`` (LLM calls,
tokens and latency per question, for RQ3) and ``<output>.manifest.json``
(config hash and every setting that shaped the run).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import OllamaClient, config_hash, load_config, read_jsonl
from sira_cti.index import load_corpus
from sira_cti.retrieval import (
    CONTENTS_FIELD,
    DEFAULT_FIELDS,
    WeightedBM25Retriever,
    retrieve_synthesis,
    write_costs,
    write_trec_run,
)
from sira_cti.retrieval.baselines import (
    HybridRetriever,
    MultiRoundAgent,
    PlainBM25Retriever,
    SentenceTransformerEncoder,
)

SYSTEMS = ["sira", "plain_bm25", "hybrid", "agent"]


def load_queries(path: Path, limit: int | None) -> list[dict]:
    queries = []
    with path.open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if "id" not in row or "query" not in row:
                raise ValueError(f"{path}:{line_no}: a query row needs 'id' and 'query'")
            queries.append(row)
            if limit is not None and len(queries) >= limit:
                break
    return queries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--system", choices=SYSTEMS, required=True)
    parser.add_argument("--queries", required=True, help="JSONL of {id, query[, sub_queries]}")
    parser.add_argument("--enrichment", default=None, help="query-side enrichment JSONL (sira only)")
    parser.add_argument("--output", required=True, help="TREC run file to write")
    parser.add_argument("--k", type=int, default=None, help="override retrieval.top_k")
    parser.add_argument("--w", type=float, default=None, help="override retrieval.w")
    parser.add_argument("--budget", type=int, default=None, help="override retrieval.synthesis_budget")
    parser.add_argument("--id-boost", type=float, default=None, help="override retrieval.id_boost")
    parser.add_argument("--no-grounding", action="store_true", help="ablation: admit graph-rejected terms")
    parser.add_argument("--no-corpus-enrichment", action="store_true", help="ablation: base index, contents only")
    parser.add_argument("--limit", type=int, default=None, help="first N questions only (cheap iteration)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    r_cfg, index_cfg, b_cfg = cfg["retrieval"], cfg["index"], cfg.get("baselines", {})
    k = args.k if args.k is not None else r_cfg["top_k"]
    bm25 = {"k1": r_cfg["k1"], "b": r_cfg["b"]}

    sira_only = {"--enrichment": args.enrichment, "--w": args.w, "--id-boost": args.id_boost,
                 "--no-grounding": args.no_grounding, "--no-corpus-enrichment": args.no_corpus_enrichment}
    if args.system != "sira":
        used = [flag for flag, value in sira_only.items() if value not in (None, False)]
        if used:
            print(f"{', '.join(used)} only apply to --system sira")
            return 1

    use_enriched = args.system == "sira" and not args.no_corpus_enrichment
    index_dir = Path(index_cfg["enriched_dir"] if use_enriched else index_cfg["base_dir"])
    if not (index_dir / "manifest.json").exists():
        stage = "enriched" if use_enriched else "base"
        print(f"Index not found at {index_dir} -- build it first:")
        print(f"  python scripts/build_index.py --stage {stage} --config {args.config}")
        return 1

    settings: dict = {"k": k, **bm25}
    budget = 0

    if args.system == "sira":
        fields = r_cfg.get("fields", {})
        orig_fields = dict(fields.get("orig", DEFAULT_FIELDS))
        exp_fields = dict(fields.get("exp", DEFAULT_FIELDS))
        if args.no_corpus_enrichment:
            orig_fields = {CONTENTS_FIELD: orig_fields.get(CONTENTS_FIELD, 1.0)}
            exp_fields = {CONTENTS_FIELD: exp_fields.get(CONTENTS_FIELD, 1.0)}
        name = "sira_cti" + ("_nogrounding" if args.no_grounding else "") + ("_nocorpus" if args.no_corpus_enrichment else "")
        w = args.w if args.w is not None else r_cfg["w"]
        id_boost = args.id_boost if args.id_boost is not None else r_cfg.get("id_boost", 0.0)
        budget = args.budget if args.budget is not None else r_cfg.get("synthesis_budget", 0)
        retriever = WeightedBM25Retriever(
            index_dir, w=w, **bm25, orig_fields=orig_fields, exp_fields=exp_fields,
            id_boost=id_boost, include_graph_rejected=args.no_grounding, name=name,
        )
        settings.update(w=w, id_boost=id_boost, synthesis_budget=budget, orig_fields=orig_fields,
                        exp_fields=exp_fields, include_graph_rejected=args.no_grounding,
                        rrf_k=r_cfg.get("rrf_k", 60))
    else:
        plain = PlainBM25Retriever(index_dir, **bm25)
        retriever = plain
        if args.system == "hybrid":
            h_cfg = b_cfg.get("hybrid", {})
            model = h_cfg.get("model", "sentence-transformers/all-MiniLM-L6-v2")
            alpha, depth = h_cfg.get("alpha", 0.5), h_cfg.get("depth", 1000)
            corpus_cfg = cfg["corpus"]
            print(f"Encoding corpus with {model} (cached under {h_cfg.get('cache_dir')}) ...")
            retriever = HybridRetriever(
                plain, load_corpus(corpus_cfg["kb_dir"], corpus_cfg["kinds"]), SentenceTransformerEncoder(model),
                alpha=alpha, depth=depth, cache_dir=h_cfg.get("cache_dir"),
            )
            settings.update(model=model, alpha=alpha, depth=depth)
        elif args.system == "agent":
            a_cfg, llm_cfg = b_cfg.get("agent", {}), cfg["llm"]
            if llm_cfg["backend"] != "ollama":
                print(f"llm.backend={llm_cfg['backend']!r} is not supported yet (only 'ollama').")
                return 1
            client = OllamaClient(
                model=llm_cfg["model"], host=llm_cfg.get("host"),
                temperature=llm_cfg.get("temperature", 0.0), max_retries=llm_cfg.get("max_retries", 2),
            )
            agent_kwargs = {
                "max_rounds": a_cfg.get("max_rounds", 3), "read_k": a_cfg.get("read_k", 5),
                "snippet_chars": a_cfg.get("snippet_chars", 400), "rrf_k": r_cfg.get("rrf_k", 60),
            }
            retriever = MultiRoundAgent(plain, client, **agent_kwargs)
            settings.update(model=llm_cfg["model"], **agent_kwargs)

    queries = load_queries(Path(args.queries), args.limit)
    records = {rec.doc_id: rec for rec in read_jsonl(args.enrichment)} if args.enrichment else {}
    if args.system == "sira" and not records:
        print("Note: no --enrichment given, so there is no expansion half -- this is BM25 over the chosen fields.")

    print(f"Running {retriever.name} over {len(queries)} questions (index={index_dir}, k={k})")
    started = time.perf_counter()
    results = []
    for row in queries:
        qid, text = str(row["id"]), row["query"]
        subs = [(s["query"], records.get(str(s["id"]))) for s in row.get("sub_queries", [])]
        if args.system == "sira" and subs and budget > 0:
            results.append(retrieve_synthesis(
                retriever, text, subs, budget=budget, query_id=qid, enrichment=records.get(qid),
                k=k, rrf_k=r_cfg.get("rrf_k", 60),
            ))
        else:
            results.append(retriever.retrieve(text, query_id=qid, enrichment=records.get(qid), k=k))
    elapsed = time.perf_counter() - started

    output = Path(args.output)
    lines = write_trec_run(results, output)
    write_costs(results, output.with_suffix(output.suffix + ".costs.jsonl"))

    n = max(len(results), 1)
    totals = {
        "questions": len(results),
        "questions_with_enrichment": sum(1 for row in queries if str(row["id"]) in records),
        "retrieval_calls": sum(r.retrieval_calls for r in results),
        "llm_calls": sum(r.llm_calls for r in results),
        "tokens": sum(r.tokens.total for r in results),
        "retrieval_ms": sum(r.retrieval_ms for r in results),
        "llm_latency_ms": sum(r.llm_latency_ms for r in results),
        "empty_results": sum(1 for r in results if not r.hits),
    }
    manifest = {
        "system": retriever.name,
        "queries_path": str(args.queries),
        "enrichment_path": args.enrichment,
        "index_dir": str(index_dir),
        "index_manifest": json.loads((index_dir / "manifest.json").read_text()),
        "settings": settings,
        "totals": totals,
        "config_hash": config_hash(args.config),
        "created_at": time.time(),
    }
    output.with_suffix(output.suffix + ".manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"\n{lines} ranked lines -> {output}  ({elapsed:.1f}s)")
    print(f"  per question: {totals['retrieval_calls'] / n:.2f} retrieval calls, "
          f"{totals['llm_calls'] / n:.2f} LLM calls, {totals['tokens'] / n:.0f} tokens, "
          f"{totals['retrieval_ms'] / n:.1f} ms retrieval, {totals['llm_latency_ms'] / n:.0f} ms LLM")
    if totals["empty_results"]:
        print(f"  {totals['empty_results']} questions returned nothing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
