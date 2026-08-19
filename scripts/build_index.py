#!/usr/bin/env python3
"""Module 1, part B — build the base and/or enriched Lucene indexes.

The ordering is explicit, not hidden -- there is no ``--stage both`` that
tries to paper over it. Run:

    python scripts/build_index.py --stage base
    python scripts/enrich_corpus.py               # reads the base index for DF
    python scripts/build_index.py --stage enriched

    python scripts/build_index.py --stage base --limit 20 --dry-run
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import config_hash, load_config
from sira_cti.index import build_base_index, build_enriched_index, load_corpus


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--stage", choices=["base", "enriched"], required=True)
    parser.add_argument("--limit", type=int, default=None, help="cap total documents (cheap iteration)")
    parser.add_argument("--dry-run", action="store_true", help="report what would be indexed, build nothing")
    args = parser.parse_args()

    cfg = load_config(args.config)
    corpus_cfg = cfg["corpus"]
    index_cfg = cfg["index"]
    the_hash = config_hash(args.config)

    if args.stage == "base":
        if args.dry_run:
            n = sum(1 for _ in load_corpus(corpus_cfg["kb_dir"], corpus_cfg["kinds"], limit=args.limit))
            print(f"[dry-run] would build base index over {n} docs -> {index_cfg['base_dir']}")
        else:
            path = build_base_index(
                kb_dir=corpus_cfg["kb_dir"], index_dir=index_cfg["base_dir"], kinds=corpus_cfg["kinds"],
                threads=index_cfg.get("threads", 2), stemmer=index_cfg.get("stemmer", "porter"),
                limit=args.limit, config_hash=the_hash,
            )
            print(f"Base index built -> {path}")

    if args.stage == "enriched":
        enrichment_path = Path(index_cfg["enrichment_path"])
        if args.dry_run:
            exists = enrichment_path.exists()
            print(f"[dry-run] would build enriched index from {enrichment_path} (exists={exists}) -> {index_cfg['enriched_dir']}")
        else:
            path = build_enriched_index(
                kb_dir=corpus_cfg["kb_dir"], enrichment_path=enrichment_path,
                index_dir=index_cfg["enriched_dir"], kinds=corpus_cfg["kinds"],
                threads=index_cfg.get("threads", 2), stemmer=index_cfg.get("stemmer", "porter"),
                limit=args.limit, config_hash=the_hash,
            )
            print(f"Enriched index built -> {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
