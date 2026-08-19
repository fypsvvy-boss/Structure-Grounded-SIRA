"""Build the base (unenriched) Lucene/BM25 index over the CTI corpus.

This is the *first* of the two builds this package produces. It doubles as
Module 3's plain-BM25 baseline index (README, Baselines table) -- built once,
read by both this project's baseline and by :mod:`build_enriched`'s DF
lookup (:mod:`sira_cti.index.df_stats`) -- and it must exist before
corpus-side enrichment can run at all, since the DF filter has nothing to
read otherwise. That ordering is enforced at the script layer
(``scripts/build_index.py``), not hidden inside this module.

Indexing goes through Pyserini's CLI (``python -m pyserini.index.lucene``)
via subprocess, the same invocation the README's Phase 0 smoke test
documents, rather than a hand-rolled call into Anserini's Java classes --
one proven code path for both.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, Optional

from .corpus import KINDS, CorpusDocument, load_corpus


def write_json_collection(docs: Iterable[CorpusDocument], staging_dir: str | Path) -> Path:
    """Write Pyserini's ``JsonCollection`` format: one JSONL file of ``{id, contents}``."""
    staging_dir = Path(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)
    out_file = staging_dir / "docs.jsonl"
    n = 0
    with out_file.open("w", encoding="utf-8") as fh:
        for doc in docs:
            fh.write(json.dumps({"id": doc.doc_id, "contents": doc.text}) + "\n")
            n += 1
    if n == 0:
        raise ValueError(f"no documents written to {out_file} -- check kb_dir/kinds")
    return out_file


def _run_pyserini_index(
    *,
    input_dir: Path,
    index_dir: Path,
    threads: int,
    stemmer: str,
    extra_fields: Optional[list[str]] = None,
) -> None:
    index_dir.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-m", "pyserini.index.lucene",
        "--collection", "JsonCollection",
        "--input", str(input_dir),
        "--index", str(index_dir),
        "--generator", "DefaultLuceneDocumentGenerator",
        "--threads", str(threads),
        "--stemmer", stemmer,
        "--storePositions", "--storeDocvectors", "--storeRaw",
    ]
    if extra_fields:
        cmd += ["--fields", *extra_fields]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"pyserini indexing failed (exit {result.returncode}):\n"
            f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
        )


def build_base_index(
    *,
    kb_dir: str | Path,
    index_dir: str | Path,
    kinds: Iterable[str] = KINDS,
    staging_dir: Optional[str | Path] = None,
    threads: int = 2,
    stemmer: str = "porter",
    limit: Optional[int] = None,
    config_hash: Optional[str] = None,
) -> Path:
    """Build the base index from ``corpus_kb`` and write a reproducibility manifest.

    Returns the index directory. ``staging_dir`` defaults to a ``_staging``
    subdirectory next to ``index_dir`` and is left in place (cheap, and
    useful to inspect what was actually indexed).
    """
    index_dir = Path(index_dir)
    staging = Path(staging_dir) if staging_dir else index_dir.parent / f"{index_dir.name}_staging"

    docs = list(load_corpus(kb_dir, kinds, limit=limit))
    write_json_collection(docs, staging)
    _run_pyserini_index(input_dir=staging, index_dir=index_dir, threads=threads, stemmer=stemmer)

    manifest = {
        "kind": "base",
        "kb_dir": str(kb_dir),
        "kinds": list(kinds),
        "doc_count": len(docs),
        "stemmer": stemmer,
        "config_hash": config_hash,
        "created_at": time.time(),
    }
    (index_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return index_dir
