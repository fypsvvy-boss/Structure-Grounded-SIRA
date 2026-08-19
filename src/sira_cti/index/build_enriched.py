"""Build the enriched Lucene/BM25 index: base contents + an ``expansion`` field.

Injection strategy — a separate Lucene field, not appended-to-contents and
not term repetition:

* **Appended contents** would corrupt the stored raw/display text (anything
  reading the raw field for evidence display would see fabricated vocabulary
  mixed into the source document) and conflates "what the entry actually
  says" with "what the model proposed" in the one field everything else
  reads.
* **Term repetition** (padding the term into ``contents`` N times to fake a
  higher term frequency) distorts BM25's own length-normalization and TF
  saturation -- an artifact of the injection mechanism would leak into scores
  that are supposed to reflect discriminativeness, not injection technique.
* **A separate field**, summed as its own BM25 score, is a direct,
  literal reproduction of ``score(d) = BM25(q_orig,d) + w*BM25(q_exp,d)``
  (README) rather than an approximation of it: ``contents`` alone gives
  ``BM25(q_orig,d)``, ``expansion`` alone gives ``BM25(q_exp,d)``, and
  Module 3 combines the two per the formula instead of the two being
  entangled inside one field's statistics.

The ``expansion`` field is analyzed with the same analyzer (stemmer,
stopwords) as ``contents`` -- confirmed empirically not to require special
handling: the default analyzer keeps ``T1110.001`` as one token, and while
it splits ``CWE-307`` into ``["cwe", "307"]``, a query for ``CWE-307`` is
split the exact same way at search time, so retrieval still matches
correctly by construction.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable, Optional

from ..common.schemas import read_jsonl
from .build_base import _run_pyserini_index
from .corpus import KINDS, load_corpus

EXPANSION_FIELD = "expansion"


def write_json_collection_with_expansion(
    kb_dir: str | Path,
    enrichment_path: str | Path,
    staging_dir: str | Path,
    *,
    kinds: Iterable[str] = KINDS,
    limit: Optional[int] = None,
) -> Path:
    """Every base-index document, plus its accepted expansion vocabulary (or "").

    Every ``corpus_kb`` document is included, even one enrichment never
    reached (e.g. a partial ``--limit`` run) -- it just gets an empty
    ``expansion`` field, which contributes nothing to ``BM25(q_exp, d)``,
    rather than silently dropping the document from the enriched index and
    making the two indexes' doc sets diverge.
    """
    expansions: dict[str, str] = {}
    for rec in read_jsonl(enrichment_path):
        expansions[rec.doc_id] = rec.expansion_query()

    staging_dir = Path(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)
    out_file = staging_dir / "docs.jsonl"
    n = 0
    with out_file.open("w", encoding="utf-8") as fh:
        for doc in load_corpus(kb_dir, kinds, limit=limit):
            row = {
                "id": doc.doc_id,
                "contents": doc.text,
                EXPANSION_FIELD: expansions.get(doc.doc_id, ""),
            }
            fh.write(json.dumps(row) + "\n")
            n += 1
    if n == 0:
        raise ValueError(f"no documents written to {out_file} -- check kb_dir/kinds")
    return out_file


def build_enriched_index(
    *,
    kb_dir: str | Path,
    enrichment_path: str | Path,
    index_dir: str | Path,
    kinds: Iterable[str] = KINDS,
    staging_dir: Optional[str | Path] = None,
    threads: int = 2,
    stemmer: str = "porter",
    limit: Optional[int] = None,
    config_hash: Optional[str] = None,
) -> Path:
    """Build the enriched index. Requires a finished (or partial) enrichment JSONL.

    Records ``enrichment_path`` and, if the enrichment run left its sidecar
    manifest (``sira_cti.enrichment.corpus_side``), the prompt version and
    model that produced it -- so an index can always be traced back to
    exactly what enriched it (README, Reproducibility).
    """
    enrichment_path = Path(enrichment_path)
    if not enrichment_path.exists():
        raise FileNotFoundError(
            f"{enrichment_path} does not exist -- run corpus-side enrichment first "
            "(scripts/enrich_corpus.py), which itself requires the base index for DF stats"
        )

    index_dir = Path(index_dir)
    staging = Path(staging_dir) if staging_dir else index_dir.parent / f"{index_dir.name}_staging"

    write_json_collection_with_expansion(kb_dir, enrichment_path, staging, kinds=kinds, limit=limit)
    _run_pyserini_index(
        input_dir=staging, index_dir=index_dir, threads=threads, stemmer=stemmer,
        extra_fields=[EXPANSION_FIELD],
    )

    enrichment_manifest_path = enrichment_path.with_suffix(enrichment_path.suffix + ".manifest.json")
    enrichment_manifest = (
        json.loads(enrichment_manifest_path.read_text()) if enrichment_manifest_path.exists() else {}
    )

    manifest = {
        "kind": "enriched",
        "kb_dir": str(kb_dir),
        "kinds": list(kinds),
        "enrichment_path": str(enrichment_path),
        "enrichment_prompt_version": enrichment_manifest.get("prompt_version"),
        "enrichment_model": enrichment_manifest.get("model"),
        "stemmer": stemmer,
        "config_hash": config_hash,
        "created_at": time.time(),
    }
    (index_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return index_dir
