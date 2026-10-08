"""Baseline: hybrid dense-sparse retrieval over unenriched text.

A fixed scorer in the style of KGAgent4CTI (README, Baselines): a dense
bi-encoder and BM25 each score the query, and the two are mixed with a
constant weight. No LLM call, no expansion, no graph.

    score(d) = alpha * dense(q, d) + (1 - alpha) * bm25(q, d)

with both halves rescaled to [0, 1] first, because cosine similarity (at
most 1) and BM25 (unbounded) are not on one scale. Candidates are the union
of each half's top ``depth`` documents; a document missing from one half's
list scores 0 on that half. The two halves are rescaled differently for
that reason: dense scores are min-max normalised (every document has one),
while BM25 scores are divided by the top score, so that the weakest
document BM25 did match still sits above the ones it did not match at all.

The corpus is a few thousand entries, so the dense side is an exact
brute-force cosine search over one in-memory matrix -- no ANN index whose
recall would become one more variable. Documents are encoded once and
cached on disk, keyed on the encoder name and the exact doc ids.

The encoder is passed in. :class:`SentenceTransformerEncoder` is the real
one; tests hand in a deterministic stand-in so the suite stays offline.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

import numpy as np

from ...common.schemas import EnrichmentRecord
from ...index.corpus import CorpusDocument
from ..types import RetrievalResult, ranked

Encoder = Callable[[Sequence[str]], np.ndarray]
"""Texts in, one row vector per text out."""


class SentenceTransformerEncoder:
    """A ``sentence-transformers`` bi-encoder. The model loads on first use.

    Long entries are truncated at the model's own input limit (256 word
    pieces for the default model), so a dense score reflects the start of an
    entry -- its title and the opening of its JSON body.
    """

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2", *, batch_size: int = 64) -> None:
        self.name = model_name
        self.batch_size = batch_size
        self._model = None

    def __call__(self, texts: Sequence[str]) -> np.ndarray:
        if self._model is None:
            from sentence_transformers import SentenceTransformer  # heavy; import on use

            self._model = SentenceTransformer(self.name)
        return np.asarray(
            self._model.encode(list(texts), batch_size=self.batch_size, show_progress_bar=False),
            dtype=np.float32,
        )


def _unit_rows(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    return matrix / np.where(norms == 0, 1.0, norms)


def _min_max(scores: dict[str, float]) -> dict[str, float]:
    """Rescale to [0, 1]. A list whose scores are all equal carries no ranking
    signal, so it maps to all-zero instead of dividing by zero."""
    if not scores:
        return {}
    lo, hi = min(scores.values()), max(scores.values())
    if hi == lo:
        return {d: 0.0 for d in scores}
    return {d: (s - lo) / (hi - lo) for d, s in scores.items()}


def _max_scaled(scores: dict[str, float]) -> dict[str, float]:
    """Divide by the top score, keeping zero as "did not match"."""
    hi = max(scores.values(), default=0.0)
    if hi <= 0:
        return {d: 0.0 for d in scores}
    return {d: s / hi for d, s in scores.items()}


class HybridRetriever:
    name = "hybrid"

    def __init__(
        self,
        sparse,
        docs: Iterable[CorpusDocument],
        encoder: Encoder,
        *,
        alpha: float = 0.5,
        depth: int = 1000,
        cache_dir: Optional[str | Path] = None,
    ) -> None:
        """``sparse`` is the plain-BM25 baseline retriever over the base index."""
        if not 0.0 <= alpha <= 1.0:
            raise ValueError(f"alpha must be in [0, 1], got {alpha}")
        self.sparse = sparse
        self.encoder = encoder
        self.alpha = alpha
        self.depth = depth

        docs = list(docs)
        self.doc_ids = [d.doc_id for d in docs]
        self._matrix = _unit_rows(self._doc_vectors(docs, cache_dir))

    def _doc_vectors(self, docs: list[CorpusDocument], cache_dir: Optional[str | Path]) -> np.ndarray:
        encoder_name = getattr(self.encoder, "name", type(self.encoder).__name__)
        if cache_dir is None:
            return np.asarray(self.encoder([d.text for d in docs]), dtype=np.float32)

        cache_dir = Path(cache_dir)
        vectors_path, meta_path = cache_dir / "doc_vectors.npy", cache_dir / "doc_vectors.meta.json"
        meta = {"encoder": encoder_name, "doc_ids": self.doc_ids}
        if vectors_path.exists() and meta_path.exists() and json.loads(meta_path.read_text()) == meta:
            return np.load(vectors_path)

        vectors = np.asarray(self.encoder([d.text for d in docs]), dtype=np.float32)
        cache_dir.mkdir(parents=True, exist_ok=True)
        np.save(vectors_path, vectors)
        meta_path.write_text(json.dumps(meta), encoding="utf-8")
        return vectors

    def retrieve(
        self,
        query: str,
        *,
        query_id: str = "",
        enrichment: Optional[EnrichmentRecord] = None,
        k: int = 100,
    ) -> RetrievalResult:
        started = time.perf_counter()

        query_vec = _unit_rows(np.asarray(self.encoder([query]), dtype=np.float32))[0]
        sims = self._matrix @ query_vec
        top = np.argsort(-sims, kind="stable")[: self.depth]
        dense = {self.doc_ids[i]: float(sims[i]) for i in top}

        sparse = {h.doc_id: h.score for h in self.sparse.retrieve(query, k=self.depth).hits}

        dense_n, sparse_n = _min_max(dense), _max_scaled(sparse)
        fused = {
            d: self.alpha * dense_n.get(d, 0.0) + (1.0 - self.alpha) * sparse_n.get(d, 0.0)
            for d in dense_n.keys() | sparse_n.keys()
        }

        return RetrievalResult(
            query_id=query_id,
            system=self.name,
            hits=ranked(fused, k),
            retrieval_calls=2,  # one sparse, one dense
            retrieval_ms=int((time.perf_counter() - started) * 1000),
        )
