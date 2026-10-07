"""Shapes every retriever in this package returns -- SIRA-CTI and baselines alike.

Module 4 scores all four systems (weighted BM25, plain BM25, hybrid,
multi-round agent) with one harness, so they share one result type. Cost
fields sit next to the ranking on purpose: RQ3 is quality *per LLM call and
per second*, and a ranking that has lost track of what it cost cannot answer
it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Protocol, Sequence, runtime_checkable

from ..common.schemas import EnrichmentRecord, TokenUsage


@dataclass(frozen=True)
class Hit:
    doc_id: str
    score: float
    rank: int  # 1-based


@dataclass
class RetrievalResult:
    """One query's ranked list, plus what it cost to produce.

    ``retrieval_ms`` is wall-clock time spent inside the index (and, for the
    hybrid baseline, the encoder). ``llm_latency_ms`` is the LLM time: for
    SIRA-CTI it is copied from the query-side :class:`EnrichmentRecord`, for
    the multi-round agent it is measured from the calls the agent itself
    makes. They are kept apart because they scale differently -- Module 4
    adds them for the per-query latency figure.
    """

    query_id: str
    system: str
    hits: list[Hit] = field(default_factory=list)
    retrieval_calls: int = 0
    retrieval_ms: int = 0
    llm_calls: int = 0
    tokens: TokenUsage = field(default_factory=TokenUsage)
    llm_latency_ms: int = 0
    expansion_terms: list[str] = field(default_factory=list)

    @property
    def doc_ids(self) -> list[str]:
        return [h.doc_id for h in self.hits]

    def cost_dict(self) -> dict[str, Any]:
        """Everything except the ranking -- one line of the ``.costs.jsonl`` sidecar."""
        return {
            "query_id": self.query_id,
            "system": self.system,
            "retrieval_calls": self.retrieval_calls,
            "retrieval_ms": self.retrieval_ms,
            "llm_calls": self.llm_calls,
            "tokens": self.tokens.to_dict(),
            "llm_latency_ms": self.llm_latency_ms,
            "expansion_terms": self.expansion_terms,
        }


@runtime_checkable
class Retriever(Protocol):
    """What ``scripts/run_retrieval.py`` and Module 4 need from any system.

    ``enrichment`` is the query-side record (Module 2). Baselines accept and
    ignore it, so the harness can drive every system through one call.
    """

    name: str

    def retrieve(
        self,
        query: str,
        *,
        query_id: str = "",
        enrichment: Optional[EnrichmentRecord] = None,
        k: int = 100,
    ) -> RetrievalResult: ...


def ranked(scores: dict[str, float], k: int) -> list[Hit]:
    """Top-``k`` hits by score. Ties break on doc id so reruns are identical."""
    ordered = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[:k]
    return [Hit(doc_id=d, score=s, rank=i) for i, (d, s) in enumerate(ordered, start=1)]


def rrf_fuse(rankings: Sequence[Sequence[Hit]], *, k: int, rrf_k: int = 60) -> list[Hit]:
    """Reciprocal rank fusion: ``score(d) = sum over lists of 1 / (rrf_k + rank)``.

    Used wherever several ranked lists for one question have to become one
    (synthesis sub-queries, agent rounds). Rank-based rather than score-based
    because BM25 scores from different queries are not on a common scale -- a
    long query scores higher than a short one for reasons unrelated to
    relevance.
    """
    scores: dict[str, float] = {}
    for hits in rankings:
        for hit in hits:
            scores[hit.doc_id] = scores.get(hit.doc_id, 0.0) + 1.0 / (rrf_k + hit.rank)
    return ranked(scores, k)


def write_trec_run(results: Iterable[RetrievalResult], path: str | Path) -> int:
    """Write the six-column TREC run format ``pytrec_eval`` (Module 4) reads."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for result in results:
            for hit in result.hits:
                fh.write(f"{result.query_id} Q0 {hit.doc_id} {hit.rank} {hit.score:.6f} {result.system}\n")
                n += 1
    return n


def write_costs(results: Iterable[RetrievalResult], path: str | Path) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for result in results:
            fh.write(json.dumps(result.cost_dict()) + "\n")
            n += 1
    return n
