"""Baseline: plain BM25 -- the lexical-matching floor (README, Baselines).

The analyst's query, as typed, against the *base* (unenriched) index, with
the same ``k1``/``b`` as everything else. No LLM, no expansion, no graph.

It is :class:`~sira_cti.retrieval.weighted_bm25.WeightedBM25Retriever` with
the expansion half switched off, not a second implementation: the baseline
and the system under test then differ only in what the project adds, and
cannot drift apart in tokenization or scoring.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ...common.schemas import EnrichmentRecord
from ..types import RetrievalResult
from ..weighted_bm25 import CONTENTS_FIELD, WeightedBM25Retriever


class PlainBM25Retriever(WeightedBM25Retriever):
    name = "plain_bm25"

    def __init__(self, index_dir: str | Path, *, k1: float = 0.9, b: float = 0.4) -> None:
        super().__init__(
            index_dir, w=0.0, k1=k1, b=b,
            orig_fields={CONTENTS_FIELD: 1.0}, exp_fields={},
        )

    def retrieve(
        self,
        query: str,
        *,
        query_id: str = "",
        enrichment: Optional[EnrichmentRecord] = None,
        k: int = 100,
    ) -> RetrievalResult:
        # Any enrichment record is ignored outright, including its cost: this
        # baseline makes no LLM call and must not be billed for one.
        return super().retrieve(query, query_id=query_id, enrichment=None, k=k)
