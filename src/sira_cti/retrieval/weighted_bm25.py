"""Module 3 -- the weighted retrieval engine.

    score(d) = BM25(q_orig, d) + w * BM25(q_exp, d)

``q_orig`` is the analyst's query as typed. ``q_exp`` is the vocabulary the
query-side enrichment (Module 2) predicted and the graph/index filters let
through, read from an :class:`~sira_cti.common.schemas.EnrichmentRecord`.

One retrieval call, and an exact one
------------------------------------
BM25 is a sum over query terms, so the formula above is itself one bag-of-
words query in which every ``q_exp`` term carries a boost of ``w``. That is
what this module sends to Lucene: a single boolean query of boosted term
clauses. It is not two searches fused afterwards -- fusing two top-k lists
gives a document that fell outside one list a zero for that half of the
score, which is an approximation of the formula, and it is two retrieval
calls where SIRA's claim is one. ``tests/test_weighted_bm25.py`` checks the
single call against the two halves scored separately.

Which fields each half searches (``docs/04_OPEN_QUESTIONS.md`` question 4)
---------------------------------------------------------------------------
The enriched index (Module 1) keeps a document's own text in ``contents``
and the accepted corpus-side vocabulary in a separate ``expansion`` field.
Here ``BM25(q, d)`` means the sum over the fields searched::

    BM25(q, d) = sum over fields f of  boost_f * BM25_f(q, d)

and by default *both* halves search *both* fields, each at boost 1.0:

* ``q_orig`` must reach ``expansion``, or corpus-side enrichment does
  nothing -- that field holds the plain-language terms an analyst types,
  put there precisely so the analyst's own words can match.
* ``q_exp`` must reach ``contents``, or a predicted ``CWE-307`` cannot find
  the CVE records that cite it.

Lucene normalises length per field, and ``expansion`` is a few terms long,
so a match there is scored against a much shorter "document" than a match in
``contents``. The field boosts are the knob for that; they are configuration
(``retrieval.fields``), not constants, so the choice can be tuned and
reported instead of inherited.

Read-time filtering
-------------------
Rejected terms stay in the record (they are the RQ4 dataset); which of them
shape the query is decided here, when the record is read. The default takes
accepted terms only. ``include_graph_rejected=True`` also admits terms the
ontology graph refused -- the "without graph-grounding" ablation, run from
the same records with no second LLM pass.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Mapping, Optional, Sequence

from ..common.schemas import EnrichmentRecord, ProposedTerm, RejectReason, TermKind, TokenUsage
from ..graph.normalize import extract_structural_ids
from .types import Hit, RetrievalResult, rrf_fuse

CONTENTS_FIELD = "contents"
EXPANSION_FIELD = "expansion"  # must match sira_cti.index.build_enriched.EXPANSION_FIELD
ID_FIELD = "id"                # Anserini's untokenized docid field

DEFAULT_FIELDS: dict[str, float] = {CONTENTS_FIELD: 1.0, EXPANSION_FIELD: 1.0}

# Mirrors schemas._GRAPH_FAILURES: the reasons that mean "the ontology graph
# said no", as opposed to a corpus-statistics rejection.
_GRAPH_REJECTIONS = {
    RejectReason.NOT_IN_GRAPH,
    RejectReason.DEPRECATED,
    RejectReason.REVOKED,
    RejectReason.MALFORMED_ID,
}

_CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Lucene refuses a boolean query above this many clauses unless told otherwise.
_LUCENE_DEFAULT_MAX_CLAUSES = 1024


def _query_text(term: ProposedTerm) -> str:
    """What a term contributes to the query: the post-repair id for a
    structural term (``schemas.ProposedTerm``), its literal text otherwise."""
    return term.structural_id if term.kind is TermKind.STRUCTURAL else term.term


def select_terms(record: EnrichmentRecord, *, include_graph_rejected: bool = False) -> list[ProposedTerm]:
    """The terms of ``record`` that are allowed into ``q_exp``, in order, deduped."""
    seen: set[str] = set()
    out: list[ProposedTerm] = []
    for term in record.proposed_terms:
        keep = term.accepted or (include_graph_rejected and term.reject_reason in _GRAPH_REJECTIONS)
        key = _query_text(term).lower()
        if keep and key not in seen:
            seen.add(key)
            out.append(term)
    return out


def ids_named_in(query: str) -> list[str]:
    """Canonical doc ids written literally in the query text (``CWE-307``, ``CVE-…``)."""
    ids = [p.canonical for p in extract_structural_ids(query)]
    ids += [m.group(0).upper() for m in _CVE_ID.finditer(query or "")]
    return list(dict.fromkeys(ids))


class WeightedBM25Retriever:
    """``score(d) = BM25(q_orig, d) + w * BM25(q_exp, d)`` as one Lucene query.

    ``orig_fields`` / ``exp_fields`` map a field name to its boost for each
    half of the formula. Pointing this class at the *base* index with
    contents-only fields gives the "without corpus-side enrichment"
    ablation; with no enrichment record at all it reduces to plain BM25.

    ``id_boost`` (off at 0.0) answers the question Module 1 handed over: a
    CWE/CAPEC/ATT&CK entry's own id is not in its indexed text, so a query
    naming ``CWE-1321`` does not find the CWE-1321 entry. When it is above
    zero, every id named in the query, and every structural id in ``q_exp``,
    also matches the entry whose doc id it is -- an exact match on the
    index's ``id`` field, needing no change to how the index is built.
    Ids from ``q_exp`` are additionally scaled by ``w`` like the rest of it.
    """

    name = "sira_cti"

    def __init__(
        self,
        index_dir: str | Path,
        *,
        w: float = 1.0,
        k1: float = 0.9,
        b: float = 0.4,
        orig_fields: Optional[Mapping[str, float]] = None,
        exp_fields: Optional[Mapping[str, float]] = None,
        id_boost: float = 0.0,
        include_graph_rejected: bool = False,
        name: Optional[str] = None,
    ) -> None:
        from pyserini.index.lucene import LuceneIndexReader  # heavy, JVM-backed; import on use
        from pyserini.search.lucene import LuceneSearcher

        self.index_dir = Path(index_dir)
        self._searcher = LuceneSearcher(str(index_dir))
        self._searcher.set_bm25(k1, b)
        self._reader = LuceneIndexReader(str(index_dir))
        self.w = w
        self.orig_fields = dict(orig_fields if orig_fields is not None else DEFAULT_FIELDS)
        self.exp_fields = dict(exp_fields if exp_fields is not None else DEFAULT_FIELDS)
        self.id_boost = id_boost
        self.include_graph_rejected = include_graph_rejected
        if name:
            self.name = name
        self._max_clauses = _LUCENE_DEFAULT_MAX_CLAUSES

    # -- query construction -------------------------------------------------------

    def analyze(self, text: str) -> list[str]:
        """Tokens as the index's own analyzer produces them (stemmed, stopped)."""
        return list(self._reader.analyze(text)) if text and text.strip() else []

    def clause_weights(self, query: str, expansion: Sequence[ProposedTerm] = ()) -> dict[tuple[str, str], float]:
        """``(field, token) -> boost`` for the whole weighted query.

        A token that occurs twice contributes twice, the same way Lucene's
        own bag-of-words query counts it; the two occurrences are folded into
        one clause with the summed boost, which scores identically.
        """
        weights: dict[tuple[str, str], float] = {}

        def add(field: str, token: str, boost: float) -> None:
            if boost:
                weights[(field, token)] = weights.get((field, token), 0.0) + boost

        for token in self.analyze(query):
            for field, boost in self.orig_fields.items():
                add(field, token, boost)

        for term in expansion:
            for token in self.analyze(_query_text(term)):
                for field, boost in self.exp_fields.items():
                    add(field, token, self.w * boost)

        if self.id_boost:
            for doc_id in ids_named_in(query):
                add(ID_FIELD, doc_id, self.id_boost)
            for term in expansion:
                if term.kind is TermKind.STRUCTURAL:
                    add(ID_FIELD, term.structural_id, self.w * self.id_boost)

        return weights

    def _build_query(self, weights: Mapping[tuple[str, str], float]):
        from pyserini.pyclass import autoclass
        from pyserini.search.lucene import querybuilder

        if len(weights) > self._max_clauses:
            # A report-length query can exceed Lucene's default clause limit.
            self._max_clauses = len(weights)
            autoclass("org.apache.lucene.search.IndexSearcher").setMaxClauseCount(self._max_clauses)

        should = querybuilder.JBooleanClauseOccur["should"].value
        builder = querybuilder.get_boolean_query_builder()
        for (field, token), boost in weights.items():
            clause = querybuilder.JTermQuery(querybuilder.JTerm(field, token))
            builder.add(querybuilder.get_boost_query(clause, float(boost)), should)
        return builder.build()

    # -- retrieval ----------------------------------------------------------------

    def retrieve(
        self,
        query: str,
        *,
        query_id: str = "",
        enrichment: Optional[EnrichmentRecord] = None,
        k: int = 100,
    ) -> RetrievalResult:
        terms = (
            select_terms(enrichment, include_graph_rejected=self.include_graph_rejected)
            if enrichment is not None
            else []
        )
        weights = self.clause_weights(query, terms)

        started = time.perf_counter()
        hits: list[Hit] = []
        if weights:
            raw = self._searcher.search(self._build_query(weights), k)
            hits = [Hit(doc_id=h.docid, score=float(h.score), rank=i) for i, h in enumerate(raw, start=1)]
        retrieval_ms = int((time.perf_counter() - started) * 1000)

        return RetrievalResult(
            query_id=query_id,
            system=self.name,
            hits=hits,
            retrieval_calls=1,
            retrieval_ms=retrieval_ms,
            llm_calls=enrichment.llm_calls if enrichment else 0,
            tokens=enrichment.tokens if enrichment else TokenUsage(),
            llm_latency_ms=enrichment.latency_ms if enrichment else 0,
            expansion_terms=[_query_text(t) for t in terms],
        )

    def doc_text(self, doc_id: str) -> str:
        """A document's stored ``contents`` (what the entry itself says)."""
        doc = self._searcher.doc(doc_id)
        if doc is None:
            return ""
        return json.loads(doc.raw()).get(CONTENTS_FIELD, "")


# -- multi-document synthesis ---------------------------------------------------------


def retrieve_synthesis(
    retriever,
    query: str,
    sub_queries: Sequence[tuple[str, Optional[EnrichmentRecord]]],
    *,
    budget: int,
    query_id: str = "",
    enrichment: Optional[EnrichmentRecord] = None,
    k: int = 100,
    rrf_k: int = 60,
) -> RetrievalResult:
    """The BrowseComp-Wikipedia protocol: the main query plus up to ``budget`` more.

    **Evidence-blind by construction.** Every sub-query is an argument, fixed
    before the first search runs; nothing retrieved here is ever handed back
    to a model to write the next one. That is the line between this and the
    multi-round agent baseline, and it is why the sub-queries arrive as data
    rather than through a callback that could see results.

    The main query always runs, so ``budget=0`` is ordinary single-shot
    retrieval. Sub-queries beyond ``budget`` are dropped, not run. The lists
    are merged by reciprocal rank fusion (:func:`~.types.rrf_fuse`), and the
    cost fields are summed over every query actually run.
    """
    if budget < 0:
        raise ValueError(f"budget must be >= 0, got {budget}")

    runs = [(query, enrichment), *list(sub_queries)[:budget]]
    results = [retriever.retrieve(q, query_id=query_id, enrichment=rec, k=k) for q, rec in runs]

    tokens = TokenUsage()
    for r in results:
        tokens = tokens + r.tokens

    return RetrievalResult(
        query_id=query_id,
        system=retriever.name,
        hits=rrf_fuse([r.hits for r in results], k=k, rrf_k=rrf_k),
        retrieval_calls=sum(r.retrieval_calls for r in results),
        retrieval_ms=sum(r.retrieval_ms for r in results),
        llm_calls=sum(r.llm_calls for r in results),
        tokens=tokens,
        llm_latency_ms=sum(r.llm_latency_ms for r in results),
        expansion_terms=list(dict.fromkeys(t for r in results for t in r.expansion_terms)),
    )
