"""Module 3's weighted retrieval engine (sira_cti.retrieval.weighted_bm25).

Real, tiny, local Lucene indexes over ``tests/fixtures/corpus_kb`` -- the
same six documents the index-build tests use -- so the scores checked here
come from Lucene's own BM25, not a re-implementation of it. No network, no
LLM: query-side enrichment records are built by hand.
"""

from __future__ import annotations

import pytest
from helpers import build_retrieval_indexes

from sira_cti.common import EnrichmentRecord, ProposedTerm, RejectReason, Source, TermKind, TokenUsage
from sira_cti.retrieval import (
    CONTENTS_FIELD,
    Hit,
    RetrievalResult,
    Retriever,
    WeightedBM25Retriever,
    ids_named_in,
    ranked,
    retrieve_synthesis,
    rrf_fuse,
    select_terms,
    write_costs,
    write_trec_run,
)


@pytest.fixture(scope="module")
def indexes(tmp_path_factory):
    return build_retrieval_indexes(tmp_path_factory.mktemp("retrieval_indexes"))


@pytest.fixture(scope="module")
def base_dir(indexes):
    return indexes[0]


@pytest.fixture(scope="module")
def enriched_dir(indexes):
    return indexes[1]


def _query_record(*terms: ProposedTerm, **kwargs) -> EnrichmentRecord:
    return EnrichmentRecord(doc_id="q1", source=Source.QUERY, original_text="", proposed_terms=list(terms), **kwargs)


def _scores(result: RetrievalResult) -> dict[str, float]:
    return {h.doc_id: h.score for h in result.hits}


# -- the formula ----------------------------------------------------------------------


def test_without_enrichment_it_is_plain_bm25(base_dir):
    from pyserini.search.lucene import LuceneSearcher

    searcher = LuceneSearcher(str(base_dir))
    searcher.set_bm25(0.9, 0.4)
    expected = [(h.docid, h.score) for h in searcher.search("repeated password guesses", 10)]

    retriever = WeightedBM25Retriever(base_dir, orig_fields={CONTENTS_FIELD: 1.0})
    got = retriever.retrieve("repeated password guesses", k=10)

    assert expected  # the query does match something
    assert [(h.doc_id, h.score) for h in got.hits] == pytest.approx(expected)
    assert [h.rank for h in got.hits] == list(range(1, len(expected) + 1))
    assert got.retrieval_calls == 1 and got.llm_calls == 0


def test_one_call_scores_exactly_the_sum_of_the_two_halves(enriched_dir):
    # score(d) = BM25(q_orig, d) + w * BM25(q_exp, d), each half scored on its
    # own through Pyserini's ordinary multi-field search, then added by hand.
    from pyserini.search.lucene import LuceneSearcher

    q_orig, q_exp, w = "repeated password guesses lockout", "brute force canary authentication", 0.7
    fields = {"contents": 1.0, "expansion": 1.0}

    searcher = LuceneSearcher(str(enriched_dir))
    searcher.set_bm25(0.9, 0.4)
    expected: dict[str, float] = {}
    for query, weight in ((q_orig, 1.0), (q_exp, w)):
        for h in searcher.search(query, 100, fields=fields):
            expected[h.docid] = expected.get(h.docid, 0.0) + weight * h.score

    record = _query_record(*(ProposedTerm.accept(t, TermKind.COLLOQUIAL) for t in q_exp.split()))
    got = WeightedBM25Retriever(enriched_dir, w=w).retrieve(q_orig, enrichment=record)

    assert len(expected) >= 4
    assert _scores(got) == pytest.approx(expected, abs=1e-3)


def test_w_zero_switches_the_expansion_half_off(enriched_dir):
    record = _query_record(ProposedTerm.accept("canary", TermKind.COLLOQUIAL))
    plain = WeightedBM25Retriever(enriched_dir).retrieve("password")
    off = WeightedBM25Retriever(enriched_dir, w=0.0).retrieve("password", enrichment=record)
    assert _scores(off) == pytest.approx(_scores(plain))


def test_raising_w_promotes_the_document_the_expansion_predicts(enriched_dir):
    # "password" alone ranks T1110 nowhere; a predicted term that only
    # T1110's expansion field holds pulls it up as w grows.
    record = _query_record(ProposedTerm.accept("zzz-canary-term", TermKind.COLLOQUIAL))
    assert "T1110" not in WeightedBM25Retriever(enriched_dir).retrieve("password").doc_ids

    low = WeightedBM25Retriever(enriched_dir, w=0.01).retrieve("password", enrichment=record)
    high = WeightedBM25Retriever(enriched_dir, w=5.0).retrieve("password", enrichment=record)
    assert "T1110" in low.doc_ids and low.doc_ids[0] != "T1110"
    assert high.doc_ids[0] == "T1110"


# -- which fields each half searches (open question 4) --------------------------------


def test_the_analysts_own_words_reach_the_corpus_side_expansion_field(enriched_dir, base_dir):
    # "hammering" is in no document's text; Module 1 put it in T1110's
    # expansion field. By default q_orig searches that field.
    assert WeightedBM25Retriever(enriched_dir).retrieve("hammering").doc_ids == ["T1110"]

    contents_only = WeightedBM25Retriever(enriched_dir, orig_fields={CONTENTS_FIELD: 1.0})
    assert contents_only.retrieve("hammering").hits == []
    assert WeightedBM25Retriever(base_dir).retrieve("hammering").hits == []


def test_field_boosts_scale_each_fields_contribution(enriched_dir):
    one = WeightedBM25Retriever(enriched_dir, orig_fields={"expansion": 1.0}).retrieve("hammering")
    three = WeightedBM25Retriever(enriched_dir, orig_fields={"expansion": 3.0}).retrieve("hammering")
    assert three.hits[0].score == pytest.approx(3 * one.hits[0].score, rel=1e-3)


def test_query_expansion_reaches_document_contents(enriched_dir):
    # A predicted CWE-307 finds the CVE that cites it, through "contents".
    record = _query_record(ProposedTerm.accept("CWE-307", TermKind.STRUCTURAL, structural_id="CWE-307"))
    got = WeightedBM25Retriever(enriched_dir).retrieve("zzzznomatch", enrichment=record)
    assert got.doc_ids == ["CVE-2024-12345"]
    assert got.expansion_terms == ["CWE-307"]


# -- read-time term selection ---------------------------------------------------------


def test_only_accepted_terms_enter_the_query_by_default():
    record = _query_record(
        ProposedTerm.accept("brute force", TermKind.COLLOQUIAL),
        ProposedTerm.reject("attack", TermKind.COLLOQUIAL, RejectReason.TOO_COMMON),
        ProposedTerm.reject("T9999", TermKind.STRUCTURAL, RejectReason.NOT_IN_GRAPH),
    )
    assert [t.term for t in select_terms(record)] == ["brute force"]


def test_the_ungrounded_ablation_admits_graph_rejections_only():
    record = _query_record(
        ProposedTerm.accept("brute force", TermKind.COLLOQUIAL),
        ProposedTerm.reject("attack", TermKind.COLLOQUIAL, RejectReason.TOO_COMMON),
        ProposedTerm.reject("zzzabsent", TermKind.COLLOQUIAL, RejectReason.NOT_IN_INDEX),
        ProposedTerm.reject("T9999", TermKind.STRUCTURAL, RejectReason.NOT_IN_GRAPH),
        ProposedTerm.reject("T1064", TermKind.STRUCTURAL, RejectReason.DEPRECATED),
    )
    picked = select_terms(record, include_graph_rejected=True)
    assert [t.term for t in picked] == ["brute force", "T9999", "T1064"]


def test_a_repaired_term_enters_the_query_as_its_replacement_id(enriched_dir):
    record = _query_record(
        ProposedTerm.repair("t1004", structural_id="T1547.004", repaired_from_id="T1004"),
        ProposedTerm.accept("T1547.004", TermKind.STRUCTURAL, structural_id="T1547.004"),  # duplicate
    )
    got = WeightedBM25Retriever(enriched_dir).retrieve("anything", enrichment=record)
    assert got.expansion_terms == ["T1547.004"]


def test_rejected_terms_do_not_change_the_ranking(enriched_dir):
    rejected = _query_record(ProposedTerm.reject("zzz-canary-term", TermKind.COLLOQUIAL, RejectReason.TOO_COMMON))
    retriever = WeightedBM25Retriever(enriched_dir, w=5.0)
    assert _scores(retriever.retrieve("password", enrichment=rejected)) == pytest.approx(
        _scores(retriever.retrieve("password"))
    )


# -- finding an entry by its own id ---------------------------------------------------


def test_ids_named_in_a_query_are_canonicalised():
    assert ids_named_in("is cwe 307 related to T1110/001 or cve-2024-12345?") == [
        "CWE-307", "T1110.001", "CVE-2024-12345",
    ]
    assert ids_named_in("nothing structural here") == []


def test_an_entry_is_not_findable_by_its_own_id_unless_id_boost_is_on(base_dir):
    # The CWE-307 entry's text never says "307"; the CVE citing it does.
    off = WeightedBM25Retriever(base_dir).retrieve("CWE-307")
    assert "CWE-307" not in off.doc_ids

    on = WeightedBM25Retriever(base_dir, id_boost=5.0).retrieve("CWE-307")
    assert on.doc_ids[0] == "CWE-307"
    assert "CVE-2024-12345" in on.doc_ids  # ordinary matching still happens


def test_id_boost_also_applies_to_structural_expansion_terms(base_dir):
    record = _query_record(ProposedTerm.accept("t1110.001", TermKind.STRUCTURAL, structural_id="T1110.001"))
    off = WeightedBM25Retriever(base_dir).retrieve("zzzznomatch", enrichment=record)
    on = WeightedBM25Retriever(base_dir, id_boost=1.0).retrieve("zzzznomatch", enrichment=record)
    assert off.hits == []
    assert on.doc_ids == ["T1110.001"]


# -- robustness and bookkeeping -------------------------------------------------------


def test_a_query_with_nothing_searchable_returns_no_hits(base_dir):
    retriever = WeightedBM25Retriever(base_dir)
    for query in ("", "   ", "the of and"):
        result = retriever.retrieve(query, query_id="q")
        assert result.hits == [] and result.query_id == "q"


def test_a_report_length_query_exceeds_lucenes_default_clause_limit_safely(base_dir):
    long_query = " ".join(f"token{i}" for i in range(1500)) + " brute"
    result = WeightedBM25Retriever(base_dir).retrieve(long_query)
    assert "T1110" in result.doc_ids


def test_a_repeated_query_token_counts_twice(base_dir):
    retriever = WeightedBM25Retriever(base_dir)
    once, twice = retriever.retrieve("brute"), retriever.retrieve("brute brute")
    assert twice.hits[0].score == pytest.approx(2 * once.hits[0].score, rel=1e-3)


def test_query_side_llm_cost_is_carried_into_the_result(enriched_dir):
    record = _query_record(
        ProposedTerm.accept("canary", TermKind.COLLOQUIAL),
        llm_calls=1, tokens=TokenUsage(prompt=800, completion=120), latency_ms=1900, model="stub",
    )
    result = WeightedBM25Retriever(enriched_dir).retrieve("password", query_id="q7", enrichment=record)
    assert (result.llm_calls, result.llm_latency_ms, result.tokens.total) == (1, 1900, 920)
    assert result.system == "sira_cti" and result.query_id == "q7"
    assert result.cost_dict()["tokens"] == {"prompt": 800, "completion": 120}


def test_k_caps_the_result_list(base_dir):
    retriever = WeightedBM25Retriever(base_dir)
    assert len(retriever.retrieve("password authentication brute", k=2).hits) == 2


def test_every_system_satisfies_the_retriever_protocol(base_dir):
    assert isinstance(WeightedBM25Retriever(base_dir), Retriever)


def test_doc_text_returns_the_entrys_own_contents(enriched_dir):
    text = WeightedBM25Retriever(enriched_dir).doc_text("T1110")
    assert text.startswith("Brute Force") and "canary" not in text
    assert WeightedBM25Retriever(enriched_dir).doc_text("NOPE-1") == ""


# -- multi-document synthesis ---------------------------------------------------------


def test_synthesis_with_zero_budget_is_single_shot_retrieval(base_dir):
    retriever = WeightedBM25Retriever(base_dir)
    single = retriever.retrieve("brute force")
    fused = retrieve_synthesis(retriever, "brute force", [("buffer overflow", None)], budget=0)
    assert fused.doc_ids == single.doc_ids
    assert fused.retrieval_calls == 1


def test_synthesis_runs_the_main_query_plus_at_most_budget_sub_queries(base_dir):
    retriever = WeightedBM25Retriever(base_dir)
    subs = [("buffer overflow", None), ("password guessing", None), ("performance", None)]

    fused = retrieve_synthesis(retriever, "brute force", subs, budget=2, query_id="s1")
    assert fused.retrieval_calls == 3
    assert fused.query_id == "s1"
    # Each sub-query contributes documents the main query alone never reaches...
    assert {"T1110", "CVE-2023-99999", "T1110.001"} <= set(fused.doc_ids)
    # ...and the one beyond the budget was not run.
    assert "CWE-307" not in fused.doc_ids
    assert "CWE-307" in retrieve_synthesis(retriever, "brute force", subs, budget=3).doc_ids


def test_synthesis_sums_cost_over_every_query_run(enriched_dir):
    retriever = WeightedBM25Retriever(enriched_dir)

    def rec(term):
        return _query_record(
            ProposedTerm.accept(term, TermKind.COLLOQUIAL),
            llm_calls=1, tokens=TokenUsage(prompt=100, completion=10), latency_ms=50,
        )

    fused = retrieve_synthesis(
        retriever, "brute force", [("buffer overflow", rec("parsing")), ("unused", rec("x"))],
        budget=1, enrichment=rec("canary"),
    )
    assert (fused.llm_calls, fused.tokens.total, fused.llm_latency_ms) == (2, 220, 100)
    assert fused.expansion_terms == ["canary", "parsing"]


def test_synthesis_rejects_a_negative_budget(base_dir):
    with pytest.raises(ValueError):
        retrieve_synthesis(WeightedBM25Retriever(base_dir), "q", [], budget=-1)


# -- fusion and output helpers --------------------------------------------------------


def test_ranked_orders_by_score_then_doc_id():
    hits = ranked({"b": 1.0, "a": 1.0, "c": 2.0}, k=2)
    assert hits == [Hit("c", 2.0, 1), Hit("a", 1.0, 2)]


def test_rrf_rewards_documents_ranked_by_several_lists():
    first = [Hit("x", 9.0, 1), Hit("shared", 8.0, 2)]
    second = [Hit("y", 3.0, 1), Hit("shared", 2.0, 2)]
    fused = rrf_fuse([first, second], k=10, rrf_k=60)
    assert fused[0].doc_id == "shared"
    assert fused[0].score == pytest.approx(2 / 62)
    assert [h.doc_id for h in fused[1:]] == ["x", "y"]  # tie broken on doc id


def test_write_trec_run_and_costs(tmp_path):
    result = RetrievalResult(query_id="q1", system="sira_cti", hits=[Hit("CWE-307", 1.5, 1), Hit("T1110", 0.5, 2)])
    assert write_trec_run([result], tmp_path / "out" / "run.trec") == 2
    assert (tmp_path / "out" / "run.trec").read_text().splitlines() == [
        "q1 Q0 CWE-307 1 1.500000 sira_cti",
        "q1 Q0 T1110 2 0.500000 sira_cti",
    ]
    assert write_costs([result], tmp_path / "out" / "run.costs.jsonl") == 1
