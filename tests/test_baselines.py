"""Module 3's three baselines (sira_cti.retrieval.baselines).

Offline throughout: real tiny Lucene indexes for the sparse side, a
deterministic word-hashing stand-in for the dense encoder, and ``StubClient``
for the agent's LLM.
"""

from __future__ import annotations

import json
import zlib

import numpy as np
import pytest
from helpers import CORPUS_KB_FIXTURE, build_retrieval_indexes

from sira_cti.common import EnrichmentRecord, LLMError, ProposedTerm, Source, StubClient, TermKind, TokenUsage
from sira_cti.index import load_corpus
from sira_cti.retrieval import Retriever, WeightedBM25Retriever
from sira_cti.retrieval.baselines import HybridRetriever, MultiRoundAgent, PlainBM25Retriever


@pytest.fixture(scope="module")
def indexes(tmp_path_factory):
    return build_retrieval_indexes(tmp_path_factory.mktemp("baseline_indexes"))


@pytest.fixture(scope="module")
def plain(indexes):
    return PlainBM25Retriever(indexes[0])


# -- plain BM25 -----------------------------------------------------------------------


def test_plain_bm25_ignores_enrichment_and_is_never_billed_for_it(plain):
    record = EnrichmentRecord(
        doc_id="q", source=Source.QUERY, original_text="",
        proposed_terms=[ProposedTerm.accept("overflow", TermKind.COLLOQUIAL)],
        llm_calls=1, tokens=TokenUsage(prompt=500, completion=50), latency_ms=900,
    )
    bare = plain.retrieve("brute force")
    with_record = plain.retrieve("brute force", enrichment=record)

    assert with_record.hits == bare.hits
    assert with_record.llm_calls == 0 and with_record.tokens.total == 0
    assert with_record.expansion_terms == []
    assert with_record.system == "plain_bm25"


def test_plain_bm25_never_reads_the_expansion_field(indexes):
    # Even if pointed at the enriched index by mistake.
    assert PlainBM25Retriever(indexes[1]).retrieve("hammering").hits == []


# -- hybrid ---------------------------------------------------------------------------


class HashingEncoder:
    """Bag-of-words into a fixed number of hashed buckets. Deterministic, no model."""

    name = "hashing-test-encoder"

    def __init__(self, dim: int = 256) -> None:
        self.dim = dim
        self.calls = 0

    def __call__(self, texts):
        self.calls += 1
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for word in "".join(c.lower() if c.isalnum() else " " for c in text).split():
                out[row, zlib.crc32(word.encode()) % self.dim] += 1.0
        return out


def _hybrid(plain, **kwargs) -> HybridRetriever:
    return HybridRetriever(plain, load_corpus(CORPUS_KB_FIXTURE), HashingEncoder(), **kwargs)


def test_hybrid_at_alpha_zero_ranks_like_bm25(plain):
    query = "repeated password guesses"
    sparse = plain.retrieve(query).doc_ids
    assert _hybrid(plain, alpha=0.0).retrieve(query).doc_ids[: len(sparse)] == sparse


def test_hybrid_at_alpha_one_ranks_by_dense_similarity_alone(plain):
    # "linux" is only in T1110.001; BM25 and the dense side agree on it, and at
    # alpha=1 documents BM25 never matched are still ranked.
    result = _hybrid(plain, alpha=1.0).retrieve("linux windows platforms")
    assert result.doc_ids[0] == "T1110.001"
    assert len(result.hits) == 6
    assert plain.retrieve("linux windows platforms").doc_ids == ["T1110.001"]


def test_hybrid_mixes_both_signals_and_reports_two_retrieval_calls(plain):
    result = _hybrid(plain, alpha=0.5).retrieve("brute force", query_id="h1")
    assert result.doc_ids[0] == "T1110"
    assert result.hits[0].score == pytest.approx(1.0)  # top of both normalised lists
    assert all(0.0 <= h.score <= 1.0 for h in result.hits)
    assert (result.retrieval_calls, result.llm_calls, result.system) == (2, 0, "hybrid")


def test_hybrid_caches_document_vectors_and_reuses_them(plain, tmp_path):
    docs = list(load_corpus(CORPUS_KB_FIXTURE))
    first = HashingEncoder()
    HybridRetriever(plain, docs, first, cache_dir=tmp_path)
    assert first.calls == 1
    assert json.loads((tmp_path / "doc_vectors.meta.json").read_text())["encoder"] == "hashing-test-encoder"

    second = HashingEncoder()
    reused = HybridRetriever(plain, docs, second, cache_dir=tmp_path)
    assert second.calls == 0
    assert reused.retrieve("brute force").doc_ids[0] == "T1110"

    # A different document set must not be served the old vectors.
    third = HashingEncoder()
    HybridRetriever(plain, docs[:3], third, cache_dir=tmp_path)
    assert third.calls == 1


def test_hybrid_rejects_an_alpha_outside_zero_to_one(plain):
    with pytest.raises(ValueError):
        _hybrid(plain, alpha=1.5)


# -- multi-round agent ----------------------------------------------------------------


def _scripted(*replies: str) -> StubClient:
    queue = list(replies)
    return StubClient(responder=lambda _prompt: queue.pop(0))


def test_agent_reformulates_after_reading_and_pays_one_llm_call_per_extra_round(plain):
    client = _scripted(json.dumps({"query": "buffer overflow parsing"}), json.dumps({"done": True}))
    agent = MultiRoundAgent(plain, client, max_rounds=3)

    result = agent.retrieve("brute force", query_id="a1")

    assert result.retrieval_calls == 2 and result.llm_calls == 2
    assert result.tokens.total == 30  # StubClient bills 10 + 5 per call
    assert result.expansion_terms == ["buffer overflow parsing"]
    # Round 1 found T1110; round 2's rewrite found the overflow CVE.
    assert {"T1110", "CVE-2023-99999"} <= set(result.doc_ids)
    assert [r.tag for r in client.log.records] == ["agent_round_1", "agent_round_2"]
    assert result.system == "multi_round_agent"


def test_agent_shows_the_model_what_it_retrieved(plain):
    # The property that makes this a multi-round agent and not SIRA: evidence
    # from the index is read back into the prompt.
    client = _scripted(json.dumps({"done": True}))
    MultiRoundAgent(plain, client, snippet_chars=40).retrieve("brute force")
    assert "[T1110] Brute Force" in client.prompts[0]
    assert "Question:\nbrute force" in client.prompts[0]


def test_agent_with_one_round_is_plain_bm25_and_makes_no_llm_call(plain):
    client = _scripted()
    result = MultiRoundAgent(plain, client, max_rounds=1).retrieve("brute force")
    assert result.doc_ids == plain.retrieve("brute force").doc_ids
    assert result.llm_calls == 0 and client.prompts == []


def test_agent_stops_at_max_rounds(plain):
    client = StubClient(responder=lambda prompt: json.dumps({"query": f"password {prompt.count('.')}"}))
    result = MultiRoundAgent(plain, client, max_rounds=3).retrieve("brute force")
    assert result.retrieval_calls == 3
    assert result.llm_calls == 2  # no call after the final search


def test_agent_stops_on_an_unparseable_reply_but_still_counts_the_call(plain):
    client = _scripted("I am not sure what to search for next.")
    result = MultiRoundAgent(plain, client, max_rounds=4).retrieve("brute force")
    assert result.retrieval_calls == 1 and result.llm_calls == 1
    assert result.doc_ids == plain.retrieve("brute force").doc_ids


def test_agent_stops_when_the_model_repeats_a_query(plain):
    client = _scripted(json.dumps({"query": "Brute Force"}))
    result = MultiRoundAgent(plain, client, max_rounds=4).retrieve("brute force")
    assert result.retrieval_calls == 1 and result.llm_calls == 1


def test_agent_does_not_hide_an_llm_outage_as_a_bm25_result(plain):
    client = StubClient(fail_times=10, max_retries=0)
    with pytest.raises(LLMError):
        MultiRoundAgent(plain, client, max_rounds=3).retrieve("brute force")


def test_agent_rejects_zero_rounds(plain):
    with pytest.raises(ValueError):
        MultiRoundAgent(plain, _scripted(), max_rounds=0)


def test_baselines_satisfy_the_retriever_protocol(plain):
    assert isinstance(plain, Retriever)
    assert isinstance(_hybrid(plain), Retriever)
    assert isinstance(MultiRoundAgent(plain, _scripted()), Retriever)
    assert isinstance(plain, WeightedBM25Retriever)
