"""Cost and latency accounting (``sira_cti.eval.cost``).

RQ3's numbers come from here, so the fixtures are small enough to add up by
hand, and the two things most likely to go quietly wrong are pinned
directly: a question with no cost row must not be counted as free, and the
offline corpus-enrichment cost must never leak into a per-question figure.
"""

from __future__ import annotations

import json

import pytest
from eval_helpers import cost_row

from sira_cti.common import EnrichmentRecord, ProposedTerm, Source, TermKind, TokenUsage, write_jsonl
from sira_cti.eval.cost import (
    FIELDS,
    amortise,
    distribution,
    efficiency,
    median,
    offline_enrichment_cost,
    percentile,
    read_costs,
    read_costs_for_run,
    summarise_costs,
)
from sira_cti.eval.runs import ERROR, WARNING


def _write(path, rows):
    path.write_text("".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in rows), encoding="utf-8")
    return path


def _three_questions(tmp_path):
    return _write(tmp_path / "run.trec.costs.jsonl", [
        cost_row("q1", "sira_cti", llm_calls=1, prompt=100, completion=20, llm_latency_ms=1000, retrieval_ms=10,
                 expansion_terms=["CWE-307", "brute force"]),
        cost_row("q2", "sira_cti", llm_calls=1, prompt=200, completion=40, llm_latency_ms=2000, retrieval_ms=20),
        cost_row("q3", "sira_cti", llm_calls=4, prompt=600, completion=60, llm_latency_ms=6000, retrieval_ms=30,
                 retrieval_calls=3),
    ])


# -- reading ----------------------------------------------------------------------------


def test_read_costs_parses_the_documented_row(tmp_path):
    costs, issues = read_costs(_three_questions(tmp_path))
    assert issues == []
    q1 = costs["q1"]
    assert (q1.system, q1.llm_calls, q1.prompt_tokens, q1.completion_tokens) == ("sira_cti", 1, 100, 20)
    assert q1.total_tokens == 120
    assert q1.total_ms == 1010          # retrieval 10 + LLM 1000
    assert q1.expansion_terms == 2


def test_a_malformed_cost_row_is_reported_and_skipped(tmp_path):
    good = cost_row("q1", "s")
    missing = {k: v for k, v in cost_row("q2", "s").items() if k != "llm_calls"}
    negative = cost_row("q3", "s", llm_latency_ms=-5)
    not_a_number = dict(cost_row("q4", "s"), retrieval_ms="fast")
    costs, issues = read_costs(_write(tmp_path / "c.jsonl", [good, missing, negative, not_a_number, "{broken", "[1, 2]"]))
    assert set(costs) == {"q1"}
    issue = next(i for i in issues if i.code == "malformed_cost_row")
    assert issue.severity == ERROR
    assert issue.message.startswith("5x:")
    assert "missing 'llm_calls'" in issue.message


def test_a_question_costed_twice_is_an_error_and_the_first_row_wins(tmp_path):
    rows = [cost_row("q1", "s", llm_calls=1), cost_row("q1", "s", llm_calls=9)]
    costs, issues = read_costs(_write(tmp_path / "c.jsonl", rows))
    assert costs["q1"].llm_calls == 1
    assert [i.code for i in issues] == ["duplicate_cost_row"]


def test_cost_rows_from_two_systems_in_one_file_are_an_error(tmp_path):
    _, issues = read_costs(_write(tmp_path / "c.jsonl", [cost_row("q1", "sira_cti"), cost_row("q2", "plain_bm25")]))
    assert [i.code for i in issues] == ["mixed_systems"]


def test_a_run_with_no_costs_sidecar_gives_a_warning_not_zeros(tmp_path):
    costs, issues = read_costs_for_run(tmp_path / "run.trec")
    assert costs is None
    assert [(i.severity, i.code) for i in issues] == [(WARNING, "no_costs")]


def test_read_costs_for_run_finds_the_sidecar(tmp_path):
    _three_questions(tmp_path)
    costs, issues = read_costs_for_run(tmp_path / "run.trec")
    assert set(costs) == {"q1", "q2", "q3"} and issues == []


# -- mean / median / p95 ----------------------------------------------------------------


def test_percentile_is_nearest_rank():
    assert percentile(list(range(1, 101)), 95) == 95      # ceil(0.95 * 100) = 95th value
    assert percentile(list(range(1, 21)), 95) == 19       # ceil(0.95 * 20)  = 19th value
    assert percentile([30, 10, 20], 95) == 30             # ceil(0.95 * 3)   = 3rd value
    assert percentile([7], 95) == 7
    assert percentile([10, 20, 30, 40], 50) == 20         # ceil(0.5 * 4)    = 2nd value
    assert percentile([], 95) is None
    with pytest.raises(ValueError):
        percentile([1], 0)


def test_median_of_odd_and_even_samples():
    assert median([3, 1, 2]) == 2
    assert median([4, 1, 3, 2]) == 2.5
    assert median([]) is None


def test_distribution_of_nothing_is_none_not_zero():
    assert distribution([]) == {"mean": None, "median": None, "p95": None, "total": None}


def test_summarise_costs_by_hand(tmp_path):
    costs, _ = read_costs(_three_questions(tmp_path))
    out = summarise_costs(costs)
    assert out["n"] == 3 and out["missing"] == []
    assert set(FIELDS) <= set(out)
    # LLM calls 1, 1, 4.
    assert out["llm_calls"] == {"mean": 2.0, "median": 1, "p95": 4, "total": 6}
    # Tokens: prompt 100/200/600, completion 20/40/60, total 120/240/660.
    assert out["prompt_tokens"]["total"] == 900
    assert out["completion_tokens"]["mean"] == 40.0
    assert out["total_tokens"] == {"mean": 340.0, "median": 240, "p95": 660, "total": 1020}
    # Latency: LLM 1000/2000/6000, retrieval 10/20/30, total 1010/2020/6030.
    assert out["llm_latency_ms"] == {"mean": 3000.0, "median": 2000, "p95": 6000, "total": 9000}
    assert out["retrieval_ms"]["mean"] == 20.0
    assert out["retrieval_calls"]["total"] == 5
    assert out["total_ms"] == {"mean": 3020.0, "median": 2020, "p95": 6030, "total": 9060}


def test_summarise_costs_is_restricted_to_the_scored_questions(tmp_path):
    costs, _ = read_costs(_three_questions(tmp_path))
    out = summarise_costs(costs, query_ids=["q1", "q2"])
    assert out["n"] == 2
    assert out["llm_calls"]["total"] == 2          # q3's four calls are outside this split


def test_a_question_without_a_cost_row_is_listed_not_counted_as_free(tmp_path):
    costs, _ = read_costs(_three_questions(tmp_path))
    out = summarise_costs(costs, query_ids=["q1", "q2", "q9"])
    assert out["missing"] == ["q9"]
    assert out["n"] == 2
    assert out["llm_calls"]["mean"] == 1.0         # 2 calls over the 2 costed questions, not over 3


# -- quality per unit of cost -----------------------------------------------------------


def test_efficiency_by_hand(tmp_path):
    costs, _ = read_costs(_three_questions(tmp_path))
    out = efficiency({"recall@10": 0.6, "ndcg@10": 0.3}, summarise_costs(costs))
    # Per question: 2.0 LLM calls, 340 tokens, 3.02 s.
    assert out["recall@10"]["per_llm_call"] == pytest.approx(0.3)
    assert out["recall@10"]["per_1k_tokens"] == pytest.approx(0.6 / 0.34)
    assert out["recall@10"]["per_second"] == pytest.approx(0.6 / 3.02)
    assert out["ndcg@10"]["per_llm_call"] == pytest.approx(0.15)


def test_a_system_that_calls_no_llm_has_no_per_call_figure(tmp_path):
    # Plain BM25. "Infinite quality per call" is not a result.
    costs, _ = read_costs(_write(tmp_path / "c.jsonl", [cost_row("q1", "plain_bm25", retrieval_ms=5)]))
    out = efficiency({"recall@10": 0.5}, summarise_costs(costs))
    assert out["recall@10"]["per_llm_call"] is None
    assert out["recall@10"]["per_1k_tokens"] is None
    assert out["recall@10"]["per_second"] == pytest.approx(0.5 / 0.005)


def test_efficiency_of_an_unscored_metric_is_none(tmp_path):
    costs, _ = read_costs(_three_questions(tmp_path))
    assert efficiency({"recall@10": None}, summarise_costs(costs))["recall@10"]["per_llm_call"] is None


# -- offline corpus-enrichment cost, kept apart -----------------------------------------


def _enrichment(tmp_path):
    def record(doc_id, calls, prompt, completion, latency):
        return EnrichmentRecord(
            doc_id=doc_id, source=Source.CWE, original_text="...",
            proposed_terms=[ProposedTerm.accept("brute force login", TermKind.COLLOQUIAL)],
            llm_calls=calls, tokens=TokenUsage(prompt=prompt, completion=completion),
            latency_ms=latency, model="qwen2.5:7b",
        )

    path = tmp_path / "corpus.jsonl"
    write_jsonl([record("CWE-1", 1, 800, 100, 17000), record("CWE-2", 3, 2400, 300, 51000)], path)
    return path


def test_offline_enrichment_cost_by_hand(tmp_path):
    out = offline_enrichment_cost(_enrichment(tmp_path))
    assert out["scope"] == "offline"
    assert out["records"] == 2
    assert out["models"] == {"qwen2.5:7b": 2}
    assert out["llm_calls"]["total"] == 4
    assert out["prompt_tokens"]["total"] == 3200
    assert out["completion_tokens"]["total"] == 400
    assert out["total_tokens"] == {"mean": 1800.0, "median": 1800.0, "p95": 2700, "total": 3600}
    assert out["llm_latency_ms"]["total"] == 68000
    assert out["failed_without_record"] == 0 and out["manifest"] is None


def test_offline_cost_reports_failed_documents_and_the_run_manifest(tmp_path):
    path = _enrichment(tmp_path)
    (tmp_path / "corpus.jsonl.failures.jsonl").write_text(
        json.dumps({"doc_id": "CAPEC-587", "error": "MalformedReplyError"}) + "\n", encoding="utf-8"
    )
    (tmp_path / "corpus.jsonl.manifest.json").write_text(
        json.dumps({"prompt_version": "corpus-v3", "model": "qwen2.5:7b", "config_hash": "abc"}), encoding="utf-8"
    )
    out = offline_enrichment_cost(path)
    assert out["failed_without_record"] == 1       # its tokens are not in the totals above
    assert out["manifest"]["prompt_version"] == "corpus-v3"


def test_amortise_spreads_the_offline_total_over_the_questions(tmp_path):
    out = amortise(offline_enrichment_cost(_enrichment(tmp_path)), 100)
    assert out == {"n_queries": 100, "llm_calls": 0.04, "total_tokens": 36.0, "llm_latency_ms": 680.0}
    with pytest.raises(ValueError):
        amortise(offline_enrichment_cost(_enrichment(tmp_path)), 0)


def test_offline_cost_never_enters_a_per_question_figure(tmp_path):
    costs, _ = read_costs(_three_questions(tmp_path))
    before = summarise_costs(costs)
    offline_enrichment_cost(_enrichment(tmp_path))
    assert summarise_costs(costs) == before
    assert before["total_tokens"]["total"] == 1020      # the run's own tokens; none of the corpus's 3,600
