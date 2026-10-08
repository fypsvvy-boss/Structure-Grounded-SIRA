"""Retrieval metrics (``sira_cti.eval.metrics``).

Every expected value here is worked out by hand in the comment beside it.
These numbers are what RQ2 reports, so the tests pin the definitions
themselves -- what counts as recall when a question has two gold entries,
what a question the system did not answer scores -- not just that the code
runs.
"""

from __future__ import annotations

import math

import pytest

from sira_cti.eval.metrics import (
    DEFAULT_METRICS,
    bootstrap_ci,
    compare,
    group_of,
    mean,
    metric_names,
    ndcg_at_k,
    paired_randomisation_test,
    parse_metric,
    per_query_metrics,
    recall_at_k,
    summarise,
)

# -- recall -----------------------------------------------------------------------------


def test_recall_counts_relevant_documents_in_the_top_k_over_all_relevant():
    ranking, grades = ["a", "b", "c"], {"b": 1, "d": 1}
    assert recall_at_k(ranking, grades, 1) == 0.0      # top-1 is "a"
    assert recall_at_k(ranking, grades, 2) == 0.5      # "b" found, "d" never retrieved
    assert recall_at_k(ranking, grades, 100) == 0.5    # k beyond the list changes nothing


def test_recall_of_a_single_gold_entry_is_a_hit_or_a_miss():
    assert recall_at_k(["x", "gold"], {"gold": 1}, 1) == 0.0
    assert recall_at_k(["x", "gold"], {"gold": 1}, 10) == 1.0


def test_recall_ignores_documents_judged_non_relevant():
    assert recall_at_k(["a"], {"a": 0, "b": 1}, 10) == 0.0


def test_metrics_are_undefined_without_a_relevant_document():
    with pytest.raises(ValueError):
        recall_at_k(["a"], {}, 10)
    with pytest.raises(ValueError):
        ndcg_at_k(["a"], {"a": 0}, 10)


# -- NDCG -------------------------------------------------------------------------------


def test_ndcg_is_one_for_a_perfect_ranking_and_zero_for_a_miss():
    assert ndcg_at_k(["gold", "x"], {"gold": 1}, 10) == 1.0
    assert ndcg_at_k(["x", "y"], {"gold": 1}, 10) == 0.0


def test_ndcg_discounts_by_log2_of_rank_plus_one():
    # One gold entry at rank 2: DCG = 1/log2(3), IDCG = 1/log2(2) = 1.
    assert ndcg_at_k(["x", "gold"], {"gold": 1}, 10) == pytest.approx(1 / math.log2(3))
    assert ndcg_at_k(["x", "gold"], {"gold": 1}, 10) == pytest.approx(0.63093, abs=1e-5)


def test_ndcg_with_two_gold_entries():
    # Gold a, b; ranking [a, x, b].
    #   DCG  = 1/log2(2) + 1/log2(4) = 1 + 0.5      = 1.5
    #   IDCG = 1/log2(2) + 1/log2(3) = 1 + 0.63093  = 1.63093
    assert ndcg_at_k(["a", "x", "b"], {"a": 1, "b": 1}, 10) == pytest.approx(1.5 / (1 + 1 / math.log2(3)))
    assert ndcg_at_k(["a", "x", "b"], {"a": 1, "b": 1}, 10) == pytest.approx(0.91972, abs=1e-5)


def test_ndcg_uses_linear_gain_for_graded_relevance():
    # Grades a=2, b=1; ranking [b, a].
    #   DCG  = 1/1 + 2/log2(3) = 2.26186
    #   IDCG = 2/1 + 1/log2(3) = 2.63093
    assert ndcg_at_k(["b", "a"], {"a": 2, "b": 1}, 10) == pytest.approx(2.26186 / 2.63093, abs=1e-5)


def test_ndcg_cutoff_ignores_everything_below_k():
    ranking = [f"x{i}" for i in range(10)] + ["gold"]     # gold at rank 11
    assert ndcg_at_k(ranking, {"gold": 1}, 10) == 0.0
    assert ndcg_at_k(ranking, {"gold": 1}, 11) == pytest.approx(1 / math.log2(12))


def test_ndcg_ideal_is_truncated_at_k_too():
    # Three gold entries, k=2, both slots filled with gold: that is the best
    # any ranking can do at depth 2, so it scores 1.0 (not 2/3).
    assert ndcg_at_k(["a", "b"], {"a": 1, "b": 1, "c": 1}, 2) == pytest.approx(1.0)


# -- per-question scoring ---------------------------------------------------------------


def test_metric_names_parse_and_reject():
    assert parse_metric("recall@10") == ("recall", 10)
    assert parse_metric("NDCG@10") == ("ndcg", 10)
    for bad in ("recall", "recall@0", "precision@10", "ndcg@ten"):
        with pytest.raises(ValueError):
            parse_metric(bad)
    assert metric_names(None) == DEFAULT_METRICS == ("recall@1", "recall@10", "recall@100", "ndcg@10")
    assert metric_names(["Recall@5"]) == ("recall@5",)


def test_per_query_metrics_scores_every_question_in_the_qrels():
    qrels = {"q1": {"a": 1}, "q2": {"b": 1}}
    scores = per_query_metrics({"q1": ["a"], "q2": ["x", "b"]}, qrels)
    assert scores["q1"] == {"recall@1": 1.0, "recall@10": 1.0, "recall@100": 1.0, "ndcg@10": 1.0}
    assert scores["q2"]["recall@1"] == 0.0
    assert scores["q2"]["recall@10"] == 1.0
    assert scores["q2"]["ndcg@10"] == pytest.approx(1 / math.log2(3))


def test_a_question_missing_from_the_run_scores_zero_not_nothing():
    # trec_eval would average over q1 alone and report 1.0. A system must not
    # be able to raise its mean by returning nothing for a hard question.
    scores = per_query_metrics({"q1": ["a"]}, {"q1": {"a": 1}, "q2": {"b": 1}})
    assert scores["q2"] == {"recall@1": 0.0, "recall@10": 0.0, "recall@100": 0.0, "ndcg@10": 0.0}
    assert mean([s["recall@10"] for s in scores.values()]) == 0.5


def test_a_question_with_no_relevant_document_is_skipped():
    scores = per_query_metrics({"q1": ["a"], "q2": ["a"]}, {"q1": {"a": 1}, "q2": {"a": 0}})
    assert set(scores) == {"q1"}


def test_questions_in_the_run_but_not_the_qrels_are_ignored():
    assert set(per_query_metrics({"q1": ["a"], "other": ["a"]}, {"q1": {"a": 1}})) == {"q1"}


def test_mean_of_nothing_is_none_not_zero():
    assert mean([]) is None
    assert mean([0.0, 1.0]) == 0.5


# -- bootstrap confidence interval ------------------------------------------------------


def test_bootstrap_ci_of_constant_scores_is_that_constant():
    assert bootstrap_ci([0.5] * 20, n_resamples=200) == (0.5, 0.5)


def test_bootstrap_ci_of_nothing_is_none():
    assert bootstrap_ci([]) == (None, None)


def test_bootstrap_ci_of_one_question_is_that_question():
    assert bootstrap_ci([1.0], n_resamples=50) == (1.0, 1.0)


def test_bootstrap_ci_brackets_the_mean_and_stays_in_range():
    values = [0.0, 0.0, 1.0, 1.0, 1.0, 0.5, 0.0, 1.0, 1.0, 0.0]
    lo, hi = bootstrap_ci(values, n_resamples=2000, seed=42)
    assert 0.0 <= lo < mean(values) < hi <= 1.0


def test_bootstrap_ci_is_reproducible_for_a_seed():
    values = [0.0, 1.0, 1.0, 0.0, 1.0, 0.5, 0.25]
    assert bootstrap_ci(values, seed=1) == bootstrap_ci(values, seed=1)


def test_bootstrap_ci_narrows_as_confidence_drops():
    values = [0.0, 1.0, 1.0, 0.0, 1.0, 0.5, 0.25, 0.75, 0.0, 1.0]
    lo95, hi95 = bootstrap_ci(values, n_resamples=2000, alpha=0.05)
    lo50, hi50 = bootstrap_ci(values, n_resamples=2000, alpha=0.50)
    assert lo95 <= lo50 <= hi50 <= hi95
    assert (hi50 - lo50) < (hi95 - lo95)


def test_bootstrap_ci_rejects_bad_arguments():
    with pytest.raises(ValueError):
        bootstrap_ci([1.0], n_resamples=0)
    with pytest.raises(ValueError):
        bootstrap_ci([1.0], alpha=1.0)


# -- paired randomisation test ----------------------------------------------------------


def test_randomisation_test_is_exact_for_a_small_sample():
    # Three questions, system A better by 1.0 on each. Of the 2^3 = 8 sign
    # assignments only (+,+,+) and (-,-,-) reach |mean| = 1, so p = 2/8.
    result = paired_randomisation_test([1.0, 1.0, 1.0], [0.0, 0.0, 0.0])
    assert result.method == "exact"
    assert result.mean_diff == 1.0
    assert result.p_value == 0.25
    assert result.n == 3


def test_randomisation_test_with_four_equal_differences():
    # 2 of 16 assignments are as extreme as the observed one.
    assert paired_randomisation_test([0.5] * 4, [0.0] * 4).p_value == 0.125


def test_randomisation_test_with_mixed_differences():
    # Differences (1, 1, -1): observed mean 1/3. Every assignment has
    # |mean| of 1/3 or 1, so all 8 are at least as extreme: p = 1.
    assert paired_randomisation_test([1.0, 1.0, 0.0], [0.0, 0.0, 1.0]).p_value == 1.0


def test_identical_systems_have_p_value_one():
    result = paired_randomisation_test([0.2, 0.8, 1.0], [0.2, 0.8, 1.0])
    assert (result.mean_diff, result.p_value) == (0.0, 1.0)


def test_randomisation_test_is_symmetric_in_its_arguments():
    a, b = [1.0, 0.5, 0.0, 1.0], [0.0, 0.5, 0.5, 0.0]
    ab, ba = paired_randomisation_test(a, b), paired_randomisation_test(b, a)
    assert ab.p_value == ba.p_value
    assert ab.mean_diff == -ba.mean_diff


def test_randomisation_test_falls_back_to_monte_carlo_for_a_large_sample():
    # 2^20 assignments > 1000 resamples. A consistent advantage on 20
    # questions is as extreme as it gets, so the estimate is near its floor
    # of 1/(1000+1) -- never exactly zero.
    result = paired_randomisation_test([1.0] * 20, [0.0] * 20, n_resamples=1000, seed=42)
    assert result.method == "monte_carlo"
    assert 0 < result.p_value < 0.01
    assert result == paired_randomisation_test([1.0] * 20, [0.0] * 20, n_resamples=1000, seed=42)


def test_randomisation_test_needs_paired_scores():
    with pytest.raises(ValueError):
        paired_randomisation_test([1.0], [1.0, 0.0])
    assert paired_randomisation_test([], []).method == "none"


# -- aggregation ------------------------------------------------------------------------


def _scores():
    return {
        "rcm-1": {"recall@10": 1.0},
        "rcm-2": {"recall@10": 0.0},
        "ata-1": {"recall@10": 1.0},
        "new-1": {"recall@10": 0.5},
    }


def test_summarise_reports_overall_and_per_group_means():
    out = summarise(
        _scores(),
        groupings={"task": {"rcm-1": "rcm", "rcm-2": "rcm", "ata-1": "ata"}},
        metrics=["recall@10"],
        n_resamples=100,
    )
    assert out["overall"]["n"] == 4
    assert out["overall"]["recall@10"]["mean"] == 0.625            # (1 + 0 + 1 + 0.5) / 4
    assert out["by_task"]["rcm"]["n"] == 2
    assert out["by_task"]["rcm"]["recall@10"]["mean"] == 0.5
    assert out["by_task"]["ata"]["recall@10"] == {"mean": 1.0, "ci_low": 1.0, "ci_high": 1.0}


def test_summarise_keeps_ungrouped_questions_visible():
    out = summarise(_scores(), groupings={"task": {"rcm-1": "rcm"}}, metrics=["recall@10"], n_resamples=50)
    assert out["by_task"]["(unknown)"]["n"] == 3
    assert sum(g["n"] for g in out["by_task"].values()) == out["overall"]["n"]


def test_summarise_of_nothing_has_no_mean():
    out = summarise({}, metrics=["recall@10"], n_resamples=10)
    assert out["overall"] == {"n": 0, "recall@10": {"mean": None, "ci_low": None, "ci_high": None}}


def test_group_of_reads_a_metadata_field():
    metadata = {"q1": {"task": "rcm", "category": "entity_linking"}, "q2": {"category": "entity_linking"}}
    assert group_of(metadata, "task") == {"q1": "rcm"}
    assert group_of(metadata, "category") == {"q1": "entity_linking", "q2": "entity_linking"}


def test_compare_pairs_the_questions_both_systems_were_scored_on():
    a = {"q1": {"recall@10": 1.0}, "q2": {"recall@10": 1.0}, "q3": {"recall@10": 1.0}, "only_a": {"recall@10": 0.0}}
    b = {"q1": {"recall@10": 0.0}, "q2": {"recall@10": 0.0}, "q3": {"recall@10": 0.0}}
    out = compare(a, b, metrics=["recall@10"])
    assert out["recall@10"] == {"mean_diff": 1.0, "p_value": 0.25, "n": 3, "method": "exact"}


# -- optional cross-check against the reference implementation -------------------------


def test_metrics_agree_with_pytrec_eval_when_it_is_installed():
    pytrec_eval = pytest.importorskip("pytrec_eval")

    qrels = {"q1": {"a": 1, "b": 1}, "q2": {"c": 2, "d": 1}}
    run = {"q1": {"a": 3.0, "x": 2.0, "b": 1.0}, "q2": {"d": 3.0, "y": 2.0, "c": 1.0}}
    rankings = {q: sorted(docs, key=lambda d: -docs[d]) for q, docs in run.items()}   # distinct scores: no ties

    reference = pytrec_eval.RelevanceEvaluator(qrels, {"recall.1,10", "ndcg_cut.10"}).evaluate(run)
    ours = per_query_metrics(rankings, qrels, ["recall@1", "recall@10", "ndcg@10"])
    for q in qrels:
        assert ours[q]["recall@1"] == pytest.approx(reference[q]["recall_1"])
        assert ours[q]["recall@10"] == pytest.approx(reference[q]["recall_10"])
        assert ours[q]["ndcg@10"] == pytest.approx(reference[q]["ndcg_cut_10"])
