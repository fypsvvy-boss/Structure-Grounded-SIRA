"""The harness end to end (``sira_cti.eval.report`` and ``scripts/run_eval.py``).

Fixture QA rows -> query file and qrels -> two stand-in retrieval systems
writing run files in Module 3's documented format -> one results file.
Nothing here builds an index, calls a model or touches the network.

Two systems are scored:

* ``oracle`` -- returns each question's gold entries in order, where the
  corpus has them. Its scores are known by hand (below), so the whole
  pipeline is checked against arithmetic rather than against itself.
* ``fake_overlap`` -- a real, if crude, retriever (word overlap with the
  fixture corpus), for a run whose contents nobody chose.
"""

from __future__ import annotations

import json

import pytest
from eval_helpers import (
    DEFAULT_CONFIG,
    QA_FIXTURE,
    FakeOverlapRetriever,
    cost_row,
    fixture_doc_ids,
    load_script,
    write_module3_run,
)
from helpers import CORPUS_KB_FIXTURE

from sira_cti.common import (
    EnrichmentRecord,
    ProposedTerm,
    RejectReason,
    Source,
    TermKind,
    TokenUsage,
    config_hash,
    write_jsonl,
)
from sira_cti.eval import evaluate, load_qa, render_markdown, write_benchmark, write_results
from sira_cti.eval.report import RESULTS_SCHEMA, detect_attack_version

CONFIG_HASH = config_hash(DEFAULT_CONFIG)


def _benchmark(root):
    bench = load_qa(QA_FIXTURE)
    write_benchmark(bench, root, seed=42, dev_fraction=0.5, qa_dir=QA_FIXTURE,
                    config_hash=CONFIG_HASH, known_doc_ids=fixture_doc_ids())
    return bench


def _oracle_run(root, bench, **manifest):
    """Gold entries first, for every question whose gold is in the corpus.

    ``rcm-002``'s gold weaknesses are not in the fixture corpus, so no
    system can return them: it has no lines in the run at all.
    """
    corpus = fixture_doc_ids()
    rankings = {
        i.query_id: [(d, float(len(i.gold_ids) - n)) for n, d in enumerate(i.gold_ids)]
        for i in bench.items if set(i.gold_ids) <= corpus
    }
    costs = [
        cost_row(i.query_id, "oracle", llm_calls=1, prompt=100, completion=20, llm_latency_ms=1000, retrieval_ms=10)
        for i in bench.items
    ]
    body = {"index_manifest": {"kind": "enriched", "config_hash": CONFIG_HASH, "enrichment_model": "qwen2.5:7b",
                               "enrichment_prompt_version": "corpus-v3"},
            "enrichment_path": "indexes/enrichment/queries.jsonl"}
    body.update(manifest)
    return write_module3_run(root / "oracle.trec", "oracle", rankings, costs=costs, manifest=body, config_hash=CONFIG_HASH)


def _overlap_run(root, bench):
    retriever = FakeOverlapRetriever()
    rankings = {i.query_id: retriever.retrieve(i.query) for i in bench.items}
    costs = [cost_row(i.query_id, retriever.name, retrieval_ms=5) for i in bench.items]
    return write_module3_run(root / "overlap.trec", retriever.name, rankings, costs=costs, config_hash=CONFIG_HASH)


def _corpus_enrichment(root):
    record = EnrichmentRecord(
        doc_id="CWE-307", source=Source.CWE, original_text="...", model="qwen2.5:7b",
        proposed_terms=[
            ProposedTerm.accept("unlimited login tries", TermKind.SYMPTOM),
            ProposedTerm.accept("CAPEC-49", TermKind.STRUCTURAL, structural_id="CAPEC-49"),
            ProposedTerm.reject("T9999", TermKind.STRUCTURAL, RejectReason.NOT_IN_GRAPH, structural_id="T9999"),
            ProposedTerm.reject("CWE-79", TermKind.STRUCTURAL, RejectReason.TOO_COMMON, structural_id="CWE-79"),
        ],
        llm_calls=1, tokens=TokenUsage(prompt=50000, completion=5000), latency_ms=17000,
    )
    path = root / "corpus.jsonl"
    write_jsonl([record], path)
    (root / "corpus.jsonl.manifest.json").write_text(
        json.dumps({"prompt_version": "corpus-v3", "model": "qwen2.5:7b", "config_hash": CONFIG_HASH}), encoding="utf-8"
    )
    return path


@pytest.fixture
def scored(tmp_path):
    bench = _benchmark(tmp_path / "benchmark")
    runs = [_oracle_run(tmp_path, bench), _overlap_run(tmp_path, bench)]
    results, per_query = evaluate(
        qrels_path=tmp_path / "benchmark" / "qrels.all.trec",
        run_paths=runs,
        config_path=DEFAULT_CONFIG,
        known_doc_ids=fixture_doc_ids(),
        corpus_enrichment_paths=[_corpus_enrichment(tmp_path)],
        attack_version="v17.1",
        n_bootstrap=200,
        n_randomisation=1000,
    )
    return results, per_query


# -- quality ----------------------------------------------------------------------------


def test_oracle_scores_match_the_hand_computed_values(scored):
    results, _ = scored
    overall = results["systems"]["oracle"]["quality"]["overall"]
    # Eight questions. Gold found at the top for seven; rcm-002 unanswerable.
    #   recall@1 : 1 for the five single-gold questions, 0.5 for atd-001 and
    #              ata-001 (two gold entries, one slot), 0 for rcm-002 -> 6/8
    #   recall@10, ndcg@10 : 1 for seven, 0 for rcm-002                 -> 7/8
    assert overall["n"] == 8
    assert overall["recall@1"]["mean"] == pytest.approx(0.75)
    assert overall["recall@10"]["mean"] == pytest.approx(0.875)
    assert overall["recall@100"]["mean"] == pytest.approx(0.875)
    assert overall["ndcg@10"]["mean"] == pytest.approx(0.875)
    assert overall["recall@10"]["ci_low"] <= 0.875 <= overall["recall@10"]["ci_high"]


def test_results_are_broken_down_by_task_and_category(scored):
    quality = scored[0]["systems"]["oracle"]["quality"]
    assert set(quality["by_task"]) == {"ata", "atd", "esd", "rcm", "vca", "wim"}
    assert quality["by_task"]["rcm"]["n"] == 2
    assert quality["by_task"]["rcm"]["recall@10"]["mean"] == 0.5          # rcm-001 found, rcm-002 not
    assert quality["by_task"]["ata"]["recall@1"]["mean"] == 0.75          # 0.5 and 1.0
    assert quality["by_category"]["entity_linking"]["n"] == 5
    assert quality["by_category"]["entity_attribution"]["recall@10"]["mean"] == 1.0
    assert sum(g["n"] for g in quality["by_task"].values()) == quality["overall"]["n"]


def test_an_unanswered_question_is_scored_zero_and_reported(scored):
    results, per_query = scored
    assert results["systems"]["oracle"]["coverage"] == {"questions_scored": 8, "missing_from_run": 1, "extra_in_run": 0}
    row = next(r for r in per_query if r["system"] == "oracle" and r["query_id"] == "rcm-002")
    assert row["recall@100"] == 0.0
    assert any(i["code"] == "missing_query" and "rcm-002" in i["message"] for i in results["issues"])


def test_per_query_rows_carry_task_category_and_split(scored):
    _, per_query = scored
    assert len(per_query) == 16                 # 8 questions x 2 systems
    row = next(r for r in per_query if r["system"] == "oracle" and r["query_id"] == "ata-001")
    assert (row["task"], row["category"]) == ("ata", "entity_attribution")
    assert row["split"] in ("dev", "test")
    assert row["recall@1"] == 0.5


def test_the_fake_retriever_is_scored_like_any_other_system(scored):
    results, _ = scored
    overlap = results["systems"]["fake_overlap"]
    assert overlap["coverage"]["questions_scored"] == 8
    assert 0.0 <= overlap["quality"]["overall"]["recall@10"]["mean"] <= 1.0
    assert overlap["quality"]["overall"]["recall@10"]["mean"] > 0      # word overlap does find some gold entries


def test_systems_are_compared_with_a_paired_test_per_metric(scored):
    comparisons = scored[0]["comparisons"]
    assert {(c["a"], c["b"]) for c in comparisons} == {("oracle", "fake_overlap")}
    assert {c["metric"] for c in comparisons} == {"recall@1", "recall@10", "recall@100", "ndcg@10"}
    for c in comparisons:
        assert c["n"] == 8 and c["method"] == "exact" and 0 < c["p_value"] <= 1


# -- cost -------------------------------------------------------------------------------


def test_online_cost_and_efficiency(scored):
    oracle = scored[0]["systems"]["oracle"]
    assert oracle["cost"]["n"] == 8 and oracle["cost"]["missing"] == []
    assert oracle["cost"]["llm_calls"]["mean"] == 1.0
    assert oracle["cost"]["total_tokens"]["mean"] == 120.0
    assert oracle["cost"]["total_ms"]["p95"] == 1010
    assert oracle["efficiency"]["recall@10"]["per_llm_call"] == pytest.approx(0.875)
    assert oracle["efficiency"]["recall@10"]["per_second"] == pytest.approx(0.875 / 1.01)
    # The baseline makes no LLM call: no per-call figure, rather than an infinite one.
    assert scored[0]["systems"]["fake_overlap"]["efficiency"]["recall@10"]["per_llm_call"] is None


def test_offline_corpus_cost_is_reported_separately(scored):
    results, _ = scored
    offline = results["offline_costs"][0]
    assert offline["scope"] == "offline"
    assert offline["total_tokens"]["total"] == 55000
    assert offline["amortised"] == {"n_queries": 8, "llm_calls": 0.125, "total_tokens": 6875.0, "llm_latency_ms": 2125.0}
    # None of those 55,000 tokens reach a per-question figure.
    assert results["systems"]["oracle"]["cost"]["total_tokens"]["total"] == 8 * 120
    assert results["systems"]["fake_overlap"]["cost"]["total_tokens"]["total"] == 0


# -- audit, blocked work, provenance ----------------------------------------------------


def test_the_enrichment_audit_is_included(scored):
    audit = scored[0]["audit"]["corpus"][0]
    assert audit["proposed"] == 4
    assert audit["structural"]["graph_rejection_rate"] == pytest.approx(1 / 3)
    assert audit["structural"]["structural_rejection_rate"] == pytest.approx(2 / 3)
    assert scored[0]["audit"]["query"] == []


def test_synthesis_is_reported_as_blocked_with_no_number(scored):
    results, _ = scored
    blocked = results["blocked"]["multi_doc_synthesis"]
    assert blocked["status"] == "blocked"
    assert blocked["reason"] == "synthesis_scoring_undefined"
    assert blocked["blocked_questions_by_task"] == {"csc": 1, "tap": 1}
    for system in results["systems"].values():
        assert not {"csc", "tap", "mla"} & set(system["quality"]["by_task"])
        assert "multi_doc_synthesis" not in system["quality"]["by_category"]


def test_provenance_is_complete(scored):
    prov = scored[0]["provenance"]
    assert scored[0]["schema"] == RESULTS_SCHEMA
    assert prov["config_hash"] == CONFIG_HASH
    assert prov["attack_version"] == {"value": "v17.1", "source": "stated"}
    assert prov["eval"]["metrics"] == ["recall@1", "recall@10", "recall@100", "ndcg@10"]
    assert prov["eval"]["seed"] == 42                                   # eval.seed in the config
    assert prov["benchmark"]["manifest"]["seed"] == 42
    assert prov["benchmark"]["manifest"]["dev_fraction"] == 0.5

    oracle = prov["runs"]["oracle"]
    assert oracle["config_hash"] == CONFIG_HASH
    assert oracle["index_kind"] == "enriched"
    assert oracle["corpus_enrichment_model"] == "qwen2.5:7b"
    assert oracle["corpus_enrichment_prompt_version"] == "corpus-v3"
    assert oracle["query_enrichment_path"] == "indexes/enrichment/queries.jsonl"
    assert oracle["manifest"]["settings"]["k"] == 100                   # the run's full manifest travels too
    assert oracle["run_path"].endswith("oracle.trec") and oracle["costs_path"].endswith("oracle.trec.costs.jsonl")

    corpus = prov["enrichment"]["corpus"][0]
    assert (corpus["models"], corpus["prompt_version"], corpus["config_hash"]) == (["qwen2.5:7b"], "corpus-v3", CONFIG_HASH)


def test_a_clean_evaluation_has_no_errors(scored):
    results, _ = scored
    assert results["status"] == "ok"
    assert [i for i in results["issues"] if i["severity"] == "error"] == []


def test_results_are_json_serialisable_and_reproducible(scored, tmp_path):
    results, per_query = scored
    paths = write_results(results, per_query, tmp_path / "out")
    reloaded = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert reloaded["systems"] == results["systems"]
    assert len(paths["per_query"].read_text(encoding="utf-8").splitlines()) == 16

    # Same inputs, same seed -> the same numbers, intervals and p-values included.
    again, _ = evaluate(
        qrels_path=tmp_path / "benchmark" / "qrels.all.trec",
        run_paths=[tmp_path / "oracle.trec", tmp_path / "overlap.trec"],
        config_path=DEFAULT_CONFIG, known_doc_ids=fixture_doc_ids(),
        attack_version="v17.1", n_bootstrap=200, n_randomisation=1000,
    )
    assert again["systems"]["oracle"]["quality"] == results["systems"]["oracle"]["quality"]
    assert again["comparisons"] == results["comparisons"]


def test_markdown_report_has_every_section(scored):
    text = render_markdown(scored[0])
    for heading in (
        "## Provenance", "## Retrieval quality", "### By category", "### By task", "## Cost per question (online)",
        "## Quality per unit of cost", "## Paired randomisation tests", "## Offline cost: corpus-side enrichment",
        "## Enrichment audit (corpus-side)", "## Not scored", "## Issues", "## Caveats",
    ):
        assert heading in text, heading
    assert CONFIG_HASH in text and "v17.1" in text and "corpus-v3" in text
    assert "| oracle | 8 | 0.7500 [" in text
    assert "multi_doc_synthesis** -- blocked" in text
    assert "validation errors" not in text


# -- when the inputs are not sound ------------------------------------------------------


def test_scoring_one_split_ignores_the_other_splits_questions(tmp_path):
    bench = _benchmark(tmp_path / "benchmark")
    results, _ = evaluate(
        qrels_path=tmp_path / "benchmark" / "qrels.test.trec", run_paths=[_oracle_run(tmp_path, bench)],
        config_path=DEFAULT_CONFIG, known_doc_ids=fixture_doc_ids(), attack_version="v17.1", n_bootstrap=50,
    )
    coverage = results["systems"]["oracle"]["coverage"]
    assert coverage["questions_scored"] == 2          # dev took 6 of the 8 at dev_fraction 0.5
    assert coverage["extra_in_run"] >= 4
    assert results["systems"]["oracle"]["cost"]["n"] == 2
    assert results["status"] == "ok"                  # extra questions are a warning, not an error


def test_a_retrieved_doc_id_outside_the_corpus_marks_the_results(tmp_path):
    _benchmark(tmp_path / "benchmark")
    run = write_module3_run(tmp_path / "bad.trec", "bad", {"rcm-001": [("CWE-99999", 1.0)]}, config_hash=CONFIG_HASH)
    results, _ = evaluate(
        qrels_path=tmp_path / "benchmark" / "qrels.all.trec", run_paths=[run], config_path=DEFAULT_CONFIG,
        known_doc_ids=fixture_doc_ids(), attack_version="v17.1", n_bootstrap=50,
    )
    assert results["status"] == "errors"
    assert any(i["code"] == "unknown_doc" for i in results["issues"])
    assert "validation errors" in render_markdown(results)


def test_runs_from_different_configs_are_refused_as_comparable(tmp_path):
    bench = _benchmark(tmp_path / "benchmark")
    runs = [_oracle_run(tmp_path, bench, config_hash="another-config"), _overlap_run(tmp_path, bench)]
    results, _ = evaluate(
        qrels_path=tmp_path / "benchmark" / "qrels.all.trec", run_paths=runs, config_path=DEFAULT_CONFIG,
        known_doc_ids=fixture_doc_ids(), attack_version="v17.1", n_bootstrap=50, n_randomisation=100,
    )
    assert results["status"] == "errors"
    assert any(i["code"] == "config_hash_mismatch" for i in results["issues"])


def test_missing_provenance_is_flagged_not_invented(tmp_path):
    bench = _benchmark(tmp_path / "benchmark")
    run = _overlap_run(tmp_path, bench)
    (tmp_path / "overlap.trec.manifest.json").unlink()
    (tmp_path / "overlap.trec.costs.jsonl").unlink()
    # Qrels copied away from their manifest and metadata; no corpus; no ATT&CK version.
    lone = tmp_path / "lone" / "qrels.trec"
    lone.parent.mkdir()
    lone.write_text((tmp_path / "benchmark" / "qrels.all.trec").read_text(encoding="utf-8"), encoding="utf-8")

    results, _ = evaluate(qrels_path=lone, run_paths=[run], config_path=DEFAULT_CONFIG, n_bootstrap=50)
    codes = {i["code"] for i in results["issues"]}
    assert {"no_manifest", "no_costs", "no_metadata", "doc_ids_unchecked", "provenance_missing"} <= codes
    assert results["provenance"]["runs"]["fake_overlap"]["config_hash"] is None
    assert results["provenance"]["benchmark"]["manifest"] is None
    assert results["systems"]["fake_overlap"]["cost"] is None
    assert "by_task" not in results["systems"]["fake_overlap"]["quality"]
    assert results["status"] == "ok"            # incomplete provenance warns; it does not invalidate the scores
    assert "no cost file" in render_markdown(results)


def test_attack_version_is_read_from_the_stix_bundle(tmp_path):
    bundle = tmp_path / "enterprise-attack.json"
    bundle.write_text(json.dumps({"objects": [
        {"type": "attack-pattern", "name": "Brute Force"},
        {"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "17.1"},
    ]}), encoding="utf-8")
    assert detect_attack_version([bundle, tmp_path / "not-fetched.json"]) == ["17.1"]
    assert detect_attack_version([tmp_path / "not-fetched.json"]) == []


# -- the command line -------------------------------------------------------------------


def test_cli_prepare_then_score(tmp_path, capsys):
    cli = load_script("run_eval")
    bench_dir, out_dir = tmp_path / "benchmark", tmp_path / "results"

    assert cli.main([
        "prepare", "--config", str(DEFAULT_CONFIG), "--qa-dir", str(QA_FIXTURE),
        "--kb-dir", str(CORPUS_KB_FIXTURE), "--output-dir", str(bench_dir), "--dev-fraction", "0.5",
    ]) == 0
    prepared = capsys.readouterr().out
    assert "scoreable questions: 8" in prepared
    assert "blocked (not scored): 2" in prepared
    assert "rcm-002: CWE-120" in prepared                      # gold not in the corpus, surfaced up front

    bench = load_qa(QA_FIXTURE)
    oracle, overlap = _oracle_run(tmp_path, bench), _overlap_run(tmp_path, bench)
    assert cli.main([
        "score", "--config", str(DEFAULT_CONFIG), "--qrels", str(bench_dir / "qrels.all.trec"),
        "--run", str(oracle), "--run", str(overlap), "--kb-dir", str(CORPUS_KB_FIXTURE),
        "--corpus-enrichment", str(_corpus_enrichment(tmp_path)), "--baseline", "fake_overlap",
        "--attack-version", "v17.1", "--bootstrap", "100", "--randomisation", "500",
        "--output-dir", str(out_dir),
    ]) == 0
    assert "multi_doc_synthesis: blocked" in capsys.readouterr().out

    results = json.loads((out_dir / "results.json").read_text(encoding="utf-8"))
    assert results["status"] == "ok"
    assert results["systems"]["oracle"]["quality"]["overall"]["recall@10"]["mean"] == pytest.approx(0.875)
    assert {(c["a"], c["b"]) for c in results["comparisons"]} == {("oracle", "fake_overlap")}
    assert results["provenance"]["config_hash"] == CONFIG_HASH
    assert (out_dir / "results.md").read_text(encoding="utf-8").startswith("# SIRA-CTI evaluation results")
    assert (out_dir / "per_query.jsonl").exists()


def test_cli_refuses_to_write_results_from_an_invalid_run(tmp_path, capsys):
    cli = load_script("run_eval")
    _benchmark(tmp_path / "benchmark")
    bad = write_module3_run(tmp_path / "bad.trec", "bad", {"rcm-001": [("CWE-99999", 1.0)]}, config_hash=CONFIG_HASH)
    args = [
        "score", "--config", str(DEFAULT_CONFIG), "--qrels", str(tmp_path / "benchmark" / "qrels.all.trec"),
        "--run", str(bad), "--kb-dir", str(CORPUS_KB_FIXTURE), "--attack-version", "v17.1",
        "--bootstrap", "50", "--output-dir", str(tmp_path / "results"),
    ]
    assert cli.main(args) == 1
    assert "nothing written" in capsys.readouterr().out
    assert not (tmp_path / "results").exists()

    assert cli.main(args + ["--allow-errors"]) == 0
    assert json.loads((tmp_path / "results" / "results.json").read_text(encoding="utf-8"))["status"] == "errors"


def test_cli_reports_missing_inputs(tmp_path, capsys):
    cli = load_script("run_eval")
    assert cli.main(["prepare", "--config", str(DEFAULT_CONFIG), "--qa-dir", str(tmp_path / "nope"),
                     "--output-dir", str(tmp_path / "b")]) == 1
    assert cli.main(["score", "--config", str(DEFAULT_CONFIG), "--qrels", str(tmp_path / "nope.trec"),
                     "--run", str(tmp_path / "nope.run"), "--output-dir", str(tmp_path / "r")]) == 1
    assert "Not found" in capsys.readouterr().out
