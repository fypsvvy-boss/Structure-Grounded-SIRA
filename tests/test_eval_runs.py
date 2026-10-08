"""Reading and validating Module 3's run files (``sira_cti.eval.runs``).

The run files are written here as plain text, line by line, in the format
``docs/05_MODULE3_STATE.md`` documents -- so these tests pin the *format*
the harness accepts, and each kind of damage a run file can carry is shown
to be reported rather than silently scored.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from eval_helpers import write_module3_run

import sira_cti.eval
from sira_cti.eval.runs import ERROR, WARNING, check_consistency, errors, read_run, sidecar

GOOD = (
    "q1 Q0 CWE-307 1 9.500000 sira_cti\n"
    "q1 Q0 T1110 2 4.250000 sira_cti\n"
    "q2 Q0 CAPEC-49 1 3.000000 sira_cti\n"
)


def _run(tmp_path, text: str, name: str = "run.trec", **kwargs):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return read_run(path, **kwargs)


def _codes(issues, severity=None) -> set[str]:
    return {i.code for i in issues if severity is None or i.severity == severity}


# -- a well-formed run ------------------------------------------------------------------


def test_a_well_formed_run_parses_with_no_errors(tmp_path):
    run = _run(tmp_path, GOOD)
    assert run.system == "sira_cti"
    assert run.doc_rankings() == {"q1": ["CWE-307", "T1110"], "q2": ["CAPEC-49"]}
    assert run.rankings["q1"][0].score == 9.5
    assert errors(run.issues) == []


def test_rankings_follow_the_rank_column_not_line_order(tmp_path):
    shuffled = "q1 Q0 T1110 2 4.25 s\nq1 Q0 CWE-307 1 9.5 s\n"
    assert _run(tmp_path, shuffled).doc_rankings() == {"q1": ["CWE-307", "T1110"]}


def test_tied_scores_are_allowed(tmp_path):
    # Rank-fused lists (synthesis, the agent baseline) contain ties.
    run = _run(tmp_path, "q1 Q0 a 1 0.5 s\nq1 Q0 b 2 0.5 s\n")
    assert errors(run.issues) == []


def test_blank_lines_are_skipped(tmp_path):
    assert errors(_run(tmp_path, "\n" + GOOD + "\n\n").issues) == []


def test_a_run_written_by_the_documented_writer_round_trips(tmp_path):
    path = write_module3_run(tmp_path / "run.trec", "plain_bm25", {"q1": [("CWE-307", 2.0), ("T1110", 1.0)]})
    run = read_run(path)
    assert run.system == "plain_bm25"
    assert run.doc_rankings() == {"q1": ["CWE-307", "T1110"]}
    assert run.manifest["system"] == "plain_bm25"
    assert run.issues == []


# -- malformed, duplicate and inconsistent records --------------------------------------


def test_a_line_with_the_wrong_number_of_columns_is_an_error(tmp_path):
    run = _run(tmp_path, GOOD + "q3 Q0 CWE-307 1 9.5\n")
    assert "malformed_line" in _codes(run.issues, ERROR)
    assert "q3" not in run.rankings          # reported and skipped, never repaired


def test_a_non_numeric_rank_or_score_is_an_error(tmp_path):
    assert "malformed_line" in _codes(_run(tmp_path, "q1 Q0 a first 9.5 s\n").issues, ERROR)
    assert "malformed_line" in _codes(_run(tmp_path, "q1 Q0 a 1 high s\n").issues, ERROR)


def test_a_non_finite_score_or_non_positive_rank_is_an_error(tmp_path):
    assert "malformed_line" in _codes(_run(tmp_path, "q1 Q0 a 1 nan s\n").issues, ERROR)
    assert "malformed_line" in _codes(_run(tmp_path, "q1 Q0 a 0 1.0 s\n").issues, ERROR)


def test_a_document_listed_twice_for_one_question_is_an_error(tmp_path):
    run = _run(tmp_path, "q1 Q0 a 1 2.0 s\nq1 Q0 a 2 1.0 s\n")
    assert "duplicate_doc" in _codes(run.issues, ERROR)
    assert run.doc_rankings() == {"q1": ["a"]}       # a duplicate must not be able to count twice


def test_two_documents_at_one_rank_is_an_error(tmp_path):
    assert "duplicate_rank" in _codes(_run(tmp_path, "q1 Q0 a 1 2.0 s\nq1 Q0 b 1 1.0 s\n").issues, ERROR)


def test_ranks_that_skip_or_do_not_start_at_one_are_an_error(tmp_path):
    assert "rank_gap" in _codes(_run(tmp_path, "q1 Q0 a 1 2.0 s\nq1 Q0 b 3 1.0 s\n").issues, ERROR)
    assert "rank_gap" in _codes(_run(tmp_path, "q1 Q0 a 2 2.0 s\n").issues, ERROR)


def test_a_score_that_rises_with_rank_is_an_error(tmp_path):
    # Rank and score disagree about the order: one of them is wrong, and
    # trec_eval (which sorts by score) would score a different list than we do.
    assert "score_order" in _codes(_run(tmp_path, "q1 Q0 a 1 1.0 s\nq1 Q0 b 2 2.0 s\n").issues, ERROR)


def test_more_than_one_system_in_a_file_is_an_error(tmp_path):
    run = _run(tmp_path, "q1 Q0 a 1 2.0 sira_cti\nq2 Q0 a 1 2.0 sira_cti\nq3 Q0 a 1 2.0 plain_bm25\n")
    assert "mixed_systems" in _codes(run.issues, ERROR)
    assert run.system == "sira_cti"           # the majority tag, for the report's label


def test_an_empty_run_is_an_error(tmp_path):
    assert "empty_run" in _codes(_run(tmp_path, "").issues, ERROR)


def test_every_problem_in_a_file_is_reported_in_one_pass(tmp_path):
    text = "bad line\nq1 Q0 a 1 2.0 s\nq1 Q0 a 2 1.0 s\nq2 Q0 b 2 1.0 s\n"
    assert {"malformed_line", "duplicate_doc", "rank_gap"} <= _codes(_run(tmp_path, text).issues, ERROR)


def test_repeated_problems_are_counted_and_summarised(tmp_path):
    run = _run(tmp_path, "".join(f"broken {i}\n" for i in range(12)))
    issue = next(i for i in run.issues if i.code == "malformed_line")
    assert issue.message.startswith("12x:")
    assert "+7 more" in issue.message


# -- query ids and document ids ---------------------------------------------------------


def test_a_doc_id_that_is_not_in_the_corpus_is_an_error(tmp_path):
    run = _run(tmp_path, GOOD, known_doc_ids={"CWE-307", "CAPEC-49"})
    issue = next(i for i in run.issues if i.code == "unknown_doc")
    assert issue.severity == ERROR
    assert "T1110" in issue.message


def test_doc_ids_are_not_checked_without_a_corpus(tmp_path):
    assert "unknown_doc" not in _codes(_run(tmp_path, GOOD).issues)


def test_a_question_missing_from_the_run_is_a_warning(tmp_path):
    run = _run(tmp_path, GOOD, known_query_ids={"q1", "q2", "q3"})
    issue = next(i for i in run.issues if i.code == "missing_query")
    assert issue.severity == WARNING and "q3" in issue.message
    assert errors(run.issues) == []


def test_a_question_outside_the_qrels_is_a_warning_not_an_error(tmp_path):
    # Scoring a run over all questions against the test split's qrels is normal.
    run = _run(tmp_path, GOOD, known_query_ids={"q1"})
    assert "extra_query" in _codes(run.issues, WARNING)
    assert errors(run.issues) == []


# -- the manifest sidecar ---------------------------------------------------------------


def test_sidecar_paths_append_to_the_run_file_name():
    assert sidecar("runs/sira.trec", ".costs.jsonl") == Path("runs/sira.trec.costs.jsonl")
    assert sidecar("runs/sira.trec", ".manifest.json") == Path("runs/sira.trec.manifest.json")


def test_a_missing_manifest_is_a_warning(tmp_path):
    run = _run(tmp_path, GOOD)
    assert run.manifest is None
    assert "no_manifest" in _codes(run.issues, WARNING)


def test_a_manifest_naming_another_system_is_an_error(tmp_path):
    path = write_module3_run(tmp_path / "run.trec", "sira_cti", {"q1": [("a", 1.0)]}, manifest={"system": "plain_bm25"})
    assert "manifest_system_mismatch" in _codes(read_run(path).issues, ERROR)


def test_a_manifest_without_a_config_hash_is_flagged(tmp_path):
    path = write_module3_run(tmp_path / "run.trec", "sira_cti", {"q1": [("a", 1.0)]}, manifest={"config_hash": None})
    issue = next(i for i in read_run(path).issues if i.code == "manifest_field_missing")
    assert "config_hash" in issue.message


def test_an_unreadable_manifest_is_an_error(tmp_path):
    path = write_module3_run(tmp_path / "run.trec", "sira_cti", {"q1": [("a", 1.0)]})
    sidecar(path, ".manifest.json").write_text("{not json", encoding="utf-8")
    run = read_run(path)
    assert run.manifest is None
    assert "malformed_manifest" in _codes(run.issues, ERROR)


# -- consistency across runs ------------------------------------------------------------


def _two_runs(tmp_path, *, a=None, b=None, b_system="plain_bm25", b_rankings=None):
    rankings = {"q1": [("a", 1.0)], "q2": [("b", 1.0)]}
    first = read_run(write_module3_run(tmp_path / "a.trec", "sira_cti", rankings, manifest=a))
    second = read_run(write_module3_run(tmp_path / "b.trec", b_system, b_rankings or rankings, manifest=b))
    return [first, second]


def test_comparable_runs_raise_no_issue(tmp_path):
    assert check_consistency(_two_runs(tmp_path), config_hash="test-hash") == []


def test_runs_produced_under_different_configs_are_an_error(tmp_path):
    issues = check_consistency(_two_runs(tmp_path, b={"config_hash": "other-hash"}))
    assert "config_hash_mismatch" in _codes(issues, ERROR)


def test_a_config_that_changed_since_the_runs_is_a_warning(tmp_path):
    issues = check_consistency(_two_runs(tmp_path), config_hash="edited-since")
    assert _codes(issues) == {"config_hash_differs_from_eval"}
    assert errors(issues) == []


def test_two_files_for_one_system_are_an_error(tmp_path):
    assert "duplicate_system" in _codes(check_consistency(_two_runs(tmp_path, b_system="sira_cti")), ERROR)


def test_runs_over_different_query_files_or_depths_are_flagged(tmp_path):
    issues = check_consistency(
        _two_runs(tmp_path, b={"queries_path": "queries.dev.jsonl", "settings": {"k": 10}})
    )
    assert {"queries_path_mismatch", "k_mismatch"} <= _codes(issues, WARNING)


def test_runs_covering_different_questions_are_flagged(tmp_path):
    issues = check_consistency(_two_runs(tmp_path, b_rankings={"q1": [("a", 1.0)]}))
    issue = next(i for i in issues if i.code == "query_set_mismatch")
    assert "plain_bm25 lacks 1 question" in issue.message


def test_runs_without_manifests_cannot_be_called_inconsistent(tmp_path):
    runs = [_run(tmp_path, GOOD, name="a.trec"), _run(tmp_path, GOOD.replace("sira_cti", "plain_bm25"), name="b.trec")]
    assert check_consistency(runs, config_hash="test-hash") == []


# -- the boundary with Module 3 ---------------------------------------------------------


def test_the_eval_package_never_imports_module_3():
    # Module 3 lives on an unmerged branch. The harness consumes its
    # documented file formats; importing its classes would make Module 4
    # unrunnable on this branch and unable to score a run made elsewhere.
    importing = re.compile(r"^\s*(?:from|import)\s+(?:\.+|sira_cti\.)retrieval\b", re.MULTILINE)
    for source in Path(sira_cti.eval.__file__).parent.glob("*.py"):
        assert not importing.search(source.read_text(encoding="utf-8")), source.name
    script = Path(sira_cti.eval.__file__).parents[3] / "scripts" / "run_eval.py"
    assert not importing.search(script.read_text(encoding="utf-8"))


def test_issues_serialise_for_the_results_file(tmp_path):
    issue = _run(tmp_path, "").issues[0]
    assert json.loads(json.dumps(issue.to_dict()))["code"] == issue.code
