"""The CTIConnect adapter (``sira_cti.eval.cticonnect``).

Runs against the hand-written miniature under ``tests/fixtures/cticonnect/qa``
-- no clone of CTIConnect, no network. The fixture's gold ids point at the
entries of ``tests/fixtures/corpus_kb``, except ``rcm-002``, whose gold
weaknesses are deliberately absent from that corpus.
"""

from __future__ import annotations

import json

import pytest
from eval_helpers import QA_FIXTURE, fixture_doc_ids

from sira_cti.eval.cticonnect import (
    BLOCKED_EVAL_TYPE,
    BLOCKED_NO_GOLD,
    BLOCKED_SYNTHESIS,
    canonical_doc_id,
    load_qa,
    read_metadata,
    read_qrels,
    split_dev_test,
    write_benchmark,
    QAItem,
)


def _by_id(bench):
    return {item.query_id: item for item in bench.items}


def _write_rows(root, rows, *, category="entity_linking", task="rcm"):
    path = root / category / f"{task}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return root


def _row(**overrides):
    row = {
        "id": "rcm-001", "task": "rcm", "category": "entity_linking", "eval_type": "single_id_match",
        "question": "Which weakness?", "ground_truth": {"target_type": "cwe", "target_id": "CWE-307"},
        "source": {"source_type": "cve", "source_id": "CVE-2024-12345"},
    }
    row.update(overrides)
    return row


# -- loading ----------------------------------------------------------------------------


def test_load_qa_reads_every_task_file():
    bench = load_qa(QA_FIXTURE)
    assert sorted(i.query_id for i in bench.items) == [
        "ata-001", "ata-002", "atd-001", "esd-001", "rcm-001", "rcm-002", "vca-001", "wim-001",
    ]


def test_query_row_is_exactly_the_shape_module_3_reads():
    # docs/05_MODULE3_STATE.md: the runner reads JSONL {"id", "query"}.
    item = _by_id(load_qa(QA_FIXTURE))["rcm-001"]
    assert item.query_row() == {"id": "rcm-001", "query": item.query}
    assert item.query.startswith("Which weakness is the root cause")


def test_task_category_and_eval_type_are_preserved():
    items = _by_id(load_qa(QA_FIXTURE))
    assert (items["rcm-001"].task, items["rcm-001"].category, items["rcm-001"].eval_type) == (
        "rcm", "entity_linking", "single_id_match",
    )
    assert (items["ata-001"].task, items["ata-001"].category, items["ata-001"].eval_type) == (
        "ata", "entity_attribution", "id_set_match",
    )
    assert (items["rcm-001"].source_type, items["rcm-001"].source_id) == ("cve", "CVE-2024-12345")


def test_gold_ids_are_canonicalised_to_the_index_convention():
    items = _by_id(load_qa(QA_FIXTURE))
    assert items["esd-001"].gold_ids == ("CAPEC-49",)                # written "49"
    assert items["rcm-002"].gold_ids == ("CWE-120", "CWE-787")       # "120" + valid_target_ids, deduped
    assert items["atd-001"].gold_ids == ("T1110", "T1110.001")       # target_id repeated in valid_target_ids
    assert items["ata-001"].gold_ids == ("T1110.001", "T1110")       # target_id given as a list


def test_gold_ids_match_real_corpus_doc_ids():
    # The point of canonicalising: a gold id has to be spelled exactly like
    # the doc id sira_cti.index.corpus gives the entry it names.
    corpus = fixture_doc_ids()
    for item in load_qa(QA_FIXTURE).items:
        if item.query_id != "rcm-002":
            assert set(item.gold_ids) <= corpus, item.query_id


def test_canonical_doc_id_rules():
    assert canonical_doc_id("cwe", "307") == "CWE-307"
    assert canonical_doc_id("cwe", "CWE-307") == "CWE-307"
    assert canonical_doc_id("capec", "49") == "CAPEC-49"
    assert canonical_doc_id("cve", "2024-12345") == "CVE-2024-12345"
    assert canonical_doc_id("attack", "1110.001") == "T1110.001"
    assert canonical_doc_id("mitre", "T1110") == "T1110"
    assert canonical_doc_id("attack", "G0016") == "G0016"       # not a technique: no "T" invented for it
    assert canonical_doc_id("something_else", "X-1") == "X-1"   # unknown type: left as written


def test_synthesis_questions_are_blocked_not_scored():
    bench = load_qa(QA_FIXTURE)
    assert {(b.query_id, b.task, b.reason) for b in bench.blocked} == {
        ("csc-001", "csc", BLOCKED_SYNTHESIS),
        ("tap-001", "tap", BLOCKED_SYNTHESIS),
    }
    assert not {"csc-001", "tap-001"} & {i.query_id for i in bench.items}


def test_synthesis_is_blocked_even_if_a_row_carries_a_target(tmp_path):
    # No metric is defined for these tasks; a target id on the row must not
    # quietly turn one into a scored retrieval question.
    root = _write_rows(tmp_path, [_row(id="csc-9", task="csc", category="multi_doc_synthesis")],
                       category="multi_doc_synthesis", task="csc")
    bench = load_qa(root)
    assert bench.items == []
    assert bench.blocked[0].reason == BLOCKED_SYNTHESIS


def test_an_unrecognised_eval_type_is_blocked_not_guessed(tmp_path):
    bench = load_qa(_write_rows(tmp_path, [_row(eval_type="fuzzy_match")]))
    assert bench.items == []
    assert bench.blocked[0].reason == BLOCKED_EVAL_TYPE


def test_a_row_without_a_gold_target_is_blocked(tmp_path):
    bench = load_qa(_write_rows(tmp_path, [_row(ground_truth={"target_type": "cwe"})]))
    assert bench.items == []
    assert bench.blocked[0].reason == BLOCKED_NO_GOLD


def test_task_and_category_default_to_the_file_location(tmp_path):
    row = _row()
    del row["task"], row["category"]
    item = load_qa(_write_rows(tmp_path, [row], category="entity_linking", task="wim")).items[0]
    assert (item.task, item.category) == ("wim", "entity_linking")


def test_a_scoreable_row_without_question_text_raises_with_its_location(tmp_path):
    with pytest.raises(ValueError) as exc:
        load_qa(_write_rows(tmp_path, [_row(), _row(id="rcm-002", question="  ")]))
    assert "rcm.jsonl:2" in str(exc.value)


def test_malformed_json_raises_with_its_location(tmp_path):
    path = tmp_path / "entity_linking" / "rcm.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_row()) + "\n{not json\n", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        load_qa(tmp_path)
    assert "rcm.jsonl:2" in str(exc.value)


def test_duplicate_question_ids_raise(tmp_path):
    with pytest.raises(ValueError, match="duplicate question id"):
        load_qa(_write_rows(tmp_path, [_row(), _row()]))


def test_an_id_with_whitespace_raises(tmp_path):
    # It would split into two columns in a TREC run or qrels file.
    with pytest.raises(ValueError, match="whitespace"):
        load_qa(_write_rows(tmp_path, [_row(id="rcm 001")]))


def test_an_empty_directory_raises():
    with pytest.raises(FileNotFoundError):
        load_qa(QA_FIXTURE / "entity_linking")   # holds .jsonl files, but no <category>/ level


# -- dev/test split ---------------------------------------------------------------------


def _items(task: str, n: int) -> list[QAItem]:
    return [
        QAItem(query_id=f"{task}-{i:03d}", query="q", task=task, category="c", eval_type="single_id_match",
               gold_ids=("CWE-1",))
        for i in range(n)
    ]


def test_split_is_deterministic_for_a_seed_and_changes_with_it():
    items = _items("rcm", 50)
    a = split_dev_test(items, seed=42)
    assert a == split_dev_test(items, seed=42)
    assert a != split_dev_test(items, seed=7)


def test_split_is_stratified_by_task():
    assignment = split_dev_test(_items("rcm", 50) + _items("ata", 10), seed=42, dev_fraction=0.2)
    dev = [q for q, s in assignment.items() if s == "dev"]
    assert sum(q.startswith("rcm") for q in dev) == 10
    assert sum(q.startswith("ata") for q in dev) == 2
    assert set(assignment.values()) == {"dev", "test"}
    assert len(assignment) == 60


def test_a_tasks_split_does_not_depend_on_other_tasks_or_on_row_order():
    rcm = _items("rcm", 50)
    alone = split_dev_test(rcm, seed=42)
    with_others = split_dev_test(_items("ata", 30) + list(reversed(rcm)), seed=42)
    assert all(with_others[q] == s for q, s in alone.items())


def test_split_extremes_and_bad_fraction():
    items = _items("rcm", 10)
    assert set(split_dev_test(items, seed=42, dev_fraction=0.0).values()) == {"test"}
    assert set(split_dev_test(items, seed=42, dev_fraction=1.0).values()) == {"dev"}
    with pytest.raises(ValueError):
        split_dev_test(items, seed=42, dev_fraction=1.5)


# -- written files ----------------------------------------------------------------------


def test_write_benchmark_writes_queries_qrels_metadata_and_manifest(tmp_path):
    bench = load_qa(QA_FIXTURE)
    manifest = write_benchmark(bench, tmp_path, seed=42, dev_fraction=0.5, qa_dir=QA_FIXTURE, config_hash="test-hash")

    rows = [json.loads(l) for l in (tmp_path / "queries.all.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [set(r) for r in rows] == [{"id", "query"}] * 8

    qrels = read_qrels(tmp_path / "qrels.all.trec")
    assert qrels["rcm-001"] == {"CWE-307": 1}
    assert qrels["atd-001"] == {"T1110": 1, "T1110.001": 1}
    assert "csc-001" not in qrels

    assert manifest["questions"]["all"] == 8
    assert manifest["questions_by_task"]["all"] == {"ata": 2, "atd": 1, "esd": 1, "rcm": 2, "vca": 1, "wim": 1}
    assert manifest["questions_by_category"] == {"entity_attribution": 3, "entity_linking": 5}
    assert manifest["multi_gold_questions"] == 3
    assert manifest["blocked"] == 2
    assert manifest["blocked_by_reason"] == {BLOCKED_SYNTHESIS: 2}
    assert manifest["blocked_by_task"] == {"csc": 1, "tap": 1}
    assert (manifest["seed"], manifest["dev_fraction"], manifest["config_hash"]) == (42, 0.5, "test-hash")
    assert manifest["cticonnect_manifest"]["snapshot_date"] == "2025-09-01"
    assert json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))["kind"] == "cticonnect_eval"

    blocked = [json.loads(l) for l in (tmp_path / "blocked.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {b["id"] for b in blocked} == {"csc-001", "tap-001"}


def test_dev_and_test_files_partition_the_questions(tmp_path):
    manifest = write_benchmark(load_qa(QA_FIXTURE), tmp_path, seed=42, dev_fraction=0.5)
    dev, test, everything = (read_qrels(tmp_path / f"qrels.{s}.trec") for s in ("dev", "test", "all"))
    assert not dev.keys() & test.keys()
    assert dev.keys() | test.keys() == everything.keys()
    assert manifest["questions"]["dev"] + manifest["questions"]["test"] == 8
    # Half of each task, rounding half up: rcm 1 of 2, ata 1 of 2, and each of
    # the four single-question tasks gives its one question.
    assert manifest["questions"]["dev"] == 6
    metadata = read_metadata(tmp_path / "metadata.jsonl")
    assert {q for q, row in metadata.items() if row["split"] == "dev"} == set(dev)
    assert metadata["rcm-001"]["task"] == "rcm" and metadata["rcm-001"]["gold_ids"] == ["CWE-307"]


def test_gold_ids_missing_from_the_corpus_are_reported_but_stay_in_the_qrels(tmp_path):
    manifest = write_benchmark(load_qa(QA_FIXTURE), tmp_path, seed=42, known_doc_ids=fixture_doc_ids())
    assert manifest["gold_not_in_corpus"] == [
        {"id": "rcm-002", "gold_id": "CWE-120"},
        {"id": "rcm-002", "gold_id": "CWE-787"},
    ]
    # Dropping an unreachable gold entry would raise every system's recall.
    assert read_qrels(tmp_path / "qrels.all.trec")["rcm-002"] == {"CWE-120": 1, "CWE-787": 1}


def test_gold_check_is_recorded_as_not_done_when_no_corpus_is_given(tmp_path):
    assert write_benchmark(load_qa(QA_FIXTURE), tmp_path, seed=42)["gold_not_in_corpus"] is None


def test_read_qrels_rejects_malformed_and_duplicate_lines(tmp_path):
    path = tmp_path / "qrels.trec"
    path.write_text("q1 0 CWE-307\n", encoding="utf-8")
    with pytest.raises(ValueError, match="4 columns"):
        read_qrels(path)
    path.write_text("q1 0 CWE-307 yes\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not an integer"):
        read_qrels(path)
    path.write_text("q1 0 CWE-307 1\nq1 0 CWE-307 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        read_qrels(path)
