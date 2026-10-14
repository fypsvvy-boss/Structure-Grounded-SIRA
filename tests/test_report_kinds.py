"""Every corpus kind reaches every report, under one translation of its name.

ATT&CK has two fixed names: the corpus_kb file (and config kind) ``mitre``
and the record source ``attack``. Kaggle session 1's end-of-session printout
showed capec, cve and cwe but not attack, although 557 + 519 ATT&CK records
were written: the per-kind block is sorted, ``attack`` comes first, and the
notebook printed only the last 12 lines of the log.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import enrich_corpus  # noqa: E402
import kaggle_stage1 as ks  # noqa: E402
import report_enrichment  # noqa: E402

from sira_cti.common import EnrichmentRecord, Source, write_jsonl  # noqa: E402
from sira_cti.index import KINDS, kind_of_source, source_of_kind  # noqa: E402

RUN_KINDS = ["cwe", "capec", "mitre", "cve"]          # the Stage 1 order
ALL_SOURCES = ["cwe", "capec", "attack", "cve"]
DOC_ID = {"cwe": "CWE-79", "capec": "CAPEC-66", "attack": "T1059", "cve": "CVE-2024-0001"}


def _run_file(path: Path, sources=ALL_SOURCES, kinds=RUN_KINDS) -> Path:
    records = [
        EnrichmentRecord(doc_id=DOC_ID[s], source=Source(s), original_text="x", proposed_terms=[],
                         llm_calls=1, model="m")
        for s in sources
    ]
    write_jsonl(records, path)
    path.with_suffix(path.suffix + ".manifest.json").write_text(json.dumps({"kinds": kinds}))
    return path


@pytest.mark.parametrize("kind", KINDS)
def test_every_kind_round_trips_through_its_source(kind):
    assert kind_of_source(source_of_kind(kind)) == kind


def test_attack_and_mitre_are_the_same_kind():
    assert source_of_kind("mitre") is source_of_kind("attack") is Source.ATTACK
    assert kind_of_source(Source.ATTACK) == kind_of_source("attack") == "mitre"
    with pytest.raises(ValueError):
        source_of_kind("report")


def test_the_session_summary_lists_every_kind_in_run_order(tmp_path):
    lines = enrich_corpus.by_source_lines(_run_file(tmp_path / "run.jsonl"), RUN_KINDS)
    heads = [line.split(":")[0].strip() for line in lines if not line.startswith("    ")]
    assert heads == ALL_SOURCES


def test_a_kind_with_no_records_yet_is_shown_as_zero_not_left_out(tmp_path):
    lines = enrich_corpus.by_source_lines(_run_file(tmp_path / "run.jsonl", sources=["cwe", "cve"]), RUN_KINDS)
    assert "  attack: 0 docs" in lines and "  capec: 0 docs" in lines


def test_the_notebook_prints_the_whole_summary_not_a_fixed_tail(tmp_path):
    """The session 1 bug, end to end: the per-kind block from a real file, inside a log."""
    block = enrich_corpus.by_source_lines(_run_file(tmp_path / "run.jsonl"), RUN_KINDS)
    log = "\n".join(
        ["progress line"] * 30
        + ["", "2329 docs total, 0 already done, 2329 processed, 0 failed, 1 unparseable, 40000.0s",
           "STOPPED AT THE TIME LIMIT (660 min): 670 documents still to do.",
           "", "Accept/reject summary (cumulative, whole file):", "  accepted: 0", "  rejected: 0",
           "", "By source document type:", *block]
    )
    old_tail = "\n".join(log.splitlines()[-12:])                     # what session 1 printed
    assert not all(f"  {source}:" in old_tail for source in ALL_SOURCES)
    shown = "\n".join(ks.summary_block(log))
    assert shown.startswith("2329 docs total")
    for source in ALL_SOURCES:
        assert f"  {source}: 1 docs" in shown


def test_a_log_with_no_summary_falls_back_to_its_tail():
    log = "\n".join(f"line {i}" for i in range(40)) + "\nTraceback: boom"
    assert ks.summary_block(log)[-1] == "Traceback: boom" and len(ks.summary_block(log)) == 12


def test_report_enrichment_counts_and_prints_every_kind(tmp_path):
    path = _run_file(tmp_path / "run.jsonl", sources=["cwe", "attack", "cve"])
    summary = report_enrichment.summarise(path)
    assert summary["docs_by_source"] == {"cwe": 1, "capec": 0, "attack": 1, "cve": 1}
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        report_enrichment._print(summary)
    documents_line = next(line for line in out.getvalue().splitlines() if "documents:" in line)
    for source in ALL_SOURCES:
        assert f"'{source}'" in documents_line


def test_seconds_per_doc_keys_are_kinds_for_every_source(tmp_path):
    assert set(ks.seconds_per_doc_from(_run_file(tmp_path / "run.jsonl"))) == set(RUN_KINDS)
