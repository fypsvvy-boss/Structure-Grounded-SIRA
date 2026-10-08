"""The enrichment audit (``sira_cti.eval.audit``).

The rejection log is the RQ4 dataset, and there are three different
"rejection rates" one can read off it. The main fixture below is built so
all three come out different, which is the only way to show the code is not
mixing them up.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from sira_cti.common import (
    EnrichmentRecord,
    ProposedTerm,
    RejectReason,
    Source,
    TermKind,
    write_jsonl,
)
from sira_cti.common import schemas
from sira_cti.eval.audit import (
    CORPUS_STAT_REASONS,
    GRAPH_REASONS,
    audit_file,
    audit_records,
    catalogue_of,
    classify_reason,
)

S, C = TermKind.STRUCTURAL, TermKind.COLLOQUIAL


def _records():
    """Two records, twelve proposals.

    CVE record, model 7b (6 terms, 3 structural):
        colloquial  "password spraying"   accepted
        symptom     "attack"              rejected  too_common
        structural  CWE-307               accepted
        structural  T9999                 rejected  not_in_graph   <- graph
        structural  CWE-79                rejected  too_common     <- passed the graph
        colloquial  "lockout"             accepted

    ATT&CK record, model 14b (6 terms, 5 structural):
        structural  T1004                 rejected  revoked        <- graph
        structural  T1064                 rejected  deprecated     <- graph
        structural  CWE-abc               rejected  malformed_id   <- graph
        structural  t1562/001 -> T1685    accepted, repaired
        structural  CAPEC-49              accepted
        product     "windows"             rejected  too_common
    """
    cve = EnrichmentRecord(
        doc_id="CVE-2024-12345", source=Source.CVE, original_text="...", model="qwen2.5:7b",
        proposed_terms=[
            ProposedTerm.accept("password spraying", C),
            ProposedTerm.reject("attack", TermKind.SYMPTOM, RejectReason.TOO_COMMON, doc_freq=3989),
            ProposedTerm.accept("CWE-307", S, structural_id="CWE-307"),
            ProposedTerm.reject("T9999", S, RejectReason.NOT_IN_GRAPH, structural_id="T9999"),
            ProposedTerm.reject("CWE-79", S, RejectReason.TOO_COMMON, structural_id="CWE-79", doc_freq=900),
            ProposedTerm.accept("lockout", C),
        ],
    )
    attack = EnrichmentRecord(
        doc_id="T1110", source=Source.ATTACK, original_text="...", model="qwen2.5:14b",
        proposed_terms=[
            ProposedTerm.reject("T1004", S, RejectReason.REVOKED, structural_id="T1004"),
            ProposedTerm.reject("T1064", S, RejectReason.DEPRECATED, structural_id="T1064"),
            ProposedTerm.reject("CWE-abc", S, RejectReason.MALFORMED_ID),
            ProposedTerm.repair("t1562/001", structural_id="T1685", repaired_from_id="T1562.001"),
            ProposedTerm.accept("CAPEC-49", S, structural_id="CAPEC-49"),
            ProposedTerm.reject("windows", TermKind.PRODUCT, RejectReason.TOO_COMMON, doc_freq=2000),
        ],
    )
    return [cve, attack]


# -- classification ---------------------------------------------------------------------


def test_every_current_reject_reason_is_a_graph_or_a_corpus_statistics_failure():
    for reason in RejectReason:
        assert classify_reason(reason) in ("graph", "corpus_stats"), reason


def test_the_graph_reasons_match_the_frozen_contract():
    # schemas.py decides which reasons mean "the graph said no" (it sets
    # graph_validated from them). The audit keeps its own copy by value so a
    # new enum member needs no edit here -- this pins the two together.
    assert GRAPH_REASONS == {r.value for r in schemas._GRAPH_FAILURES}
    assert not GRAPH_REASONS & CORPUS_STAT_REASONS


def test_too_common_is_not_a_graph_failure():
    assert classify_reason(RejectReason.TOO_COMMON) == "corpus_stats"
    assert classify_reason("not_in_index") == "corpus_stats"
    assert classify_reason(RejectReason.NOT_IN_GRAPH) == "graph"
    assert classify_reason(None) is None


def test_a_reason_the_schema_does_not_have_yet_gets_its_own_bucket():
    # docs/proposals/already-in-document-gate.md proposes a seventh reason.
    # It is neither a graph failure nor a DF failure and must not be folded
    # into either.
    assert classify_reason("already_in_document") == "other"


def test_catalogue_of_a_structural_term():
    assert catalogue_of(ProposedTerm.accept("T1110.001", S, structural_id="T1110.001")) == "attack"
    assert catalogue_of(ProposedTerm.accept("CWE-307", S, structural_id="CWE-307")) == "cwe"
    assert catalogue_of(ProposedTerm.accept("CAPEC-49", S, structural_id="CAPEC-49")) == "capec"
    assert catalogue_of(ProposedTerm.reject("CWE-abc", S, RejectReason.MALFORMED_ID)) == "other"


# -- the three rates --------------------------------------------------------------------


def test_overall_counts_by_reason():
    out = audit_records(_records())
    assert (out["records"], out["proposed"], out["accepted"], out["rejected"]) == (2, 12, 5, 7)
    assert out["rejected_by_reason"] == {
        "deprecated": 1, "malformed_id": 1, "not_in_graph": 1, "revoked": 1, "too_common": 3,
    }
    assert out["rejected_by_class"] == {"graph": 4, "corpus_stats": 3, "other": 0}


def test_graph_failures_are_separated_from_df_failures():
    s = audit_records(_records())["structural"]
    assert (s["proposed"], s["accepted"], s["repaired"]) == (8, 3, 1)
    assert s["graph_rejected"] == 4
    assert s["graph_rejected_by_reason"] == {"deprecated": 1, "malformed_id": 1, "not_in_graph": 1, "revoked": 1}
    assert s["corpus_stats_rejected"] == 1
    assert s["corpus_stats_rejected_by_reason"] == {"too_common": 1}       # CWE-79: valid id, too common
    assert s["other_rejected"] == 0


def test_the_three_rejection_rates_are_three_different_numbers():
    out = audit_records(_records())
    s = out["structural"]
    assert out["total_rejection_rate"] == pytest.approx(7 / 12)       # every term, every reason
    assert s["structural_rejection_rate"] == pytest.approx(5 / 8)     # structural terms, every reason
    assert s["graph_rejection_rate"] == pytest.approx(4 / 8)          # structural terms the GRAPH refused
    assert len({out["total_rejection_rate"], s["structural_rejection_rate"], s["graph_rejection_rate"]}) == 3


def test_record_rejection_rate_is_the_structural_rate_not_the_graph_rate():
    # EnrichmentRecord.rejection_rate() counts CWE-79 (too_common) as a
    # rejection. Reporting it as "graph-validation rejection rate" would
    # overstate what the graph caught: 2 of 3 by that method, 1 of 3 in truth.
    cve = _records()[0]
    s = audit_records([cve])["structural"]
    assert cve.rejection_rate() == pytest.approx(2 / 3)
    assert s["structural_rejection_rate"] == pytest.approx(cve.rejection_rate())
    assert s["graph_rejection_rate"] == pytest.approx(1 / 3)


def test_hallucination_and_staleness_are_reported_apart():
    s = audit_records(_records())["structural"]
    assert s["hallucination_rate"] == pytest.approx(1 / 8)      # T9999 only: never existed
    assert s["staleness_rate"] == pytest.approx(2 / 8)          # T1004 revoked + one repaired
    # ... and staleness agrees with the frozen contract's own definition.
    assert audit_records([_records()[1]])["structural"]["staleness_rate"] == pytest.approx(
        _records()[1].staleness_rate()
    )


def test_rates_are_none_when_nothing_was_proposed():
    empty = EnrichmentRecord(doc_id="q1", source=Source.QUERY, original_text="odd logins", model="m")
    out = audit_records([empty])
    assert out["records"] == 1 and out["records_without_proposals"] == 1
    assert out["total_rejection_rate"] is None
    assert out["structural"]["graph_rejection_rate"] is None
    assert audit_records([])["total_rejection_rate"] is None


def test_a_run_with_no_structural_terms_has_no_graph_rate():
    rec = EnrichmentRecord(
        doc_id="CVE-1", source=Source.CVE, original_text="...", model="m",
        proposed_terms=[ProposedTerm.reject("attack", C, RejectReason.TOO_COMMON)],
    )
    out = audit_records([rec])
    assert out["total_rejection_rate"] == 1.0
    assert out["structural"]["graph_rejection_rate"] is None     # not 0.0: the graph was never asked


# -- breakdowns -------------------------------------------------------------------------


def test_breakdown_by_source_type():
    by_source = audit_records(_records())["by_source"]
    assert set(by_source) == {"attack", "cve"}
    assert (by_source["cve"]["records"], by_source["cve"]["proposed"], by_source["cve"]["accepted"]) == (1, 6, 3)
    assert by_source["cve"]["structural"]["graph_rejection_rate"] == pytest.approx(1 / 3)
    assert by_source["attack"]["structural"]["graph_rejection_rate"] == pytest.approx(3 / 5)
    assert by_source["attack"]["rejected_by_reason"] == {
        "deprecated": 1, "malformed_id": 1, "revoked": 1, "too_common": 1,
    }


def test_breakdown_by_model():
    by_model = audit_records(_records())["by_model"]
    assert set(by_model) == {"qwen2.5:14b", "qwen2.5:7b"}
    assert by_model["qwen2.5:7b"]["structural"]["proposed"] == 3
    assert by_model["qwen2.5:14b"]["structural"]["proposed"] == 5
    assert by_model["qwen2.5:14b"]["structural"]["graph_rejected"] == 3


def test_breakdown_by_catalogue_counts_structural_terms_only():
    by_cat = audit_records(_records())["by_catalogue"]
    # attack: T9999, T1004, T1064, T1685 (repaired).  cwe: CWE-307, CWE-79.
    # capec: CAPEC-49.  other: "CWE-abc", which is not an identifier.
    assert {k: v["proposed"] for k, v in by_cat.items()} == {"attack": 4, "capec": 1, "cwe": 2, "other": 1}
    assert sum(v["proposed"] for v in by_cat.values()) == audit_records(_records())["structural"]["proposed"]
    assert by_cat["attack"]["structural"]["graph_rejected"] == 3
    assert by_cat["cwe"]["structural"]["corpus_stats_rejected"] == 1
    assert by_cat["cwe"]["structural"]["graph_rejected"] == 0


def test_a_source_whose_records_proposed_nothing_still_appears():
    empty = EnrichmentRecord(doc_id="CAPEC-1", source=Source.CAPEC, original_text="...", model="qwen2.5:7b")
    by_source = audit_records(_records() + [empty])["by_source"]
    assert by_source["capec"]["records"] == 1
    assert by_source["capec"]["proposed"] == 0
    assert by_source["capec"]["total_rejection_rate"] is None


def test_a_seventh_reject_reason_needs_no_code_change():
    # The frozen schema cannot build this term yet, so stand in for the
    # record shape. When already_in_document is added to RejectReason, this
    # is what the audit will see.
    def term(accepted, reason=None):
        return SimpleNamespace(
            kind=S, accepted=accepted, structural_id="CWE-79", repaired_from_id=None,
            reject_reason=SimpleNamespace(value=reason) if reason else None,
        )

    record = SimpleNamespace(
        source=Source.CVE, model="m",
        proposed_terms=[term(True), term(False, "already_in_document"), term(False, "not_in_graph"), term(False, "too_common")],
    )
    out = audit_records([record])
    s = out["structural"]
    assert out["rejected_by_class"] == {"graph": 1, "corpus_stats": 1, "other": 1}
    assert s["other_rejected_by_reason"] == {"already_in_document": 1}
    assert s["graph_rejection_rate"] == pytest.approx(1 / 4)      # the copy is not a graph failure
    assert s["structural_rejection_rate"] == pytest.approx(3 / 4)


# -- from a file ------------------------------------------------------------------------


def test_audit_file_reads_an_enrichment_jsonl(tmp_path):
    path = tmp_path / "corpus.jsonl"
    write_jsonl(_records(), path)
    out = audit_file(path)
    assert out["path"] == str(path)
    assert out["proposed"] == 12
    assert out["structural"]["graph_rejection_rate"] == pytest.approx(0.5)
    assert out["caveats"]          # what the numbers cannot show travels with them
