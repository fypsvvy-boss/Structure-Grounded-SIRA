"""The shared enrichment-record contract.

The invariant tests matter more than they look: four people are writing
against this shape in parallel, and a record that serialises fine but is
internally inconsistent (a rejected term with no reason, a colloquial term
carrying a structural ID) will not fail until Module 4 tries to compute a
rejection rate from it in week 11.
"""

import pytest

from sira_cti.common import (
    EnrichmentRecord,
    ProposedTerm,
    RejectReason,
    Source,
    TermKind,
    TokenUsage,
    read_jsonl,
    write_jsonl,
)


def _structural(term="T1110", accepted=True, reason=None):
    if accepted:
        return ProposedTerm.accept(term, TermKind.STRUCTURAL, structural_id=term, doc_freq=41)
    return ProposedTerm.reject(term, TermKind.STRUCTURAL, reason, structural_id=term)


def test_accepted_term_carries_no_reject_reason():
    term = ProposedTerm.accept("brute force login", TermKind.COLLOQUIAL, doc_freq=412)
    assert term.accepted
    assert term.reject_reason is None
    assert term.graph_validated is None
    assert term.structural_id is None


def test_structural_term_requires_a_structural_id():
    with pytest.raises(ValueError):
        ProposedTerm(term="T1110", kind=TermKind.STRUCTURAL, graph_validated=True, accepted=True)


def test_non_structural_term_must_not_carry_a_structural_id():
    with pytest.raises(ValueError):
        ProposedTerm(
            term="brute force",
            kind=TermKind.COLLOQUIAL,
            structural_id="T1110",
            accepted=True,
        )


def test_rejected_term_must_carry_a_reason():
    with pytest.raises(ValueError):
        ProposedTerm(term="T9999", kind=TermKind.STRUCTURAL, structural_id="T9999",
                     graph_validated=False, accepted=False)


def test_accepted_term_must_not_carry_a_reason():
    with pytest.raises(ValueError):
        ProposedTerm(
            term="brute force",
            kind=TermKind.COLLOQUIAL,
            accepted=True,
            reject_reason=RejectReason.TOO_COMMON,
        )


def test_graph_failure_marks_graph_validated_false():
    term = _structural("T9999", accepted=False, reason=RejectReason.NOT_IN_GRAPH)
    assert term.graph_validated is False


def test_corpus_statistic_failure_keeps_graph_validated_true():
    # The term passed the graph and failed the DF filter. Conflating the two
    # would inflate the RQ4 hallucination rate with terms that were real.
    term = _structural("T1110", accepted=False, reason=RejectReason.TOO_COMMON)
    assert term.graph_validated is True


def test_empty_term_is_rejected():
    with pytest.raises(ValueError):
        ProposedTerm.accept("   ", TermKind.SYMPTOM)


# -- repair (RevokedPolicy="repair" downstream) --------------------------------


def test_repaired_term_is_accepted_and_preserves_the_original_id():
    term = ProposedTerm.repair("t1562/001", structural_id="T1685", repaired_from_id="T1562.001")
    assert term.accepted
    assert term.reject_reason is None
    assert term.graph_validated is True
    assert term.structural_id == "T1685"
    assert term.repaired_from_id == "T1562.001"
    assert term.term == "t1562/001"


def test_repaired_from_id_requires_accepted():
    with pytest.raises(ValueError):
        ProposedTerm(
            term="T1562.001",
            kind=TermKind.STRUCTURAL,
            structural_id="T1685",
            graph_validated=True,
            accepted=False,
            reject_reason=RejectReason.REVOKED,
            repaired_from_id="T1562.001",
        )


def test_repaired_from_id_requires_a_structural_term():
    with pytest.raises(ValueError):
        ProposedTerm(
            term="brute force",
            kind=TermKind.COLLOQUIAL,
            accepted=True,
            repaired_from_id="T1562.001",
        )


def test_repaired_from_id_must_differ_from_structural_id():
    with pytest.raises(ValueError):
        ProposedTerm(
            term="T1562.001",
            kind=TermKind.STRUCTURAL,
            structural_id="T1562.001",
            graph_validated=True,
            accepted=True,
            repaired_from_id="T1562.001",
        )


def _record():
    return EnrichmentRecord(
        doc_id="CVE-2024-12345",
        source=Source.CVE,
        original_text="Authentication bypass in the login endpoint.",
        proposed_terms=[
            ProposedTerm.accept("brute force login", TermKind.COLLOQUIAL, doc_freq=412),
            _structural("T1110.001", accepted=True),
            _structural("T9999", accepted=False, reason=RejectReason.NOT_IN_GRAPH),
            ProposedTerm.reject("attack", TermKind.SYMPTOM, RejectReason.TOO_COMMON, doc_freq=90210),
        ],
        llm_calls=1,
        tokens=TokenUsage(prompt=812, completion=143),
        latency_ms=1904,
        model="qwen2.5:7b",
    )


def test_accepted_and_rejected_views_partition_the_proposals():
    rec = _record()
    assert len(rec.accepted_terms) == 2
    assert len(rec.rejected_terms) == 2
    assert len(rec.accepted_terms) + len(rec.rejected_terms) == len(rec.proposed_terms)


def test_rejected_terms_are_retained_not_dropped():
    # The rejection log *is* the RQ4 dataset — a round trip must not lose it.
    rec = EnrichmentRecord.from_json(_record().to_json())
    reasons = {t.reject_reason for t in rec.rejected_terms}
    assert reasons == {RejectReason.NOT_IN_GRAPH, RejectReason.TOO_COMMON}


def test_rejection_rate_counts_structural_terms_only_by_default():
    rec = _record()
    assert rec.rejection_rate() == pytest.approx(0.5)          # 1 of 2 structural
    assert rec.rejection_rate(structural_only=False) == pytest.approx(0.5)


def test_rejection_rate_is_none_when_nothing_was_proposed():
    rec = EnrichmentRecord(doc_id="q1", source=Source.QUERY, original_text="odd logins")
    assert rec.rejection_rate() is None


def test_staleness_rate_counts_repairs_and_revoked_rejections():
    # 4 structural terms: one clean accept, one repaired, one REVOKED
    # rejection, one NOT_IN_GRAPH rejection (a hallucination, not staleness).
    rec = EnrichmentRecord(
        doc_id="CVE-2024-12345",
        source=Source.CVE,
        original_text="...",
        proposed_terms=[
            _structural("T1110", accepted=True),
            ProposedTerm.repair("t1562/001", structural_id="T1685", repaired_from_id="T1562.001"),
            _structural("T1656", accepted=False, reason=RejectReason.REVOKED),
            _structural("T9999", accepted=False, reason=RejectReason.NOT_IN_GRAPH),
        ],
    )
    assert rec.repaired_terms == [rec.proposed_terms[1]]
    assert rec.staleness_rate() == pytest.approx(0.5)   # 2 of 4 structural terms


def test_staleness_rate_is_none_when_there_are_no_structural_terms():
    rec = EnrichmentRecord(doc_id="q1", source=Source.QUERY, original_text="odd logins")
    assert rec.staleness_rate() is None


def test_expansion_query_uses_accepted_terms_only():
    q_exp = _record().expansion_query()
    assert "brute force login" in q_exp
    assert "T1110.001" in q_exp
    assert "T9999" not in q_exp


def test_json_round_trip_is_lossless():
    original = _record()
    restored = EnrichmentRecord.from_json(original.to_json())
    assert restored.to_dict() == original.to_dict()


def test_jsonl_round_trip(tmp_path):
    path = tmp_path / "enrichment.jsonl"
    written = write_jsonl([_record(), _record()], path)
    assert written == 2
    assert len(list(read_jsonl(path))) == 2


def test_malformed_jsonl_line_reports_its_line_number(tmp_path):
    path = tmp_path / "broken.jsonl"
    path.write_text(_record().to_json() + "\nnot json at all\n", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        list(read_jsonl(path))
    assert ":2:" in str(exc.value)


def test_v1_0_0_records_without_repaired_from_id_load_cleanly():
    # A record written before schema 1.1.0 has no "repaired_from_id" key at
    # all -- from_dict must default it to None, not KeyError, and the record
    # must behave as if nothing was ever repaired.
    d = _record().to_dict()
    d["schema_version"] = "1.0.0"
    for t in d["proposed_terms"]:
        t.pop("repaired_from_id", None)

    rec = EnrichmentRecord.from_dict(d)
    assert rec.schema_version == "1.0.0"
    assert rec.repaired_terms == []
    assert all(t.repaired_from_id is None for t in rec.proposed_terms)


def test_token_usage_adds():
    total = TokenUsage(10, 5) + TokenUsage(1, 2)
    assert (total.prompt, total.completion, total.total) == (11, 7, 18)
