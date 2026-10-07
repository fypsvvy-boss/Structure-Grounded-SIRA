"""Module 1's corpus-side enrichment pipeline.

No network, no live LLM: every case drives ``StubClient`` (common/llm.py)
with a canned reply. The graph-validation cases reuse the same mini ATT&CK
fixture (revoked T1004, deprecated T1064, sub-technique T1110.001) the
ontology tests already established, rather than inventing a second one.
"""

from __future__ import annotations

import json

import pytest
from helpers import FakeDFLookup, build_fixture_graph

from sira_cti.common import (
    RejectReason,
    RejectStage,
    Source,
    StubClient,
    TermKind,
    read_jsonl,
)
from sira_cti.enrichment.corpus_side import (
    MalformedReplyError,
    propose_terms,
    run_corpus_enrichment,
    summarize,
)
from sira_cti.enrichment.prompts.corpus_side import PROMPT_VERSION
from sira_cti.graph import RevokedPolicy
from sira_cti.index.corpus import CorpusDocument


def _doc(doc_id="T1110", text="Brute Force techniques against accounts.") -> CorpusDocument:
    return CorpusDocument(doc_id=doc_id, source=Source.ATTACK, title="Brute Force", text=text)


def _reply(payload) -> str:
    return json.dumps(payload)


def _client(payload, **kwargs) -> StubClient:
    return StubClient(responder=lambda _prompt: _reply(payload), **kwargs)


def _df(total_docs: int = 100, **counts) -> FakeDFLookup:
    return FakeDFLookup(counts, total_docs=total_docs)


# -- propose_terms: shape validation --------------------------------------------------


def test_malformed_json_reply_raises_not_an_empty_list():
    client = StubClient(responder=lambda _p: "not json at all, sorry, I refuse")
    with pytest.raises(MalformedReplyError):
        propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)


def test_wrong_top_level_type_raises():
    client = _client({"terms": []})  # a dict, not an array
    with pytest.raises(MalformedReplyError):
        propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)


def test_non_object_item_raises():
    client = _client(["T1110"])
    with pytest.raises(MalformedReplyError):
        propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)


def test_missing_term_field_raises():
    client = _client([{"kind": "colloquial"}])
    with pytest.raises(MalformedReplyError):
        propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)


def test_unrecognised_kind_raises():
    client = _client([{"term": "brute force", "kind": "vibes"}])
    with pytest.raises(MalformedReplyError):
        propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)


def test_genuinely_empty_reply_is_not_malformed():
    client = _client([])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)
    assert terms == []


def test_json_wrapped_in_a_code_fence_still_parses():
    # parse_json_loose (llm.py) is reused, not reimplemented -- prove it's
    # actually wired in, not bypassed.
    client = StubClient(responder=lambda _p: "```json\n" + _reply([{"term": "x", "kind": "colloquial"}]) + "\n```")
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)
    assert len(terms) == 1 and terms[0].accepted


def test_max_terms_per_doc_truncates_the_reply():
    payload = [{"term": f"term{i}", "kind": "colloquial"} for i in range(5)]
    client = _client(payload)
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=2, df_max_ratio=0.9)
    assert len(terms) == 2


# -- graph validation gate --------------------------------------------------------------


def test_non_structural_terms_are_accepted_without_graph_involvement():
    client = _client([{"term": "brute force login", "kind": "colloquial"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)
    assert terms[0].accepted
    assert terms[0].structural_id is None
    assert terms[0].graph_validated is None


def test_valid_structural_term_is_accepted_and_canonicalised():
    client = _client([{"term": "t1110/001", "kind": "structural"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)
    assert terms[0].accepted
    assert terms[0].structural_id == "T1110.001"
    assert terms[0].graph_validated is True


def test_hallucinated_structural_id_is_rejected_and_kept():
    client = _client([{"term": "T9999", "kind": "structural"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)
    assert len(terms) == 1
    assert not terms[0].accepted
    assert terms[0].reject_reason is RejectReason.NOT_IN_GRAPH
    assert terms[0].graph_validated is False


def test_deprecated_structural_id_is_rejected_with_its_own_reason():
    client = _client([{"term": "T1064", "kind": "structural"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)
    assert terms[0].reject_reason is RejectReason.DEPRECATED


def test_revoked_structural_id_is_rejected_with_its_own_reason():
    client = _client([{"term": "T1004", "kind": "structural"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)
    assert terms[0].reject_reason is RejectReason.REVOKED


def test_revoked_policy_repair_records_the_pre_repair_id():
    client = _client([{"term": "T1004", "kind": "structural"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5,
        revoked_policy=RevokedPolicy.REPAIR,
    )
    assert terms[0].accepted
    assert terms[0].structural_id == "T1547.004"
    assert terms[0].repaired_from_id == "T1004"


def test_malformed_structural_id_is_rejected_without_reaching_the_graph():
    client = _client([{"term": "T99", "kind": "structural"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)
    assert terms[0].reject_reason is RejectReason.MALFORMED_ID


# -- DF gate ------------------------------------------------------------------------


def test_too_common_term_is_rejected_and_records_doc_freq():
    client = _client([{"term": "attack", "kind": "colloquial"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(total_docs=100, attack=50), max_terms=12, df_max_ratio=0.10)
    assert not terms[0].accepted
    assert terms[0].reject_reason is RejectReason.TOO_COMMON
    assert terms[0].doc_freq == 50


def test_df_ratio_exactly_at_the_threshold_is_not_too_common():
    client = _client([{"term": "attack", "kind": "colloquial"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(total_docs=100, attack=10), max_terms=12, df_max_ratio=0.10)
    assert terms[0].accepted


def test_df_ratio_just_over_the_threshold_is_too_common():
    client = _client([{"term": "attack", "kind": "colloquial"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(total_docs=100, attack=11), max_terms=12, df_max_ratio=0.10)
    assert not terms[0].accepted


def test_structural_term_rejected_as_too_common_keeps_graph_validated_true():
    # It passed the graph and failed only the DF filter -- a different RQ4
    # finding from a hallucination, and must stay distinguishable.
    client = _client([{"term": "T1110", "kind": "structural"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(total_docs=100, t1110=50), max_terms=12, df_max_ratio=0.10)
    assert terms[0].reject_reason is RejectReason.TOO_COMMON
    assert terms[0].graph_validated is True


# -- run_corpus_enrichment: resumability, writing, failures -------------------------


def test_run_writes_one_record_per_doc_with_rejects_kept(tmp_path):
    docs = [_doc("T1110", "Brute Force"), _doc("CWE-307", "Improper Restriction")]
    out = tmp_path / "enrichment.jsonl"

    def responder(prompt: str) -> str:
        if "Brute Force" in prompt:   # keyed on text: corpus-v3 prompts carry no doc id
            return _reply([{"term": "T1110", "kind": "structural"}, {"term": "T9999", "kind": "structural"}])
        return _reply([{"term": "auth bypass", "kind": "colloquial"}])

    summary = run_corpus_enrichment(
        docs,
        client_factory=lambda: StubClient(responder=responder),
        graph=build_fixture_graph(),
        df_lookup=_df(),
        output_path=out,
        max_terms=12,
        df_max_ratio=0.9,
    )
    assert summary.processed == 2 and summary.failed == 0

    records = {r.doc_id: r for r in read_jsonl(out)}
    assert set(records) == {"T1110", "CWE-307"}
    t1110_terms = {t.structural_id: t.accepted for t in records["T1110"].proposed_terms}
    assert t1110_terms == {"T1110": True, "T9999": False}


def test_rejected_terms_survive_into_the_written_jsonl(tmp_path):
    doc = _doc("T1110")
    client = StubClient(responder=lambda _p: _reply([{"term": "T9999", "kind": "structural"}]))
    out = tmp_path / "enrichment.jsonl"

    run_corpus_enrichment(
        [doc], client_factory=lambda: client, graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9,
    )
    rec = next(read_jsonl(out))
    assert len(rec.rejected_terms) == 1
    assert rec.rejected_terms[0].reject_reason is RejectReason.NOT_IN_GRAPH


def test_malformed_reply_is_not_written_and_is_logged_as_a_failure(tmp_path):
    doc = _doc("T1110")
    client = StubClient(responder=lambda _p: "not json")
    out = tmp_path / "enrichment.jsonl"

    summary = run_corpus_enrichment(
        [doc], client_factory=lambda: client, graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9,
    )
    assert summary.processed == 0
    assert summary.failed == 1
    assert not out.exists()  # nothing written -- never a fake empty-proposals record
    failures_path = out.with_suffix(out.suffix + ".failures.jsonl")
    assert failures_path.exists()
    entries = [json.loads(l) for l in failures_path.read_text().splitlines()]
    assert entries[0]["doc_id"] == "T1110"


def test_resume_after_crash_retries_only_the_undone_doc(tmp_path):
    docs = [_doc("T1110"), _doc("CWE-307")]
    out = tmp_path / "enrichment.jsonl"

    # First run: the first LLM call fails outright (0 retries), the second succeeds.
    flaky = StubClient(
        responder=lambda _p: _reply([{"term": "x", "kind": "colloquial"}]),
        fail_times=1, max_retries=0, retry_backoff_s=0,
    )
    first = run_corpus_enrichment(
        docs, client_factory=lambda: flaky, graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9,
    )
    assert first.processed == 1 and first.failed == 1
    assert {r.doc_id for r in read_jsonl(out)} == {"CWE-307"}

    # Second run: fresh, working client. Must not re-do CWE-307.
    healthy = StubClient(responder=lambda _p: _reply([{"term": "y", "kind": "colloquial"}]))
    second = run_corpus_enrichment(
        docs, client_factory=lambda: healthy, graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9,
    )
    assert second.already_done == 1
    assert second.processed == 1 and second.failed == 0
    assert {r.doc_id for r in read_jsonl(out)} == {"T1110", "CWE-307"}


def test_dry_run_processes_but_writes_nothing(tmp_path):
    doc = _doc("T1110")
    client = StubClient(responder=lambda _p: _reply([{"term": "x", "kind": "colloquial"}]))
    out = tmp_path / "enrichment.jsonl"

    seen = []
    summary = run_corpus_enrichment(
        [doc], client_factory=lambda: client, graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9, dry_run=True, on_record=seen.append,
    )
    assert summary.processed == 1
    assert not out.exists()
    assert len(seen) == 1 and seen[0].doc_id == "T1110"


def test_manifest_records_prompt_version_model_and_config_hash(tmp_path):
    doc = _doc("T1110")
    client = StubClient(model="qwen-test", responder=lambda _p: _reply([]))
    out = tmp_path / "enrichment.jsonl"

    run_corpus_enrichment(
        [doc], client_factory=lambda: client, graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9, config_hash="deadbeef1234",
        corpus_kinds=["mitre"],
    )
    manifest = json.loads(out.with_suffix(out.suffix + ".manifest.json").read_text())
    assert manifest["prompt_version"] == PROMPT_VERSION   # records it; not pinned to a literal
    assert manifest["model"] == "qwen-test"
    assert manifest["config_hash"] == "deadbeef1234"
    assert manifest["kinds"] == ["mitre"]


def test_concurrency_processes_every_doc_exactly_once_without_cross_talk(tmp_path):
    docs = [_doc(f"T{1100 + i}", text=f"doc number {i}") for i in range(6)]

    def responder(prompt: str) -> str:
        # Deterministic, stateless function of the prompt -- safe across threads.
        # Keyed on the document text: since corpus-v3 the prompt no longer
        # carries the doc id.
        i = int(prompt.split("doc number ")[1].split()[0])
        return _reply([{"term": f"term-for-T{1100 + i}", "kind": "colloquial"}])

    out = tmp_path / "enrichment.jsonl"
    summary = run_corpus_enrichment(
        docs,
        client_factory=lambda: StubClient(responder=responder),
        graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9, concurrency=3,
    )
    assert summary.processed == 6
    records = {r.doc_id: r for r in read_jsonl(out)}
    assert len(records) == 6
    for doc in docs:
        rec = records[doc.doc_id]
        assert rec.proposed_terms[0].term == f"term-for-{doc.doc_id}"


# -- summarize ------------------------------------------------------------------------


def test_summarize_breaks_down_rejections_by_reason_and_counts_repairs(tmp_path):
    doc = _doc("T1110")
    payload = [
        {"term": "T1110", "kind": "structural"},       # accepted
        {"term": "T9999", "kind": "structural"},        # not_in_graph
        {"term": "T1064", "kind": "structural"},        # deprecated
        {"term": "T1004", "kind": "structural"},        # revoked (reject policy)
    ]
    client = StubClient(responder=lambda _p: _reply(payload))
    out = tmp_path / "enrichment.jsonl"

    run_corpus_enrichment(
        [doc], client_factory=lambda: client, graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9,
    )
    result = summarize(out)
    assert result["accepted"] == 1
    assert result["rejected"] == 3
    assert result["rejected_by_reason"] == {"not_in_graph": 1, "deprecated": 1, "revoked": 1}
    assert result["staleness_rate"] == pytest.approx(0.25)  # 1 REVOKED of 4 structural terms


def test_summarize_staleness_rate_counts_repairs_too(tmp_path):
    doc = _doc("T1110")
    client = StubClient(responder=lambda _p: _reply([{"term": "T1004", "kind": "structural"}]))
    out = tmp_path / "enrichment.jsonl"

    run_corpus_enrichment(
        [doc], client_factory=lambda: client, graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9, revoked_policy=RevokedPolicy.REPAIR,
    )
    result = summarize(out)
    assert result["repaired"] == 1
    assert result["staleness_rate"] == pytest.approx(1.0)


def test_summarize_returns_none_staleness_rate_with_no_structural_terms(tmp_path):
    doc = _doc("T1110")
    client = StubClient(responder=lambda _p: _reply([{"term": "brute force", "kind": "colloquial"}]))
    out = tmp_path / "enrichment.jsonl"

    run_corpus_enrichment(
        [doc], client_factory=lambda: client, graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9,
    )
    assert summarize(out)["staleness_rate"] is None


# -- kind routing: a mislabelled "structural" is not a hallucination -----------------


def test_mislabelled_structural_is_rerouted_and_judged_on_its_merits():
    # zzip_get32 is a real zziplib symbol the model tagged kind="structural"
    # in the first real Qwen run. It never reached for an identifier, so it
    # must not be booked as MALFORMED_ID -- and with DF 0 it is maximally
    # discriminative, exactly the vocabulary enrichment exists to add.
    client = _client([{"term": "zzip_get32", "kind": "structural"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(total_docs=100), max_terms=12, df_max_ratio=0.10)
    assert terms[0].accepted
    assert terms[0].reject_reason is None
    assert terms[0].kind is not TermKind.STRUCTURAL
    assert terms[0].structural_id is None
    assert terms[0].graph_validated is None


def test_mislabelled_structural_still_faces_the_df_gate():
    # Re-routing is not an amnesty: a common word rejected as TOO_COMMON is a
    # different RQ4 fact from a hallucinated identifier, and both differ from
    # an accept.
    client = _client([{"term": "medium", "kind": "structural"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(total_docs=100, medium=50), max_terms=12, df_max_ratio=0.10
    )
    assert terms[0].reject_reason is RejectReason.TOO_COMMON
    assert terms[0].kind is not TermKind.STRUCTURAL


def test_a_botched_identifier_is_still_malformed_id():
    # The RQ4 signal we actually want: the model aimed at an identifier and
    # missed. Re-routing must not swallow this.
    for term in ("CWE-abc", "T99"):
        client = _client([{"term": term, "kind": "structural"}])
        terms = propose_terms(_doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5)
        assert terms[0].reject_reason is RejectReason.MALFORMED_ID, term
        assert terms[0].kind is TermKind.STRUCTURAL, term


def test_kind_routing_only_demotes_never_promotes():
    # A valid id labelled "colloquial" stays colloquial: promoting it would
    # put an unvalidated identifier into the structural pool and silently
    # change what RQ4's denominator counts.
    client = _client([{"term": "T1110", "kind": "colloquial"}])
    terms = propose_terms(_doc(), client, build_fixture_graph(), _df(total_docs=100), max_terms=12, df_max_ratio=0.10)
    assert terms[0].kind is TermKind.COLLOQUIAL
    assert terms[0].structural_id is None


# -- DF gate: structural ids are judged on their rarest token ------------------------


def test_structural_id_is_not_rejected_for_its_namespace_prefix():
    # Regression for docs/04_OPEN_QUESTIONS.md question 1. Under the old
    # max-across-tokens rule "CWE-307" was scored as DF("cwe"), a constant
    # shared by every identifier in the catalogue -- measured at 2974/6044 =
    # 0.492 on the real base index, so *every* CWE was rejected regardless of
    # which one it was, while one-token ATT&CK ids bypassed the gate entirely.
    client = _client([{"term": "CWE-307", "kind": "structural"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(total_docs=100, cwe=50, **{"307": 2}),
        max_terms=12, df_max_ratio=0.10,
    )
    assert terms[0].accepted
    assert terms[0].doc_freq == 2          # the number, not the namespace prefix
    assert terms[0].graph_validated is True


def test_a_genuinely_common_structural_id_is_still_too_common():
    # The gate still bites -- an identifier whose own number is everywhere is
    # undiscriminative and must fail, or the fix would be an exemption.
    client = _client([{"term": "CWE-307", "kind": "structural"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(total_docs=100, cwe=50, **{"307": 40}),
        max_terms=12, df_max_ratio=0.10,
    )
    assert terms[0].reject_reason is RejectReason.TOO_COMMON
    assert terms[0].doc_freq == 40


def test_ordinary_phrases_still_judged_by_their_most_common_word():
    # The min rule is scoped to structural ids only. "remote attacker" is
    # undiscriminative because of "attacker", however rare "remote" is.
    client = _client([{"term": "remote attacker", "kind": "colloquial"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(total_docs=100, remote=2, attacker=60),
        max_terms=12, df_max_ratio=0.10,
    )
    assert terms[0].reject_reason is RejectReason.TOO_COMMON
    assert terms[0].doc_freq == 60


# -- sampling provenance + per-source summary ------------------------------------------


def test_manifest_records_how_the_documents_were_sampled(tmp_path):
    out = tmp_path / "enrichment.jsonl"
    run_corpus_enrichment(
        [_doc("T1110")], client_factory=lambda: StubClient(responder=lambda _p: _reply([])),
        graph=build_fixture_graph(), df_lookup=_df(), output_path=out, max_terms=12, df_max_ratio=0.9,
        sampling={"method": "per_kind", "per_kind": 10, "seed": 42},
    )
    manifest = json.loads(out.with_suffix(out.suffix + ".manifest.json").read_text())
    assert manifest["sampling"] == {"method": "per_kind", "per_kind": 10, "seed": 42}


def test_summarize_by_source_splits_counts_by_document_type_and_catalogue(tmp_path):
    from sira_cti.enrichment.corpus_side import summarize_by_source

    cve_doc = CorpusDocument(doc_id="CVE-2024-1", source=Source.CVE, title="x", text="cve record text")
    attack_doc = _doc("T1110")

    def responder(prompt: str) -> str:
        if "cve record text" in prompt:   # keyed on text: corpus-v3 prompts carry no doc id
            return _reply([
                {"term": "CWE-307", "kind": "structural"},
                {"term": "T9999", "kind": "structural"},
                {"term": "CVE-2017-5974", "kind": "structural"},
            ])
        return _reply([{"term": "CAPEC-49", "kind": "structural"}, {"term": "spraying", "kind": "colloquial"}])

    out = tmp_path / "enrichment.jsonl"
    run_corpus_enrichment(
        [cve_doc, attack_doc], client_factory=lambda: StubClient(responder=responder),
        graph=build_fixture_graph(), df_lookup=_df(), output_path=out, max_terms=12, df_max_ratio=0.9,
    )
    by_source = summarize_by_source(out)

    assert set(by_source) == {"cve", "attack"}
    cve = by_source["cve"]
    assert cve["docs"] == 1 and cve["proposed"] == 3 and cve["accepted"] == 1
    assert cve["structural_proposed_by_namespace"] == {"cwe": 1, "attack": 1, "other": 1}
    assert cve["structural_accepted_by_namespace"] == {"cwe": 1}
    assert cve["rejected_by_reason"] == {"not_in_graph": 1, "malformed_id": 1}

    attack = by_source["attack"]
    assert attack["structural_proposed_by_namespace"] == {"capec": 1}
    assert attack["accepted"] == 2


def test_prompt_does_not_give_the_model_the_documents_own_id():
    # corpus-v3: with the id in the header, every structural id proposed on a
    # CWE/ATT&CK entry was that entry's own id copied back. Decision 2 in
    # docs/proposals/already-in-document-gate.md.
    from sira_cti.enrichment.prompts.corpus_side import build_prompt

    doc = CorpusDocument(doc_id="CWE-1321", source=Source.CWE, title="Prototype Pollution", text="Prototype Pollution {}")
    prompt = build_prompt(doc, max_terms=12)
    assert "CWE-1321" not in prompt
    assert "1321" not in prompt
    assert "Prototype Pollution" in prompt


# == name-ID consistency: the new stage 2 ============================================
#
# The finding that motivates all of this: on 2026-10-07 qwen2.5:14b proposed
# CWE-73 through CWE-81 for CWE-512 "Spyware" and the graph accepted all nine,
# because each id exists. Existence is nearly free in a dense integer
# namespace. These tests cover the check that is not.


def test_a_structural_proposal_can_carry_the_name_the_model_claims():
    client = _client([{"term": "T1110.001", "kind": "structural", "name": "Password Guessing"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5,
        name_match_min_overlap=0.5,
    )
    assert terms[0].accepted
    assert terms[0].claimed_name == "Password Guessing"
    assert terms[0].official_name == "Password Guessing"


def test_a_real_id_with_the_wrong_claimed_name_is_rejected_as_name_mismatch():
    client = _client([{"term": "T1110.001", "kind": "structural", "name": "Spyware"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5,
        name_match_min_overlap=0.5,
    )
    assert terms[0].accepted is False
    assert terms[0].reject_reason is RejectReason.NAME_MISMATCH
    assert terms[0].rejected_at_stage is RejectStage.NAME
    # It passed the graph. Saying otherwise would merge this with hallucination.
    assert terms[0].graph_validated is True
    assert terms[0].claimed_name == "Spyware"
    assert terms[0].official_name == "Password Guessing"


def test_a_structural_proposal_with_no_claimed_name_is_a_name_mismatch():
    # Not a parse error: the document is kept, the proposal is rejected with a
    # reason, and the whole thing stays in the RQ4 dataset.
    client = _client([{"term": "T1110.001", "kind": "structural"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5,
        name_match_min_overlap=0.5,
    )
    assert terms[0].reject_reason is RejectReason.NAME_MISMATCH
    assert terms[0].claimed_name is None


def test_the_name_check_is_off_by_default_so_corpus_v3_stays_reproducible():
    client = _client([{"term": "T1110.001", "kind": "structural", "name": "Spyware"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5,
    )
    assert terms[0].accepted is True
    assert terms[0].claimed_name == "Spyware"   # recorded, just not adjudicated


def test_a_hallucinated_id_fails_at_the_graph_stage_not_the_name_stage():
    # Stage order matters: an id that does not exist has no official title, so
    # checking the name first would report every hallucination as a name
    # mismatch and merge the two most distinct RQ4 findings.
    client = _client([{"term": "T9999", "kind": "structural", "name": "Totally Real"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5,
        name_match_min_overlap=0.5,
    )
    assert terms[0].reject_reason is RejectReason.NOT_IN_GRAPH
    assert terms[0].rejected_at_stage is RejectStage.GRAPH
    assert terms[0].official_name is None


def test_the_name_check_runs_before_the_df_gate():
    client = _client([{"term": "T1110.001", "kind": "structural", "name": "Spyware"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(),
        _df(total_docs=100, **{"t1110.001": 99}),       # also wildly too common
        max_terms=12, df_max_ratio=0.1, name_match_min_overlap=0.5,
    )
    assert terms[0].reject_reason is RejectReason.NAME_MISMATCH
    assert terms[0].doc_freq is None      # never reached the DF lookup


def test_the_name_survives_a_too_common_rejection():
    client = _client([{"term": "T1110.001", "kind": "structural", "name": "Password Guessing"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(),
        _df(total_docs=100, **{"t1110.001": 99}),
        max_terms=12, df_max_ratio=0.1, name_match_min_overlap=0.5,
    )
    assert terms[0].reject_reason is RejectReason.TOO_COMMON
    assert terms[0].claimed_name == "Password Guessing"
    assert terms[0].official_name == "Password Guessing"


def test_id_is_accepted_as_a_synonym_for_term():
    # A model told to emit an identifier and a title writes {"id", "name"}
    # often enough that rejecting the document would bias the loss towards
    # exactly the structural proposals this experiment is about.
    client = _client([{"id": "T1110.001", "kind": "structural", "name": "Password Guessing"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5,
        name_match_min_overlap=0.5,
    )
    assert terms[0].accepted
    assert terms[0].term == "T1110.001"


def test_a_name_on_a_non_structural_term_is_not_recorded():
    client = _client([{"term": "brute force login", "kind": "colloquial", "name": "whatever"}])
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5,
        name_match_min_overlap=0.5,
    )
    assert terms[0].accepted
    assert terms[0].claimed_name is None


# == counting-run detection: measurement only ========================================


def test_three_consecutive_ids_are_flagged_as_a_counting_run():
    g = build_fixture_graph()
    client = _client([
        {"term": "CWE-307", "kind": "structural", "name": "Improper Restriction of Excessive Authentication Attempts"},
        {"term": "CWE-308", "kind": "structural", "name": "Whatever"},
        {"term": "CWE-309", "kind": "structural", "name": "Whatever"},
    ])
    terms = propose_terms(_doc(), client, g, _df(), max_terms=12, df_max_ratio=0.5)
    assert [t.in_counting_run for t in terms] == [True, True, True]


def test_two_consecutive_ids_are_not_a_counting_run():
    # Real sibling sub-techniques come in short consecutive pairs. Flagging
    # those would make the measurement useless.
    g = build_fixture_graph()
    client = _client([
        {"term": "T1110.001", "kind": "structural", "name": "Password Guessing"},
        {"term": "T1110.002", "kind": "structural", "name": "Password Spraying"},
    ])
    terms = propose_terms(_doc(), client, g, _df(), max_terms=12, df_max_ratio=0.5)
    assert [t.in_counting_run for t in terms] == [False, False]


def test_a_counting_run_flag_never_changes_the_verdict():
    # The whole point: this is measurement. CWE-307 is valid and must stay
    # accepted even though it sits in a run.
    g = build_fixture_graph()
    client = _client([
        {"term": "CWE-307", "kind": "structural", "name": "Improper Restriction of Excessive Authentication Attempts"},
        {"term": "CWE-308", "kind": "structural", "name": "x"},
        {"term": "CWE-309", "kind": "structural", "name": "x"},
    ])
    terms = propose_terms(_doc(), client, g, _df(), max_terms=12, df_max_ratio=0.5)
    accepted = {t.structural_id for t in terms if t.accepted}
    assert "CWE-307" in accepted
    assert terms[0].in_counting_run is True


def test_rejected_ids_are_part_of_the_run_they_belong_to():
    # The invented tail (T1056.005+) is the most informative part of a run.
    # Dropping rejects would show every run stopping where the graph caught it.
    g = build_fixture_graph()
    client = _client([
        {"term": "T1110.001", "kind": "structural", "name": "Password Guessing"},
        {"term": "T1110.002", "kind": "structural", "name": "Password Spraying"},
        {"term": "T1110.003", "kind": "structural", "name": "Nope"},   # not in the fixture
    ])
    terms = propose_terms(_doc(), client, g, _df(), max_terms=12, df_max_ratio=0.5)
    assert all(t.in_counting_run for t in terms)
    assert terms[2].accepted is False


def test_sub_techniques_of_different_parents_are_not_neighbours():
    # T1110.001 and T1547.001 share a number but belong to different series.
    g = build_fixture_graph()
    client = _client([
        {"term": "T1110.001", "kind": "structural", "name": "Password Guessing"},
        {"term": "T1547.004", "kind": "structural", "name": "Winlogon Helper DLL"},
    ])
    terms = propose_terms(_doc(), client, g, _df(), max_terms=12, df_max_ratio=0.5)
    assert [t.in_counting_run for t in terms] == [False, False]


def test_non_structural_terms_are_never_in_a_counting_run():
    g = build_fixture_graph()
    client = _client([{"term": f"phrase {i}", "kind": "colloquial"} for i in range(5)])
    terms = propose_terms(_doc(), client, g, _df(), max_terms=12, df_max_ratio=0.5)
    assert not any(t.in_counting_run for t in terms)


# == ontology distance: reported, never filtered on ==================================


def test_graph_distance_is_measured_from_the_documents_own_node():
    g = build_fixture_graph()
    client = _client([
        {"term": "T1110.001", "kind": "structural", "name": "Password Guessing"},
        {"term": "brute force login", "kind": "colloquial"},
    ])
    terms = propose_terms(
        _doc(doc_id="T1110"), client, g, _df(), max_terms=12, df_max_ratio=0.5
    )
    assert terms[0].graph_distance == 1          # sub-technique of the document
    assert terms[1].graph_distance is None       # not a structural term


def test_graph_distance_is_zero_for_the_documents_own_id():
    g = build_fixture_graph()
    client = _client([{"term": "T1110", "kind": "structural", "name": "Brute Force"}])
    terms = propose_terms(_doc(doc_id="T1110"), client, g, _df(), max_terms=12, df_max_ratio=0.5)
    assert terms[0].graph_distance == 0


def test_graph_distance_is_none_for_a_document_that_is_not_an_ontology_node():
    # Every CVE. "Not measurable" must not be readable as "unrelated".
    g = build_fixture_graph()
    client = _client([{"term": "T1110.001", "kind": "structural", "name": "Password Guessing"}])
    doc = CorpusDocument(
        doc_id="CVE-2024-0001", source=Source.CVE, title="x", text="a buffer overflow"
    )
    terms = propose_terms(doc, client, g, _df(), max_terms=12, df_max_ratio=0.5)
    assert terms[0].graph_distance is None
    assert terms[0].accepted is True             # distance never vetoes


def test_a_far_away_id_is_still_accepted():
    # Enrichment exists to add links the entry's own data lacks, so the
    # distant ids include the ones that would justify the method. Filtering on
    # distance would reject exactly those.
    g = build_fixture_graph()
    client = _client([{"term": "CWE-620", "kind": "structural", "name": "Unverified Password Change"}])
    terms = propose_terms(
        _doc(doc_id="T1110"), client, g, _df(), max_terms=12, df_max_ratio=0.5,
        name_match_min_overlap=0.5,
    )
    assert terms[0].accepted is True


# == an unparseable reply, recorded rather than retried forever ======================
#
# CAPEC-587 broke the 2026-10-07 14B run: the model emitted an array with one
# element's opening brace missing. At temperature 0 the identical prompt
# returns the identical reply, so leaving the document unwritten meant it could
# never be finished and the run could never reach "all done".


def test_a_parse_failure_is_retried_with_a_nudge():
    replies = ["not json at all", _reply([{"term": "brute force login", "kind": "colloquial"}])]
    seen: list[str] = []

    def responder(prompt: str) -> str:
        seen.append(prompt)
        return replies[min(len(seen) - 1, len(replies) - 1)]

    client = StubClient(responder=responder)
    terms = propose_terms(
        _doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5,
        json_retries=1,
    )
    assert [t.term for t in terms] == ["brute force login"]
    # The retry has to change the prompt. A bare retry at temperature 0 would
    # return the same bytes, so it could only ever fail again.
    assert seen[0] != seen[1]
    assert "could not be parsed" in seen[1]


def test_a_parse_failure_that_survives_the_nudge_still_raises():
    client = StubClient(responder=lambda _p: "still not json")
    with pytest.raises(MalformedReplyError) as excinfo:
        propose_terms(
            _doc(), client, build_fixture_graph(), _df(), max_terms=12, df_max_ratio=0.5,
            json_retries=1,
        )
    assert excinfo.value.raw == "still not json"   # the evidence, kept


def test_an_unparseable_document_can_be_recorded_as_a_permanent_failure(tmp_path):
    out = tmp_path / "enrichment.jsonl"
    summary = run_corpus_enrichment(
        [_doc("T1110")], client_factory=lambda: StubClient(responder=lambda _p: "nope"),
        graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9,
        record_json_failures=True,
    )
    assert summary.json_failures == 1
    assert summary.failed == 0          # it is finished, not outstanding
    assert summary.processed == 1

    rec = next(read_jsonl(out))
    assert rec.doc_id == "T1110"
    assert len(rec.rejected_terms) == 1
    assert rec.rejected_terms[0].reject_reason is RejectReason.LLM_JSON_ERROR
    assert rec.rejected_terms[0].rejected_at_stage is RejectStage.PARSE
    assert rec.accepted_terms == []     # nothing can reach the index from it
    assert "nope" in rec.rejected_terms[0].term    # the raw reply is the evidence


def test_a_recorded_failure_lets_a_resume_reach_all_done(tmp_path):
    out = tmp_path / "enrichment.jsonl"
    docs = [_doc("T1110"), _doc("T1547", text="Boot or Logon Autostart Execution.")]

    def factory():
        return StubClient(
            responder=lambda p: "nope" if "Brute Force" in p else _reply(
                [{"term": "autostart", "kind": "colloquial"}]
            )
        )

    kwargs = dict(
        client_factory=factory, graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9, record_json_failures=True,
    )
    run_corpus_enrichment(docs, **kwargs)
    again = run_corpus_enrichment(docs, **kwargs)
    assert again.already_done == 2
    assert again.processed == 0          # nothing left to retry


def test_the_raw_unparseable_reply_is_saved_in_full_beside_the_run(tmp_path):
    out = tmp_path / "enrichment.jsonl"
    long_reply = "[" + "x" * 500
    run_corpus_enrichment(
        [_doc("T1110")], client_factory=lambda: StubClient(responder=lambda _p: long_reply),
        graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9, record_json_failures=True,
    )
    raw_path = out.with_suffix(out.suffix + ".raw_failures.jsonl")
    saved = json.loads(raw_path.read_text().strip())
    assert saved["doc_id"] == "T1110"
    assert saved["raw"] == long_reply            # not the 200-char term snippet
    assert saved["raw_chars"] == len(long_reply)
    assert saved["truncated_by_token_cap"] is False


def test_recording_failures_is_off_by_default(tmp_path):
    # A transient failure (dropped connection, model still loading) should be
    # retried next run, not written off. Only determinism justifies writing it.
    out = tmp_path / "enrichment.jsonl"
    summary = run_corpus_enrichment(
        [_doc("T1110")], client_factory=lambda: StubClient(responder=lambda _p: "nope"),
        graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9,
    )
    assert summary.json_failures == 1
    assert summary.failed == 1
    assert not out.exists()


def test_the_manifest_records_which_gates_were_on(tmp_path):
    out = tmp_path / "enrichment.jsonl"
    run_corpus_enrichment(
        [_doc("T1110")],
        client_factory=lambda: _client([{"term": "brute force login", "kind": "colloquial"}]),
        graph=build_fixture_graph(), df_lookup=_df(),
        output_path=out, max_terms=12, df_max_ratio=0.9,
        name_match_min_overlap=0.5, json_retries=1, record_json_failures=True,
        max_new_tokens=512, json_mode="schema",
    )
    manifest = json.loads(out.with_suffix(out.suffix + ".manifest.json").read_text())
    assert manifest["gates"]["name_match_min_overlap"] == 0.5
    assert manifest["gates"]["max_new_tokens"] == 512
    assert manifest["gates"]["json_mode"] == "schema"
    assert manifest["gates"]["record_json_failures"] is True
