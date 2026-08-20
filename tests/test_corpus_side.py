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

from sira_cti.common import RejectReason, Source, StubClient, TermKind, read_jsonl
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
        if "T1110" in prompt:
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
    docs = [_doc(f"T{1100 + i}", text=f"doc {i}") for i in range(6)]

    def responder(prompt: str) -> str:
        # Deterministic, stateless function of the prompt -- safe across threads.
        doc_id = prompt.split("id ")[1].split(")")[0]
        return _reply([{"term": f"term-for-{doc_id}", "kind": "colloquial"}])

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
