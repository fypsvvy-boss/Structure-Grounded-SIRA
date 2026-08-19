"""The corpus_kb loader (``sira_cti.index.corpus``)."""

from helpers import CORPUS_KB_FIXTURE

from sira_cti.common import Source
from sira_cti.index import KINDS, CorpusDocument, load_corpus, load_kb


def test_load_kb_canonicalises_ids_like_cticonnects_own_baselines():
    docs = list(load_kb(CORPUS_KB_FIXTURE, "cwe"))
    assert docs[0].doc_id == "CWE-307"

    docs = list(load_kb(CORPUS_KB_FIXTURE, "capec"))
    assert docs[0].doc_id == "CAPEC-49"

    docs = list(load_kb(CORPUS_KB_FIXTURE, "cve"))
    assert docs[0].doc_id == "CVE-2024-12345"

    docs = list(load_kb(CORPUS_KB_FIXTURE, "mitre"))
    assert [d.doc_id for d in docs] == ["T1110", "T1110.001"]


def test_load_kb_assigns_the_matching_source():
    assert list(load_kb(CORPUS_KB_FIXTURE, "cve"))[0].source is Source.CVE
    assert list(load_kb(CORPUS_KB_FIXTURE, "cwe"))[0].source is Source.CWE
    assert list(load_kb(CORPUS_KB_FIXTURE, "capec"))[0].source is Source.CAPEC
    assert list(load_kb(CORPUS_KB_FIXTURE, "mitre"))[0].source is Source.ATTACK


def test_text_is_title_and_contents_concatenated():
    doc = list(load_kb(CORPUS_KB_FIXTURE, "capec"))[0]
    assert doc.title == "Password Brute Forcing"
    assert doc.title in doc.text
    assert "attacker tries many passwords" in doc.text


def test_load_kb_rejects_an_unknown_kind():
    import pytest

    with pytest.raises(ValueError):
        list(load_kb(CORPUS_KB_FIXTURE, "bogus"))


def test_load_kb_limit_caps_this_kind_only():
    docs = list(load_kb(CORPUS_KB_FIXTURE, "cve", limit=1))
    assert len(docs) == 1


def test_load_corpus_streams_every_kind_by_default():
    docs = list(load_corpus(CORPUS_KB_FIXTURE))
    ids = {d.doc_id for d in docs}
    assert {"CVE-2024-12345", "CWE-307", "CAPEC-49", "T1110", "T1110.001"} <= ids
    # every kind actually contributed something
    assert len(docs) == sum(1 for _ in load_corpus(CORPUS_KB_FIXTURE, KINDS))


def test_load_corpus_can_be_restricted_to_specific_kinds():
    docs = list(load_corpus(CORPUS_KB_FIXTURE, kinds=["mitre"]))
    assert {d.doc_id for d in docs} == {"T1110", "T1110.001"}


def test_load_corpus_limit_caps_the_total_across_kinds():
    docs = list(load_corpus(CORPUS_KB_FIXTURE, limit=3))
    assert len(docs) == 3


def test_corpus_document_is_a_plain_frozen_record():
    doc = CorpusDocument(doc_id="T1110", source=Source.ATTACK, title="Brute Force", text="Brute Force ...")
    assert doc.doc_id == "T1110"
