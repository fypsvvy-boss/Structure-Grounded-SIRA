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


# -- sample_corpus ---------------------------------------------------------------


def _write_kb(tmp_path, kind: str, n: int):
    """A synthetic kb file with ``n`` rows, big enough that a sample and a prefix differ."""
    import json

    id_field = {"cve": "cve_id", "cwe": "cwe_id", "capec": "capec_id", "mitre": "mitre_id"}[kind]
    with (tmp_path / f"{kind}.jsonl").open("w", encoding="utf-8") as fh:
        for i in range(n):
            raw_id = {"cve": f"CVE-2020-{1000 + i}", "cwe": str(100 + i), "capec": str(100 + i), "mitre": f"T{1000 + i}"}[kind]
            fh.write(json.dumps({"id": str(i), id_field: raw_id, "title": f"t{i}", "contents": "{}"}) + "\n")


def test_sample_corpus_takes_per_kind_from_every_kind():
    from sira_cti.index import sample_corpus

    docs = sample_corpus(CORPUS_KB_FIXTURE, per_kind=1, seed=42)
    assert sorted(d.source.value for d in docs) == ["attack", "capec", "cve", "cwe"]


def test_sample_corpus_is_not_a_prefix(tmp_path):
    from sira_cti.index import sample_corpus

    _write_kb(tmp_path, "mitre", 50)
    sampled = [d.doc_id for d in sample_corpus(tmp_path, ["mitre"], per_kind=5, seed=42)]
    prefix = [d.doc_id for d in load_kb(tmp_path, "mitre", limit=5)]
    assert len(sampled) == 5
    assert sampled != prefix


def test_sample_corpus_is_deterministic_for_a_seed_and_changes_with_it(tmp_path):
    from sira_cti.index import sample_corpus

    _write_kb(tmp_path, "mitre", 50)
    a = [d.doc_id for d in sample_corpus(tmp_path, ["mitre"], per_kind=5, seed=42)]
    b = [d.doc_id for d in sample_corpus(tmp_path, ["mitre"], per_kind=5, seed=42)]
    c = [d.doc_id for d in sample_corpus(tmp_path, ["mitre"], per_kind=5, seed=7)]
    assert a == b     # same seed -> same docs, which is what makes a sampled run resumable
    assert a != c


def test_sample_corpus_one_kinds_sample_does_not_depend_on_the_others(tmp_path):
    from sira_cti.index import sample_corpus

    _write_kb(tmp_path, "cve", 50)
    _write_kb(tmp_path, "mitre", 50)
    alone = [d.doc_id for d in sample_corpus(tmp_path, ["mitre"], per_kind=5, seed=42)]
    with_cve = [d.doc_id for d in sample_corpus(tmp_path, ["cve", "mitre"], per_kind=5, seed=42) if d.doc_id.startswith("T")]
    assert alone == with_cve


def test_sample_corpus_keeps_file_order_within_a_kind(tmp_path):
    from sira_cti.index import sample_corpus

    _write_kb(tmp_path, "mitre", 50)
    ids = [int(d.doc_id[1:]) for d in sample_corpus(tmp_path, ["mitre"], per_kind=10, seed=42)]
    assert ids == sorted(ids)


def test_sample_corpus_takes_everything_from_a_small_kind():
    from sira_cti.index import sample_corpus

    docs = sample_corpus(CORPUS_KB_FIXTURE, ["mitre"], per_kind=99, seed=42)
    assert {d.doc_id for d in docs} == {"T1110", "T1110.001"}


def test_sample_corpus_rejects_a_non_positive_per_kind():
    import pytest

    from sira_cti.index import sample_corpus

    with pytest.raises(ValueError):
        sample_corpus(CORPUS_KB_FIXTURE, per_kind=0, seed=42)


# -- choosing the order the document types are processed in ----------------------------


def test_order_kinds_defaults_to_the_configured_order():
    from sira_cti.index import order_kinds

    assert order_kinds(None, ["cve", "cwe", "capec", "mitre"]) == ["cve", "cwe", "capec", "mitre"]


def test_order_kinds_takes_a_comma_separated_order_and_the_attack_alias():
    from sira_cti.index import order_kinds

    configured = ["cve", "cwe", "capec", "mitre"]
    assert order_kinds("cwe,capec,attack,cve", configured) == ["cwe", "capec", "mitre", "cve"]
    assert order_kinds(" CWE , Capec ", configured) == ["cwe", "capec"]          # a subset, untidy input
    assert order_kinds(["mitre", "cve"], configured) == ["mitre", "cve"]


def test_order_kinds_rejects_unknown_repeated_and_empty():
    import pytest

    from sira_cti.index import order_kinds

    configured = ["cve", "cwe", "capec", "mitre"]
    with pytest.raises(ValueError, match="unknown"):
        order_kinds("cwe,reports", configured)
    with pytest.raises(ValueError, match="more than once"):
        order_kinds("cwe,cve,cwe", configured)
    with pytest.raises(ValueError, match="no kinds"):
        order_kinds(" , ", configured)
    with pytest.raises(ValueError, match="unknown"):
        order_kinds("mitre", ["cve", "cwe"])                 # not in *this* config


def test_load_corpus_yields_documents_in_the_requested_kind_order():
    from sira_cti.index import order_kinds

    kinds = order_kinds("cwe,capec,attack,cve", KINDS)
    sources = [d.source for d in load_corpus(CORPUS_KB_FIXTURE, kinds)]
    firsts = list(dict.fromkeys(sources))                    # order of first appearance
    assert firsts == [Source.CWE, Source.CAPEC, Source.ATTACK, Source.CVE]
    assert sorted(d.doc_id for d in load_corpus(CORPUS_KB_FIXTURE, kinds)) == sorted(
        d.doc_id for d in load_corpus(CORPUS_KB_FIXTURE, KINDS)
    )                                                        # same documents, only reordered


# -- sharding (--shard I/N): splitting a run across processes ---------------------------


def test_parse_shard_reads_index_and_count_and_rejects_nonsense():
    import pytest

    from sira_cti.index import parse_shard

    assert parse_shard(None) is None
    assert parse_shard("1/2") == (1, 2)
    assert parse_shard("3/3") == (3, 3)
    for bad in ("0/2", "3/2", "1/0", "1", "a/b", "1/2/3", ""):
        with pytest.raises(ValueError):
            parse_shard(bad)


def test_a_documents_shard_depends_only_on_its_id():
    # Pinned values: if these ever change, two machines running different
    # versions of the code would disagree about whose a document is.
    from sira_cti.index import shard_of

    assert [shard_of(d, 2) for d in ("CVE-2021-44228", "CWE-79", "CAPEC-126", "T1110.001")] == [1, 1, 1, 2]
    assert shard_of("CWE-79", 1) == 1
    assert {shard_of("CWE-79", 5) for _ in range(3)} == {shard_of("CWE-79", 5)}


def test_shards_never_overlap_and_together_miss_nothing():
    from sira_cti.index import shard_corpus

    docs = [CorpusDocument(doc_id=f"CVE-2024-{i}", source=Source.CVE, title="t", text="x") for i in range(300)]
    parts = [[d.doc_id for d in shard_corpus(docs, (i, 3))] for i in (1, 2, 3)]

    assert sorted(sum(parts, [])) == sorted(d.doc_id for d in docs)       # nothing lost, nothing twice
    assert all(60 < len(p) < 140 for p in parts)                          # roughly even
    assert parts[0] == [d for d in (x.doc_id for x in docs) if d in set(parts[0])]   # order kept
    assert [d.doc_id for d in shard_corpus(docs, None)] == [d.doc_id for d in docs]


def test_a_documents_shard_does_not_depend_on_which_kinds_are_selected():
    from sira_cti.index import shard_corpus

    everything = {d.doc_id for d in shard_corpus(load_corpus(CORPUS_KB_FIXTURE), (1, 2))}
    cve_only = {d.doc_id for d in shard_corpus(load_corpus(CORPUS_KB_FIXTURE, ["cve"]), (1, 2))}
    assert cve_only == {d for d in everything if d.startswith("CVE-")}
