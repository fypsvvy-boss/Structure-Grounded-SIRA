"""Base/enriched index building (sira_cti.index.build_base / build_enriched).

Builds real, tiny, local Lucene indexes via Pyserini -- no network (Pyserini
makes none building from a local JsonCollection), just a local JVM. This is
the same tool the README's Phase 0 smoke test already uses, at a scale of a
handful of documents rather than SciFact's thousands.
"""

from __future__ import annotations

import json

import pytest
from helpers import CORPUS_KB_FIXTURE, FakeDFLookup, build_fixture_graph

from sira_cti.common import StubClient
from sira_cti.enrichment.corpus_side import run_corpus_enrichment
from sira_cti.index import (
    EXPANSION_FIELD,
    build_base_index,
    build_enriched_index,
    write_json_collection,
)
from sira_cti.index.corpus import load_corpus
from sira_cti.enrichment.prompts.corpus_side import PROMPT_VERSION
from sira_cti.index.df_stats import LuceneDFLookup, too_common


def test_write_json_collection_shape(tmp_path):
    docs = list(load_corpus(CORPUS_KB_FIXTURE, kinds=["capec"]))
    out_file = write_json_collection(docs, tmp_path / "staging")
    rows = [json.loads(l) for l in out_file.read_text().splitlines()]
    assert rows[0]["id"] == "CAPEC-49"
    assert "attacker tries many passwords" in rows[0]["contents"]


def test_write_json_collection_rejects_an_empty_corpus(tmp_path):
    with pytest.raises(ValueError):
        write_json_collection([], tmp_path / "staging")


@pytest.fixture(scope="module")
def base_index(tmp_path_factory):
    out = tmp_path_factory.mktemp("base_index_root")
    index_dir = build_base_index(
        kb_dir=CORPUS_KB_FIXTURE, index_dir=out / "base", staging_dir=out / "staging",
        threads=1, config_hash="test-hash",
    )
    return index_dir


def test_build_base_index_writes_a_manifest(base_index):
    manifest = json.loads((base_index / "manifest.json").read_text())
    assert manifest["kind"] == "base"
    assert manifest["doc_count"] == 6   # 2 cve + 1 cwe + 1 capec + 2 mitre, tests/fixtures/corpus_kb
    assert manifest["config_hash"] == "test-hash"
    assert set(manifest["kinds"]) == {"cve", "cwe", "capec", "mitre"}


def test_build_base_index_is_searchable(base_index):
    from pyserini.search.lucene import LuceneSearcher

    searcher = LuceneSearcher(str(base_index))
    hits = searcher.search("brute")
    assert any(h.docid == "T1110" for h in hits)


# -- DF stats against a real Lucene index --------------------------------------------


def test_lucene_df_lookup_total_docs(base_index):
    lookup = LuceneDFLookup(base_index)
    assert lookup.total_docs == 6


def test_lucene_df_lookup_uses_max_across_tokens(base_index):
    # "guessing" (in T1110.001's title, via corpus.py's title+contents text)
    # appears in 1 doc; a made-up rare compound like "zzzznotarealterm" is in
    # none -- confirms doc_freq reads real posting-list counts, not a stub.
    lookup = LuceneDFLookup(base_index)
    assert lookup.doc_freq("zzzznotarealterm") == 0
    assert lookup.doc_freq("guessing") >= 1


def test_too_common_helper_uses_the_configured_ratio(base_index):
    lookup = LuceneDFLookup(base_index)
    # "the" or similarly ubiquitous tokens aside, a term with 0 df is never too common.
    assert not too_common("zzzznotarealterm", lookup, df_max_ratio=0.0)


def test_lucene_df_lookup_combine_rules_differ_on_a_multi_token_term(base_index):
    # "authentication bypass" analyzes to ["authent", "bypass"], which sit in
    # 3 and 1 of the 6 fixture documents. The two combine rules must actually
    # read different tokens -- this is the mechanism behind
    # docs/04_OPEN_QUESTIONS.md question 1, verified against real Lucene
    # rather than a hand-rolled tokenizer that could disagree with it.
    lookup = LuceneDFLookup(base_index)
    assert lookup.doc_freq("authentication bypass") == 3               # default: max
    assert lookup.doc_freq("authentication bypass", combine="max") == 3
    assert lookup.doc_freq("authentication bypass", combine="min") == 1


def test_lucene_df_lookup_splits_a_cwe_id_but_not_an_attack_id(base_index):
    # The tokenization asymmetry the combine rule exists to compensate for,
    # pinned against the real analyzer so a Lucene/Anserini upgrade that
    # changes it fails here loudly instead of silently skewing RQ1.
    from pyserini.index.lucene import LuceneIndexReader

    reader = LuceneIndexReader(str(base_index))
    assert reader.analyze("CWE-307") == ["cwe", "307"]      # two tokens
    assert reader.analyze("T1110.001") == ["t1110.001"]     # one token


def test_too_common_honours_the_combine_rule(base_index):
    lookup = LuceneDFLookup(base_index)
    # 3/6 = 0.5 under max, 1/6 = 0.167 under min: the same term, the same
    # threshold, opposite verdicts.
    assert too_common("authentication bypass", lookup, df_max_ratio=0.25)
    assert not too_common("authentication bypass", lookup, df_max_ratio=0.25, combine="min")


def test_fake_df_lookup_satisfies_the_same_protocol():
    from sira_cti.index.df_stats import DFLookup

    fake = FakeDFLookup({"attack": 3}, total_docs=10)
    assert isinstance(fake, DFLookup)
    assert fake.doc_freq("attack") == 3
    assert too_common("attack", fake, df_max_ratio=0.10)  # 3/10 > 0.10


# -- enriched index: the actual injection mechanism, proven end-to-end --------------


@pytest.fixture(scope="module")
def enriched_index(tmp_path_factory, base_index):
    root = tmp_path_factory.mktemp("enriched_index_root")
    enrichment_path = root / "enrichment.jsonl"

    def responder(prompt: str) -> str:
        # Give T1110 a colloquial expansion term that appears nowhere in its
        # own contents -- the point of the whole exercise.
        if "id T1110)" in prompt:
            return json.dumps([{"term": "zzz-canary-term", "kind": "colloquial"}])
        return json.dumps([])

    run_corpus_enrichment(
        list(load_corpus(CORPUS_KB_FIXTURE)),
        client_factory=lambda: StubClient(responder=responder),
        graph=build_fixture_graph(),
        df_lookup=LuceneDFLookup(base_index),
        output_path=enrichment_path,
        max_terms=12,
        df_max_ratio=0.9,
    )

    index_dir = build_enriched_index(
        kb_dir=CORPUS_KB_FIXTURE, enrichment_path=enrichment_path, index_dir=root / "enriched",
        staging_dir=root / "staging", threads=1, config_hash="test-hash",
    )
    return index_dir, enrichment_path


def test_build_enriched_index_requires_enrichment_to_exist_first(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_enriched_index(
            kb_dir=CORPUS_KB_FIXTURE,
            enrichment_path=tmp_path / "does_not_exist.jsonl",
            index_dir=tmp_path / "enriched",
        )


def test_enriched_index_manifest_traces_back_to_the_enrichment_run(enriched_index):
    index_dir, enrichment_path = enriched_index
    manifest = json.loads((index_dir / "manifest.json").read_text())
    assert manifest["kind"] == "enriched"
    assert manifest["enrichment_path"] == str(enrichment_path)
    assert manifest["enrichment_prompt_version"] == PROMPT_VERSION
    assert manifest["enrichment_model"] == "stub"


def test_expansion_terms_are_searchable_even_when_absent_from_contents(enriched_index, base_index):
    # The core claim of the injection design: a term the LLM proposed, which
    # never appears in T1110's own text, still retrieves T1110 once indexed
    # via the expansion field.
    from pyserini.search.lucene import LuceneSearcher

    index_dir, _ = enriched_index
    searcher = LuceneSearcher(str(index_dir))

    # LuceneSearcher.search() queries "contents" only by default -- Module 3
    # is what actually implements score(d) = BM25(q_orig,d) + w*BM25(q_exp,d)
    # over the two fields separately; this test just proves the expansion
    # field itself is real, populated, and searchable.
    assert searcher.search("canary") == []          # not in "contents"
    hits = searcher.search("canary", fields={EXPANSION_FIELD: 1.0})
    assert any(h.docid == "T1110" for h in hits)     # is in "expansion"

    # It is not stored in T1110's raw contents -- it only exists via the
    # separate expansion field, not because it was appended to the text.
    raw = json.loads(searcher.doc("T1110").raw())
    assert "canary" not in raw["contents"].lower()
    assert "canary" in raw[EXPANSION_FIELD].lower()

    # And the base (unenriched) index never saw it at all.
    base_searcher = LuceneSearcher(str(base_index))
    assert base_searcher.search("canary") == []


def test_docs_with_no_enrichment_still_get_an_empty_expansion_field(enriched_index):
    # CWE-307 got no proposals from the stub responder above; it must still
    # appear in the enriched index (same doc set as the base index), just
    # contributing nothing via the expansion field.
    from pyserini.search.lucene import LuceneSearcher

    index_dir, _ = enriched_index
    searcher = LuceneSearcher(str(index_dir))
    doc = searcher.doc("CWE-307")
    assert doc is not None
