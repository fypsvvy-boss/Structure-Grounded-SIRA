"""Splicing re-enriched documents into a full run (``scripts/splice_enrichment.py``)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import splice_enrichment as sp  # noqa: E402
from sira_cti.common import EnrichmentRecord, RejectReason, Source  # noqa: E402
from sira_cti.index.corpus import CorpusDocument  # noqa: E402

NEW_HASH = "06e891b2b957"


def _term(term, accepted=True, reason=None):
    return {"term": term, "kind": "colloquial", "structural_id": None, "graph_validated": None, "doc_freq": 3,
            "accepted": accepted, "reject_reason": reason}


def _rec(doc_id, text, terms):
    return {"doc_id": doc_id, "source": "cve", "original_text": text, "proposed_terms": terms, "llm_calls": 1,
            "tokens": {"prompt": 10, "completion": 5, "thinking": 0}, "latency_ms": 1, "model": "m",
            "schema_version": "1.5.0"}


FULL = {"method": "prefix", "limit": None}


def _manifest(config_hash, **extra):
    m = {"config_hash": config_hash, "model": "m", "model_digest": "d", "prompt_version": "corpus-v4",
         "sampling": FULL, "kinds": ["cve"], "gates": {"name_scorer": "v2", "df_max_ratio": 0.1},
         "llm": {"backend": "ollama", "temperature": 0}, "code": {"code_commit": config_hash},
         "usage": {"llm_calls": 1}}
    m.update(extra)
    return m


def _write(path, records, manifest, sidecar=None):
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")
    path.with_suffix(path.suffix + ".manifest.json").write_text(json.dumps(manifest))
    if sidecar:
        path.with_suffix(path.suffix + ".raw_failures.jsonl").write_text(
            "".join(json.dumps({"doc_id": d, "error": "x"}) + "\n" for d in sidecar))
    return path


CORPUS = {
    "CVE-1": CorpusDocument("CVE-1", Source.CVE, "CVE-1", "CVE-1 real text"),
    "CVE-2": CorpusDocument("CVE-2", Source.CVE, "CVE-2", 'CVE-2 {"descriptions": [{"value": "now filled"}]}'),
    "CVE-3": CorpusDocument("CVE-3", Source.CVE, "CVE-3", "CVE-3 ünchanged"),
}


def _files(tmp_path, *, new_records=None, new_manifest=None, old_sidecar=None, new_sidecar=None):
    old = _write(tmp_path / "old.jsonl", [
        _rec("CVE-1", "CVE-1 real text", [_term("auth bypass")]),
        _rec("CVE-2", "CVE-2 null", [_term("zero day")]),
        _rec("CVE-3", "CVE-3 ünchanged", [_term("rce", False, "too_common")]),
    ], _manifest("364d30da6c75"), sidecar=old_sidecar)
    new = _write(tmp_path / "new.jsonl", new_records if new_records is not None else [
        _rec("CVE-2", CORPUS["CVE-2"].text, [_term("use after free")]),
    ], new_manifest or _manifest(NEW_HASH, sampling={"method": "ids", "ids": ["CVE-2"]}, kinds=["cve"]),
       sidecar=new_sidecar)
    return old, new


def _same(rec, gates):
    return rec


def _run(tmp_path, old, new, corpus=CORPUS, readjudicate=_same, config_hash=NEW_HASH):
    return sp.splice(old, new, tmp_path / "out.jsonl", corpus=corpus, current_config_hash=config_hash,
                     readjudicate=readjudicate, reason="test")


def test_changed_documents_are_replaced_in_place_and_the_rest_copied_byte_for_byte(tmp_path):
    old, new = _files(tmp_path)

    manifest = _run(tmp_path, old, new)

    old_lines = old.read_text(encoding="utf-8").splitlines()
    out_lines = (tmp_path / "out.jsonl").read_text(encoding="utf-8").splitlines()
    assert out_lines[0] == old_lines[0] and out_lines[2] == old_lines[2]
    assert out_lines[1] == new.read_text(encoding="utf-8").splitlines()[0]
    s = manifest["spliced"]
    assert s["carried"]["records"] == 2 and s["new"]["doc_ids"] == ["CVE-2"]
    assert s["carried"]["manifest"]["config_hash"] == "364d30da6c75"
    assert manifest["config_hash"] == NEW_HASH
    assert s["carried"]["verdicts_rechecked"] == {"documents": 2, "terms": 2, "changed": 0}
    assert manifest["usage"] == {"carried": {"llm_calls": 1}, "new": {"llm_calls": 1}}


def test_a_carried_record_whose_verdicts_change_under_the_current_index_is_refused(tmp_path):
    old, new = _files(tmp_path)

    def flips(rec, gates):
        if rec.doc_id != "CVE-3":
            return rec
        d = rec.to_dict()
        d["proposed_terms"][0].update(accepted=True, reject_reason=None, rejected_at_stage=None)
        return EnrichmentRecord.from_dict(d)

    with pytest.raises(sp.SpliceError, match="changes verdicts on 1 carried"):
        _run(tmp_path, old, new, readjudicate=flips)
    assert not (tmp_path / "out.jsonl").exists()


def test_the_gates_the_new_run_used_are_the_ones_replayed(tmp_path):
    old, new = _files(tmp_path)
    seen = []
    _run(tmp_path, old, new, readjudicate=lambda rec, gates: seen.append(gates) or rec)
    assert seen and all(g == {"name_scorer": "v2", "df_max_ratio": 0.1} for g in seen)


def test_a_changed_document_without_a_new_record_is_refused(tmp_path):
    old, new = _files(tmp_path, new_records=[])
    with pytest.raises(sp.SpliceError, match="CVE-2: its text changed and the new file has no record"):
        _run(tmp_path, old, new)


def test_a_new_record_for_an_unchanged_document_is_refused(tmp_path):
    old, new = _files(tmp_path, new_records=[
        _rec("CVE-2", CORPUS["CVE-2"].text, []), _rec("CVE-1", "CVE-1 real text", [])])
    with pytest.raises(sp.SpliceError, match="CVE-1: has a new record although its text did not change"):
        _run(tmp_path, old, new)


def test_a_new_record_made_from_other_text_is_refused(tmp_path):
    old, new = _files(tmp_path, new_records=[_rec("CVE-2", "CVE-2 null", [])])
    with pytest.raises(sp.SpliceError, match="not the current corpus text"):
        _run(tmp_path, old, new)


def test_a_document_in_neither_file_is_refused(tmp_path):
    old, new = _files(tmp_path)
    corpus = dict(CORPUS, **{"CVE-4": CorpusDocument("CVE-4", Source.CVE, "CVE-4", "CVE-4 x")})
    with pytest.raises(sp.SpliceError, match="CVE-4: in the corpus but in neither file"):
        _run(tmp_path, old, new, corpus=corpus)


def test_the_new_file_must_be_made_under_the_current_config(tmp_path):
    old, new = _files(tmp_path, new_manifest=_manifest("aaaaaaaaaaaa"))
    with pytest.raises(sp.SpliceError, match="the current config is 06e891b2b957"):
        _run(tmp_path, old, new)


@pytest.mark.parametrize("change", [
    {"model_digest": "other"},
    {"gates": {"name_scorer": "v1", "df_max_ratio": 0.1}},
    {"llm": {"backend": "ollama", "temperature": 0.7}},
    {"prompt_version": "corpus-v3"},
])
def test_any_difference_in_method_is_refused(tmp_path, change):
    old, new = _files(tmp_path, new_manifest=_manifest(NEW_HASH, **change))
    with pytest.raises(sp.SpliceError, match="not made with the same method"):
        _run(tmp_path, old, new)


def test_an_existing_output_is_never_overwritten(tmp_path):
    old, new = _files(tmp_path)
    (tmp_path / "out.jsonl").write_text("keep me")
    with pytest.raises(sp.SpliceError, match="already exists"):
        _run(tmp_path, old, new)
    assert (tmp_path / "out.jsonl").read_text() == "keep me"


def test_failure_logs_follow_their_records(tmp_path):
    old, new = _files(tmp_path, old_sidecar=["CVE-3", "CVE-2"], new_sidecar=["CVE-2"])
    _run(tmp_path, old, new)
    rows = [json.loads(l) for l in (tmp_path / "out.jsonl.raw_failures.jsonl").read_text().splitlines()]
    assert [r["doc_id"] for r in rows] == ["CVE-3", "CVE-2"]   # the old CVE-2 failure is gone, the new one kept


def test_records_parse_like_any_other_enrichment_file(tmp_path):
    old, new = _files(tmp_path)
    _run(tmp_path, old, new)
    from sira_cti.common import read_jsonl
    recs = list(read_jsonl(tmp_path / "out.jsonl"))
    assert [r.doc_id for r in recs] == ["CVE-1", "CVE-2", "CVE-3"]
    assert recs[2].proposed_terms[0].reject_reason is RejectReason.TOO_COMMON


def test_the_output_claims_the_whole_corpus_and_keeps_the_new_files_selection(tmp_path):
    old, new = _files(tmp_path)
    manifest = _run(tmp_path, old, new)
    assert manifest["sampling"] == FULL
    assert manifest["spliced"]["new"]["sampling"] == {"method": "ids", "ids": ["CVE-2"]}
