"""Script-level helpers for the paid Gemini runs: the file-wide cost cap and the model check."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import check_gemini_model  # noqa: E402
import enrich_corpus  # noqa: E402

from sira_cti.common import EnrichmentRecord, Source, TokenUsage, write_jsonl  # noqa: E402


def _record(doc_id, prompt, completion, thinking):
    return EnrichmentRecord(
        doc_id=doc_id, source=Source.CWE, original_text="t", proposed_terms=[],
        llm_calls=1, tokens=TokenUsage(prompt=prompt, completion=completion, thinking=thinking),
        latency_ms=1, model="gemini-test",
    )


def _list_price(tokens):
    # $2 in, $12 out; thinking billed as output -- the formula enrich_corpus uses.
    return (tokens.prompt * 2.0 + (tokens.completion + tokens.thinking) * 12.0) / 1e6


def test_the_cap_counts_what_earlier_sessions_spent_on_the_file(tmp_path):
    out = tmp_path / "run.jsonl"
    write_jsonl([_record("CWE-1", 1000, 200, 800), _record("CWE-2", 1_000_000, 0, 0)], out)

    done, spent = enrich_corpus.spend_in_file(out, _list_price)

    assert done == {"CWE-1", "CWE-2"}
    # CWE-1: 0.002 + 0.012 = 0.014; CWE-2: one million prompt tokens = $2.
    assert abs(spent - 2.014) < 1e-9


def test_a_new_file_has_spent_nothing(tmp_path):
    assert enrich_corpus.spend_in_file(tmp_path / "absent.jsonl", _list_price) == (set(), 0.0)


def test_no_prices_means_no_spend_but_the_documents_are_still_known(tmp_path):
    out = tmp_path / "run.jsonl"
    write_jsonl([_record("CWE-1", 10, 10, 10)], out)
    assert enrich_corpus.spend_in_file(out, lambda _t: None) == ({"CWE-1"}, 0.0)


def test_model_ids_are_read_from_both_routes_naming_schemes():
    names = [
        "publishers/google/models/gemini-3.1-pro-preview",      # Vertex
        "models/gemini-2.5-flash",                              # AI Studio
        "publishers/google/models/imagen-4",                    # not Gemini
        "models/gemini-2.5-flash",                              # duplicate
    ]
    assert check_gemini_model.gemini_model_ids(names) == ["gemini-2.5-flash", "gemini-3.1-pro-preview"]


def test_the_probe_wants_a_non_empty_array_of_objects():
    assert check_gemini_model.probe_verdict('[{"term": "CWE-89", "kind": "id"}]')[0]
    for bad in ('{"term": "CWE-89"}', "[]", "[1, 2]", "not json", None):
        assert not check_gemini_model.probe_verdict(bad)[0]
