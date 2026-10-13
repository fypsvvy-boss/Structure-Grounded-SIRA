"""``scripts/compare_enrichment.py``: the same documents enriched on two machines."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from helpers import FakeDFLookup, build_fixture_graph

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from compare_enrichment import compare  # noqa: E402

from sira_cti.common import Source, StubClient  # noqa: E402
from sira_cti.enrichment.corpus_side import run_corpus_enrichment  # noqa: E402
from sira_cti.index.corpus import CorpusDocument  # noqa: E402

DIGEST = "7cdf5a0187d5" + "0" * 52
DOCS = [CorpusDocument(doc_id=d, source=Source.ATTACK, title="t", text=f"text of {d}") for d in ("T1110", "T1078", "T1059")]
BASE = [
    {"term": "password guessing", "kind": "colloquial"},
    {"term": "T1110.001", "kind": "structural", "name": "Password Guessing"},
]


def _run(out, replies, *, hostname, docs=DOCS, **overrides):
    """Enrich ``docs``; ``replies`` maps a document id to what the model says for it."""
    def responder(prompt):
        for doc_id, reply in replies.items():
            if f"text of {doc_id}" in prompt:
                return json.dumps(reply)
        return json.dumps(BASE)

    settings = dict(
        client_factory=lambda: StubClient(model="qwen2.5:14b", responder=responder),
        graph=build_fixture_graph(), df_lookup=FakeDFLookup({}, total_docs=100), output_path=out,
        max_terms=12, df_max_ratio=0.9, config_hash="364d30da6c75", name_match_min_overlap=0.5,
        sampling={"method": "per_kind", "per_kind": 10, "seed": 42}, model_digest=DIGEST,
        machine={"hostname": hostname, "platform": "test", "python": "3", "gpu": ["Tesla T4"], "cuda_visible_devices": None},
    )
    settings.update(overrides)
    run_corpus_enrichment(docs, **settings)
    return out


def test_two_identical_runs_report_every_reply_identical_and_no_number_moved(tmp_path):
    mac = _run(tmp_path / "mac.jsonl", {}, hostname="mac")
    kaggle = _run(tmp_path / "kaggle.jsonl", {}, hostname="kaggle")

    result = compare(mac, kaggle)

    assert (result["replies_identical"], result["replies_compared"]) == (3, 3)
    assert result["replies_differing"] == [] and result["table_numbers_moved"] == {}
    assert result["settings_that_differ"] == {} and result["same_documents"]
    assert result["model_digest"] == [DIGEST, DIGEST]
    assert [m["hostname"] for m in result["machines"]] == ["mac", "kaggle"]


def test_a_changed_reply_is_counted_named_and_shows_which_numbers_moved(tmp_path):
    mac = _run(tmp_path / "mac.jsonl", {}, hostname="mac")
    # On the other machine one document gets an id that does not exist instead of the real one.
    drifted = [BASE[0], {"term": "T9999", "kind": "structural", "name": "Password Guessing"}]
    kaggle = _run(tmp_path / "kaggle.jsonl", {"T1078": drifted}, hostname="kaggle")

    result = compare(mac, kaggle)

    assert (result["replies_identical"], result["replies_compared"]) == (2, 3)
    (diff,) = result["replies_differing"]
    assert diff["doc_id"] == "T1078" and not diff["same_proposals_different_order"]
    assert diff["only_in_reference"] == [("T1110.001", "structural", "Password Guessing")]
    assert diff["only_in_other"] == [("T9999", "structural", "Password Guessing")]
    assert diff["accepted_ids"] == [["T1110.001"], []]
    moved = result["table_numbers_moved"]
    assert moved["structural_accepted"] == [3, 2] and moved["accepted"] == [6, 5]
    assert "structural_proposed" not in moved and "docs" not in moved     # these did not change


def test_the_same_proposals_in_another_order_is_not_an_identical_reply(tmp_path):
    mac = _run(tmp_path / "mac.jsonl", {}, hostname="mac")
    kaggle = _run(tmp_path / "kaggle.jsonl", {"T1059": BASE[::-1]}, hostname="kaggle")

    result = compare(mac, kaggle)
    assert result["replies_identical"] == 2
    assert result["replies_differing"][0]["same_proposals_different_order"] is True
    assert result["table_numbers_moved"] == {}                            # order alone moves no count


def test_different_settings_and_different_documents_are_called_out(tmp_path):
    mac = _run(tmp_path / "mac.jsonl", {}, hostname="mac")
    kaggle = _run(
        tmp_path / "kaggle.jsonl", {}, hostname="kaggle", docs=DOCS[:2], model_digest="f" * 64,
        name_match_min_overlap=None,
    )

    result = compare(mac, kaggle)
    assert result["model_digest"] == [DIGEST, "f" * 64]
    assert result["settings_that_differ"]["gates.name_match_min_overlap"] == [0.5, None]
    assert "model_digest" not in result["settings_that_differ"]           # reported on its own line
    assert result["documents"]["only_in_reference"] == ["T1059"] and not result["same_documents"]
    assert result["replies_compared"] == 2


def test_the_report_prints_the_two_answers(tmp_path, capsys):
    from compare_enrichment import _print

    mac = _run(tmp_path / "mac.jsonl", {}, hostname="mac")
    kaggle = _run(tmp_path / "kaggle.jsonl", {"T1078": [BASE[0]]}, hostname="kaggle")
    _print(compare(mac, kaggle))
    text = capsys.readouterr().out
    assert "REPLIES IDENTICAL: 2 of 3" in text and "T1078 (attack): 2 / 1 proposals" in text
    assert "model digest: the same" in text and "TABLE NUMBERS:" in text and "counts move" in text

    _print(compare(mac, mac))
    text = capsys.readouterr().out
    assert "REPLIES IDENTICAL: 3 of 3" in text and "TABLE NUMBERS: none of the" in text
