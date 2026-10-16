"""``scripts/merge_enrichment.py``: joining the files of a split run.

The source files are made by the real driver (``run_corpus_enrichment`` with a
stub model), so their manifests have exactly the shape a real run writes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from helpers import FakeDFLookup, build_fixture_graph

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from merge_enrichment import MergeError, manifest_path, merge  # noqa: E402

from sira_cti.common import Source, StubClient, read_jsonl  # noqa: E402
from sira_cti.enrichment.corpus_side import run_corpus_enrichment  # noqa: E402
from sira_cti.index.corpus import CorpusDocument, shard_corpus  # noqa: E402

DIGEST = "7cdf5a0187d5" + "0" * 52
DOCS = [
    CorpusDocument(doc_id=f"T{1000 + i}", source=Source.ATTACK, title="t", text=f"text {i}") for i in range(12)
] + [CorpusDocument(doc_id=f"CVE-2024-{i}", source=Source.CVE, title="t", text=f"text {i}") for i in range(12)]


def _machine(hostname):
    return {"hostname": hostname, "platform": "Linux-test", "python": "3.11", "gpu": ["Tesla T4"],
            "cuda_visible_devices": "0"}


def _run(out, docs, *, shard=None, hostname="kaggle-1", reply="[]", **overrides):
    settings = dict(
        client_factory=lambda: StubClient(model="qwen2.5:14b", responder=lambda _p: reply),
        graph=build_fixture_graph(), df_lookup=FakeDFLookup({}, total_docs=100), output_path=out,
        max_terms=12, df_max_ratio=0.9, config_hash="364d30da6c75", name_match_min_overlap=0.5,
        name_scorer="v2", concurrency=1, max_doc_chars=6000, corpus_kinds=["mitre", "cve"],
        sampling={"method": "prefix", "limit": None}, model_digest=DIGEST, machine=_machine(hostname),
        llm_settings={"backend": "ollama", "temperature": 0.0, "seed_sent": 42, "num_ctx": 4096},
        code_version={"head": "a" * 40, "code_commit": "a" * 40, "dirty": False, "dirty_files": [], "paths": ["src"]},
        shard=shard,
    )
    settings.update(overrides)
    run_corpus_enrichment(list(shard_corpus(docs, shard)), **settings)
    return out


@pytest.fixture
def shards(tmp_path):
    return [
        _run(tmp_path / "full.shard1of2.jsonl", DOCS, shard=(1, 2), hostname="kaggle-gpu0"),
        _run(tmp_path / "full.shard2of2.jsonl", DOCS, shard=(2, 2), hostname="kaggle-gpu1"),
    ]


def test_two_shards_merge_into_every_document_exactly_once(tmp_path, shards):
    out = tmp_path / "merged.jsonl"
    merge(shards, out, expect=len(DOCS))

    ids = [r.doc_id for r in read_jsonl(out)]
    assert sorted(ids) == sorted(d.doc_id for d in DOCS) and len(set(ids)) == len(ids)
    # Records are carried over byte for byte, not re-serialised.
    source_lines = {line for p in shards for line in p.read_text().splitlines()}
    assert set(out.read_text().splitlines()) == source_lines


def test_the_merged_manifest_lists_every_source_file_and_machine(tmp_path, shards):
    out = tmp_path / "merged.jsonl"
    manifest = merge(shards, out)

    assert manifest == json.loads(manifest_path(out).read_text())
    assert manifest["model"] == "qwen2.5:14b" and manifest["model_digest"] == DIGEST
    assert manifest["config_hash"] == "364d30da6c75" and manifest["gates"]["name_scorer"] == "v2"
    assert manifest["llm"] == {"backend": "ollama", "temperature": 0.0, "seed_sent": 42, "num_ctx": 4096}
    assert "shard" not in manifest                                    # the merged file is not a slice
    assert [m["hostname"] for m in manifest["machines"]] == ["kaggle-gpu0", "kaggle-gpu1"]
    sources = manifest["merged"]["sources"]
    assert [s["path"] for s in sources] == [str(p) for p in shards]
    assert [s["shard"] for s in sources] == [{"index": 1, "of": 2}, {"index": 2, "of": 2}]
    assert sum(s["records"] for s in sources) == manifest["merged"]["documents"] == len(DOCS)
    assert all(len(s["sha256"]) == 64 and s["code_commits"] == ["a" * 40] for s in sources)
    assert manifest["merged"]["documents_by_source"] == {"attack": 12, "cve": 12}
    assert manifest["usage"]["llm_calls"] == len(DOCS)                # recounted from the records


def test_a_file_continued_on_a_second_machine_brings_both_machines(tmp_path):
    part = tmp_path / "part.jsonl"
    _run(part, DOCS[:3], hostname="mac")
    _run(part, DOCS[:6], hostname="kaggle-1")
    rest = _run(tmp_path / "rest.jsonl", DOCS[6:], hostname="kaggle-2")

    manifest = merge([part, rest], tmp_path / "merged.jsonl", expect=len(DOCS))
    assert [m["hostname"] for m in manifest["machines"]] == ["mac", "kaggle-1", "kaggle-2"]
    assert [m["hostname"] for m in manifest["merged"]["sources"][0]["machines"]] == ["mac", "kaggle-1"]


def test_one_machine_running_two_gpus_is_listed_once_with_both_processes(tmp_path):
    """The Kaggle shape: two sessions, each running shard 1 on GPU 0 and shard 2 on GPU 1.

    Stage 1's merged manifest listed each session's machine twice: the two
    entries differ only in which GPU and port the process used.
    """
    def machine(hostname, gpu):
        return {**_machine(hostname), "cuda_visible_devices": str(gpu),
                "ollama_host": f"http://127.0.0.1:{11434 + gpu}"}

    paths = []
    for index, gpu in ((1, 0), (2, 1)):
        path = tmp_path / f"full.shard{index}of2.jsonl"
        _run(path, DOCS[:12], shard=(index, 2), machine=machine("session-1", gpu))
        _run(path, DOCS, shard=(index, 2), machine=machine("session-2", gpu))
        paths.append(path)

    manifest = merge(paths, tmp_path / "merged.jsonl", expect=len(DOCS))
    assert [m["hostname"] for m in manifest["machines"]] == ["session-1", "session-2"]
    for entry in manifest["machines"]:
        assert entry["processes"] == [
            {"cuda_visible_devices": "0", "ollama_host": "http://127.0.0.1:11434"},
            {"cuda_visible_devices": "1", "ollama_host": "http://127.0.0.1:11435"},
        ]
        assert "cuda_visible_devices" not in entry
    # Each source file still names every process that wrote it, in full.
    assert [m["cuda_visible_devices"] for m in manifest["merged"]["sources"][1]["machines"]] == ["1", "1"]


def test_a_kind_with_no_records_is_counted_as_zero_not_left_out(tmp_path):
    only_cve = _run(tmp_path / "cve.jsonl", DOCS[12:])
    manifest = merge([only_cve], tmp_path / "merged.jsonl")
    assert manifest["merged"]["documents_by_source"] == {"attack": 0, "cve": 12}


@pytest.mark.parametrize(
    "override, label",
    [
        ({"config_hash": "bbbbbbbbbbbb"}, "config_hash"),
        ({"model_digest": "f" * 64}, "model_digest"),
        ({"prompt_version": "corpus-v5"}, "prompt_version"),
        ({"name_scorer": "v1"}, "gates.name_scorer"),
        ({"max_doc_chars": 8000}, "gates.max_doc_chars"),
        ({"sampling": {"method": "per_kind", "per_kind": 10, "seed": 7}}, "sampling"),
        ({"llm_settings": {"backend": "ollama", "temperature": 0.0, "seed_sent": 7, "num_ctx": 4096}}, "llm.seed_sent"),
        ({"client_factory": lambda: StubClient(model="qwen2.5:7b", responder=lambda _p: "[]")}, "model"),
    ],
)
def test_files_made_under_different_settings_are_refused(tmp_path, override, label):
    one = _run(tmp_path / "one.jsonl", DOCS, shard=(1, 2))
    two = _run(tmp_path / "two.jsonl", DOCS, shard=(2, 2), **override)
    out = tmp_path / "merged.jsonl"

    with pytest.raises(MergeError) as excinfo:
        merge([one, two], out)

    assert f"  {label}:" in str(excinfo.value)
    assert not out.exists() and not manifest_path(out).exists()        # nothing written


def test_a_truncation_rule_change_is_refused(tmp_path, monkeypatch):
    from sira_cti.enrichment import corpus_side

    one = _run(tmp_path / "one.jsonl", DOCS, shard=(1, 2))
    monkeypatch.setattr(corpus_side, "TRUNCATION_VERSION", "sections-v9")
    two = _run(tmp_path / "two.jsonl", DOCS, shard=(2, 2))
    with pytest.raises(MergeError, match="gates.truncation_version"):
        merge([one, two], tmp_path / "merged.jsonl")


def test_a_file_without_a_manifest_or_without_a_digest_is_refused(tmp_path, shards):
    undigested = _run(tmp_path / "old.jsonl", DOCS[:2], model_digest=None)
    with pytest.raises(MergeError, match="model_digest"):
        merge([undigested, _run(tmp_path / "old2.jsonl", DOCS[2:4], model_digest=None)], tmp_path / "m1.jsonl")

    manifest_path(shards[1]).unlink()
    with pytest.raises(MergeError, match="no manifest"):
        merge(shards, tmp_path / "m2.jsonl")


def test_the_same_record_twice_is_kept_once(tmp_path):
    whole = _run(tmp_path / "whole.jsonl", DOCS[:6])
    # A copy taken part-way through, as when an earlier session's file is kept beside its continuation.
    early = tmp_path / "early.jsonl"
    early.write_text("".join(whole.read_text().splitlines(keepends=True)[:4]))
    manifest_path(early).write_text(manifest_path(whole).read_text())

    manifest = merge([early, whole], tmp_path / "merged.jsonl", expect=6)
    assert manifest["merged"]["identical_duplicates_dropped"] == 4
    assert [r.doc_id for r in read_jsonl(tmp_path / "merged.jsonl")] == [d.doc_id for d in DOCS[:6]]


def test_the_same_document_with_different_content_is_refused(tmp_path):
    one = _run(tmp_path / "one.jsonl", DOCS[:4])
    two = _run(tmp_path / "two.jsonl", DOCS[2:6], reply='[{"term": "password guessing", "kind": "colloquial"}]')
    out = tmp_path / "merged.jsonl"

    with pytest.raises(MergeError) as excinfo:
        merge([one, two], out)

    message = str(excinfo.value)
    assert "2 document id(s)" in message and "T1002" in message and "T1003" in message
    assert "proposed_terms" in message                                 # says what differs
    assert not out.exists()


def test_a_record_in_the_wrong_shards_file_is_refused(tmp_path, shards):
    stray = shards[1].read_text().splitlines()[0]
    with shards[0].open("a") as fh:
        fh.write(stray + "\n")
    with pytest.raises(MergeError, match="wrong shard"):
        merge(shards, tmp_path / "merged.jsonl")


def test_an_unfinished_run_fails_the_expected_count(tmp_path, shards):
    with pytest.raises(MergeError, match=f"expected {len(DOCS) + 1} documents"):
        merge(shards, tmp_path / "merged.jsonl", expect=len(DOCS) + 1)
    with pytest.raises(MergeError, match="shard is missing"):
        merge(shards[:1], tmp_path / "merged.jsonl", expect=len(DOCS))


def test_an_existing_output_is_never_overwritten_and_inputs_are_left_alone(tmp_path, shards):
    before = [p.read_bytes() for p in shards]
    out = tmp_path / "merged.jsonl"
    merge(shards, out)
    with pytest.raises(MergeError, match="already exists"):
        merge(shards, out)
    with pytest.raises(MergeError, match="one of the source files"):
        merge(shards, shards[0])
    with pytest.raises(MergeError, match="more than once"):
        merge([shards[0], shards[0]], tmp_path / "other.jsonl")
    assert [p.read_bytes() for p in shards] == before


def test_failure_logs_travel_with_the_merged_file(tmp_path, shards):
    shards[0].with_suffix(".jsonl.raw_failures.jsonl").write_text('{"doc_id": "T1000", "raw": "x"}\n')
    shards[1].with_suffix(".jsonl.raw_failures.jsonl").write_text('{"doc_id": "T1001", "raw": "y"}')
    out = tmp_path / "merged.jsonl"
    merge(shards, out)
    merged = out.with_suffix(".jsonl.raw_failures.jsonl").read_text().splitlines()
    assert [json.loads(line)["doc_id"] for line in merged] == ["T1000", "T1001"]
    assert not out.with_suffix(".jsonl.failures.jsonl").exists()


def test_the_command_line_reports_a_refusal_with_exit_status_2(tmp_path, shards):
    import subprocess

    script = Path(__file__).resolve().parents[1] / "scripts" / "merge_enrichment.py"
    ok = subprocess.run(
        [sys.executable, str(script), *map(str, shards), "--output", str(tmp_path / "m.jsonl"),
         "--expect", str(len(DOCS))], capture_output=True, text=True,
    )
    assert ok.returncode == 0 and "kaggle-gpu1" in ok.stdout and f"documents: {len(DOCS)}" in ok.stdout
    again = subprocess.run(
        [sys.executable, str(script), *map(str, shards), "--output", str(tmp_path / "m.jsonl")],
        capture_output=True, text=True,
    )
    assert again.returncode == 2 and "already exists" in again.stdout
