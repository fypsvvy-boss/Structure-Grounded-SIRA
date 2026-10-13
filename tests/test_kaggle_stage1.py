"""``scripts/kaggle_stage1.py``: the logic behind the Kaggle notebook. No GPU, no network."""

from __future__ import annotations

import json
import shutil
import sys
import zipfile
from pathlib import Path

import pytest
from helpers import CORPUS_KB_FIXTURE, CWE_FIXTURE

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import kaggle_stage1 as ks  # noqa: E402

from sira_cti.common import EnrichmentRecord, Source, write_jsonl  # noqa: E402
from sira_cti.graph import load_all  # noqa: E402

CFG = {
    "corpus": {"kb_dir": "data/CTIConnect/corpus_kb", "kinds": ["cve", "cwe", "capec", "mitre"]},
    "graph": {
        "attack_path": ["data/raw/attack/enterprise-attack.json", "data/raw/attack/mobile-attack.json"],
        "cwe_path": "data/raw/cwe/cwec_latest.xml.zip",
        "capec_path": "data/raw/capec/capec_latest.xml",
    },
    "index": {"base_dir": "indexes/base"},
}


def _dataset(root: Path, *, cwe: str = "zip", index: bool = True) -> Path:
    """An uploaded dataset laid out like the repository (``docs/kaggle-run.md``)."""
    shutil.copytree(CORPUS_KB_FIXTURE, root / "data/CTIConnect/corpus_kb")
    for name in ("enterprise-attack.json", "mobile-attack.json"):
        (root / "data/raw/attack").mkdir(parents=True, exist_ok=True)
        (root / "data/raw/attack" / name).write_text('{"objects": []}')
    (root / "data/raw/capec").mkdir(parents=True)
    (root / "data/raw/capec/capec_latest.xml").write_text("<capec/>")
    (root / "data/raw/cwe").mkdir(parents=True)
    if cwe == "zip":
        with zipfile.ZipFile(root / "data/raw/cwe/cwec_latest.xml.zip", "w") as zf:
            zf.write(CWE_FIXTURE, arcname="cwec_v4.17.xml")
    elif cwe == "unpacked":       # what Kaggle leaves when it unpacks an uploaded archive
        (root / "data/raw/cwe/cwec_latest.xml.zip").mkdir()
        shutil.copyfile(CWE_FIXTURE, root / "data/raw/cwe/cwec_latest.xml.zip/cwec_v4.17.xml")
    if index:
        (root / "indexes/base").mkdir(parents=True)
        (root / "indexes/base/manifest.json").write_text(json.dumps({"kind": "base", "doc_count": 6}))
        (root / "indexes/base/segments_1").write_bytes(b"lucene")
    return root


def test_stage_inputs_puts_every_file_where_the_config_expects_it(tmp_path):
    dataset, repo = _dataset(tmp_path / "input" / "sira-corpus"), tmp_path / "repo"

    report = ks.stage_inputs(tmp_path / "input", repo, CFG)

    for relative in ("data/CTIConnect/corpus_kb/cve.jsonl", "data/CTIConnect/corpus_kb/mitre.jsonl",
                     "data/raw/attack/mobile-attack.json", "data/raw/capec/capec_latest.xml",
                     "data/raw/cwe/cwec_latest.xml.zip", "indexes/base/manifest.json", "indexes/base/segments_1"):
        assert (repo / relative).read_bytes() == (dataset / relative).read_bytes()
    assert len(report) == 9                                    # 4 corpus + 2 attack + capec + cwe + index


def test_a_cwe_zip_that_kaggle_unpacked_is_zipped_again_and_still_loads(tmp_path):
    _dataset(tmp_path / "input" / "sira-corpus", cwe="unpacked")
    repo = tmp_path / "repo"

    report = ks.stage_inputs(tmp_path / "input", repo, CFG)

    target = repo / "data/raw/cwe/cwec_latest.xml.zip"
    assert zipfile.is_zipfile(target) and any("zipped again" in line for line in report)
    assert load_all(cwe_path=target).nodes == load_all(cwe_path=CWE_FIXTURE).nodes


def test_files_uploaded_flat_are_found_by_name(tmp_path):
    nested = _dataset(tmp_path / "scratch")
    flat = tmp_path / "input" / "sira-corpus"
    flat.mkdir(parents=True)
    for path in nested.rglob("*"):
        if path.is_file() and path.parent.name != "base":
            shutil.copyfile(path, flat / path.name)
    shutil.copytree(nested / "indexes/base", flat / "base")

    ks.stage_inputs(tmp_path / "input", tmp_path / "repo", CFG)
    assert (tmp_path / "repo/data/CTIConnect/corpus_kb/cwe.jsonl").exists()
    assert (tmp_path / "repo/indexes/base/segments_1").exists()


def test_everything_missing_is_listed_in_one_error(tmp_path):
    dataset = _dataset(tmp_path / "input" / "sira-corpus", cwe="none", index=False)
    (dataset / "data/CTIConnect/corpus_kb/cve.jsonl").unlink()

    with pytest.raises(ks.StageError) as excinfo:
        ks.stage_inputs(tmp_path / "input", tmp_path / "repo", CFG)
    message = str(excinfo.value)
    assert "corpus_kb/cve.jsonl" in message and "cwec_latest.xml.zip" in message and "indexes/base" in message


def test_two_different_files_of_the_same_name_are_not_guessed_between(tmp_path):
    _dataset(tmp_path / "input" / "sira-corpus")
    for folder in ("a", "b"):
        (tmp_path / "input" / folder).mkdir()
        (tmp_path / "input" / folder / "capec_latest.xml").write_text("<other/>")
    (tmp_path / "input/sira-corpus/data/raw/capec/capec_latest.xml").unlink()
    with pytest.raises(ks.StageError, match="More than one file named capec_latest.xml"):
        ks.stage_inputs(tmp_path / "input", tmp_path / "repo", CFG)


# -- carrying on from an earlier session ------------------------------------------------


def _output(path: Path, n: int, *, manifest: bool = True) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps({"doc_id": f"T{i}"}) + "\n" for i in range(n)))
    if manifest:
        path.with_name(path.name + ".manifest.json").write_text(json.dumps({"records": n}))
    return path


def test_restore_previous_copies_the_fullest_attached_copy_with_its_manifest_and_logs(tmp_path):
    older = _output(tmp_path / "input/run-v1/full.shard1of2.jsonl", 3)
    newer = _output(tmp_path / "input/run-v2/full.shard1of2.jsonl", 7)
    newer.with_name(newer.name + ".raw_failures.jsonl").write_text("{}\n")
    working = tmp_path / "working"

    report = ks.restore_previous(tmp_path / "input", working, ["full.shard1of2.jsonl", "full.shard2of2.jsonl"])

    assert ks.count_lines(working / "full.shard1of2.jsonl") == 7
    assert json.loads((working / "full.shard1of2.jsonl.manifest.json").read_text()) == {"records": 7}
    assert (working / "full.shard1of2.jsonl.raw_failures.jsonl").exists()
    assert "resuming from" in report[0] and "(7 records)" in report[0]
    assert "no earlier output attached" in report[1] and not (working / "full.shard2of2.jsonl").exists()
    assert ks.count_lines(older) == 3                           # the attached input is untouched


def test_restore_previous_never_replaces_a_working_copy_that_is_further_on(tmp_path):
    _output(tmp_path / "input/run-v1/out.jsonl", 3)
    _output(tmp_path / "working/out.jsonl", 5)
    report = ks.restore_previous(tmp_path / "input", tmp_path / "working", ["out.jsonl"])
    assert ks.count_lines(tmp_path / "working/out.jsonl") == 5 and "keeping the working copy" in report[0]


def test_restore_previous_refuses_an_output_with_no_manifest(tmp_path):
    _output(tmp_path / "input/run-v1/out.jsonl", 3, manifest=False)
    with pytest.raises(ks.StageError, match="no .manifest.json"):
        ks.restore_previous(tmp_path / "input", tmp_path / "working", ["out.jsonl"])


def test_restore_previous_copes_with_nothing_attached(tmp_path):
    report = ks.restore_previous(tmp_path / "no-such-folder", tmp_path / "working", ["out.jsonl"])
    assert "no earlier output attached" in report[0]


# -- sizing the shares, and the time limit ---------------------------------------------

KINDS = ["cve", "cwe", "capec", "mitre"]
ONE_SECOND = {k: 3600.0 for k in KINDS}       # an hour per document makes hours == documents


def test_two_hash_shards_cover_every_document_exactly_once(tmp_path):
    plan = [{"kinds": "cwe,capec,attack,cve", "shard": "1/2"}, {"kinds": "cwe,capec,attack,cve", "shard": "2/2"}]
    shares = ks.plan_shares(CORPUS_KB_FIXTURE, plan, KINDS, ONE_SECOND)

    assert sum(s["documents"] for s in shares) == 6            # the fixture corpus: 2 cve, 1 cwe, 1 capec, 2 mitre
    assert [s["hours"] for s in shares] == [s["documents"] for s in shares]
    assert list(shares[0]["documents_by_kind"]) == ["cwe", "capec", "mitre", "cve"]   # --kinds order, alias resolved


def test_a_split_by_kind_is_also_accepted_and_hours_use_each_kinds_own_speed(tmp_path):
    plan = [{"kinds": "cve"}, {"kinds": "cwe,capec,attack"}]
    speeds = {"cve": 1800.0, "cwe": 3600.0, "capec": 3600.0, "mitre": 7200.0}
    shares = ks.plan_shares(CORPUS_KB_FIXTURE, plan, KINDS, speeds)
    assert [s["documents"] for s in shares] == [2, 4]
    assert [s["hours"] for s in shares] == [1.0, 1 + 1 + 4]


@pytest.mark.parametrize(
    "plan, problem",
    [
        ([{"kinds": "cve"}, {"kinds": "cve,cwe,capec,attack"}], "in two shares"),
        ([{"kinds": "cve"}, {"kinds": "cwe,capec"}], "2 in none"),
        ([{"kinds": "cve,cwe,capec,attack", "shard": "1/2"}, {"kinds": "cve,cwe,capec,attack", "shard": "1/2"}], "in two shares"),
    ],
)
def test_a_plan_that_overlaps_or_leaves_documents_out_is_refused(plan, problem):
    with pytest.raises(ks.StageError, match=problem):
        ks.plan_shares(CORPUS_KB_FIXTURE, plan, KINDS, ONE_SECOND)


def test_the_real_freeze_figures_are_the_ones_built_in():
    # docs/proposals/module1-freeze.md, "Time and cost": seconds per document, sustained.
    assert ks.MAC_SECONDS_PER_DOC == {"cwe": 48.2, "capec": 39.6, "mitre": 40.7, "cve": 45.1}


def test_seconds_per_doc_is_averaged_per_kind_from_a_sample_file(tmp_path):
    def record(doc_id, source, ms):
        return EnrichmentRecord(doc_id=doc_id, source=source, original_text="x", proposed_terms=[],
                                llm_calls=1, latency_ms=ms, model="m")

    out = tmp_path / "sample.jsonl"
    write_jsonl([record("T1", Source.ATTACK, 10_000), record("T2", Source.ATTACK, 20_000),
                 record("CVE-2024-1", Source.CVE, 8_000)], out)
    assert ks.seconds_per_doc_from(out) == {"mitre": 15.0, "cve": 8.0}


def test_stop_after_leaves_the_safety_margin_and_takes_off_time_already_used():
    assert ks.stop_after_minutes(12, 45, 0) == 675
    assert ks.stop_after_minutes(12, 45, 20 * 60) == 655       # 20 minutes went on installs
    with pytest.raises(ks.StageError, match="not enough"):
        ks.stop_after_minutes(12, 45, 11.3 * 3600)


def test_the_enrich_command_carries_host_shard_output_and_time_limit():
    cmd = ks.enrich_command(
        "python", {"gpu": 1, "port": 11435, "kinds": "cwe,capec,attack,cve", "shard": "2/2"},
        "/kaggle/working/full.shard2of2.jsonl", extra_args=["--model", "qwen2.5:14b", "--name-scorer", "v2"],
        stop_after=655,
    )
    assert cmd == [
        "python", "scripts/enrich_corpus.py", "--model", "qwen2.5:14b", "--name-scorer", "v2",
        "--host", "http://127.0.0.1:11435", "--output", "/kaggle/working/full.shard2of2.jsonl",
        "--kinds", "cwe,capec,attack,cve", "--shard", "2/2", "--stop-after-minutes", "655",
    ]
    sample = ks.enrich_command("python", {"port": 11434}, "s.jsonl", extra_args=["--per-kind", "10"])
    assert "--shard" not in sample and "--kinds" not in sample and "--stop-after-minutes" not in sample


def test_the_built_command_is_one_the_real_script_accepts(tmp_path):
    import subprocess

    cmd = ks.enrich_command(
        sys.executable, {"port": 11434, "kinds": "cwe,capec,attack,cve", "shard": "2/2"}, tmp_path / "o.jsonl",
        extra_args=["--model", "qwen2.5:14b", "--name-scorer", "v2"], stop_after=655,
    )
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([*cmd, "--help"], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0 and "--stop-after-minutes" in result.stdout


# -- progress and the runner --------------------------------------------------------------


def test_progress_line_gives_rate_and_time_left_from_this_sessions_work_only():
    line = ks.progress_line("gpu0", 1200, 3000, 900, 3600)
    assert line.startswith("gpu0: 1200/3000 (40.0%)  +300 this session  300/h  about 6.0 h left")
    assert "left" not in ks.progress_line("gpu0", 900, 3000, 900, 3600)       # nothing done yet: no rate


def test_run_and_watch_reports_progress_and_a_failed_job_without_raising(tmp_path):
    good, bad = tmp_path / "good.jsonl", tmp_path / "bad.jsonl"
    _output(good, 1)
    write_two = f"import time; f=open(r'{good}','a'); f.write('{{}}\\n{{}}\\n'); f.close(); time.sleep(0.3)"
    jobs = [
        {"label": "gpu0", "cmd": [sys.executable, "-c", write_two], "output": good, "total": 3,
         "log_path": tmp_path / "good.log", "env": {"CUDA_VISIBLE_DEVICES": "0"}},
        {"label": "gpu1", "cmd": [sys.executable, "-c", "print('boom'); raise SystemExit(3)"], "output": bad,
         "total": 4, "log_path": tmp_path / "bad.log"},
    ]
    lines: list[str] = []
    import time as _time

    done = ks.run_and_watch(jobs, cwd=tmp_path, every_minutes=0.01, log=lines.append, sleep=lambda _s: _time.sleep(0.02))

    assert [(j["returncode"], j["done"], j["complete"]) for j in done] == [(0, 3, True), (3, 0, False)]
    text = "\n".join(lines)
    assert "gpu0: 3/3 (100.0%)  +2 this session" in text
    assert "gpu1: exit status 3, 0/4 -- 4 documents still to do" in text and "boom" in text
