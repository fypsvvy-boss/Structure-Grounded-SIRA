#!/usr/bin/env python3
"""What ``notebooks/kaggle_stage1.ipynb`` does, kept here so it can be tested.

The notebook installs things and calls these functions; nothing in it is
clever. Everything a Kaggle session has to work out lives here:

* where the uploaded corpus files are, and putting them where the config
  expects them (:func:`stage_inputs`);
* picking up the output of an earlier session (:func:`restore_previous`);
* how many documents and hours each GPU's share is (:func:`plan_shares`);
* how long a process may run before the session is switched off
  (:func:`stop_after_minutes`);
* starting one Ollama server per GPU and checking the model really is on the
  GPU (:func:`start_ollama`, :func:`warm_up`);
* running the enrichment processes side by side and printing progress
  (:func:`run_and_watch`).

Not a command-line tool. See ``docs/kaggle-run.md``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sira_cti.common import OllamaClient, read_jsonl  # noqa: E402
from sira_cti.index.corpus import load_kb, order_kinds, parse_shard, shard_of  # noqa: E402

SIDECARS = (".manifest.json", ".failures.jsonl", ".raw_failures.jsonl")

MAC_SECONDS_PER_DOC = {"cwe": 48.2, "capec": 39.6, "mitre": 40.7, "cve": 45.1}
"""Sustained seconds per document on the Mac, by source: the measured table in
``docs/proposals/module1-freeze.md`` ("Time and cost"). Each rests on only 5
documents, so +/-15%. Used to size the two GPUs' shares against each other,
not to predict Kaggle's clock time -- a T4 is not the Mac."""

SOURCE_TO_KIND = {"attack": "mitre"}     # a record's ``source`` vs corpus_kb's file name


class StageError(RuntimeError):
    """Something the session needs is missing or is not what was expected."""


# -- the uploaded corpus ---------------------------------------------------------------


def _as_list(value: Any) -> list[str]:
    return [value] if isinstance(value, str) else list(value)


def required_inputs(cfg: dict[str, Any]) -> tuple[list[str], str, str]:
    """``(files, cwe_path, base_index_dir)`` the enrichment run reads, as the config names them."""
    kb = cfg["corpus"]["kb_dir"].rstrip("/")
    graph = cfg["graph"]
    files = [f"{kb}/{kind}.jsonl" for kind in cfg["corpus"]["kinds"]]
    files += _as_list(graph["attack_path"]) + [graph["capec_path"]]
    return files, graph["cwe_path"], cfg["index"]["base_dir"].rstrip("/")


def _find_file(input_root: Path, relative: str) -> Optional[Path]:
    """The uploaded copy of ``relative``: by its path first, then by its name alone."""
    name = Path(relative).name
    matches = sorted(p for p in input_root.rglob(name) if p.is_file())
    exact = [p for p in matches if p.as_posix().endswith("/" + relative)]
    if exact:
        return exact[0]
    if len(matches) > 1:
        raise StageError(
            f"More than one file named {name} under {input_root} and none at .../{relative}:\n"
            + "\n".join(f"  {m}" for m in matches)
        )
    return matches[0] if matches else None


def _stage_cwe(input_root: Path, relative: str, target: Path) -> Optional[str]:
    """Put the CWE catalogue at ``target`` (a ``.zip``), whatever form the upload took.

    Kaggle may unpack an uploaded archive, so the zip the config points at can
    arrive as the XML file it contained. The loader reads either, but the
    config names the ``.zip`` and the config must not be edited (its hash
    identifies the run) -- so an unpacked catalogue is zipped back up.
    """
    found = _find_file(input_root, relative)
    if found is not None and zipfile.is_zipfile(found):
        shutil.copyfile(found, target)
        return f"{found} (zip)"
    xmls = sorted(
        p for p in input_root.rglob("cwec_*.xml*")
        if p.is_file() and not zipfile.is_zipfile(p) and p.stat().st_size > 0
    )
    if not xmls:
        return None
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(xmls[0], arcname="cwec_latest.xml")
    return f"{xmls[0]} (unpacked by Kaggle; zipped again)"


def _find_base_index(input_root: Path) -> Optional[Path]:
    for manifest in sorted(input_root.rglob("manifest.json")):
        try:
            if json.loads(manifest.read_text(encoding="utf-8")).get("kind") == "base":
                return manifest.parent
        except (OSError, ValueError):
            continue
    return None


def stage_inputs(input_root: str | Path, repo_dir: str | Path, cfg: dict[str, Any]) -> list[str]:
    """Copy the uploaded corpus, ontology files and base index into the checkout.

    They are gitignored, so a fresh clone has none of them. Returns one line
    per item saying where it was found; raises :class:`StageError` listing
    everything that is missing.
    """
    input_root, repo_dir = Path(input_root), Path(repo_dir)
    files, cwe_path, base_dir = required_inputs(cfg)
    report: list[str] = []
    missing: list[str] = []

    for relative in files:
        found = _find_file(input_root, relative)
        if found is None:
            missing.append(relative)
            continue
        target = repo_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(found, target)
        report.append(f"{relative}  <-  {found}")

    cwe_target = repo_dir / cwe_path
    cwe_target.parent.mkdir(parents=True, exist_ok=True)
    cwe_from = _stage_cwe(input_root, cwe_path, cwe_target)
    if cwe_from is None:
        missing.append(cwe_path)
    else:
        report.append(f"{cwe_path}  <-  {cwe_from}")

    index = _find_base_index(input_root)
    if index is None:
        missing.append(f"{base_dir}/ (the base index: a folder with manifest.json saying kind=base)")
    else:
        target = repo_dir / base_dir
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(index, target)
        report.append(f"{base_dir}/  <-  {index}/")

    if missing:
        raise StageError(
            f"Not found under {input_root} -- is the corpus dataset attached?\n"
            + "\n".join(f"  {m}" for m in missing)
        )
    return report


def check_base_index(base_dir: str | Path, *, total_docs: int, doc_freqs: dict[str, int]) -> list[str]:
    """Confirm the uploaded index answers the way the Mac's does.

    The ``too_common`` gate reads document frequencies from this index through
    Lucene. A different index, or a Pyserini that analyses text differently,
    would change verdicts without changing a single reply.
    """
    from sira_cti.index import LuceneDFLookup

    lookup = LuceneDFLookup(base_dir)
    lines = [f"documents: {lookup.total_docs} (expected {total_docs})"]
    wrong = lookup.total_docs != total_docs
    for term, expected in doc_freqs.items():
        got = lookup.doc_freq(term)
        lines.append(f"document frequency of {term!r}: {got} (expected {expected})")
        wrong = wrong or got != expected
    if wrong:
        raise StageError("The base index does not match the Mac's:\n" + "\n".join(f"  {x}" for x in lines))
    return lines


# -- carrying on from an earlier session ---------------------------------------------


def count_lines(path: str | Path) -> int:
    """Records in an output file (0 if it does not exist yet)."""
    path = Path(path)
    if not path.exists():
        return 0
    with path.open("rb") as fh:
        return sum(1 for line in fh if line.strip())


def restore_previous(input_root: str | Path, working_dir: str | Path, names: Iterable[str]) -> list[str]:
    """Copy an earlier session's output files into the working folder, to resume them.

    Attached inputs are read-only and a resume appends, so the files have to
    be copied. If several attached inputs hold a file of the same name, the
    one with the most records wins. A file already in the working folder with
    at least as many records is left alone. The manifest and failure logs come
    along with each file -- a resume without the manifest is refused.
    """
    input_root, working_dir = Path(input_root), Path(working_dir)
    working_dir.mkdir(parents=True, exist_ok=True)
    report: list[str] = []
    for name in names:
        candidates = [p for p in input_root.rglob(name) if p.is_file()] if input_root.exists() else []
        target = working_dir / name
        if not candidates:
            report.append(f"{name}: no earlier output attached -- {count_lines(target)} records in the working folder")
            continue
        best = max(candidates, key=count_lines)
        have, found = count_lines(target), count_lines(best)
        if target.exists() and have >= found:
            report.append(f"{name}: keeping the working copy ({have} records; attached copy has {found})")
            continue
        if not best.with_name(best.name + ".manifest.json").exists():
            raise StageError(f"{best} has no .manifest.json beside it; a resume would be refused.")
        shutil.copyfile(best, target)
        for suffix in SIDECARS:
            side = best.with_name(best.name + suffix)
            if side.exists():
                shutil.copyfile(side, working_dir / (name + suffix))
        report.append(f"{name}: resuming from {best} ({found} records)")
    return report


# -- sizing each GPU's share -----------------------------------------------------------


def plan_shares(
    kb_dir: str | Path, plan: list[dict[str, Any]], configured_kinds: Iterable[str],
    seconds_per_doc: dict[str, float],
) -> list[dict[str, Any]]:
    """For each process in ``plan``: its documents per kind and its estimated hours.

    ``plan`` entries carry ``kinds`` (as for ``--kinds``) and optionally
    ``shard`` (as for ``--shard``). Also checks the plan as a whole: raises
    :class:`StageError` if any document is in two shares or in none.
    """
    configured = list(configured_kinds)
    ids = {kind: [d.doc_id for d in load_kb(kb_dir, kind)] for kind in configured}
    owners: dict[str, int] = {}
    shares: list[dict[str, Any]] = []
    for entry in plan:
        shard = parse_shard(entry.get("shard"))
        docs: dict[str, int] = {}
        for kind in order_kinds(entry["kinds"], configured):
            mine = [d for d in ids[kind] if shard is None or shard_of(d, shard[1]) == shard[0]]
            docs[kind] = len(mine)
            for doc_id in mine:
                owners[doc_id] = owners.get(doc_id, 0) + 1
        hours = {kind: n * seconds_per_doc[kind] / 3600 for kind, n in docs.items()}
        shares.append({
            **entry, "documents": sum(docs.values()), "documents_by_kind": docs,
            "hours": sum(hours.values()), "hours_by_kind": hours,
        })
    everything = [d for kind in configured for d in ids[kind]]
    twice = [d for d, n in owners.items() if n > 1]
    never = [d for d in everything if d not in owners]
    if twice or never:
        raise StageError(
            f"The plan does not cover every document exactly once: {len(twice)} in two shares "
            f"(e.g. {twice[:3]}), {len(never)} in none (e.g. {never[:3]})."
        )
    return shares


def seconds_per_doc_from(sample_jsonl: str | Path) -> dict[str, float]:
    """Mean seconds per document by kind, measured from a finished sample run."""
    totals: dict[str, list[float]] = {}
    for record in read_jsonl(sample_jsonl):
        kind = SOURCE_TO_KIND.get(record.source.value, record.source.value)
        totals.setdefault(kind, []).append(record.latency_ms / 1000)
    return {kind: sum(v) / len(v) for kind, v in totals.items()}


def stop_after_minutes(session_limit_hours: float, safety_minutes: float, elapsed_seconds: float) -> float:
    """Minutes a process started now may run and still end ``safety_minutes`` before the limit.

    The session clock started before the installs and the model download, so
    what they used is taken off.
    """
    minutes = session_limit_hours * 60 - safety_minutes - elapsed_seconds / 60
    if minutes < 5:
        raise StageError(
            f"Only {minutes:.0f} minutes are left before the safety margin -- not enough to start a run."
        )
    return round(minutes, 1)


def enrich_command(
    python: str, entry: dict[str, Any], output: str | Path, *, extra_args: Iterable[str] = (),
    stop_after: Optional[float] = None,
) -> list[str]:
    """The ``enrich_corpus.py`` command line for one process of the plan."""
    cmd = [python, "scripts/enrich_corpus.py", *extra_args,
           "--host", f"http://127.0.0.1:{entry['port']}", "--output", str(output)]
    if entry.get("kinds"):
        cmd += ["--kinds", entry["kinds"]]
    if entry.get("shard"):
        cmd += ["--shard", entry["shard"]]
    if stop_after is not None:
        cmd += ["--stop-after-minutes", f"{stop_after:g}"]
    return cmd


# -- Ollama: one server per GPU --------------------------------------------------------


def start_ollama(gpu: int, port: int, log_path: str | Path, *, wait_seconds: float = 60) -> subprocess.Popen:
    """Start an Ollama server that can see only GPU ``gpu``, listening on ``port``.

    ``CUDA_VISIBLE_DEVICES`` is what pins it: the server cannot use a card it
    cannot see. One request at a time and the model never unloaded, so the
    two servers behave like the single one on the Mac.
    """
    env = {
        **os.environ,
        "CUDA_VISIBLE_DEVICES": str(gpu),
        "OLLAMA_HOST": f"127.0.0.1:{port}",
        "OLLAMA_KEEP_ALIVE": "-1",
        "OLLAMA_NUM_PARALLEL": "1",
        "OLLAMA_MAX_LOADED_MODELS": "1",
    }
    log = open(log_path, "ab")
    process = subprocess.Popen(["ollama", "serve"], env=env, stdout=log, stderr=subprocess.STDOUT)
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        if process.poll() is not None:
            raise StageError(f"The Ollama server for GPU {gpu} exited at once -- see {log_path}")
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/version", timeout=2).read()
            return process
        except OSError:
            time.sleep(1)
    raise StageError(f"The Ollama server for GPU {gpu} did not answer on port {port} -- see {log_path}")


def warm_up(port: int, model: str, *, num_ctx: Optional[int], timeout_s: float = 900) -> float:
    """Load ``model`` on the server at ``port`` and return how much of it is on the GPU (1.0 = all).

    Loaded with the same context size the run will ask for, so the first real
    document does not trigger a reload.
    """
    client = OllamaClient(
        model=model, host=f"http://127.0.0.1:{port}", num_ctx=num_ctx, seed=42, max_new_tokens=4,
        timeout_s=timeout_s, max_retries=0,
    )
    client.generate("Reply with the word OK.", tag="warm_up")
    fraction = client.gpu_fraction()
    return 0.0 if fraction is None else fraction


def gpu_report() -> list[str]:
    """One line per NVIDIA card: index, name, memory in use, load."""
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=index,name,memory.used,memory.total,utilization.gpu",
             "--format=csv,noheader"], capture_output=True, text=True, check=True, timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"nvidia-smi failed: {exc}"]
    return [line.strip() for line in out.splitlines() if line.strip()]


# -- running the processes and watching them -------------------------------------------


def progress_line(label: str, done: int, total: int, done_at_start: int, elapsed_s: float) -> str:
    """``label: 1200/2999 (40.0%)  +300 this session  82/h  about 21.9 h left``."""
    this_session = done - done_at_start
    line = f"{label}: {done}/{total} ({done / total:.1%})  +{this_session} this session" if total else f"{label}: {done}"
    if this_session > 0 and elapsed_s > 0:
        per_hour = this_session / (elapsed_s / 3600)
        line += f"  {per_hour:.0f}/h  about {(total - done) / per_hour:.1f} h left at this rate"
    return line


def run_and_watch(
    jobs: list[dict[str, Any]], *, cwd: str | Path, every_minutes: float = 10,
    log: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep,
) -> list[dict[str, Any]]:
    """Start every job, print progress until all have ended, and never raise.

    Each job: ``label``, ``cmd``, ``output``, ``total`` (documents in its
    share), ``log_path`` and optionally ``env``. A job that fails is reported,
    not raised: the other job's work, and whatever this one wrote before
    failing, must still be saved when the notebook finishes.
    """
    started = time.time()
    for job in jobs:
        job["done_at_start"] = count_lines(job["output"])
        handle = open(job["log_path"], "ab")
        job["process"] = subprocess.Popen(
            job["cmd"], cwd=str(cwd), env={**os.environ, **job.get("env", {})},
            stdout=handle, stderr=subprocess.STDOUT,
        )
        log(f"started {job['label']}: {' '.join(job['cmd'])}")

    while any(job["process"].poll() is None for job in jobs):
        waited = 0.0
        while waited < every_minutes * 60 and any(job["process"].poll() is None for job in jobs):
            sleep(5)
            waited += 5
        elapsed = time.time() - started
        log(f"--- {elapsed / 60:.0f} min ---")
        for job in jobs:
            log("  " + progress_line(job["label"], count_lines(job["output"]), job["total"],
                                     job["done_at_start"], elapsed))
        for line in gpu_report():
            log("  gpu " + line)

    for job in jobs:
        job["returncode"] = job["process"].returncode
        job["done"] = count_lines(job["output"])
        job["complete"] = job["done"] >= job["total"]
        tail = Path(job["log_path"]).read_text(encoding="utf-8", errors="replace").splitlines()[-12:]
        state = "COMPLETE" if job["complete"] else f"{job['total'] - job['done']} documents still to do"
        log(f"\n{job['label']}: exit status {job['returncode']}, {job['done']}/{job['total']} -- {state}")
        for line in tail:
            log("    " + line)
    return jobs
