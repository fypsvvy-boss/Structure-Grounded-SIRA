#!/usr/bin/env python3
"""How fast does corpus enrichment *stay* on this machine? (Module 1, run planning.)

A laptop is fastest in its first few minutes. Once it heats up it slows itself
down ("thermal throttling"), and a 2-day run spends almost all of its time in
that slower state. The 8-document benchmark in ``04_OPEN_QUESTIONS.md``
question 11 only ever saw the fast state. This script runs long enough to see
the slow one, and turns it into a per-source estimate for the whole corpus.

    # plugged in, nothing else using Ollama, lid open:
    caffeinate -i .venv/bin/python scripts/bench_enrichment_speed.py \
        --model qwen2.5:14b --minutes 45

Read-only as far as the project is concerned: it writes one timing log
(``--log``, default ``indexes/enrichment/bench_speed_<model>.jsonl``) and no
enrichment records. It uses the same prompt, schema, cap, seed, ``num_ctx``
and truncation as ``scripts/enrich_corpus.py``, and a *different* sample
(``--seed 7``) from the seed-42 documents the results are reported on.

"Sustained" below means: documents that started after ``--warm-minutes``
(default 30) of continuous work.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import LLMError, OllamaClient, load_config  # noqa: E402
from sira_cti.enrichment.corpus_side import truncate_document  # noqa: E402
from sira_cti.enrichment.prompts.corpus_side import REPLY_SCHEMA, SYSTEM_PROMPT, build_prompt  # noqa: E402
from sira_cti.index import load_corpus, sample_corpus  # noqa: E402


def _on_battery() -> bool:
    try:
        out = subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return False        # not macOS, or pmset missing: cannot tell
    return "Battery Power" in out


def _rate(rows: list[dict], count_key: str, seconds_key: str) -> float:
    seconds = sum(r[seconds_key] for r in rows)
    return sum(r[count_key] for r in rows) / seconds if seconds else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--model", default=None, help="override config's llm.model")
    parser.add_argument("--minutes", type=float, default=45.0, help="stop starting new documents after this long")
    parser.add_argument("--warm-minutes", type=float, default=30.0, help="'sustained' = documents started after this")
    parser.add_argument("--per-kind", type=int, default=60, help="documents sampled per type (more than will be used)")
    parser.add_argument("--seed", type=int, default=7, help="sampling seed; keep it off the reported sample's 42")
    parser.add_argument("--log", default=None)
    parser.add_argument("--allow-battery", action="store_true", help="measure anyway; macOS slows down on battery")
    args = parser.parse_args()

    if _on_battery() and not args.allow_battery:
        print("On battery power: the machine slows itself down and the numbers would be wrong. Plug in, or pass --allow-battery.")
        return 1

    cfg = load_config(args.config)
    llm_cfg, enrich_cfg, corpus_cfg = cfg["llm"], cfg["enrichment"], cfg["corpus"]
    model = args.model or llm_cfg["model"]
    log_path = Path(args.log or f"indexes/enrichment/bench_speed_{model.replace(':', '-')}.jsonl")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    client = OllamaClient(
        model=model, host=llm_cfg.get("host"), temperature=llm_cfg.get("temperature", 0.0),
        seed=llm_cfg.get("seed"), num_ctx=llm_cfg.get("num_ctx"), max_retries=0, timeout_s=600.0,
        max_new_tokens=enrich_cfg.get("max_new_tokens"), json_schema=REPLY_SCHEMA,
    )
    docs = sample_corpus(corpus_cfg["kb_dir"], corpus_cfg["kinds"], per_kind=args.per_kind, seed=args.seed)
    # Interleave the types, so each one is measured in both the fast and the
    # slow phase instead of all CVEs first and all ATT&CK entries last.
    by_source: dict[str, list] = {}
    for d in docs:
        by_source.setdefault(d.source.value, []).append(d)
    order = [d for group in zip(*by_source.values()) for d in group]

    max_doc_chars = enrich_cfg.get("max_doc_chars")
    rows: list[dict] = []
    unplugged = False
    started = time.perf_counter()
    print(f"Benchmarking {model} for {args.minutes:.0f} min -> {log_path}")
    with log_path.open("w", encoding="utf-8") as fh:
        for doc in order:
            at_s = time.perf_counter() - started
            if at_s > args.minutes * 60:
                break
            # Checked before every document, not just at the start: unplugging
            # part-way roughly halves the speed (measured 2026-10-09) and the
            # result would look like thermal throttling when it is not.
            if _on_battery() and not args.allow_battery:
                print(f"STOPPED at {at_s / 60:.1f} min: the machine went onto battery power. "
                      "Everything after this point would be a battery measurement. Plug in and run again.")
                unplugged = True
                break
            prompt = build_prompt(truncate_document(doc, max_doc_chars)[0], max_terms=enrich_cfg["max_terms_per_doc"])
            t0 = time.perf_counter()
            try:
                client.generate(prompt, system=SYSTEM_PROMPT, tag="bench")
            except LLMError as exc:
                print(f"  {doc.doc_id}: {exc}")
                continue
            timings = client.last_timings
            row = {
                "doc_id": doc.doc_id, "source": doc.source.value, "started_at_s": round(at_s, 1),
                "wall_s": round(time.perf_counter() - t0, 2),
                "prompt_tokens": client.log.records[-1].tokens.prompt,
                "completion_tokens": int(timings["eval_count"]),
                "eval_s": timings["eval_duration_s"], "prompt_eval_s": timings["prompt_eval_duration_s"],
                "load_s": timings["load_duration_s"], "context_overflow": client.last_context_overflow,
            }
            rows.append(row)
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            if len(rows) % 10 == 0:
                recent = rows[-10:]
                print(f"  {at_s / 60:5.1f} min  {len(rows):3d} docs  last 10: "
                      f"{_rate(recent, 'completion_tokens', 'eval_s'):.1f} tok/s, "
                      f"{statistics.mean(r['wall_s'] for r in recent):.1f} s/doc", flush=True)

    rows = rows[1:]     # the first call includes loading the model into memory
    if not rows:
        print("No documents completed.")
        return 1
    early = [r for r in rows if r["started_at_s"] < 600]
    warm = [r for r in rows if r["started_at_s"] >= args.warm_minutes * 60]
    print(f"\n{len(rows)} documents timed (first one dropped: model load).")
    if unplugged:
        print("  INCOMPLETE: stopped when the power source changed; no sustained figure from this run.")
    print(f"  first 10 minutes : {_rate(early, 'completion_tokens', 'eval_s'):.1f} generation tok/s"
          f"  ({len(early)} docs)")
    if not warm:
        print(f"  no document started after {args.warm_minutes:.0f} min -- run longer for a sustained figure.")
        return 0
    print(f"  after {args.warm_minutes:.0f} minutes : {_rate(warm, 'completion_tokens', 'eval_s'):.1f} generation tok/s,"
          f" {_rate(warm, 'prompt_tokens', 'prompt_eval_s'):.0f} prompt tok/s  ({len(warm)} docs)  <- sustained")

    corpus_counts = Counter(d.source.value for d in load_corpus(corpus_cfg["kb_dir"], corpus_cfg["kinds"]))
    print("\nFull-corpus estimate from the sustained phase (sampled documents; the corpus's own")
    print("length mix per type may differ a little):")
    total_h = 0.0
    for source, n in sorted(corpus_counts.items()):
        mine = [r for r in warm if r["source"] == source]
        if not mine:
            print(f"  {source:<7} {n:>5} docs   no sustained-phase documents")
            continue
        s_per_doc = statistics.mean(r["wall_s"] for r in mine)
        hours = n * s_per_doc / 3600
        total_h += hours
        print(f"  {source:<7} {n:>5} docs x {s_per_doc:5.1f} s = {hours:5.1f} h   (from {len(mine)} docs)")
    print(f"  total   {sum(corpus_counts.values()):>5} docs            = {total_h:5.1f} h  ({total_h / 24:.1f} days)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
