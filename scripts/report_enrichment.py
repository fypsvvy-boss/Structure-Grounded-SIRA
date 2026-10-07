#!/usr/bin/env python3
"""Per-run summary of a corpus-side enrichment JSONL, for comparing models.

Raw counts first, rates in brackets. The samples here are 40 documents; a
percentage on a denominator of 14 reads as if it were a measurement.

    .venv/bin/python scripts/report_enrichment.py \
        indexes/enrichment/corpus_stratified_v4_7b.jsonl \
        indexes/enrichment/corpus_stratified_v4_14b.jsonl

    # what became of the ids an older run proposed in counting runs
    .venv/bin/python scripts/report_enrichment.py \
        indexes/enrichment/corpus_stratified_v4_14b.jsonl \
        --counting-ids-from indexes/enrichment/corpus_stratified_v3_14b.jsonl

Read-only, no LLM, no index: everything comes from the JSONL, its sidecar
manifest, and the ontology graph when ``--graph`` is passed (needed only to
recompute official names, which the records already carry from corpus-v4 on).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from measure_redundancy import structural_provenance  # noqa: E402  (sibling script)

from sira_cti.common import read_jsonl  # noqa: E402
from sira_cti.enrichment.corpus_side import flag_counting_runs  # noqa: E402
from sira_cti.graph import name_tokens  # noqa: E402

PROVENANCE_ORDER = ["literal", "labelled_field", "own_id", "not_found"]


def _manifest(path: Path) -> dict:
    side = path.with_suffix(path.suffix + ".manifest.json")
    return json.loads(side.read_text()) if side.exists() else {}


def _records(path: Path, *, recompute_runs: bool):
    """Load records, optionally re-deriving ``in_counting_run`` in memory.

    Runs written before schema 1.2.0 have the field absent (so False). The
    detector is a pure function of a document's own proposals, so it can be
    applied to an old file after the fact -- which is the only way to ask what
    happened to ids a pre-1.2.0 run proposed.
    """
    for rec in read_jsonl(path):
        if recompute_runs:
            flag_counting_runs(rec.proposed_terms)
        yield rec


def summarise(path: Path) -> dict:
    """Counts for one run.

    ``in_counting_run`` is always recomputed from the proposals rather than
    read from the records. It is a pure function of a document's own proposal
    set, so recomputing gives a 1.2.0 file the identical answer it already
    stores -- and gives an older file an answer at all, which is the only way
    to compare before and after.
    """
    m = _manifest(path)
    recompute_runs = True
    out = {
        "path": str(path),
        "model": m.get("model", "?"),
        "prompt_version": m.get("prompt_version", "?"),
        "gates": m.get("gates", {}),
        "docs": 0,
        "docs_by_source": {},
        "proposed": 0,
        "accepted": 0,
        "by_reason": {},
        "by_stage": {},
        "structural_proposed": 0,
        "structural_accepted": 0,
        "structural_by_namespace": {},
        "provenance": {},
        "counting_run_total": 0,
        "counting_run_accepted": 0,
        "distance_accepted": {},
        "claimed_name_missing": 0,
        "name_pass_on_one_word": 0,
        "name_pass_total": 0,
        "parse_failures": [],
        "records_distances": m.get("prompt_version", "") not in ("corpus-v1", "corpus-v2", "corpus-v3"),
    }
    for rec in _records(path, recompute_runs=recompute_runs):
        out["docs"] += 1
        src = rec.source.value
        out["docs_by_source"][src] = out["docs_by_source"].get(src, 0) + 1
        out["proposed"] += len(rec.proposed_terms)
        out["accepted"] += len(rec.accepted_terms)
        for t in rec.rejected_terms:
            reason = t.reject_reason.value
            out["by_reason"][reason] = out["by_reason"].get(reason, 0) + 1
            stage = t.rejected_at_stage.value if t.rejected_at_stage else "unknown"
            out["by_stage"][stage] = out["by_stage"].get(stage, 0) + 1
            if reason == "llm_json_error":
                out["parse_failures"].append(rec.doc_id)

        for t in rec.structural_terms:
            out["structural_proposed"] += 1
            if t.accepted:
                out["structural_accepted"] += 1
            label = structural_provenance(t.structural_id, rec.doc_id, rec.original_text)
            out["provenance"][label] = out["provenance"].get(label, 0) + 1
            if t.in_counting_run:
                out["counting_run_total"] += 1
                if t.accepted:
                    out["counting_run_accepted"] += 1
            if t.claimed_name is None:
                out["claimed_name_missing"] += 1
            elif t.official_name:
                # A pass resting on one shared content word against a long
                # official title is the overlap coefficient's known soft spot
                # (see OntologyGraph.check_name). Counted, not corrected.
                shared = name_tokens(t.claimed_name) & name_tokens(t.official_name)
                if t.accepted:
                    out["name_pass_total"] += 1
                    if len(shared) == 1 and len(name_tokens(t.official_name)) >= 3:
                        out["name_pass_on_one_word"] += 1
            if t.accepted:
                key = "unreachable" if t.graph_distance is None else str(t.graph_distance)
                out["distance_accepted"][key] = out["distance_accepted"].get(key, 0) + 1
    return out


def _counting_ids(path: Path) -> set[tuple[str, str]]:
    """``(doc_id, structural_id)`` for every id in a counting run in ``path``."""
    found: set[tuple[str, str]] = set()
    for rec in _records(path, recompute_runs=True):
        for t in rec.structural_terms:
            if t.in_counting_run:
                found.add((rec.doc_id, t.structural_id))
    return found


def _fates(path: Path, ids: set[tuple[str, str]]) -> dict:
    """What the run at ``path`` did with each of ``ids``."""
    fate: dict[str, int] = {}
    detail: list[str] = []
    seen: set[tuple[str, str]] = set()
    for rec in read_jsonl(path):
        for t in rec.structural_terms:
            key = (rec.doc_id, t.structural_id)
            if key not in ids:
                continue
            seen.add(key)
            verdict = "accepted" if t.accepted else t.reject_reason.value
            fate[verdict] = fate.get(verdict, 0) + 1
            if verdict == "name_mismatch":
                detail.append(
                    f"{rec.doc_id} {t.structural_id}: claimed {t.claimed_name!r} "
                    f"vs official {t.official_name!r}"
                )
    fate["not_proposed_again"] = len(ids - seen)
    return {"fate": fate, "name_mismatch_detail": detail}


def _pct(n: int, d: int) -> str:
    return f" ({n / d:.0%})" if d else ""


def _print(s: dict) -> None:
    g = s["gates"]
    print(f"\n{'=' * 78}\n{s['path']}")
    print(f"  model={s['model']}  prompt={s['prompt_version']}")
    print(
        f"  gates: name_overlap={g.get('name_match_min_overlap')}  "
        f"decoding={g.get('json_mode')}  max_new_tokens={g.get('max_new_tokens')}  "
        f"df_max_ratio={g.get('df_max_ratio')}"
    )
    print(f"\n  documents: {s['docs']}  {s['docs_by_source']}")
    print(f"  terms proposed: {s['proposed']}   accepted: {s['accepted']}"
          f"{_pct(s['accepted'], s['proposed'])}")
    print("\n  rejected by reason:")
    for reason in sorted(s["by_reason"]):
        print(f"    {reason:<16} {s['by_reason'][reason]:>4}")
    print("  rejected by stage:")
    for stage in ("parse", "graph", "name", "df"):
        if stage in s["by_stage"]:
            print(f"    {stage:<16} {s['by_stage'][stage]:>4}")

    sp, sa = s["structural_proposed"], s["structural_accepted"]
    print(f"\n  structural ids proposed: {sp}   accepted: {sa}{_pct(sa, sp)}")
    print("  where each one could have come from:")
    for label in PROVENANCE_ORDER:
        if label in s["provenance"]:
            print(f"    {label:<16} {s['provenance'][label]:>4}{_pct(s['provenance'][label], sp)}")
    copied = sum(s["provenance"].get(k, 0) for k in ("literal", "labelled_field", "own_id"))
    print(f"    -> copied {copied}{_pct(copied, sp)}, "
          f"generated {s['provenance'].get('not_found', 0)}"
          f"{_pct(s['provenance'].get('not_found', 0), sp)}")

    print(f"\n  in a counting run (>=3 consecutive): {s['counting_run_total']}"
          f"{_pct(s['counting_run_total'], sp)}, of which accepted "
          f"{s['counting_run_accepted']}")
    print(f"  structural proposals with no claimed name: {s['claimed_name_missing']}")
    print(f"  name-check passes resting on one shared word: "
          f"{s['name_pass_on_one_word']}/{s['name_pass_total']}")

    print("  ontology distance of accepted ids from the document's own node:")
    if not s["records_distances"]:
        print("    (not recorded -- this run predates schema 1.2.0)")
    elif not s["distance_accepted"]:
        print("    (none accepted)")
    for key in sorted(s["distance_accepted"], key=lambda k: (k == "unreachable", k)) if s["records_distances"] else []:
        label = "not in graph / no path" if key == "unreachable" else f"{key} hop(s)"
        print(f"    {label:<24} {s['distance_accepted'][key]:>4}")
    if s["parse_failures"]:
        print(f"  documents recorded as unparseable: {s['parse_failures']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("enrichment_jsonl", nargs="+", type=Path)
    ap.add_argument("--counting-ids-from", type=Path, default=None,
                    help="an earlier run; report what the given run(s) did with its counting-run ids")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    summaries = [summarise(p) for p in args.enrichment_jsonl]
    if args.json:
        print(json.dumps(summaries, indent=2))
    else:
        for s in summaries:
            _print(s)

    if args.counting_ids_from:
        ids = _counting_ids(args.counting_ids_from)
        print(f"\n{'=' * 78}")
        print(f"Counting-run ids in {args.counting_ids_from}: {len(ids)}")
        for p in args.enrichment_jsonl:
            r = _fates(p, ids)
            print(f"\n  what {p.name} did with them:")
            for verdict, n in sorted(r["fate"].items(), key=lambda kv: -kv[1]):
                print(f"    {verdict:<22} {n:>4}")
            if r["name_mismatch_detail"]:
                print("    the name mismatches among them:")
                for line in r["name_mismatch_detail"]:
                    print(f"      - {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
