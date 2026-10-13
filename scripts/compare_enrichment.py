#!/usr/bin/env python3
"""Did two runs of the same documents give the same replies? (Same model, two machines.)

Written for the cross-hardware check: the 40-document sample enriched on a
Kaggle GPU against the same sample enriched on the Mac. Two questions:

1. **How many replies are identical?** For each document, the proposals the
   model made -- term, kind and claimed name, in order -- are compared. (The
   raw reply text is not saved; the proposals are everything the pipeline
   kept of it.)
2. **Do the table numbers move?** Every count ``report_enrichment.py`` prints
   is worked out for both files, and the ones that differ are listed.

    .venv/bin/python scripts/compare_enrichment.py \
        indexes/enrichment/corpus_stratified_v4_14b_sections-v2.jsonl \
        indexes/enrichment/corpus_stratified_v4_14b_sections-v2_kaggle.jsonl

The first file is the reference. Read-only, no LLM, no index. Exit status is
0 whatever the answer: a difference is a finding to write down, not an error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from merge_enrichment import method_settings  # noqa: E402  (sibling script)
from report_enrichment import _manifest, summarise  # noqa: E402  (sibling script)

from sira_cti.common import read_jsonl  # noqa: E402

NOT_NUMBERS = {"path", "model", "prompt_version", "gates", "parse_failures", "records_distances"}
"""Entries of ``report_enrichment.summarise`` that are labels, not counts."""


def proposals(record) -> list[tuple[str, str, Any]]:
    """What the model proposed for one document, as saved: (term, kind, claimed name)."""
    return [(t.term, t.kind.value, t.claimed_name) for t in record.proposed_terms]


def table_numbers(summary: dict[str, Any]) -> dict[str, int]:
    """Every count in a run summary, flattened to ``label -> number``."""
    out: dict[str, int] = {}
    for key, value in summary.items():
        if key in NOT_NUMBERS:
            continue
        if isinstance(value, dict):
            for sub, n in value.items():
                out[f"{key}.{sub}"] = n
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            out[key] = value
    return out


def compare(reference: Path, other: Path) -> dict[str, Any]:
    """Everything the report prints, as data."""
    ref = {r.doc_id: r for r in read_jsonl(reference)}
    oth = {r.doc_id: r for r in read_jsonl(other)}
    both = [d for d in ref if d in oth]

    differing = []
    for doc_id in both:
        a, b = proposals(ref[doc_id]), proposals(oth[doc_id])
        if a == b:
            continue
        only_ref = [p for p in a if p not in b]
        only_other = [p for p in b if p not in a]
        differing.append({
            "doc_id": doc_id,
            "source": ref[doc_id].source.value,
            "proposals": [len(a), len(b)],
            "same_proposals_different_order": not only_ref and not only_other,
            "only_in_reference": only_ref,
            "only_in_other": only_other,
            "accepted_ids": [
                sorted(t.structural_id for t in rec.accepted_terms if t.structural_id)
                for rec in (ref[doc_id], oth[doc_id])
            ],
        })

    manifests = [_manifest(reference), _manifest(other)]
    settings = [method_settings(m) for m in manifests]
    settings_differ = {
        key: [s.get(key) for s in settings]
        for key in sorted(set(settings[0]) | set(settings[1]))
        if key != "model_digest" and settings[0].get(key) != settings[1].get(key)
    }
    same_docs = len(both) == len(ref) == len(oth)
    numbers = [table_numbers(summarise(p)) for p in (reference, other)]
    moved = {
        key: [numbers[0].get(key, 0), numbers[1].get(key, 0)]
        for key in sorted(set(numbers[0]) | set(numbers[1]))
        if numbers[0].get(key, 0) != numbers[1].get(key, 0)
    }
    return {
        "reference": str(reference),
        "other": str(other),
        # A merged file's manifest lists several machines; the last one is shown.
        "machines": [m.get("machine") or (m.get("machines") or [None])[-1] for m in manifests],
        "model": [m.get("model") for m in manifests],
        "model_digest": [m.get("model_digest") for m in manifests],
        "settings_that_differ": settings_differ,
        "documents": {
            "reference": len(ref), "other": len(oth), "in_both": len(both),
            "only_in_reference": [d for d in ref if d not in oth],
            "only_in_other": [d for d in oth if d not in ref],
        },
        "replies_identical": len(both) - len(differing),
        "replies_compared": len(both),
        "replies_differing": differing,
        "same_documents": same_docs,
        "table_numbers": numbers,
        "table_numbers_moved": moved,
    }


def _machine_label(machine: Any) -> str:
    if not isinstance(machine, dict):
        return "(machine not recorded)"
    return f"{machine.get('hostname')}  {machine.get('platform')}  gpu={machine.get('gpu')}"


def _print(result: dict[str, Any]) -> None:
    print(f"reference: {result['reference']}\n    {_machine_label(result['machines'][0])}")
    print(f"other:     {result['other']}\n    {_machine_label(result['machines'][1])}")

    ref_digest, other_digest = result["model_digest"]
    if ref_digest and other_digest:
        same = "the same" if ref_digest == other_digest else "DIFFERENT -- these are not the same weights"
        print(f"\nmodel digest: {same}  ({ref_digest[:12]} / {other_digest[:12]})")
    else:
        where = "either manifest" if not (ref_digest or other_digest) else "one of the manifests"
        print(f"\nmodel digest: not recorded in {where} "
              f"({(ref_digest or '-')[:12]} / {(other_digest or '-')[:12]}); "
              "compare `ollama list` on the two machines by hand")
    if result["settings_that_differ"]:
        print("settings that DIFFER between the two runs (so a difference below may not be the hardware):")
        for key, (a, b) in result["settings_that_differ"].items():
            print(f"    {key}: {a!r} / {b!r}")
    else:
        print("settings: the same in both manifests (config, prompt, gates, sampling, seed, context)")

    docs = result["documents"]
    print(f"\ndocuments: {docs['reference']} / {docs['other']}, {docs['in_both']} in both")
    for label in ("only_in_reference", "only_in_other"):
        if docs[label]:
            print(f"    {label.replace('_', ' ')}: {docs[label]}")

    print(f"\nREPLIES IDENTICAL: {result['replies_identical']} of {result['replies_compared']}")
    for d in result["replies_differing"]:
        note = "  (same proposals, different order)" if d["same_proposals_different_order"] else ""
        print(f"  {d['doc_id']} ({d['source']}): {d['proposals'][0]} / {d['proposals'][1]} proposals{note}")
        for label, key in (("reference only", "only_in_reference"), ("other only", "only_in_other")):
            for term, kind, name in d[key]:
                print(f"      {label}: {term!r} [{kind}]" + (f" claimed {name!r}" if name else ""))
        if d["accepted_ids"][0] != d["accepted_ids"][1]:
            print(f"      accepted ids: {d['accepted_ids'][0]} / {d['accepted_ids'][1]}")

    if not result["same_documents"]:
        print("\nTABLE NUMBERS: not comparable -- the two files do not hold the same documents.")
        return
    moved = result["table_numbers_moved"]
    total = len(set(result["table_numbers"][0]) | set(result["table_numbers"][1]))
    if not moved:
        print(f"\nTABLE NUMBERS: none of the {total} counts moves.")
        return
    print(f"\nTABLE NUMBERS: {len(moved)} of {total} counts move (reference -> other):")
    for key, (a, b) in moved.items():
        print(f"  {key:<44} {a:>5} -> {b:<5} ({b - a:+})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reference", type=Path, help="the run to compare against (the Mac file)")
    ap.add_argument("other", type=Path, help="the run being checked (the Kaggle file)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    result = compare(args.reference, args.other)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
