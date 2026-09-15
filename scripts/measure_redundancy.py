#!/usr/bin/env python3
"""Measure how many accepted enrichment terms were already in their own document.

This is the measurement behind ``docs/04_OPEN_QUESTIONS.md`` question 7 (and
the rule the proposed ``already_in_document`` gate would enforce -- see
``docs/proposals/already-in-document-gate.md``). It reads an enrichment JSONL
and the base index's analyzer; it makes no LLM calls and changes nothing.

    .venv/bin/python scripts/measure_redundancy.py indexes/enrichment/corpus.jsonl

A term counts as "already present" if:

* **structural** -- its canonical id (``structural_id``) appears in the
  document text as a whole token, ignoring punctuation (so ``CWE-331`` matches
  ``CWE 331`` or ``"CWE-331"``, but not ``CWE-3310``);
* **anything else** -- its analyzed token sequence appears as a *contiguous*
  run in the document's analyzed tokens.

Contiguous, not set membership: ``CWE-331`` analyzes to ``["cwe", "331"]``,
and both tokens occur separately in most CVE records, so a set check reports
redundancy that isn't there.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import TermKind, load_config, read_jsonl

_NON_ALNUM = re.compile(r"[^0-9a-z]+")


def _squash(text: str) -> str:
    """Lowercase, and collapse every run of punctuation/whitespace to one space."""
    return f" {_NON_ALNUM.sub(' ', text.lower()).strip()} "


def structural_id_in_text(structural_id: str, text: str) -> bool:
    return _squash(structural_id) in _squash(text)


def contains_contiguous(haystack: list[str], needle: list[str]) -> bool:
    if not needle or len(needle) > len(haystack):
        return False
    n = len(needle)
    first = needle[0]
    return any(haystack[i] == first and haystack[i : i + n] == needle for i in range(len(haystack) - n + 1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("enrichment_jsonl")
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--json", action="store_true", help="print machine-readable totals only")
    args = parser.parse_args()

    from pyserini.index.lucene import LuceneIndexReader

    reader = LuceneIndexReader(str(load_config(args.config)["index"]["base_dir"]))

    # (source, kind) -> [present, accepted]
    table: dict[tuple[str, str], list[int]] = {}
    for rec in read_jsonl(args.enrichment_jsonl):
        doc_tokens = reader.analyze(rec.original_text)
        for t in rec.accepted_terms:
            if t.kind is TermKind.STRUCTURAL:
                present = structural_id_in_text(t.structural_id, rec.original_text)
            else:
                present = contains_contiguous(doc_tokens, reader.analyze(t.term))
            cell = table.setdefault((rec.source.value, t.kind.value), [0, 0])
            cell[0] += present
            cell[1] += 1

    total_present = sum(v[0] for v in table.values())
    total_accepted = sum(v[1] for v in table.values())

    if args.json:
        print(json.dumps({
            "present": total_present,
            "accepted": total_accepted,
            "by_source_kind": {f"{s}/{k}": v for (s, k), v in sorted(table.items())},
        }))
        return 0

    print(f"{args.enrichment_jsonl}")
    rate = f"{total_present / total_accepted:.1%}" if total_accepted else "n/a"
    print(f"  accepted terms already in their own document: {total_present}/{total_accepted} ({rate})\n")
    for source in sorted({s for s, _ in table}):
        rows = {k: v for (s, k), v in table.items() if s == source}
        p, a = sum(v[0] for v in rows.values()), sum(v[1] for v in rows.values())
        print(f"  {source}: {p}/{a} already present")
        for kind, (kp, ka) in sorted(rows.items()):
            print(f"    {kind:<12} {kp:>3}/{ka:<3}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
