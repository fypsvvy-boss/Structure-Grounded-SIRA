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

That headline rule is kept exactly as the question-7 numbers were measured,
so old and new runs stay comparable. It undercounts copied *structural* ids,
so the script also reports the rule Module 1 approved for the gate
(``docs/proposals/already-in-document-gate.md``, decision 1): a structural id
is already present if it is written in the text **or** named by a labelled id
field in it. And it classifies every structural proposal (accepted or not) by
where it could have come from, first match wins:

* ``literal``        -- written in the text (``CWE-331``);
* ``labelled_field`` -- named by an id field in the entry's JSON, with the
                        catalogue taken from the field, not guessed from the
                        number: ``"@CWE_ID": "120"`` -> ``CWE-120``;
                        ``"@CAPEC_ID"``/``"@Exclude_ID"`` -> ``CAPEC-``;
                        ``"Entry_ID"`` -> ``T``, but only inside an
                        ``"@Taxonomy_Name": "ATTACK"`` mapping (WASC and OWASP
                        mappings use ``Entry_ID`` too, for unrelated codes).
                        In ``corpus_kb`` only CAPEC entries have these fields;
* ``own_id``         -- the document's own id. Up to ``corpus-v1`` the prompt
                        header supplied it; from ``corpus-v3`` it does not, so an
                        own-id proposal means the model recalled it itself.
                        Not part of the gate (decision 2), counted separately;
* ``not_found``      -- none of the above; the only candidates for a genuine
                        inference rather than a transcription.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import TermKind, load_config, read_jsonl
from sira_cti.graph import extract_structural_ids

_NON_ALNUM = re.compile(r"[^0-9a-z]+")


def _squash(text: str) -> str:
    """Lowercase, and collapse every run of punctuation/whitespace to one space."""
    return f" {_NON_ALNUM.sub(' ', text.lower()).strip()} "


def structural_id_in_text(structural_id: str, text: str) -> bool:
    return _squash(structural_id) in _squash(text)


_LABELLED_FIELDS = [
    (re.compile(r'"@CWE_ID"\s*:\s*"(\d+)"'), "CWE-"),
    (re.compile(r'"@(?:CAPEC|Exclude)_ID"\s*:\s*"(\d+)"'), "CAPEC-"),
    (re.compile(r'\{[^{}]*"@Taxonomy_Name"\s*:\s*"ATTACK"[^{}]*"Entry_ID"\s*:\s*"(\d{4}(?:\.\d{3})?)"'), "T"),
]


def labelled_ids_in_text(text: str) -> set[str]:
    """Catalogue ids named by labelled JSON fields, e.g. ``"@CWE_ID": "120"`` -> ``CWE-120``."""
    return {prefix + str(int(n)) if prefix != "T" else prefix + n
            for pattern, prefix in _LABELLED_FIELDS for n in pattern.findall(text)}


def already_in_document_structural(structural_id: str, text: str) -> bool:
    """Decision 1's rule for a structural id: written in the text, or named by a labelled field."""
    return structural_id_in_text(structural_id, text) or structural_id in labelled_ids_in_text(text)


def structural_provenance(structural_id: str, doc_id: str, text: str) -> str:
    # A malformed proposal keeps the model's raw string as its structural_id
    # ("CWE-331: Use of Inadequate Randomness"); recover the id inside it first,
    # or it can never match anything and gets miscounted as a novel inference.
    found = extract_structural_ids(structural_id)
    if found:
        structural_id = found[0].canonical
    if structural_id_in_text(structural_id, text):
        return "literal"
    if structural_id in labelled_ids_in_text(text):
        return "labelled_field"
    if structural_id == doc_id:
        return "own_id"
    return "not_found"


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
    gate_present = 0   # accepted terms decision 1's gate rule would reject
    provenance: dict[str, dict[str, int]] = {}   # source -> provenance label -> count
    not_found: list[tuple[str, str]] = []
    for rec in read_jsonl(args.enrichment_jsonl):
        for t in rec.structural_terms:
            label = structural_provenance(t.structural_id, rec.doc_id, rec.original_text)
            row = provenance.setdefault(rec.source.value, {})
            row[label] = row.get(label, 0) + 1
            if label == "not_found":
                not_found.append((rec.doc_id, t.structural_id))
        doc_tokens = reader.analyze(rec.original_text)
        for t in rec.accepted_terms:
            if t.kind is TermKind.STRUCTURAL:
                present = structural_id_in_text(t.structural_id, rec.original_text)
                gate_present += already_in_document_structural(t.structural_id, rec.original_text)
            else:
                present = contains_contiguous(doc_tokens, reader.analyze(t.term))
                gate_present += present
            cell = table.setdefault((rec.source.value, t.kind.value), [0, 0])
            cell[0] += present
            cell[1] += 1

    total_present = sum(v[0] for v in table.values())
    total_accepted = sum(v[1] for v in table.values())

    if args.json:
        print(json.dumps({
            "present": total_present,
            "accepted": total_accepted,
            "gate_rule_present": gate_present,
            "by_source_kind": {f"{s}/{k}": v for (s, k), v in sorted(table.items())},
            "structural_provenance": provenance,
            "structural_not_found": not_found,
        }))
        return 0

    print(f"{args.enrichment_jsonl}")
    rate = f"{total_present / total_accepted:.1%}" if total_accepted else "n/a"
    print(f"  accepted terms already in their own document: {total_present}/{total_accepted} ({rate})")
    gate_rate = f"{gate_present / total_accepted:.1%}" if total_accepted else "n/a"
    print(f"  ...under the approved gate rule (adds labelled id fields): {gate_present}/{total_accepted} ({gate_rate})\n")
    for source in sorted({s for s, _ in table}):
        rows = {k: v for (s, k), v in table.items() if s == source}
        p, a = sum(v[0] for v in rows.values()), sum(v[1] for v in rows.values())
        print(f"  {source}: {p}/{a} already present")
        for kind, (kp, ka) in sorted(rows.items()):
            print(f"    {kind:<12} {kp:>3}/{ka:<3}")

    print("\n  Structural proposals by where they could have come from (all, not just accepted):")
    for source, row in sorted(provenance.items()):
        print(f"    {source:<7} " + "  ".join(f"{k}={v}" for k, v in sorted(row.items())))
    print(f"  not_found (candidate genuine inferences): {not_found or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
