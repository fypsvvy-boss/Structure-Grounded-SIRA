#!/usr/bin/env python3
"""RQ4 numbers for one corpus-side enrichment file: what was rejected, where, and why.

RQ4 asks how often the model proposes vocabulary the checks have to throw
away. Every proposal stays in the record with its verdict, so this is a
count over the file -- no model, no index, no graph.

    .venv/bin/python scripts/rq4_breakdown.py indexes/enrichment/corpus_full_v4_14b.jsonl

Sections, in order:

1. records and the run's settings, as the manifest gives them;
2. per source document type: proposals, acceptances, rejections by stage
   (``parse`` / ``graph`` / ``name`` / ``df``) and by reason;
3. proposals by term kind (colloquial, product, ... structural);
4. structural ids by document type x the catalogue the id belongs to, with
   the name-mismatch rate: name mismatches / ids that passed the existence
   check and so reached the name check;
5. ``malformed_id`` on CVE documents: the model proposing a CVE id as a
   structural term, split into the entry's own id and others;
6. other ``malformed_id`` shapes, digits shown as 9;
7. counting runs (3+ consecutive ids from one catalogue in one reply):
   measured, never gated;
8. a document's own id among its accepted terms;
9. the records whose reply could not be parsed.

The same table layout as ``docs/results/stage1_session1_breakdown.txt``, so
the numbers can be compared line by line.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sira_cti.common import read_jsonl  # noqa: E402
from sira_cti.common.schemas import RejectReason, TermKind  # noqa: E402
from sira_cti.index import source_of_kind  # noqa: E402

STAGES = ["parse", "graph", "name", "df"]
GRAPH_REASONS = ["deprecated", "revoked", "not_in_graph", "malformed_id"]
CATALOGUES = ["attack", "capec", "cwe", "other"]
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def catalogue_of(structural_id: str | None) -> str:
    """``CWE-79`` -> cwe, ``CAPEC-66`` -> capec, ``T1110.001`` -> attack, anything else -> other.

    ATT&CK also has tactic (``TA0007``), software (``S0106``), group, mitigation,
    data source and campaign ids; the model proposes the first two now and then.
    """
    sid = (structural_id or "").strip().upper()
    if re.match(r"^CWE-\d+$", sid):
        return "cwe"
    if re.match(r"^CAPEC-\d+$", sid):
        return "capec"
    if re.match(r"^(T\d{4}(\.\d{3})?|TA\d{4}|[SGMC]\d{4}|DS\d{4})$", sid):
        return "attack"
    return "other"


def _pct(n: int, d: int) -> str:
    return f"{n / d:.0%}" if d else "-"


def _manifest(path: Path) -> dict:
    side = path.with_suffix(path.suffix + ".manifest.json")
    return json.loads(side.read_text(encoding="utf-8")) if side.exists() else {}


def breakdown(path: Path) -> dict:
    """Every count the report prints, as plain dicts (``--json`` prints this)."""
    manifest = _manifest(path)
    order = [source_of_kind(k).value for k in manifest.get("kinds") or []]
    totals: dict[str, Counter] = defaultdict(Counter)
    stages: dict[str, Counter] = defaultdict(Counter)
    reasons: dict[str, Counter] = defaultdict(Counter)
    by_kind: dict[str, Counter] = defaultdict(Counter)
    structural: dict[tuple[str, str], Counter] = defaultdict(Counter)
    cve_malformed: Counter = Counter()
    cve_malformed_docs: set[str] = set()
    other_malformed: dict[str, Counter] = defaultdict(Counter)
    counting: dict[str, Counter] = defaultdict(Counter)
    own_id: dict[str, Counter] = defaultdict(Counter)
    parse_failures: list[dict] = []

    for rec in read_jsonl(path):
        src = rec.source.value
        if src not in order:
            order.append(src)
        t = totals[src]
        t["docs"] += 1
        t["proposed"] += len(rec.proposed_terms)
        t["accepted"] += len(rec.accepted_terms)
        doc_has_run = False
        own_accepted = own_proposed = False
        for term in rec.proposed_terms:
            kind = term.kind.value
            by_kind[kind]["proposed"] += 1
            by_kind[kind]["accepted"] += term.accepted
            if not term.accepted:
                stages[src][term.rejected_at_stage or "?"] += 1
                reasons[src][term.reject_reason.value if term.reject_reason else "?"] += 1
                by_kind[kind][term.reject_reason.value if term.reject_reason else "?"] += 1
            if term.reject_reason is RejectReason.LLM_JSON_ERROR:
                parse_failures.append({"doc_id": rec.doc_id, "source": src, "llm_calls": rec.llm_calls,
                                       "completion_tokens": rec.tokens.completion})
            if term.kind is not TermKind.STRUCTURAL:
                continue
            sid = term.structural_id or term.term
            cat = catalogue_of(sid)
            cell = structural[(src, cat)]
            cell["proposed"] += 1
            cell["accepted"] += term.accepted
            if term.reject_reason:
                cell[term.reject_reason.value] += 1
            if term.in_counting_run:
                cell["counting"] += 1
                counting[src]["ids"] += 1
                counting[src]["accepted"] += term.accepted
                doc_has_run = True
            if sid.strip().upper() == rec.doc_id.upper():
                own_proposed = True
                own_accepted = own_accepted or term.accepted
            if term.reject_reason is RejectReason.MALFORMED_ID:
                if src == "cve":
                    cve_malformed_docs.add(rec.doc_id)
                    s = sid.strip()
                    if s.upper() == rec.doc_id.upper():
                        cve_malformed["own CVE id"] += 1
                    elif _CVE_ID.match(s):
                        cve_malformed["other CVE id"] += 1
                    elif s.lower() == "cve":
                        cve_malformed["bare 'cve'"] += 1
                    else:
                        cve_malformed["other"] += 1
                        other_malformed[src][re.sub(r"\d", "9", s)] += 1
                else:
                    other_malformed[src][re.sub(r"\d", "9", sid.strip())] += 1
        counting[src]["docs_with_run"] += doc_has_run
        own_id[src]["docs_proposing_own_id"] += own_proposed
        own_id[src]["docs_accepting_own_id"] += own_accepted

    return {
        "path": str(path),
        "manifest": {k: manifest.get(k) for k in ("model", "model_digest", "prompt_version", "config_hash", "kinds")},
        "code_commit": (manifest.get("code") or {}).get("code_commit"),
        "name_scorer": (manifest.get("gates") or {}).get("name_scorer"),
        "order": order,
        "totals": {s: dict(totals[s]) for s in order},
        "stages": {s: {st: stages[s].get(st, 0) for st in STAGES} for s in order},
        "reasons": {s: dict(sorted(reasons[s].items())) for s in order},
        "by_kind": {k: dict(v) for k, v in sorted(by_kind.items())},
        "structural": {f"{s}/{c}": dict(v) for (s, c), v in sorted(structural.items())},
        "cve_malformed": dict(cve_malformed),
        "cve_malformed_docs": len(cve_malformed_docs),
        "other_malformed": {s: v.most_common() for s, v in other_malformed.items()},
        "counting": {s: dict(counting[s]) for s in order},
        "own_id": {s: dict(own_id[s]) for s in order},
        "parse_failures": parse_failures,
    }


def _structural_row(label_doc: str, label_cat: str, c: Counter) -> str:
    graph = sum(c.get(r, 0) for r in GRAPH_REASONS)
    reached = c["proposed"] - graph
    name = c.get("name_mismatch", 0)
    return (f"{label_doc:<7} {label_cat:<7} {c['proposed']:>6} {c['accepted']:>6} {_pct(c['accepted'], c['proposed']):>5}"
            f" {graph:>6} {name:>6} {f'{name}/{reached}':>11} {_pct(name, reached):>4} {c.get('counting', 0):>6}"
            f" {c.get('deprecated', 0):>4} {c.get('revoked', 0):>4} {c.get('not_in_graph', 0):>4} {c.get('malformed_id', 0):>4}")


def print_report(b: dict) -> None:
    order = b["order"]
    m = b["manifest"]
    print(f"{b['path']}")
    print(f"  model {m['model']}  digest {str(m['model_digest'])[:12]}  prompt {m['prompt_version']}  "
          f"name scorer {b['name_scorer']}  config {m['config_hash']}  commit {str(b['code_commit'])[:12]}")
    docs = sum(t["docs"] for t in b["totals"].values())
    print(f"  records {docs}  {({s: b['totals'][s]['docs'] for s in order})}")

    print("\n== 1. Proposals, acceptances and rejections per source document type ==")
    print(f"{'source':<7} {'docs':>5} {'proposed':>9} {'accepted':>9} {'acc%':>5} " + " ".join(f"{s:>6}" for s in STAGES))
    all_t: Counter = Counter()
    all_s: Counter = Counter()
    for s in order:
        t, st = b["totals"][s], b["stages"][s]
        all_t.update(t)
        all_s.update(st)
        print(f"{s:<7} {t['docs']:>5} {t['proposed']:>9} {t['accepted']:>9} {_pct(t['accepted'], t['proposed']):>5} "
              + " ".join(f"{st[x]:>6}" for x in STAGES))
    print(f"{'ALL':<7} {all_t['docs']:>5} {all_t['proposed']:>9} {all_t['accepted']:>9} "
          f"{_pct(all_t['accepted'], all_t['proposed']):>5} " + " ".join(f"{all_s[x]:>6}" for x in STAGES))
    print("\nBy reason:")
    all_r: Counter = Counter()
    for s in order:
        all_r.update(b["reasons"][s])
        print(f"  {s:<7} {b['reasons'][s]}")
    print(f"  {'ALL':<7} {dict(sorted(all_r.items()))}")

    print("\n== 2. Proposals by term kind (all document types) ==")
    for kind, c in b["by_kind"].items():
        rest = {k: v for k, v in c.items() if k not in ("proposed", "accepted")}
        print(f"  {kind:<12} proposed {c['proposed']:>6}  accepted {c['accepted']:>6} ({_pct(c['accepted'], c['proposed'])})  {rest}")

    print("\n== 3. Structural ids: document type x catalogue the id belongs to ==")
    print("graph = rejected at the existence stage (deprecated + revoked + not_in_graph + malformed_id)")
    print("name/reached = name mismatches / ids that passed the existence check and so reached the name check")
    print("count = ids in a counting run (3+ consecutive numbers); measured, never gated")
    print(f"{'doc':<7} {'ns':<7} {'prop':>6} {'acc':>6} {'acc%':>5} {'graph':>6} {'name':>6} {'name/reached':>11}"
          f" {'':>4} {'count':>6} {'dep':>4} {'rev':>4} {'nig':>4} {'mal':>4}")
    cells = {tuple(k.split("/")): Counter(v) for k, v in b["structural"].items()}
    every: Counter = Counter()
    for c in cells.values():
        every.update(c)
    print(_structural_row("ALL", "ALL", every))
    for cat in CATALOGUES:
        row: Counter = Counter()
        for (_, cc), c in cells.items():
            if cc == cat:
                row.update(c)
        if row:
            print(_structural_row("ALL", cat, row))
    for s in order:
        row = Counter()
        for (ss, _), c in cells.items():
            if ss == s:
                row.update(c)
        print(_structural_row(s, "ALL", row))
        for cat in CATALOGUES:
            if (s, cat) in cells:
                print(_structural_row(s, cat, cells[(s, cat)]))

    cve_docs = b["totals"].get("cve", {}).get("docs", 0)
    print("\n== 4. malformed_id on CVE documents (a CVE id proposed as a structural term) ==")
    print(f"  {b['cve_malformed']}  total {sum(b['cve_malformed'].values())}")
    print(f"  CVE documents affected: {b['cve_malformed_docs']} of {cve_docs} ({_pct(b['cve_malformed_docs'], cve_docs)})")

    print("\n== 5. Other malformed_id shapes (digits shown as 9) ==")
    for s, shapes in b["other_malformed"].items():
        print(f"  {s} {shapes[:15]}" + (f" ... and {len(shapes) - 15} more shapes" if len(shapes) > 15 else ""))

    print("\n== 6. Counting runs (3+ consecutive ids from one catalogue in one reply) ==")
    for s in order:
        c = b["counting"][s]
        print(f"  {s:<7} ids in runs {c.get('ids', 0):>5}  of which accepted {c.get('accepted', 0):>5}  "
              f"documents with a run {c.get('docs_with_run', 0):>5} of {b['totals'][s]['docs']}")

    print("\n== 7. A document's own id among its proposals ==")
    for s in order:
        c = b["own_id"][s]
        print(f"  {s:<7} proposed {c.get('docs_proposing_own_id', 0):>5}  accepted {c.get('docs_accepting_own_id', 0):>5}"
              f"  of {b['totals'][s]['docs']} documents")

    print("\n== 8. Replies that could not be parsed (one llm_json_error placeholder each) ==")
    for f in b["parse_failures"] or ["none"]:
        print(f"  {f}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("enrichment_jsonl", nargs="+", type=Path)
    ap.add_argument("--json", action="store_true", help="print the counts as JSON instead of tables")
    args = ap.parse_args()
    for i, path in enumerate(args.enrichment_jsonl):
        b = breakdown(path)
        if args.json:
            print(json.dumps(b))
            continue
        if i:
            print("\n" + "=" * 100 + "\n")
        print_report(b)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
