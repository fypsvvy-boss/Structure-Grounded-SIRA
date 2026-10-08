#!/usr/bin/env python3
"""Re-adjudicate a saved enrichment run under a different name scorer. No model calls.

Every gate after the model's reply is a pure function of that reply, the
ontology graph and the base index, and each saved term keeps what the model
wrote and what it claimed. So a new scorer can be applied to an old run and
the result is what that run would have produced:

    # compare all scorers on two saved runs, list verdicts that change, report repairs
    .venv/bin/python scripts/rescore_enrichment.py \\
        indexes/enrichment/corpus_stratified_v4_7b.jsonl \\
        indexes/enrichment/corpus_stratified_v4_14b.jsonl

    # write the v2 re-adjudication out as its own JSONL (+ manifest)
    .venv/bin/python scripts/rescore_enrichment.py IN.jsonl --name-scorer v2 --write OUT.jsonl

The first thing it does for each file is re-adjudicate under the scorer the
run was written with and check the verdicts come out identical. If they do
not, the graph, the index or the gates have changed since the run, and a
comparison between scorers would be measuring that instead.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import RejectReason, load_config, read_jsonl, write_jsonl
from sira_cti.enrichment.corpus_side import (
    REPAIR_MAX_HOPS,
    readjudicate_record,
    repair_candidates,
)
from sira_cti.graph import NAME_SCORERS, OntologyGraph
from sira_cti.index import LuceneDFLookup
from sira_cti.index.corpus import CorpusDocument

_GRAPH_REASONS = {
    RejectReason.NOT_IN_GRAPH, RejectReason.DEPRECATED,
    RejectReason.REVOKED, RejectReason.MALFORMED_ID,
}


def _manifest(path: Path) -> dict:
    side = path.with_suffix(path.suffix + ".manifest.json")
    return json.loads(side.read_text()) if side.exists() else {}


def _verdict(t) -> str:
    return "accepted" if t.accepted else t.reject_reason.value


def _doc(rec) -> CorpusDocument:
    return CorpusDocument(doc_id=rec.doc_id, source=rec.source, title="", text=rec.original_text)


def rescore(records, graph, df, cfg, *, scorer: str, gates: dict):
    enrich, graph_cfg = cfg["enrichment"], cfg["graph"]
    overlap = gates.get("name_match_min_overlap", enrich.get("name_match_min_overlap"))
    return [
        readjudicate_record(
            rec, graph, df,
            df_max_ratio=gates.get("df_max_ratio", enrich["df_max_ratio"]),
            allow_deprecated=gates.get("allow_deprecated", graph_cfg.get("allow_deprecated", False)),
            revoked_policy=graph_cfg.get("revoked_policy", "reject"),
            name_match_min_overlap=overlap,
            name_scorer=scorer,
            name_match_min_jaccard=float(enrich.get("name_match_min_jaccard", 0.6)),
        )
        for rec in records
    ]


def tally(records) -> dict:
    out = {"structural": 0, "accepted": 0, "graph": 0, "name": 0, "df": 0,
           "name_stage": 0, "fallback": 0, "run": 0, "run_accepted": 0}
    for rec in records:
        for t in rec.structural_terms:
            out["structural"] += 1
            out["accepted"] += t.accepted
            if t.reject_reason in _GRAPH_REASONS:
                out["graph"] += 1
            elif t.reject_reason is RejectReason.NAME_MISMATCH:
                out["name"] += 1
            elif t.reject_reason is RejectReason.TOO_COMMON:
                out["df"] += 1
            if t.name_scorer:
                out["name_stage"] += 1
                out["fallback"] += t.name_scorer.endswith("fallback")
            if t.in_counting_run:
                out["run"] += 1
                out["run_accepted"] += t.accepted
    return out


def changes(base, other) -> list[str]:
    lines = []
    for a, b in zip(base, other):
        for ta, tb in zip(a.proposed_terms, b.proposed_terms):
            if _verdict(ta) != _verdict(tb):
                lines.append(
                    f"    {a.doc_id:<15} {tb.structural_id or tb.term:<11} "
                    f"{_verdict(ta)} -> {_verdict(tb)}  [{tb.name_scorer}]\n"
                    f"        claimed  {tb.claimed_name!r}\n"
                    f"        official {tb.official_name!r}"
                )
    return lines


def repair_report(records, graph, df, cfg, gates) -> dict:
    enrich = cfg["enrichment"]
    kw = dict(df_max_ratio=gates.get("df_max_ratio", enrich["df_max_ratio"]),
              min_jaccard=float(enrich.get("name_match_min_jaccard", 0.6)))
    out = {"mismatches": 0, "near": 0, "no_anchor": 0, "clean": [], "ambiguous": [], "none_near": 0}
    for rec in records:
        doc = _doc(rec)
        has_anchor = graph.resolve(rec.doc_id) is not None
        for t in rec.proposed_terms:
            if t.reject_reason is not RejectReason.NAME_MISMATCH:
                continue
            out["mismatches"] += 1
            if not has_anchor:
                out["no_anchor"] += 1
                continue
            near = t.graph_distance is not None and t.graph_distance <= REPAIR_MAX_HOPS
            out["near"] += near
            cands = repair_candidates(t, doc, graph, df, **kw)
            row = (rec.doc_id, t.structural_id, t.claimed_name, cands, near)
            if len(cands) == 1:
                out["clean"].append(row)
            elif cands:
                out["ambiguous"].append(row)
            elif near:
                out["none_near"] += 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("enrichment_jsonl", nargs="+", type=Path)
    ap.add_argument("--config", default="configs/default.yaml")
    ap.add_argument("--name-scorer", choices=NAME_SCORERS, default="v2",
                    help="scorer the repair report and --write use (default v2)")
    ap.add_argument("--write", type=Path, default=None,
                    help="write the re-adjudicated records here (single input only)")
    args = ap.parse_args()
    if args.write and len(args.enrichment_jsonl) != 1:
        ap.error("--write takes exactly one input file")

    cfg = load_config(args.config)
    g = cfg["graph"]
    graph = OntologyGraph.from_files(attack_path=g["attack_path"], cwe_path=g["cwe_path"],
                                     capec_path=g["capec_path"], domains=g.get("domains"))
    df = LuceneDFLookup(Path(cfg["index"]["base_dir"]))

    for path in args.enrichment_jsonl:
        manifest = _manifest(path)
        gates = {k: v for k, v in (manifest.get("gates") or {}).items() if v is not None}
        written_with = gates.get("name_scorer") or "v1"
        stored = list(read_jsonl(path))
        print(f"\n{'=' * 78}\n{path}   model={manifest.get('model')}  "
              f"prompt={manifest.get('prompt_version')}  written with scorer {written_with}")

        by_scorer = {s: rescore(stored, graph, df, cfg, scorer=s, gates=gates) for s in NAME_SCORERS}
        drift = changes(stored, by_scorer[written_with])
        print(f"  replay under {written_with}: "
              + ("identical verdicts -- comparison is clean" if not drift
                 else f"{len(drift)} VERDICTS DIFFER from the saved run:"))
        for line in drift:
            print(line)

        print(f"\n  {'scorer':<8}{'structural':>11}{'accepted':>10}{'rej@graph':>11}"
              f"{'rej@name':>10}{'rej@df':>8}{'v1-fallback':>13}{'run acc.':>10}")
        for s in NAME_SCORERS:
            t = tally(by_scorer[s])
            print(f"  {s:<8}{t['structural']:>11}{t['accepted']:>10}{t['graph']:>11}{t['name']:>10}"
                  f"{t['df']:>8}{(str(t['fallback']) + '/' + str(t['name_stage'])):>13}"
                  f"{(str(t['run_accepted']) + '/' + str(t['run'])):>10}")
        for s in NAME_SCORERS:
            if s == written_with:
                continue
            diff = changes(by_scorer[written_with], by_scorer[s])
            print(f"\n  verdicts that change, {written_with} -> {s}: {len(diff)}")
            for line in diff:
                print(line)

        chosen = by_scorer[args.name_scorer]
        r = repair_report(chosen, graph, df, cfg, gates)
        print(f"\n  repair ablation under {args.name_scorer} (candidates within {REPAIR_MAX_HOPS} hops "
              f"of the document, matched symmetrically):")
        print(f"    name mismatches {r['mismatches']}  (on documents that are not graph nodes: "
              f"{r['no_anchor']}; proposed id itself within {REPAIR_MAX_HOPS} hops: {r['near']})")
        near_clean = sum(1 for row in r["clean"] if row[4])
        near_amb = sum(1 for row in r["ambiguous"] if row[4])
        print(f"    of those {r['near']} near ones: {near_clean} repair cleanly, {near_amb} ambiguous, "
              f"{r['none_near']} match nothing nearby")
        print(f"    all clean repairs: {len(r['clean'])}")
        for doc_id, sid, claimed, cands, near in r["clean"]:
            nid, score, hops = cands[0]
            tag = "  (the document's OWN id -- never indexed)" if nid == doc_id else ""
            print(f"      {doc_id:<13} {sid:<11} -> {nid:<11} {hops} hop  score {score:.2f}  "
                  f"{claimed!r}{tag}")
        print(f"    ambiguous (more than one candidate, NOT repaired): {len(r['ambiguous'])}")
        for doc_id, sid, claimed, cands, near in r["ambiguous"]:
            print(f"      {doc_id:<13} {sid:<11} {claimed!r} -> "
                  + ", ".join(f"{n}({sc:.2f},{h}h)" for n, sc, h in cands))

        if args.write:
            write_jsonl(chosen, args.write)
            manifest = dict(manifest)
            manifest["gates"] = {**(manifest.get("gates") or {}), "name_scorer": args.name_scorer,
                                 "name_match_min_jaccard": float(cfg["enrichment"].get("name_match_min_jaccard", 0.6))}
            manifest["rescored_from"] = str(path)
            manifest["rescored_at"] = time.time()
            args.write.with_suffix(args.write.suffix + ".manifest.json").write_text(
                json.dumps(manifest, indent=2), encoding="utf-8")
            print(f"\n  wrote {args.write} (no model calls; cost fields carried over)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
