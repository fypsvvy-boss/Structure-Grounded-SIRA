#!/usr/bin/env python3
"""Replace the records of documents whose corpus text changed, keeping every other record as it is.

    .venv/bin/python scripts/splice_enrichment.py OLD_FULL.jsonl NEW_PART.jsonl --output OUT.jsonl

Made for the corpus fix of 2026-11-16 (open question 16). 117 CVE documents
went from ``"<id> null"`` to their real description, and the other 5,927
documents did not change at all. Rather than re-running a whole 6,044-document
run, those 117 are enriched again into a small file under the current config
(``enrich_corpus.py --doc-ids ...``), and this script joins the two:

- every document of the current corpus ends up with exactly one record;
- an old record is **carried over** only if its ``original_text`` is the
  current corpus text byte for byte, *and* re-running every gate on it against
  the current graph and base index gives the same verdict for every term (so
  it is exactly the record a run on the fixed corpus would have written,
  given the same reply);
- a new record must be for a document whose text changed, and its text must
  be the current text; a new record for an unchanged document is refused;
- both files must share every method setting (model, digest, prompt, gates,
  decoding, backend, thinking level). Only ``config_hash``, ``sampling`` (the
  new file is a ``--doc-ids`` selection) and the code may differ, and the new
  file's ``config_hash`` must be the current config's;
- the base index must have been built from the current ``corpus.kb_dir``.

Old lines are copied byte for byte, in the old file's order, with each
replaced document's line put where its old one was. The failure logs travel
with the records they belong to. The manifest is the new file's, with the old
manifest kept whole under ``spliced.carried.manifest``, so nothing about
either session is lost. Nothing is written unless every check passes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from merge_enrichment import SIDECARS, manifest_path, method_settings  # noqa: E402
from sira_cti.common import EnrichmentRecord, config_hash, load_config  # noqa: E402
from sira_cti.index.corpus import CorpusDocument  # noqa: E402

IGNORED_SETTINGS = ("config_hash", "sampling")
"""Method settings the two files may differ in. The config hash differs by
design (the corpus path changed). ``sampling`` differs because the new file
holds only the changed documents (``--doc-ids``); the output covers the whole
corpus, which is checked document by document, so it takes the old file's
sampling and keeps the new one under ``spliced.new.sampling``. The code commit
is not a method setting."""


class SpliceError(RuntimeError):
    """The files cannot be spliced. Nothing has been written."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _read_lines(path: Path) -> list[tuple[str, EnrichmentRecord]]:
    out = []
    with path.open(encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if line.strip():
                try:
                    out.append((line, EnrichmentRecord.from_dict(json.loads(line))))
                except Exception as exc:  # noqa: BLE001
                    raise SpliceError(f"{path}:{n}: not a valid record: {exc}") from exc
    ids = [r.doc_id for _, r in out]
    dupes = sorted({i for i in ids if ids.count(i) > 1}) if len(set(ids)) != len(ids) else []
    if dupes:
        raise SpliceError(f"{path} has more than one record for {dupes[:5]}")
    return out


def _load_manifest(path: Path) -> dict[str, Any]:
    side = manifest_path(path)
    if not side.exists():
        raise SpliceError(f"{path} has no manifest beside it, so its settings cannot be checked")
    return json.loads(side.read_text(encoding="utf-8"))


def _verdicts(record: EnrichmentRecord) -> list[tuple[str, str, str]]:
    return [(t.term, t.kind.value, "accepted" if t.accepted else t.reject_reason.value)
            for t in record.proposed_terms]


def splice(
    old_path: Path,
    new_path: Path,
    output: Path,
    *,
    corpus: dict[str, CorpusDocument],
    current_config_hash: str,
    readjudicate: Callable[[EnrichmentRecord, dict[str, Any]], EnrichmentRecord],
    truncation: Callable[[Iterable[CorpusDocument], dict[str, Any]], Any] | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Check and write; returns the manifest. ``readjudicate(record, gates)`` re-runs the gates."""
    paths = {old_path.resolve(), new_path.resolve()}
    if len(paths) != 2:
        raise SpliceError("the old and new files are the same file")
    if output.resolve() in paths:
        raise SpliceError(f"--output {output} is one of the input files")
    if output.exists() or manifest_path(output).exists():
        raise SpliceError(f"{output} (or its manifest) already exists; choose a new --output")

    old_m, new_m = _load_manifest(old_path), _load_manifest(new_path)
    if new_m.get("config_hash") != current_config_hash:
        raise SpliceError(f"{new_path} was made with config {new_m.get('config_hash')}, "
                          f"the current config is {current_config_hash}")
    old_s, new_s = method_settings(old_m), method_settings(new_m)
    differ = sorted(k for k in set(old_s) | set(new_s)
                    if k not in IGNORED_SETTINGS and old_s.get(k) != new_s.get(k))
    if differ:
        raise SpliceError("the two files were not made with the same method:\n" + "\n".join(
            f"  {k}: old {old_s.get(k)!r}, new {new_s.get(k)!r}" for k in differ))

    old_lines, new_lines = _read_lines(old_path), _read_lines(new_path)
    old_by_id = {r.doc_id: (line, r) for line, r in old_lines}
    new_by_id = {r.doc_id: (line, r) for line, r in new_lines}

    problems: list[str] = []
    changed = {d for d, (_, r) in old_by_id.items() if d in corpus and r.original_text != corpus[d].text}
    for doc_id in sorted(set(old_by_id) - set(corpus)):
        problems.append(f"{doc_id}: in the old file but not in the current corpus")
    for doc_id, (_, rec) in sorted(new_by_id.items()):
        if doc_id not in corpus:
            problems.append(f"{doc_id}: in the new file but not in the current corpus")
        elif rec.original_text != corpus[doc_id].text:
            problems.append(f"{doc_id}: the new record's text is not the current corpus text")
        elif doc_id in old_by_id and doc_id not in changed:
            problems.append(f"{doc_id}: has a new record although its text did not change (carry it over instead)")
    for doc_id in sorted(changed - set(new_by_id)):
        problems.append(f"{doc_id}: its text changed and the new file has no record for it")
    for doc_id in sorted(set(corpus) - set(old_by_id) - set(new_by_id)):
        problems.append(f"{doc_id}: in the corpus but in neither file")
    if problems:
        raise SpliceError(f"{len(problems)} problem(s):\n  " + "\n  ".join(problems[:20])
                          + ("\n  ..." if len(problems) > 20 else ""))

    gates = {k: v for k, v in (new_m.get("gates") or {}).items() if v is not None}
    moved, terms_checked = [], 0
    for doc_id, (_, rec) in old_by_id.items():
        if doc_id in changed:
            continue
        again = readjudicate(rec, gates)
        terms_checked += len(rec.proposed_terms)
        if _verdicts(again) != _verdicts(rec):
            moved.append(doc_id)
    if moved:
        raise SpliceError(f"re-running the gates against the current graph and base index changes verdicts on "
                          f"{len(moved)} carried document(s), e.g. {moved[:5]}; those records are not what a run "
                          "on the current corpus would have written")

    out_lines = [new_by_id[r.doc_id][0] if r.doc_id in changed else line for line, r in old_lines]
    out_lines += [line for line, r in new_lines if r.doc_id not in old_by_id]

    manifest = dict(new_m)
    manifest["sampling"] = old_m.get("sampling")
    manifest["kinds"] = old_m.get("kinds", new_m.get("kinds"))
    if truncation is not None:
        manifest["truncation"] = truncation(corpus.values(), new_m.get("gates") or {})
    manifest["spliced"] = {
        "reason": reason,
        "at": time.time(),
        "records": len(out_lines),
        "carried": {
            "path": str(old_path), "sha256": _sha256(old_path), "records": len(old_lines) - len(changed),
            "config_hash": old_m.get("config_hash"),
            "verdicts_rechecked": {"documents": len(old_lines) - len(changed), "terms": terms_checked,
                                   "changed": 0},
            "manifest": old_m,
        },
        "new": {"path": str(new_path), "sha256": _sha256(new_path), "records": len(changed),
                "doc_ids": sorted(changed), "sampling": new_m.get("sampling")},
    }
    manifest["usage"] = {"carried": old_m.get("usage"), "new": new_m.get("usage")}

    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_name(output.name + ".tmp")
    tmp.write_text("".join(line + "\n" for line in out_lines), encoding="utf-8")
    for suffix in SIDECARS:
        rows = []
        for src, keep in ((old_path, lambda d: d not in changed), (new_path, lambda d: True)):
            side = src.with_suffix(src.suffix + suffix)
            if side.exists():
                rows += [line for line in side.read_text(encoding="utf-8").splitlines()
                         if line.strip() and keep(json.loads(line).get("doc_id"))]
        if rows:
            output.with_suffix(output.suffix + suffix).write_text("".join(r + "\n" for r in rows), encoding="utf-8")
    manifest_path(output).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    tmp.rename(output)
    return manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old", type=Path, help="the full run made on the earlier corpus")
    ap.add_argument("new", type=Path, help="the changed documents, enriched under the current config")
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--config", default="configs/default.yaml")
    ap.add_argument("--reason", default="corpus fix 2026-11-16: 117 CVE rows exported as 'null' filled "
                                        "(docs/04_OPEN_QUESTIONS.md q16)")
    args = ap.parse_args(argv)

    from sira_cti.enrichment.corpus_side import _truncation_summary, readjudicate_record
    from sira_cti.graph import OntologyGraph
    from sira_cti.index import LuceneDFLookup
    from sira_cti.index.corpus import load_corpus

    cfg = load_config(args.config)
    base_dir = Path(cfg["index"]["base_dir"])
    base = json.loads((base_dir / "manifest.json").read_text(encoding="utf-8"))
    if base.get("kb_dir") != cfg["corpus"]["kb_dir"]:
        print(f"Refused: the base index was built from {base.get('kb_dir')}, the config's corpus is "
              f"{cfg['corpus']['kb_dir']}. Rebuild it: scripts/build_index.py --stage base")
        return 1
    new_m = _load_manifest(args.new)
    kinds = new_m.get("kinds") or cfg["corpus"]["kinds"]
    corpus = {d.doc_id: d for d in load_corpus(cfg["corpus"]["kb_dir"], kinds)}
    g = cfg["graph"]
    graph = OntologyGraph.from_files(attack_path=g["attack_path"], cwe_path=g["cwe_path"],
                                     capec_path=g["capec_path"], domains=g.get("domains"))
    df = LuceneDFLookup(base_dir)
    enrich = cfg["enrichment"]

    def readjudicate(rec: EnrichmentRecord, gates: dict[str, Any]) -> EnrichmentRecord:
        return readjudicate_record(
            rec, graph, df,
            df_max_ratio=gates.get("df_max_ratio", enrich["df_max_ratio"]),
            allow_deprecated=gates.get("allow_deprecated", g.get("allow_deprecated", False)),
            revoked_policy=gates.get("revoked_policy", g.get("revoked_policy", "reject")),
            name_match_min_overlap=gates.get("name_match_min_overlap"),
            name_scorer=gates.get("name_scorer") or "v1",
            name_match_min_jaccard=float(gates.get("name_match_min_jaccard", enrich.get("name_match_min_jaccard", 0.6))),
        )

    def truncation(docs, gates):
        limit = gates.get("max_doc_chars")
        return None if limit is None else _truncation_summary(list(docs), limit)

    try:
        manifest = splice(args.old, args.new, args.output, corpus=corpus,
                          current_config_hash=config_hash(args.config), readjudicate=readjudicate,
                          truncation=truncation, reason=args.reason)
    except SpliceError as exc:
        print(f"Refused: {exc}")
        return 1
    s = manifest["spliced"]
    print(f"wrote {args.output}: {s['records']} records = {s['carried']['records']} carried "
          f"(verdicts re-checked on {s['carried']['verdicts_rechecked']['terms']} terms, none changed) "
          f"+ {s['new']['records']} new")
    return 0


if __name__ == "__main__":
    sys.exit(main())
