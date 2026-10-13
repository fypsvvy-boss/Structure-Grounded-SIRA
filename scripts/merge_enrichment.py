#!/usr/bin/env python3
"""Join several enrichment output files into one, after checking they belong together.

A run split across two GPUs (``enrich_corpus.py --shard 1/2`` and ``2/2``), or
continued on a second machine, leaves several ``.jsonl`` files. This puts
their records in one file, keyed by document id, and writes one manifest that
names every source file and every machine that took part.

    .venv/bin/python scripts/merge_enrichment.py \
        indexes/enrichment/corpus_full_v4_14b.shard1of2.jsonl \
        indexes/enrichment/corpus_full_v4_14b.shard2of2.jsonl \
        --output indexes/enrichment/corpus_full_v4_14b.jsonl --expect 6044

It refuses, and writes nothing, when:

* a source file has no manifest beside it;
* the manifests disagree on anything that shapes a reply or a verdict: config
  hash, model, model digest, prompt, every gate (name scorer and thresholds,
  decoding mode, reply cap, truncation budget and rules), how the documents
  were sampled, or the temperature, seed and context size sent to the model;
* the same document id appears twice with different content. The same record
  twice, byte for byte, is harmless (a file given twice, or a session's file
  and its continuation) and is kept once;
* a record sits in a file whose manifest says it holds a different shard;
* ``--expect N`` was given and the merged file does not hold exactly N documents.

Read-only on its inputs. No model call, no index.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sira_cti.index.corpus import shard_of  # noqa: E402

MUST_AGREE = ("config_hash", "model", "model_digest", "prompt_version", "sampling", "gates")
"""Manifest entries every source file must share. ``gates`` holds the name
scorer and the truncation budget and rules; ``sampling`` holds the sampling seed."""

LLM_MUST_AGREE = ("backend", "temperature", "seed_sent", "num_ctx")
"""The parts of the manifest's ``llm`` block that shape a reply. The rest of
that block (token usage, pricing) describes one session, not the method."""

SIDECARS = (".failures.jsonl", ".raw_failures.jsonl")
_MISSING = "(not recorded)"


class MergeError(RuntimeError):
    """The source files cannot be merged. Nothing has been written."""


def manifest_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".manifest.json")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _load_manifest(path: Path) -> dict[str, Any]:
    side = manifest_path(path)
    if not side.exists():
        raise MergeError(
            f"{path} has no manifest beside it ({side.name}), so there is no way to check it was "
            "made with the same settings as the others."
        )
    return json.loads(side.read_text(encoding="utf-8"))


def method_settings(manifest: dict[str, Any]) -> dict[str, Any]:
    """The settings two files must share, flattened to ``label -> value``."""
    out: dict[str, Any] = {}
    for key in MUST_AGREE:
        value = manifest.get(key, _MISSING)
        if key == "gates" and isinstance(value, dict):
            for gate, setting in value.items():
                out[f"gates.{gate}"] = setting
        else:
            out[key] = value
    llm = manifest.get("llm") or {}
    for key in LLM_MUST_AGREE:
        out[f"llm.{key}"] = llm.get(key, _MISSING)
    return out


def check_manifests_agree(paths: list[Path], manifests: list[dict[str, Any]]) -> None:
    """Raise :class:`MergeError` naming every setting the files do not share.

    A setting that one manifest never recorded counts as a disagreement: a
    file with no model digest cannot be shown to hold the same model's
    replies as one that has it.
    """
    methods = [method_settings(m) for m in manifests]
    problems: list[str] = []
    for label in sorted({k for m in methods for k in m}):
        values = [m.get(label, _MISSING) for m in methods]
        if any(v != values[0] for v in values[1:]) or (label == "model_digest" and values[0] == _MISSING):
            problems.append(f"  {label}:")
            problems.extend(f"    {p.name}: {v!r}" for p, v in zip(paths, values))
    if problems:
        raise MergeError(
            "Refusing to merge: the source files were not made with the same settings.\n"
            + "\n".join(problems)
            + "\nMerging them would put two different experiments in one file."
        )


def _differing_fields(a: dict[str, Any], b: dict[str, Any]) -> list[str]:
    return sorted(k for k in set(a) | set(b) if a.get(k, _MISSING) != b.get(k, _MISSING))


def merge_records(
    paths: list[Path], manifests: list[dict[str, Any]]
) -> tuple[list[str], list[dict[str, Any]], dict[str, int]]:
    """``(merged lines, per-file facts, counts)``; raises on a conflicting or misplaced record.

    Lines are kept exactly as written -- a record is never re-serialised, so
    the merged file holds the same bytes the run produced. Order is the order
    of ``paths``, then each file's own order.
    """
    seen: dict[str, tuple[dict[str, Any], Path]] = {}
    lines: list[str] = []
    per_file: list[dict[str, Any]] = []
    conflicts: list[str] = []
    misplaced: list[str] = []
    duplicates = 0

    for path, manifest in zip(paths, manifests):
        shard = manifest.get("shard")
        records = kept = 0
        with path.open(encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    doc_id = record["doc_id"]
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise MergeError(f"{path}:{line_no}: not an enrichment record ({exc})") from exc
                records += 1
                if shard and shard_of(doc_id, int(shard["of"])) != int(shard["index"]):
                    misplaced.append(
                        f"  {doc_id} in {path.name}, whose manifest says shard "
                        f"{shard['index']}/{shard['of']}; the id belongs to shard "
                        f"{shard_of(doc_id, int(shard['of']))}/{shard['of']}"
                    )
                if doc_id in seen:
                    earlier, earlier_path = seen[doc_id]
                    if earlier == record:
                        duplicates += 1
                    else:
                        conflicts.append(
                            f"  {doc_id}: {earlier_path.name} and {path.name} differ in "
                            f"{', '.join(_differing_fields(earlier, record))}"
                        )
                    continue
                seen[doc_id] = (record, path)
                lines.append(line)
                kept += 1
        per_file.append({"records": records, "records_kept": kept})

    if misplaced:
        raise MergeError(
            "Refusing to merge: records in the wrong shard's file.\n" + "\n".join(misplaced[:20])
            + (f"\n  ... and {len(misplaced) - 20} more" if len(misplaced) > 20 else "")
        )
    if conflicts:
        raise MergeError(
            f"Refusing to merge: {len(conflicts)} document id(s) appear more than once with different "
            "content, so one of the two would have to be thrown away.\n" + "\n".join(conflicts[:20])
            + (f"\n  ... and {len(conflicts) - 20} more" if len(conflicts) > 20 else "")
            + "\nDecide which file is the real one for those documents and merge only that."
        )
    return lines, per_file, {"documents": len(lines), "identical_duplicates_dropped": duplicates}


def _machines(manifest: dict[str, Any]) -> list[Any]:
    """Every machine a file's manifest names, oldest first."""
    out = list(manifest.get("machine_previous") or [])
    if manifest.get("machine"):
        out.append(manifest["machine"])
    return out


def _codes(manifest: dict[str, Any]) -> list[Any]:
    out = list(manifest.get("code_previous") or [])
    if manifest.get("code"):
        out.append(manifest["code"])
    return out


def _distinct(items: list[Any]) -> list[Any]:
    out: list[Any] = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


def build_manifest(
    paths: list[Path],
    manifests: list[dict[str, Any]],
    lines: list[str],
    per_file: list[dict[str, Any]],
    counts: dict[str, int],
) -> dict[str, Any]:
    """The merged file's manifest: the shared method, then where everything came from."""
    first = manifests[0]
    kinds = _distinct([k for m in manifests for k in m.get("kinds") or []])
    concurrency = _distinct([m.get("concurrency") for m in manifests])
    manifest: dict[str, Any] = {
        "prompt_version": first.get("prompt_version"),
        "model": first.get("model"),
        "model_digest": first.get("model_digest"),
        "config_hash": first.get("config_hash"),
        "kinds": kinds,
        "sampling": first.get("sampling"),
        "concurrency": concurrency[0] if len(concurrency) == 1 else concurrency,
        "gates": first.get("gates") or {},
        "created_at": time.time(),
    }
    llm = first.get("llm") or {}
    if llm:
        manifest["llm"] = {k: llm[k] for k in LLM_MUST_AGREE if k in llm}

    # Recounted from the records. A source manifest's own "usage" covers only
    # its last session, so adding those up would undercount a resumed run.
    calls = prompt = completion = thinking = 0
    by_source: dict[str, int] = {}
    for line in lines:
        record = json.loads(line)
        calls += int(record.get("llm_calls") or 0)
        tokens = record.get("tokens") or {}
        prompt += int(tokens.get("prompt") or 0)
        completion += int(tokens.get("completion") or 0)
        thinking += int(tokens.get("thinking") or 0)
        by_source[record.get("source", "?")] = by_source.get(record.get("source", "?"), 0) + 1
    usage_tokens = {"prompt": prompt, "completion": completion}
    if thinking:
        usage_tokens["thinking"] = thinking
    manifest["usage"] = {"llm_calls": calls, "tokens": usage_tokens}

    truncations = [m["truncation"] for m in manifests if m.get("truncation")]
    if truncations:
        merged_ids = {json.loads(line)["doc_id"] for line in lines}
        cut = sorted({d for t in truncations for d in t.get("truncated_docs", [])} & merged_ids)
        fallback = sorted({d for t in truncations for d in t.get("fallback_docs", [])} & merged_ids)
        manifest["truncation"] = {
            "max_doc_chars": truncations[0].get("max_doc_chars"),
            "version": truncations[0].get("version"),
            "truncated_docs": cut,
            "fallback_docs": fallback,
            "truncated_count": len(cut),
        }

    codes = _distinct([c for m in manifests for c in _codes(m)])
    if codes:
        manifest["code"] = codes[-1]
        if len(codes) > 1:
            manifest["code_previous"] = codes[:-1]
    manifest["machines"] = _distinct([machine for m in manifests for machine in _machines(m)])
    manifest["merged"] = {
        **counts,
        "documents_by_source": by_source,
        "sources": [
            {
                "path": str(path),
                "sha256": _sha256(path),
                **facts,
                "shard": m.get("shard"),
                "kinds": m.get("kinds"),
                "machines": _machines(m),
                "code_commits": [c.get("code_commit") for c in _codes(m) if isinstance(c, dict)],
                "created_at": m.get("created_at"),
            }
            for path, m, facts in zip(paths, manifests, per_file)
        ],
    }
    return manifest


def merge(paths: list[Path], output: Path, *, expect: Optional[int] = None) -> dict[str, Any]:
    """Check, merge and write. Returns the merged manifest; raises :class:`MergeError`."""
    if len({p.resolve() for p in paths}) != len(paths):
        raise MergeError("The same source file was given more than once.")
    if output.resolve() in {p.resolve() for p in paths}:
        raise MergeError(f"--output {output} is one of the source files.")
    if output.exists() or manifest_path(output).exists():
        raise MergeError(f"{output} (or its manifest) already exists. Choose a new --output or remove it first.")

    manifests = [_load_manifest(p) for p in paths]
    check_manifests_agree(paths, manifests)
    lines, per_file, counts = merge_records(paths, manifests)
    if expect is not None and len(lines) != expect:
        raise MergeError(
            f"Refusing to merge: expected {expect} documents, the source files hold {len(lines)}. "
            "A run is unfinished, or a shard is missing."
        )
    manifest = build_manifest(paths, manifests, lines, per_file, counts)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")
    # The logs of failed and unparseable replies travel with the records.
    for suffix in SIDECARS:
        parts = [p.with_suffix(p.suffix + suffix) for p in paths]
        parts = [p for p in parts if p.exists()]
        if parts:
            with output.with_suffix(output.suffix + suffix).open("w", encoding="utf-8") as fh:
                for part in parts:
                    text = part.read_text(encoding="utf-8")
                    fh.write(text if text.endswith("\n") or not text else text + "\n")
    manifest_path(output).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("enrichment_jsonl", nargs="+", type=Path, help="the files to merge, each with its manifest")
    ap.add_argument("--output", type=Path, required=True, help="the merged file; must not exist yet")
    ap.add_argument("--expect", type=int, default=None, metavar="N",
                    help="refuse unless the merged file holds exactly N documents (6044 for the full corpus)")
    args = ap.parse_args()

    try:
        manifest = merge(args.enrichment_jsonl, args.output, expect=args.expect)
    except MergeError as exc:
        print(exc)
        return 2

    merged = manifest["merged"]
    print(f"Merged {len(merged['sources'])} files -> {args.output}")
    for source in merged["sources"]:
        shard = source["shard"]
        label = f"  shard {shard['index']}/{shard['of']}" if shard else ""
        print(f"  {source['path']}: {source['records']} records{label}")
    print(f"  documents: {merged['documents']}  {merged['documents_by_source']}")
    if merged["identical_duplicates_dropped"]:
        print(f"  identical duplicates kept once: {merged['identical_duplicates_dropped']}")
    print(f"  model: {manifest['model']}  digest {str(manifest['model_digest'])[:12]}  "
          f"config {manifest['config_hash']}  prompt {manifest['prompt_version']}")
    print("  machines:")
    for machine in manifest["machines"]:
        print(f"    {machine.get('hostname')}  {machine.get('platform')}  gpu={machine.get('gpu')}")
    commits = _distinct([c for s in merged["sources"] for c in s["code_commits"]])
    if len(commits) > 1:
        print(f"  NOTE: the source files were written by more than one code commit: {[c[:12] for c in commits]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
