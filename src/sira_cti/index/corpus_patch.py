"""Fills the CVE entries that CTIConnect's corpus_kb exported without any text.

117 rows of ``corpus_kb/cve.jsonl`` have ``"contents": "null"``, so the whole
document is just ``"CVE-2025-38250 null"`` (found 2026-11-15, open question
16). Every one was published on NVD *before* the snapshot date (2025-09-01),
so this was a bug in the export, not a CVE that did not exist yet. The team
decided on 2026-11-15 to fix the corpus.

What goes in is the record **as it stood on the snapshot date**, read from
the official CVE List (``CVEProject/cvelistV5``) at the last commit of that
day, so the fixed rows hold what the snapshot should have held:

- the CNA's English description (NVD copies its description from here);
- the CWE ids attached by then, by the CNA or an ADP such as CISA (all
  labelled ``Secondary``, as NVD labels CWE ids that do not come from NVD);
- nothing added later. Most of these are Linux kernel CVEs that NVD analysed
  months after the snapshot (CVE-2025-38250: CWE-416 and a CVSS score added
  2025-11-19), and those later additions stay out. CVSS scores are left out
  entirely, because the other rows carry them in NVD's format, which the CVE
  List does not use. Each patch row says whether a score existed and was left
  out.

The first attempt (2026-11-15) rebuilt the records from NVD's CVE Change
History API instead. That service stopped answering after 21 of 117, and the
CVE List at a pinned commit is the more direct source anyway.

Two steps, both deterministic:

1. ``scripts/fetch_cve_fill.py`` reads the 117 records from the CVE List at
   the pinned commit and writes the patch file,
   ``configs/corpus_patches/cve_null_fill_v1.jsonl``. The patch file is
   committed because ``data/`` is not.
2. ``scripts/build_fixed_corpus.py`` copies CTIConnect's ``corpus_kb``
   and replaces only the ``"null"`` rows, refusing anything else. The output
   is ``data/corpus_kb_fixed`` (the config's ``corpus.kb_dir``). Every other
   line is copied byte for byte, so doc ids, order and the other 5,927
   documents are unchanged.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Iterable, Optional

NULL_CONTENTS = "null"
PATCH_VERSION = "cve-null-fill-v1"


class PatchError(ValueError):
    """The patch does not fit the corpus it is applied to."""


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def null_cve_ids(kb_dir: str | Path) -> list[str]:
    """CVE ids whose corpus_kb row has ``"contents": "null"``, in file order."""
    out = []
    with (Path(kb_dir) / "cve.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                if row.get("contents") == NULL_CONTENTS:
                    out.append(row["cve_id"])
    return out


def _cutoff_end(cutoff: str) -> str:
    """``"2025-09-01"`` -> the last moment of that day, comparable with ISO timestamps."""
    return f"{cutoff}T23:59:59.999"


def cve_list_path(cve_id: str) -> str:
    """Where cvelistV5 keeps a record: ``CVE-2025-38250`` -> ``cves/2025/38xxx/CVE-2025-38250.json``."""
    _, year, number = cve_id.split("-")
    return f"cves/{year}/{int(number) // 1000}xxx/{cve_id}.json"


def _english(descriptions: Iterable[dict[str, Any]]) -> Optional[str]:
    for d in descriptions or ():
        if str(d.get("lang", "")).lower().startswith("en") and d.get("value"):
            return d["value"]
    return None


def contents_from_cve_list(record: dict[str, Any], cutoff: str) -> dict[str, Any]:
    """One CVE's corpus_kb ``contents`` from its CVE List (JSON 5) record as of ``cutoff``.

    ``record`` must be the file as it was at the cutoff commit. Returns
    ``{"contents": {...}, "provenance": {...}}``. Raises :class:`PatchError` if
    the record is not ``PUBLISHED``, was published after the cutoff, or was
    last changed after it (which would mean the wrong commit was read).
    """
    meta = record.get("cveMetadata", {})
    cve_id = meta.get("cveId", "?")
    end = _cutoff_end(cutoff)
    if meta.get("state") != "PUBLISHED":
        raise PatchError(f"{cve_id} is {meta.get('state')!r} in the CVE List, not PUBLISHED")
    published, updated = meta.get("datePublished", ""), meta.get("dateUpdated") or ""
    if not published or published > end:
        raise PatchError(f"{cve_id} was published {published or '(unknown)'}, after the {cutoff} cutoff")
    if updated > end:
        raise PatchError(f"{cve_id} was updated {updated}, after the {cutoff} cutoff: not the cutoff-day record")

    containers = record.get("containers", {})
    cna = containers.get("cna", {})
    description = _english(cna.get("descriptions"))
    if not description:
        raise PatchError(f"{cve_id} has no English description in the CVE List")

    cwes: dict[str, None] = {}
    providers = []
    scored = bool(cna.get("metrics"))
    for container in [cna, *containers.get("adp", [])]:
        name = container.get("providerMetadata", {}).get("shortName", "")
        for pt in container.get("problemTypes", []) or ():
            for d in pt.get("descriptions", []) or ():
                if d.get("cweId"):
                    cwes[d["cweId"].strip()] = None
                    providers.append(name)
        if container is not cna and container.get("metrics"):
            scored = True

    contents: dict[str, Any] = {"id": cve_id, "descriptions": [{"value": description}]}
    if cwes:
        contents["weaknesses"] = [{"type": "Secondary", "description": [{"value": c}]} for c in cwes]
    return {
        "contents": contents,
        "provenance": {
            "published": published,
            "updated": updated,
            "cna": cna.get("providerMetadata", {}).get("shortName"),
            "cwe_from": sorted(set(providers)),
            "cvss_existed_not_included": scored,
        },
    }


def patch_row(cve_id: str, rebuilt: dict[str, Any], *, cutoff: str, commit: str) -> dict[str, Any]:
    """One line of the patch file. ``contents`` is serialised exactly as corpus_kb serialises it."""
    return {
        "cve_id": cve_id,
        "contents": json.dumps(rebuilt["contents"], ensure_ascii=False),
        "patch": PATCH_VERSION,
        "cutoff": cutoff,
        "cve_list_commit": commit,
        "source": "CVE List (CVEProject/cvelistV5) at commit " + commit,
        **rebuilt["provenance"],
    }


def read_patch(path: str | Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with Path(path).open(encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row["cve_id"] in rows:
                raise PatchError(f"{path}:{n}: {row['cve_id']} appears twice")
            json.loads(row["contents"])                     # must be valid JSON text
            rows[row["cve_id"]] = row
    return rows


def _check_source(src: Path) -> dict[str, Any]:
    manifest = json.loads((src / "MANIFEST.json").read_text(encoding="utf-8"))
    for name, info in manifest.get("files", {}).items():
        want = info.get("sha256")
        if want and sha256_file(src / name) != want:
            raise PatchError(f"{src / name} does not match its MANIFEST.json sha256; refusing to patch a changed corpus")
    return manifest


def apply_patch(src: str | Path, patch_path: str | Path, out: str | Path) -> dict[str, Any]:
    """Write ``out`` = ``src`` with every ``"null"`` CVE row's contents taken from the patch.

    Refuses if the source files differ from their MANIFEST, if a ``"null"``
    row has no patch row, or if the patch names a CVE whose row is not
    ``"null"`` (or is not in the corpus). Only ``cve.jsonl`` changes; the other
    files are copied as they are. Returns the new manifest.
    """
    src, out = Path(src), Path(out)
    manifest = _check_source(src)
    patch = read_patch(patch_path)
    if out.resolve() == src.resolve():
        raise PatchError("the output directory must not be the source directory")

    lines = (src / "cve.jsonl").read_text(encoding="utf-8").split("\n")
    seen_null, used = [], set()
    new_lines = []
    for line in lines:
        if not line.strip():
            new_lines.append(line)
            continue
        row = json.loads(line)
        cid = row.get("cve_id")
        if row.get("contents") == NULL_CONTENTS:
            seen_null.append(cid)
            if cid not in patch:
                raise PatchError(f"{cid} has no text in the corpus and no row in {patch_path}")
            row["contents"] = patch[cid]["contents"]
            used.add(cid)
            new_lines.append(json.dumps(row, ensure_ascii=False))
        else:
            if cid in patch:
                raise PatchError(f"{patch_path} has a row for {cid}, whose corpus text is not 'null'; refusing")
            new_lines.append(line)
    unused = sorted(set(patch) - used)
    if unused:
        raise PatchError(f"{patch_path} has rows for CVEs not in the corpus: {unused[:5]}")

    staging = out.with_name(out.name + ".staging")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    for f in sorted(src.iterdir()):
        if f.is_file() and f.name not in ("cve.jsonl", "MANIFEST.json"):
            shutil.copy2(f, staging / f.name)
    (staging / "cve.jsonl").write_text("\n".join(new_lines), encoding="utf-8")

    new_manifest = dict(manifest)
    files = {k: dict(v) for k, v in manifest.get("files", {}).items()}
    cve_path = staging / "cve.jsonl"
    files.setdefault("cve.jsonl", {}).update({
        "lines": sum(1 for line in new_lines if line.strip()),
        "bytes": cve_path.stat().st_size,
        "sha256": sha256_file(cve_path),
    })
    new_manifest["files"] = files
    new_manifest["fixed_by"] = {
        "patch": PATCH_VERSION,
        "patch_file": str(patch_path),
        "patch_sha256": sha256_file(patch_path),
        "rows_filled": len(used),
        "source_dir": str(src),
        "source_cve_sha256": manifest.get("files", {}).get("cve.jsonl", {}).get("sha256"),
        "note": "CVE rows exported with contents 'null' filled with their NVD record as of the snapshot date; "
                "all other lines are byte-identical to the source (src/sira_cti/index/corpus_patch.py)",
    }
    (staging / "MANIFEST.json").write_text(json.dumps(new_manifest, indent=2, ensure_ascii=False) + "\n",
                                           encoding="utf-8")
    if out.exists():
        shutil.rmtree(out)
    staging.rename(out)
    return new_manifest
