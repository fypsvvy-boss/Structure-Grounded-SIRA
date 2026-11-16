#!/usr/bin/env python
"""Fetch the CVE List records for the CVEs corpus_kb exported without text, and write the patch file.

    .venv/bin/python scripts/fetch_cve_fill.py

For every row of ``<kb-dir>/cve.jsonl`` whose contents is ``"null"`` (117 in
CTIConnect's 2025-09-01 snapshot), reads the record from the official CVE List
(``CVEProject/cvelistV5`` on GitHub) at a pinned commit, the last one of the
snapshot day, and writes one patch line per CVE to ``--out``
(``src/sira_cti/index/corpus_patch.py`` says what goes in).

The files are read from raw.githubusercontent.com at that commit; nothing
but the public file paths is sent, and no GitHub account is used. Replies are
cached under ``--cache``, so a rerun fetches only what is missing, and with a
full cache it makes no requests and rebuilds the same file.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.index.corpus_patch import (  # noqa: E402
    PatchError, contents_from_cve_list, cve_list_path, null_cve_ids, patch_row,
)

# The last commit of 2025-09-01 (UTC) in CVEProject/cvelistV5: committed
# 2025-09-01T23:35:59Z, "1 new CVEs: CVE-2025-9802". Found 2026-11-15 with
# GET api.github.com/repos/CVEProject/cvelistV5/commits?until=2025-09-01T23:59:59Z&per_page=1
SNAPSHOT_COMMIT = "98fa1ad30aab38c0795065b63e249ed0a1d93b7d"
RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5"
USER_AGENT = "sira-research-client"


class Fetcher:
    def __init__(self, cache: Path, commit: str, pause: float = 0.2, session=None, sleep=time.sleep):
        self.cache, self.commit, self.pause, self.sleep = cache, commit, pause, sleep
        self.session = session or requests.Session()
        self.requests = 0
        cache.mkdir(parents=True, exist_ok=True)

    def get(self, cve_id: str) -> dict:
        path = self.cache / f"{self.commit[:12]}.{cve_id}.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        url = f"{RAW}/{self.commit}/{cve_list_path(cve_id)}"
        for attempt in range(6):
            if self.requests:
                self.sleep(self.pause)
            self.requests += 1
            try:
                resp = self.session.get(url, headers={"User-Agent": USER_AGENT}, timeout=60)
            except requests.RequestException as exc:     # a timeout or dropped connection is not an answer
                print(f"  {cve_id}: {type(exc).__name__}, waiting and trying again", flush=True)
                self.sleep(10 * (attempt + 1))
                continue
            if resp.status_code == 200:
                data = resp.json()
                path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
                return data
            if resp.status_code in (429, 500, 502, 503, 504):
                print(f"  {cve_id}: HTTP {resp.status_code}, waiting and trying again", flush=True)
                self.sleep(10 * (attempt + 1))
                continue
            raise RuntimeError(f"{cve_id}: HTTP {resp.status_code} for {url}")
        raise RuntimeError(f"{cve_id}: kept failing; run again later (the cache keeps what was fetched)")


def build(ids: list[str], fetcher: Fetcher, cutoff: str) -> tuple[list[dict], list[str]]:
    rows, problems = [], []
    for cve_id in ids:
        try:
            rebuilt = contents_from_cve_list(fetcher.get(cve_id), cutoff)
        except PatchError as exc:
            problems.append(str(exc))
            continue
        rows.append(patch_row(cve_id, rebuilt, cutoff=cutoff, commit=fetcher.commit))
    return rows, problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kb-dir", default="data/CTIConnect/corpus_kb", help="CTIConnect's corpus_kb (the source)")
    ap.add_argument("--cutoff", default=None, help="snapshot date; default: corpus_kb MANIFEST.json snapshot_date")
    ap.add_argument("--commit", default=SNAPSHOT_COMMIT, help="cvelistV5 commit to read the records at")
    ap.add_argument("--cache", default="data/raw/cvelist_fill", help="where fetched records are kept (gitignored)")
    ap.add_argument("--out", default="configs/corpus_patches/cve_null_fill_v1.jsonl")
    args = ap.parse_args(argv)

    kb = Path(args.kb_dir)
    cutoff = args.cutoff or json.loads((kb / "MANIFEST.json").read_text(encoding="utf-8"))["snapshot_date"]
    ids = null_cve_ids(kb)
    print(f"{len(ids)} CVE rows with no text in {kb}/cve.jsonl; cutoff {cutoff}; CVE List commit {args.commit[:12]}",
          flush=True)
    fetcher = Fetcher(Path(args.cache), args.commit)
    rows, problems = build(ids, fetcher, cutoff)
    if problems:
        print("NOT written; fix these first:\n  " + "\n  ".join(problems))
        return 1
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    with_cwe = [r for r in rows if r["cwe_from"]]
    print(f"wrote {len(rows)} rows to {out} ({fetcher.requests} requests)")
    print(f"  CWE ids attached by the cutoff: {len(with_cwe)} of {len(rows)} "
          f"(from: {sorted({p for r in with_cwe for p in r['cwe_from']})})")
    print(f"  a CVSS score existed and is left out: {sum(r['cvss_existed_not_included'] for r in rows)}")
    print(f"  CNAs: {dict(sorted({r['cna']: sum(x['cna'] == r['cna'] for x in rows) for r in rows}.items()))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
