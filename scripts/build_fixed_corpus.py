#!/usr/bin/env python
"""Build the fixed corpus: CTIConnect's corpus_kb with the 117 empty CVE rows filled.

    .venv/bin/python scripts/build_fixed_corpus.py

Reads ``--src`` (CTIConnect's corpus_kb, checked against its own
MANIFEST.json), replaces the contents of every ``"null"`` CVE row with the
patch file's, and writes ``--out`` with a new MANIFEST.json that says what was
changed. Nothing else changes: the other lines are byte-identical and the
other three files are copied. Needs no network. See
``src/sira_cti/index/corpus_patch.py`` and ``data/README.md``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.index.corpus_patch import PatchError, apply_patch  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", default="data/CTIConnect/corpus_kb")
    ap.add_argument("--patch", default="configs/corpus_patches/cve_null_fill_v1.jsonl")
    ap.add_argument("--out", default="data/corpus_kb_fixed")
    args = ap.parse_args(argv)
    try:
        manifest = apply_patch(args.src, args.patch, args.out)
    except PatchError as exc:
        print(f"Refused: {exc}")
        return 1
    fixed = manifest["fixed_by"]
    print(f"wrote {args.out}: {fixed['rows_filled']} CVE rows filled from {fixed['patch_file']} "
          f"(sha256 {fixed['patch_sha256'][:12]}); cve.jsonl sha256 {manifest['files']['cve.jsonl']['sha256'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
