#!/usr/bin/env python3
"""Build the ontology graph from real MITRE data and sanity-check it.

Run this as the first thing in Phase 1, before writing any enrichment prompt.
It is the graph-tool equivalent of the Phase 0 SciFact smoke test: if the
numbers below look wrong, every downstream retrieval result is wrong too, and
you want to know now rather than in week 11.

    python scripts/build_graph.py --config configs/default.yaml

Expected magnitudes against current MITRE releases (they drift with each
release — treat these as order-of-magnitude, not exact targets):

    ATT&CK enterprise techniques + sub-techniques   ~800
    CWE weaknesses                                  ~950
    CAPEC attack patterns                           ~560
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import yaml

from sira_cti.graph import OntologyGraph

# Identifiers that should behave identically on every MITRE release. If one of
# these changes, MITRE changed something and the team should know why.
SPOT_CHECKS = [
    ("T1110", True, "Brute Force — the running example throughout the proposal"),
    ("t1110/001", True, "sloppy sub-technique spelling must still resolve"),
    ("CWE-307", True, "Improper Restriction of Excessive Authentication Attempts"),
    ("CAPEC-49", True, "Password Brute Forcing"),
    ("T9999", False, "well-formed but invented — the hallucination case"),
    ("T1110.099", False, "real parent, invented child"),
    ("T99", False, "malformed"),
    ("brute force login", False, "plain language is not a structural term"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--stats-out", default=None, help="write stats JSON here")
    args = parser.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())["graph"]

    attack_paths = cfg["attack_path"]
    if isinstance(attack_paths, str):
        attack_paths = [attack_paths]

    missing = [p for p in (*attack_paths, cfg["cwe_path"], cfg["capec_path"]) if not Path(p).exists()]
    if missing:
        print("Missing source files — see data/README.md for fetch steps:")
        for path in missing:
            print(f"  {path}")
        return 1

    graph = OntologyGraph.from_files(
        attack_path=attack_paths,
        cwe_path=cfg["cwe_path"],
        capec_path=cfg["capec_path"],
        domains=cfg.get("domains"),
    )

    stats = graph.stats()
    print(json.dumps(stats, indent=2))

    if stats["warnings"]:
        print(f"\n{stats['warnings']} loader warning(s):")
        for warning in graph.warnings[:10]:
            print(f"  {warning}")

    print("\nSpot checks:")
    failures = 0
    for term, expected_valid, note in SPOT_CHECKS:
        result = graph.validate(term)
        ok = result.valid == expected_valid
        failures += not ok
        reason = result.reject_reason.value if result.reject_reason else "valid"
        print(f"  [{'ok ' if ok else 'FAIL'}] {term:<20} {reason:<16} {note}")

    # The cross-namespace spine is the whole point of using CTI as the second
    # corpus. If these are empty, the CAPEC taxonomy mappings did not parse.
    print("\nCross-namespace spine:")
    for node_id in ("CWE-307", "CAPEC-49"):
        print(f"  {node_id} -> {graph.mapped(node_id)}")

    if args.stats_out:
        Path(args.stats_out).write_text(json.dumps(stats, indent=2))

    print(f"\n{'FAILED' if failures else 'PASSED'} — {len(SPOT_CHECKS) - failures}/{len(SPOT_CHECKS)} spot checks")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
