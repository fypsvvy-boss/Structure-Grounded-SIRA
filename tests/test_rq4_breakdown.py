"""``scripts/rq4_breakdown.py``: the RQ4 counts over one enrichment file."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from rq4_breakdown import breakdown, catalogue_of  # noqa: E402


@pytest.mark.parametrize("sid, cat", [
    ("CWE-79", "cwe"), ("cwe-79", "cwe"), ("CAPEC-66", "capec"), ("T1110", "attack"), ("T1110.001", "attack"),
    ("TA0007", "attack"), ("S0106", "attack"),   # tactic and software ids, both seen in Stage 1
    ("CVE-2024-1", "other"), ("MITRE ATT&CK", "other"), (None, "other"),
])
def test_catalogue_of(sid, cat):
    assert catalogue_of(sid) == cat


def _term(term, kind="structural", *, sid=None, accepted=False, reason=None, stage=None, run=False):
    validated = None if kind != "structural" else stage != "graph"   # False only when the graph said no
    return {"term": term, "kind": kind, "structural_id": sid, "graph_validated": validated, "doc_freq": None,
            "accepted": accepted, "reject_reason": reason, "repaired_from_id": None, "claimed_name": None,
            "official_name": None, "rejected_at_stage": stage, "in_counting_run": run, "graph_distance": None,
            "name_scorer": None, "repaired_to": None}


def test_breakdown_counts_stages_cve_ids_counting_runs_and_own_ids(tmp_path):
    records = [
        {"doc_id": "CVE-2024-0001", "source": "cve", "original_text": "x", "proposed_terms": [
            _term("CVE-2024-0001", sid="CVE-2024-0001", reason="malformed_id", stage="graph"),
            _term("CVE-2023-9999", sid="CVE-2023-9999", reason="malformed_id", stage="graph"),
            _term("CWE-89", sid="CWE-89", accepted=True),
            _term("sql injection", "colloquial", reason="too_common", stage="df"),
        ]},
        {"doc_id": "CWE-79", "source": "cwe", "original_text": "x", "proposed_terms": [
            _term("CWE-79", sid="CWE-79", accepted=True),
            _term("CWE-80", sid="CWE-80", reason="name_mismatch", stage="name", run=True),
            _term("CWE-81", sid="CWE-81", reason="name_mismatch", stage="name", run=True),
            _term("CWE-82", sid="CWE-82", accepted=True, run=True),
        ]},
    ]
    path = tmp_path / "e.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    path.with_suffix(".jsonl.manifest.json").write_text(json.dumps({"kinds": ["cwe", "capec", "mitre", "cve"]}))

    b = breakdown(path)
    assert b["order"] == ["cwe", "capec", "attack", "cve"]          # every kind, even with no records
    assert b["totals"]["attack"] == {} and b["totals"]["cve"] == {"docs": 1, "proposed": 4, "accepted": 1}
    assert b["stages"]["cve"] == {"parse": 0, "graph": 2, "name": 0, "df": 1}
    assert b["cve_malformed"] == {"own CVE id": 1, "other CVE id": 1} and b["cve_malformed_docs"] == 1
    assert b["structural"]["cwe/cwe"] == {"proposed": 4, "accepted": 2, "name_mismatch": 2, "counting": 3}
    assert b["counting"]["cwe"] == {"ids": 3, "accepted": 1, "docs_with_run": 1}
    assert b["own_id"]["cwe"] == {"docs_proposing_own_id": 1, "docs_accepting_own_id": 1}
    assert b["own_id"]["cve"] == {"docs_proposing_own_id": 1, "docs_accepting_own_id": 0}
