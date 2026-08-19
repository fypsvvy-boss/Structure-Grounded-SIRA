"""Shared builders for the test suite.

Plain functions rather than pytest fixtures: the same helpers are used by the
loader tests, the graph tests and any ad-hoc script, and fixtures would make
them pytest-only.

The fixture files under ``tests/fixtures/`` are hand-written miniatures of the
real MITRE formats — same element names, same namespaces, same edge cases
(deprecated, revoked, sub-technique, cross-catalogue links) — so the suite
runs offline and in CI without a multi-hundred-megabyte download.
"""

from __future__ import annotations

from pathlib import Path

from sira_cti.graph import OntologyGraph, load_all

FIXTURES = Path(__file__).parent / "fixtures"

ATTACK_FIXTURE = FIXTURES / "mini_attack.json"
CWE_FIXTURE = FIXTURES / "mini_cwe.xml"
CAPEC_FIXTURE = FIXTURES / "mini_capec.xml"
CORPUS_KB_FIXTURE = FIXTURES / "corpus_kb"


def load_fixture_result():
    """All three catalogues, loaded but not yet assembled into a graph."""
    return load_all(
        attack_path=ATTACK_FIXTURE,
        cwe_path=CWE_FIXTURE,
        capec_path=CAPEC_FIXTURE,
    )


def build_fixture_graph() -> OntologyGraph:
    """The full three-catalogue graph used by most of the ontology tests."""
    return OntologyGraph.from_files(
        attack_path=ATTACK_FIXTURE,
        cwe_path=CWE_FIXTURE,
        capec_path=CAPEC_FIXTURE,
    )


def build_attack_only_graph() -> OntologyGraph:
    return OntologyGraph.from_files(attack_path=ATTACK_FIXTURE)
