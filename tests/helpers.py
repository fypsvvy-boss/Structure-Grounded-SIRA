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

import re

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


class FakeDFLookup:
    """A :class:`~sira_cti.index.df_stats.DFLookup` with hand-set counts.

    Enrichment tests need a DF source that doesn't require building a real
    Lucene index per test; ``df_stats.LuceneDFLookup`` is covered separately,
    against a real (small, local, no-network) index.
    """

    def __init__(self, counts: dict[str, int], *, total_docs: int) -> None:
        self._counts = {k.lower(): v for k, v in counts.items()}
        self.total_docs = total_docs

    def doc_freq(self, term: str, *, combine: str = "max") -> int:
        # Mirror the real lookup's per-token combine policy closely enough for
        # tests. The real analyzer also splits on punctuation (``CWE-307`` ->
        # ``["cwe", "307"]``); this splits on whitespace and hyphens so a test
        # can exercise the multi-token path without a live Lucene index.
        tokens = [tok for tok in re.split(r"[\s\-]+", term) if tok]
        dfs = [self._counts.get(tok.lower(), 0) for tok in tokens]
        if not dfs:
            return 0
        return min(dfs) if combine == "min" else max(dfs)


def build_injection_graph() -> OntologyGraph:
    """A hand-built CWE injection family, with MITRE's real titles and short names.

    The mini fixtures have no entry whose title carries a quoted short name,
    and the name scorers differ *only* on entries that do. Built from nodes
    rather than XML so the titles under test are visible in one place.

        CWE-707 (parent)
          +- CWE-74 'Injection'
               +- CWE-89 'SQL Injection'      +- CWE-78 'OS Command Injection'
               +- CWE-79 'Cross-site Scripting' (alternate term: XSS)
          +- CWE-20  Improper Input Validation            (no short name)
          +- CWE-173 Improper Handling of Alternate Encoding (no short name)
    """
    from sira_cti.graph import EdgeType, Namespace, NodeType, OntologyEdge, OntologyNode
    from sira_cti.graph.loaders import cwe_short_names

    def cwe(num: int, title: str, alternates: tuple[str, ...] = ()) -> OntologyNode:
        shorts = cwe_short_names(title, alternates)
        return OntologyNode(
            node_id=f"CWE-{num}", namespace=Namespace.CWE, node_type=NodeType.WEAKNESS,
            name=title, aliases=list(shorts), attrs={"short_names": list(shorts)},
        )

    g = OntologyGraph()
    for node in (
        cwe(707, "Improper Neutralization"),
        cwe(74, "Improper Neutralization of Special Elements in Output Used by a "
                "Downstream Component ('Injection')"),
        cwe(89, "Improper Neutralization of Special Elements used in an SQL Command "
                "('SQL Injection')", ("SQLi",)),
        cwe(78, "Improper Neutralization of Special Elements used in an OS Command "
                "('OS Command Injection')"),
        cwe(79, "Improper Neutralization of Input During Web Page Generation "
                "('Cross-site Scripting')", ("XSS",)),
        cwe(20, "Improper Input Validation"),
        cwe(173, "Improper Handling of Alternate Encoding"),
    ):
        g.add_node(node)
    for child, parent in ((74, 707), (89, 74), (78, 74), (79, 74), (20, 707), (173, 707)):
        g.add_edge(OntologyEdge(f"CWE-{child}", f"CWE-{parent}", EdgeType.CHILD_OF))
    return g
