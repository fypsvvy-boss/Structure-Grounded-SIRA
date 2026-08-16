"""The graph tool itself — the component RQ1 and RQ4 are actually about.

The four rejection modes are tested separately on purpose. If ``DEPRECATED``
and ``REVOKED`` silently collapse into ``NOT_IN_GRAPH``, the RQ4 audit will
report a hallucination rate that is really a staleness rate, and no test
elsewhere in the suite would catch it.
"""

from helpers import build_attack_only_graph, build_fixture_graph

from sira_cti.common import RejectReason
from sira_cti.graph import Namespace


def test_valid_technique_passes_and_canonicalises():
    g = build_fixture_graph()
    result = g.validate("t1110/001")
    assert result.valid
    assert bool(result) is True
    assert result.canonical_id == "T1110.001"
    assert result.node.name == "Password Guessing"
    assert result.reject_reason is None


def test_malformed_identifier_is_distinguished_from_a_missing_one():
    g = build_fixture_graph()
    assert g.validate("T99").reject_reason is RejectReason.MALFORMED_ID
    assert g.validate("brute force").reject_reason is RejectReason.MALFORMED_ID


def test_well_formed_but_absent_identifier_is_the_hallucination_case():
    g = build_fixture_graph()
    result = g.validate("T9999")
    assert not result.valid
    assert result.reject_reason is RejectReason.NOT_IN_GRAPH
    assert result.canonical_id == "T9999"   # canonical form still reported, for the audit
    assert result.node is None


def test_plausible_but_invented_subtechnique_of_a_real_parent_is_caught():
    # The failure mode most likely to slip through: real parent, invented child.
    g = build_fixture_graph()
    assert g.validate("T1110.099").reject_reason is RejectReason.NOT_IN_GRAPH


def test_revoked_technique_is_rejected_and_names_its_replacement():
    g = build_fixture_graph()
    result = g.validate("T1004")
    assert not result.valid
    assert result.reject_reason is RejectReason.REVOKED
    assert result.replacement_id == "T1547.004"


def test_deprecated_technique_is_rejected_by_default():
    g = build_fixture_graph()
    assert g.validate("T1064").reject_reason is RejectReason.DEPRECATED


def test_deprecated_can_be_admitted_for_the_ablation():
    # Deprecated text is still in the corpus, so admitting it may help recall.
    g = build_fixture_graph()
    assert g.validate("T1064", allow_deprecated=True).valid


def test_revoked_stays_rejected_even_when_deprecated_is_allowed():
    g = build_fixture_graph()
    assert not g.validate("T1004", allow_deprecated=True).valid


def test_cwe_and_capec_validate_through_the_same_entry_point():
    g = build_fixture_graph()
    assert g.validate("cwe 307").canonical_id == "CWE-307"
    assert g.validate("CAPEC-49").valid
    assert g.validate("CWE-9999").reject_reason is RejectReason.NOT_IN_GRAPH
    assert g.validate("CWE-217").reject_reason is RejectReason.DEPRECATED


def test_validate_many_preserves_order():
    g = build_fixture_graph()
    results = g.validate_many(["T1110", "T9999", "CWE-307"])
    assert [r.valid for r in results] == [True, False, True]


# -- neighbourhood --------------------------------------------------------------


def test_parents_and_children_span_both_hierarchy_conventions():
    g = build_fixture_graph()
    assert g.parents("T1110.001") == ["T1110"]          # ATT&CK subtechnique-of
    assert g.parents("CWE-307") == ["CWE-799"]          # CWE ChildOf
    assert set(g.children("T1110")) == {"T1110.001", "T1110.004"}


def test_siblings_exclude_the_node_itself():
    g = build_fixture_graph()
    assert g.siblings("T1110.001") == ["T1110.004"]
    assert "T1110.001" not in g.siblings("T1110.001")


def test_tactic_lookup_falls_back_to_the_parent_technique():
    # T1110.004 carries no kill_chain_phases of its own; the tactic has to
    # come from its parent, or query enrichment silently loses tactic context.
    g = build_fixture_graph()
    assert g.tactics_for("T1110") == ["TA0006"]
    assert g.tactics_for("T1110.004") == ["TA0006"]


def test_cross_namespace_links_resolve_in_both_directions():
    g = build_fixture_graph()
    assert "CAPEC-49" in g.mapped("CWE-307")
    assert "CWE-307" in g.mapped("CAPEC-49")
    assert "T1110.001" in g.mapped("CAPEC-49")


def test_context_returns_everything_a_module_needs_in_one_call():
    ctx = build_fixture_graph().context("T1110.001")
    assert ctx["name"] == "Password Guessing"
    assert ctx["parents"] == ["T1110"]
    assert ctx["tactics"] == ["TA0006"]
    assert ctx["namespace"] == "attack"


def test_expansion_terms_include_the_parent_but_not_siblings_by_default():
    terms = build_fixture_graph().expansion_terms("T1110.001")
    assert "T1110.001" in terms and "Password Guessing" in terms
    assert "T1110" in terms and "Brute Force" in terms
    assert "Credential Stuffing" not in terms      # sibling, dilutes BM25 weight

    with_sibs = build_fixture_graph().expansion_terms("T1110.001", include_siblings=True)
    assert "Credential Stuffing" in with_sibs


def test_expansion_terms_are_deduplicated_case_insensitively():
    terms = build_fixture_graph().expansion_terms("T1110.001")
    assert len(terms) == len({t.lower() for t in terms})


# -- assembly -------------------------------------------------------------------


def test_resolve_accepts_identifiers_and_exact_names():
    g = build_fixture_graph()
    assert g.resolve("t1110").node_id == "T1110"
    assert g.resolve("Password Guessing").node_id == "T1110.001"
    assert g.resolve("no such thing") is None


def test_dangling_cross_catalogue_edges_are_recorded_not_fatal():
    # CAPEC references CWE and ATT&CK entries; loading CAPEC alone must not crash.
    from helpers import CAPEC_FIXTURE
    from sira_cti.graph import OntologyGraph

    g = OntologyGraph.from_files(capec_path=CAPEC_FIXTURE)
    assert g.stats()["dangling_edges"] > 0
    assert g.validate("CAPEC-49").valid


def test_attack_only_graph_still_validates_attack_ids():
    g = build_attack_only_graph()
    assert g.validate("T1110").valid
    assert g.validate("CWE-307").reject_reason is RejectReason.NOT_IN_GRAPH


def test_stats_report_status_and_edge_breakdowns():
    stats = build_fixture_graph().stats()
    assert stats["nodes"] > 0
    assert stats["nodes_by_status"]["revoked"] == 1
    assert stats["nodes_by_namespace"]["cwe"] >= 5
    assert "subtechnique_of" in stats["edges_by_type"]


def test_ids_listing_excludes_unusable_nodes_by_default():
    g = build_fixture_graph()
    active = g.ids(namespace=Namespace.ATTACK)
    assert "T1110" in active
    assert "T1064" not in active            # deprecated
    assert "T1004" not in active            # revoked
    assert "T1064" in g.ids(namespace=Namespace.ATTACK, active_only=False)


def test_membership_and_length():
    g = build_fixture_graph()
    assert "T1110" in g
    assert "T9999" not in g
    assert len(g) == len(g.ids(active_only=False))
