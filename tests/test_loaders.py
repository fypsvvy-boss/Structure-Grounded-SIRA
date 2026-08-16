"""Loaders for the three MITRE source formats."""

from helpers import ATTACK_FIXTURE, CAPEC_FIXTURE, CWE_FIXTURE, load_fixture_result

from sira_cti.graph import (
    EdgeType,
    Namespace,
    NodeType,
    Status,
    load_attack_stix,
    load_capec_xml,
    load_cwe_xml,
)


def _by_id(result):
    return {n.node_id: n for n in result.nodes}


# -- ATT&CK ---------------------------------------------------------------------


def test_attack_loads_techniques_tactics_and_mitigations():
    nodes = _by_id(load_attack_stix(ATTACK_FIXTURE))
    assert nodes["T1110"].node_type is NodeType.TECHNIQUE
    assert nodes["T1110.001"].node_type is NodeType.SUBTECHNIQUE
    assert nodes["TA0006"].node_type is NodeType.TACTIC
    assert nodes["M1027"].node_type is NodeType.MITIGATION
    assert nodes["T1110"].namespace is Namespace.ATTACK


def test_deprecated_technique_is_loaded_not_skipped():
    # It must be present so validate() can say "deprecated" rather than
    # "never existed" — those are different RQ4 findings.
    nodes = _by_id(load_attack_stix(ATTACK_FIXTURE))
    assert "T1064" in nodes
    assert nodes["T1064"].status is Status.DEPRECATED


def test_revoked_technique_records_its_replacement():
    nodes = _by_id(load_attack_stix(ATTACK_FIXTURE))
    assert nodes["T1004"].status is Status.REVOKED
    assert nodes["T1004"].revoked_by == "T1547.004"


def test_subtechnique_and_tactic_edges_are_built():
    result = load_attack_stix(ATTACK_FIXTURE)
    edges = {(e.src, e.dst, e.edge_type) for e in result.edges}
    assert ("T1110.001", "T1110", EdgeType.SUBTECHNIQUE_OF) in edges
    assert ("T1110", "TA0006", EdgeType.IN_TACTIC) in edges
    assert ("T1004", "T1547.004", EdgeType.REVOKED_BY) in edges


def test_domain_filter_excludes_other_matrices():
    enterprise = _by_id(load_attack_stix(ATTACK_FIXTURE, domains={"enterprise-attack"}))
    assert "T1400" not in enterprise          # mobile-only
    assert "T1110" in enterprise
    assert "T1400" in _by_id(load_attack_stix(ATTACK_FIXTURE))


# -- CWE ------------------------------------------------------------------------


def test_cwe_parses_through_the_default_namespace():
    # The catalogue declares a default xmlns; matching on local name keeps the
    # loader working when MITRE bumps cwe-7 to cwe-8.
    nodes = _by_id(load_cwe_xml(CWE_FIXTURE))
    assert nodes["CWE-307"].name.startswith("Improper Restriction")
    assert nodes["CWE-307"].description


def test_cwe_hierarchy_and_capec_links():
    result = load_cwe_xml(CWE_FIXTURE)
    edges = {(e.src, e.dst, e.edge_type) for e in result.edges}
    assert ("CWE-307", "CWE-799", EdgeType.CHILD_OF) in edges
    assert ("CWE-799", "CWE-691", EdgeType.CHILD_OF) in edges
    assert ("CWE-307", "CAPEC-49", EdgeType.MAPS_TO) in edges


def test_cwe_deprecated_status_is_captured():
    assert _by_id(load_cwe_xml(CWE_FIXTURE))["CWE-217"].status is Status.DEPRECATED


def test_cwe_categories_and_views_load_with_membership():
    result = load_cwe_xml(CWE_FIXTURE)
    nodes = _by_id(result)
    assert nodes["CWE-1015"].node_type is NodeType.WEAKNESS_CATEGORY
    assert nodes["CWE-1000"].node_type is NodeType.WEAKNESS_VIEW
    edges = {(e.src, e.dst, e.edge_type) for e in result.edges}
    assert ("CWE-307", "CWE-1015", EdgeType.MEMBER_OF) in edges


# -- CAPEC ----------------------------------------------------------------------


def test_capec_patterns_hierarchy_and_cwe_links():
    result = load_capec_xml(CAPEC_FIXTURE)
    nodes = _by_id(result)
    assert nodes["CAPEC-49"].node_type is NodeType.ATTACK_PATTERN
    assert nodes["CAPEC-49"].attrs["abstraction"] == "Standard"
    edges = {(e.src, e.dst, e.edge_type) for e in result.edges}
    assert ("CAPEC-49", "CAPEC-112", EdgeType.CHILD_OF) in edges
    assert ("CAPEC-49", "CWE-307", EdgeType.MAPS_TO) in edges


def test_capec_attack_taxonomy_entries_gain_their_T_prefix():
    # CAPEC writes ATT&CK entries as "1110.001", without the leading T.
    edges = {(e.src, e.dst) for e in load_capec_xml(CAPEC_FIXTURE).edges}
    assert ("CAPEC-49", "T1110.001") in edges
    assert ("CAPEC-112", "T1110") in edges


def test_non_attack_taxonomy_mappings_are_ignored():
    # CAPEC-112 also carries a WASC mapping with Entry_ID 11; it must not
    # become an ATT&CK edge to T0011.
    edges = {e.dst for e in load_capec_xml(CAPEC_FIXTURE).edges}
    assert "T0011" not in edges


def test_capec_obsolete_status_maps_to_deprecated():
    assert _by_id(load_capec_xml(CAPEC_FIXTURE))["CAPEC-999"].status is Status.DEPRECATED


def test_load_all_combines_three_catalogues_without_warnings():
    result = load_fixture_result()
    ids = {n.node_id for n in result.nodes}
    assert {"T1110", "CWE-307", "CAPEC-49"} <= ids
    assert result.warnings == []
