"""The graph tool itself — the component RQ1 and RQ4 are actually about.

The four rejection modes are tested separately on purpose. If ``DEPRECATED``
and ``REVOKED`` silently collapse into ``NOT_IN_GRAPH``, the RQ4 audit will
report a hallucination rate that is really a staleness rate, and no test
elsewhere in the suite would catch it.
"""

from helpers import build_attack_only_graph, build_fixture_graph

from sira_cti.common import RejectReason
from sira_cti.graph import Namespace, RevokedPolicy


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


def test_revoked_policy_defaults_to_reject():
    # Default behaviour is unchanged whether or not revoked_policy is passed.
    g = build_fixture_graph()
    result = g.validate("T1004")
    assert not result.valid
    assert result.repaired is False
    assert result.reject_reason is RejectReason.REVOKED
    assert result.replacement_id == "T1547.004"


def test_revoked_policy_repair_accepts_and_rewrites_to_the_replacement():
    g = build_fixture_graph()
    result = g.validate("T1004", revoked_policy="repair")
    assert result.valid
    assert result.canonical_id == "T1547.004"
    assert result.node.node_id == "T1547.004"
    assert result.node.name == "Winlogon Helper DLL"


def test_revoked_policy_repair_still_records_that_a_repair_happened():
    # The rejection log is the RQ4 dataset -- a repaired term must remain
    # distinguishable from a term that was simply valid all along.
    g = build_fixture_graph()
    result = g.validate("T1004", revoked_policy="repair")
    assert result.repaired is True
    assert result.reject_reason is RejectReason.REVOKED
    assert result.replacement_id == "T1547.004"

    clean = g.validate("T1110")
    assert clean.repaired is False
    assert clean.reject_reason is None


def test_revoked_policy_accepts_the_enum_too():
    g = build_fixture_graph()
    result = g.validate("T1004", revoked_policy=RevokedPolicy.REPAIR)
    assert result.valid and result.repaired


def test_revoked_policy_repair_still_rejects_deprecated_terms():
    # Repair only applies to REVOKED terms; DEPRECATED is a separate reject
    # reason with no replacement to repair to.
    g = build_fixture_graph()
    result = g.validate("T1064", revoked_policy="repair")
    assert not result.valid
    assert result.reject_reason is RejectReason.DEPRECATED
    assert result.repaired is False


def test_revoked_policy_repair_cannot_repair_without_a_replacement():
    # T1110.002 is revoked but carries no revoked-by relationship (see the
    # syntactic-parent-fallback fixture note) -- there is nothing to repair
    # to, so repair policy must fall back to reject rather than fabricate one.
    g = build_fixture_graph()
    result = g.validate("T1110.002", revoked_policy="repair")
    assert not result.valid
    assert result.repaired is False
    assert result.reject_reason is RejectReason.REVOKED
    assert result.replacement_id is None


def test_validate_many_forwards_revoked_policy():
    g = build_fixture_graph()
    results = g.validate_many(["T1004", "T1110"], revoked_policy="repair")
    assert results[0].valid and results[0].repaired
    assert results[1].valid and not results[1].repaired


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


def test_parents_falls_back_to_the_syntactic_parent_when_the_edge_is_pruned():
    # T1110.002 is revoked with no subtechnique-of relationship object in the
    # fixture at all -- modelling how revocation prunes a node's edges. It is
    # still syntactically T1110's child, and parents() should say so for the
    # audit log even though the graph carries no such edge.
    g = build_fixture_graph()
    assert g.parents("T1110.002") == ["T1110"]


def test_syntactic_parent_fallback_does_not_change_validation():
    # The fallback is read by context()/parents() for readability; validate()
    # must be completely unaware of it. A pruned-edge sub-technique is still
    # rejected as REVOKED, not smuggled in because its parent resolves.
    g = build_fixture_graph()
    result = g.validate("T1110.002")
    assert not result.valid
    assert result.reject_reason is RejectReason.REVOKED
    # A genuinely invented sub-technique of a real parent must still be
    # NOT_IN_GRAPH -- the fallback must not make up parents for IDs that were
    # never loaded at all.
    assert g.parents("T1110.099") == []
    assert g.validate("T1110.099").reject_reason is RejectReason.NOT_IN_GRAPH


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
    assert stats["nodes_by_status"]["revoked"] == 2   # T1004 and T1110.002
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


# -- name-ID consistency (the CTI adaptation of SIRA's grounding) --------------------
#
# Wikipedia categories are named, so SIRA's existence check is also a meaning
# check. MITRE ids are integers in a dense namespace, so existence alone is
# nearly free. These tests pin the behaviour of the check that replaces it.


def test_an_exactly_right_title_matches():
    g = build_fixture_graph()
    check = g.check_name("T1110.001", "Password Guessing")
    assert check.matches
    assert check.overlap == 1.0
    assert check.official_name == "Password Guessing"


def test_a_wrong_title_on_a_real_id_is_a_mismatch():
    # The failure mode the check exists for: the id is real, the model does
    # not know what it is. An existence check passes this.
    g = build_fixture_graph()
    check = g.check_name("T1110.001", "Spyware")
    assert not check.matches
    assert check.overlap == 0.0
    assert check.official_name == "Password Guessing"


def test_a_short_but_correct_title_matches_a_long_official_one():
    # CWE titles are long and formal; analysts (and models) use the short name.
    # Scoring this as a mismatch would reject correct answers.
    g = build_fixture_graph()
    check = g.check_name("CWE-307", "Excessive Authentication Attempts")
    assert check.matches
    assert check.official_name == "Improper Restriction of Excessive Authentication Attempts"


def test_a_missing_title_is_a_mismatch_not_a_pass():
    # No claim is not evidence of knowledge. Passing it would restore
    # existence-only behaviour on exactly the least confident proposals.
    g = build_fixture_graph()
    for claimed in (None, "", "   "):
        check = g.check_name("T1110.001", claimed)
        assert not check.matches
        assert check.claimed_name is None


def test_catalogue_style_words_alone_do_not_make_a_match():
    # Every second CWE title opens "Improper ..." / "Insufficient ...".
    # Two unrelated weaknesses must not match on house style.
    g = build_fixture_graph()
    assert not g.check_name("CWE-307", "Improper Control of the Other Thing").matches


def test_the_threshold_is_the_callers_choice():
    g = build_fixture_graph()
    # "guessing attacks": 1 of its 2 content words is in "Password Guessing".
    assert g.check_name("T1110.001", "guessing attacks", min_overlap=0.5).matches
    assert not g.check_name("T1110.001", "guessing attacks", min_overlap=0.9).matches


def test_a_single_word_claim_scores_full_overlap_a_known_weakness():
    # Pinning a limitation, not endorsing it. The overlap coefficient divides
    # by the *shorter* title's length, which is what lets "Cross-site
    # Scripting" match CWE-79's full official name -- and the same arithmetic
    # lets a one-word claim pass on one shared word. The alternative (a
    # minimum shared-token count) would reject genuinely one-word titles like
    # CWE-512 "Spyware", so the check keeps the generous rule and the run
    # report counts how many passes rest on a single word instead.
    g = build_fixture_graph()
    check = g.check_name("CWE-307", "authentication")
    assert check.matches
    assert check.overlap == 1.0


def test_an_unknown_id_reports_no_official_name():
    g = build_fixture_graph()
    check = g.check_name("T9999", "Anything")
    assert not check.matches
    assert check.official_name is None


def test_name_tokens_drops_punctuation_and_style_words():
    from sira_cti.graph import name_tokens

    assert name_tokens("Improper Neutralization of Input ('Cross-site Scripting')") == {
        "neutralization",
        "input",
        "cross",
        "site",
        "scripting",
    }


# -- ontology distance (reported, never filtered on) ---------------------------------


def test_distance_to_itself_is_zero():
    assert build_fixture_graph().distance("T1110", "T1110") == 0


def test_distance_follows_hierarchy_edges_ignoring_direction():
    # T1110.001 --subtechnique-of--> T1110 is one hop either way round. A
    # directed distance would be 1 one way and None the other, which would
    # measure which catalogue wrote the edge down.
    g = build_fixture_graph()
    assert g.distance("T1110.001", "T1110") == 1
    assert g.distance("T1110", "T1110.001") == 1


def test_distance_crosses_catalogues_over_mapping_edges():
    g = build_fixture_graph()
    assert g.distance("CWE-307", "T1110.001") == g.distance("T1110.001", "CWE-307")
    assert g.distance("T1110.001", "CWE-307") is not None


def test_distance_is_none_when_either_end_is_not_an_ontology_node():
    # Every CVE lands here: a corpus document with no entry in the ontology.
    g = build_fixture_graph()
    assert g.distance("CVE-2024-0001", "T1110") is None
    assert g.distance("T1110", "CVE-2024-0001") is None


def test_distance_respects_the_hop_cap():
    g = build_fixture_graph()
    assert g.distance("T1110.001", "CWE-307", max_hops=1) is None
    assert g.distance("T1110.001", "CWE-307", max_hops=6) == 2
