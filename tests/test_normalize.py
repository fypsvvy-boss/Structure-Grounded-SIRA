"""Identifier normalisation.

These cases are drawn from the ways a 7B model actually writes identifiers:
lowercase, slashed sub-techniques, prose prefixes, zero-padding it invented
or dropped.
"""

from sira_cti.graph import (
    NodeType,
    Namespace,
    extract_structural_ids,
    is_id_shaped,
    looks_structural,
    parse_structural_id,
)


def test_canonicalises_attack_techniques():
    for raw in ["T1110", "t1110", " T1110 ", "technique T1110", "ATT&CK T1110", "MITRE ATT&CK: T1110"]:
        parsed = parse_structural_id(raw)
        assert parsed is not None, raw
        assert parsed.canonical == "T1110"
        assert parsed.namespace is Namespace.ATTACK
        assert parsed.node_type is NodeType.TECHNIQUE


def test_canonicalises_subtechnique_separators_and_padding():
    for raw in ["T1110.001", "t1110/001", "T1110-001", "T1110.1", "sub-technique T1110.1"]:
        parsed = parse_structural_id(raw)
        assert parsed is not None, raw
        assert parsed.canonical == "T1110.001", raw
        assert parsed.is_subtechnique
        assert parsed.parent_id == "T1110"


def test_tactic_prefix_beats_technique_prefix():
    parsed = parse_structural_id("TA0006")
    assert parsed is not None
    assert parsed.canonical == "TA0006"
    assert parsed.node_type is NodeType.TACTIC
    # Not misread as technique T0006 by a greedy T#### match.
    assert parsed.canonical != "T0006"


def test_data_source_prefix_beats_software_prefix():
    parsed = parse_structural_id("DS0028")
    assert parsed is not None
    assert parsed.node_type is NodeType.DATA_SOURCE
    assert parsed.canonical == "DS0028"


def test_canonicalises_cwe_and_capec_spellings():
    for raw in ["CWE-307", "cwe 307", "CWE_307", "cwe307", "CWE-307."]:
        parsed = parse_structural_id(raw)
        assert parsed is not None, raw
        assert parsed.canonical == "CWE-307", raw
        assert parsed.namespace is Namespace.CWE

    parsed = parse_structural_id("capec-49")
    assert parsed is not None
    assert parsed.canonical == "CAPEC-49"
    assert parsed.namespace is Namespace.CAPEC


def test_cwe_leading_zeros_are_stripped():
    # MITRE writes CWE-79, never CWE-0079; a model that pads must still resolve.
    assert parse_structural_id("CWE-0079").canonical == "CWE-79"


def test_bare_numbers_never_parse():
    # "307" is ambiguous between CWE-307 and CAPEC-307. Accepting either would
    # let an unqualified guess through validation.
    for raw in ["307", "1110", "0001", ""]:
        assert parse_structural_id(raw) is None, raw


def test_malformed_identifiers_are_rejected():
    for raw in ["T99", "T11101", "CWE-abc", "TECHNIQUE", "T1110.0001", "CWE-", "None", "null"]:
        assert parse_structural_id(raw) is None, raw


def test_plain_language_terms_are_not_structural():
    for raw in ["brute force login", "password spraying", "failed logins from one IP"]:
        assert parse_structural_id(raw) is None, raw


def test_extract_from_prose_deduplicates_and_preserves_order():
    prose = (
        "This looks like ATT&CK T1110 (Brute Force), specifically T1110.001, "
        "which maps to CWE-307 and CAPEC-49. See also T1110 again."
    )
    found = [p.canonical for p in extract_structural_ids(prose)]
    assert found == ["T1110", "T1110.001", "CWE-307", "CAPEC-49"]


def test_extract_ignores_numbers_in_running_text():
    assert extract_structural_ids("307 failed logins in 1110 seconds") == []


# -- "was this even an attempt at an identifier?" -------------------------------------


def test_ordinary_vocabulary_is_not_id_shaped():
    # Exactly the terms Qwen2.5-7B mislabelled kind="structural" in the first
    # real run. None of them reached for an identifier, so none is RQ4
    # hallucination signal -- see docs/04_OPEN_QUESTIONS.md question 3.
    for term in ("heap-based", "zzip_get32", "local", "medium"):
        assert not is_id_shaped(term), term
        assert not looks_structural(term), term


def test_a_botched_identifier_is_id_shaped_but_not_well_formed():
    # The gap between the two predicates is the RQ4-relevant case: the model
    # aimed at an identifier and missed.
    for term in ("CWE-abc", "T99", "capec 12x", "CWE-"):
        assert is_id_shaped(term), term
        assert not looks_structural(term), term


def test_a_valid_identifier_is_both():
    for term in ("CWE-307", "T1110.001", "CAPEC-49", "cwe 307"):
        assert is_id_shaped(term), term
        assert looks_structural(term), term


def test_letter_prefix_alone_does_not_make_a_term_id_shaped():
    # "medium" opens with the mitigation prefix M and "campaign" with C; only
    # a digit sitting directly on the prefix counts.
    for term in ("medium", "campaign", "session hijacking", "goto fail"):
        assert not is_id_shaped(term), term


def test_is_id_shaped_tolerates_empty_input():
    assert not is_id_shaped("")
    assert not is_id_shaped("   ")
