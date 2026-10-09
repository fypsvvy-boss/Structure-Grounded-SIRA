"""Section-aware truncation: what the model is shown when an entry is too long.

The rule under test: whole sections go in a fixed order, least useful first;
the description and the cross-catalogue links never go; only when those alone
do not fit is the text cut blindly, and then the record says so.
"""

import json

from sira_cti.enrichment.truncation import (
    DROP_ORDER,
    PROTECTED,
    TRUNCATION_VERSION,
    record_shown_text,
    shown_text,
    split_entry,
    truncate_text,
)


def _entry(title="Example Attack", **sections) -> str:
    return f"{title} {json.dumps(sections)}"


def _capec(filler=400, **extra) -> str:
    """A CAPEC-shaped entry whose link sections sit at the very end, as they do in corpus_kb."""
    sections = {
        "@ID": "999",
        "Description": "An adversary does a thing.",
        "Prerequisites": {"Prerequisite": ["p" * filler]},
        "Consequences": {"Consequence": [{"Scope": "Integrity", "Impact": "c" * filler}]},
        "Mitigations": {"Mitigation": ["m1 " + "x" * filler, "m2 " + "y" * filler, "m3 " + "z" * filler]},
        "Example_Instances": {"Example": "e" * filler},
        "Related_Weaknesses": {"Related_Weakness": [{"@CWE_ID": "345"}, {"@CWE_ID": "352"}]},
        "References": {"Reference": [{"@External_Reference_ID": "REF-1" + "r" * filler}]},
    }
    sections.update(extra)
    return _entry(**sections)


def _sections(text: str) -> dict:
    return split_entry(text)[1]


# -- nothing to do ---------------------------------------------------------------------


def test_an_entry_that_fits_is_returned_untouched_with_no_record():
    text = _capec()
    assert truncate_text(text, len(text)) == (text, None)
    assert truncate_text(text, None) == (text, None)


# -- the order ------------------------------------------------------------------------


def test_references_go_first_and_nothing_else_if_that_is_enough():
    text = _capec()
    shown, info = truncate_text(text, len(text) - 50)

    assert info["mode"] == "sections"
    assert info["dropped"] == ["References"]
    assert "References" not in _sections(shown)
    assert set(_sections(text)) - set(_sections(shown)) == {"References"}


def test_sections_are_dropped_in_the_documented_order():
    text = _capec()
    order = [key for _cat, keys, _trim in DROP_ORDER for key in keys]
    previous: list[str] = []
    for budget in range(len(text) - 1, 300, -200):
        _shown, info = truncate_text(text, budget)
        if info["mode"] != "sections":
            break
        gone = info["dropped"] + list(info["trimmed"])
        assert gone == sorted(gone, key=order.index)       # never out of order
        assert gone[: len(previous)] == previous or set(previous) <= set(gone)
        previous = info["dropped"]


def _cve(n_versions=200, vendors=(("cisco", "ios_xe"),), layout="criteria", **extra) -> str:
    matches = [
        {"vulnerable": True, layout: f"cpe:2.3:o:{vendor}:{product}:{i}.0:*:*:*:*:*:*:*"}
        for vendor, product in vendors for i in range(n_versions)
    ]
    key = "cpeMatch" if layout == "criteria" else "cpe_match"
    sections = {
        "descriptions": [{"value": "A flaw in the widget."}],
        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
        "configurations": [{"nodes": [{key: matches}]}],
    }
    sections.update(extra)
    return _entry("CVE-2099-0001", **sections)


def test_a_cve_product_table_is_replaced_by_its_vendor_and_product_names():
    text = _cve(vendors=(("cisco", "ios_xe"), ("oracle", "banking_platform")))
    shown, info = truncate_text(text, 600)

    assert _sections(shown)["affected_products"] == ["cisco ios xe", "oracle banking platform"]
    assert "configurations" not in _sections(shown)
    assert "cpe:2.3" not in shown and "199.0" not in shown          # no CPE strings, no versions
    # Recorded as summarised, not as dropped.
    assert info["summarised"] == {"configurations": {"as": "affected_products", "products": 2, "kept": 2}}
    assert info["dropped"] == []
    # The descriptive sections are untouched.
    assert _sections(shown)["descriptions"] == [{"value": "A flaw in the widget."}]
    assert "CWE-79" in shown


def test_each_product_is_named_once_however_many_versions_it_has():
    from sira_cti.enrichment.truncation import summarise_products

    table = _sections(_cve(n_versions=300))["configurations"]
    assert summarise_products(table) == ["cisco ios xe"]


def test_both_nvd_layouts_are_read_and_first_appearance_order_is_kept():
    from sira_cti.enrichment.truncation import summarise_products

    new = _sections(_cve(n_versions=2, vendors=(("b", "two"), ("a", "one"))))["configurations"]
    old = _sections(_cve(n_versions=2, vendors=(("b", "two"), ("a", "one")), layout="cpe23Uri"))["configurations"]
    nested = [{"nodes": [{"children": [{"cpe_match": [{"cpe23Uri": "cpe:2.3:h:intel:core_i7:-:*:*:*:*:*:*:*"}]}]}]}]

    assert summarise_products(new) == summarise_products(old) == ["b two", "a one"]
    assert summarise_products(nested) == ["intel core i7"]
    assert summarise_products([{"nodes": []}]) == []
    assert summarise_products("not a table") == []


def test_a_vendor_that_repeats_the_product_name_is_not_written_twice():
    from sira_cti.enrichment.truncation import summarise_products

    assert summarise_products([{"criteria": "cpe:2.3:a:lodash:lodash:4.17:*:*:*:*:*:*:*"}]) == ["lodash"]


def test_the_product_list_itself_is_cut_to_stay_inside_the_budget():
    vendors = tuple((f"vendor{i}", f"product_{i}") for i in range(300))
    text = _cve(n_versions=3, vendors=vendors)
    shown, info = truncate_text(text, 1000)

    assert len(shown) <= 1000
    summary = info["summarised"]["configurations"]
    assert summary["products"] == 300 and 0 < summary["kept"] < 300
    assert _sections(shown)["affected_products"] == [f"vendor{i} product {i}" for i in range(summary["kept"])]


def test_when_not_even_one_name_fits_the_table_is_recorded_as_dropped():
    text = _cve(descriptions=[{"value": "d" * 300}])
    budget = len(_entry("CVE-2099-0001", descriptions=[{"value": "d" * 300}],
                        weaknesses=[{"description": [{"value": "CWE-79"}]}])) + 5
    shown, info = truncate_text(text, budget)

    assert info["mode"] == "sections"
    assert info["dropped"] == ["configurations"] and info["summarised"] == {}
    assert "affected_products" not in _sections(shown)


def test_the_summary_sits_where_the_table_was():
    text = _cve(cisaExploitAdd="2024-01-01")
    shown, _info = truncate_text(text, 700)
    assert list(_sections(shown)) == ["descriptions", "weaknesses", "affected_products", "cisaExploitAdd"]


def test_a_record_cut_under_the_older_rules_is_rebuilt_under_those_rules():
    text = _cve()
    old_shown, old_info = truncate_text(text, 600, version="sections-v1")

    assert old_info["version"] == "sections-v1" and old_info["dropped"] == ["configurations"]
    assert "affected_products" not in old_shown and "summarised" not in old_info
    assert shown_text(text, old_info) == old_shown                 # not re-cut under v2
    assert shown_text(text, truncate_text(text, 600)[1]) != old_shown


# -- protected sections ---------------------------------------------------------------


def test_related_weaknesses_survive_even_though_they_sit_at_the_end():
    text = _capec()
    shown, info = truncate_text(text, 700)       # far too small for the prose

    assert info["mode"] == "sections"
    assert _sections(shown)["Related_Weaknesses"] == _sections(text)["Related_Weaknesses"]
    assert _sections(shown)["Description"] == "An adversary does a thing."
    assert shown.startswith("Example Attack ")       # the title


def test_no_protected_section_is_ever_listed_as_dropped_or_trimmed():
    text = _capec(Taxonomy_Mappings={"Taxonomy_Mapping": [{"Entry_ID": "T1110"}]},
                  Related_Attack_Patterns={"Related_Attack_Pattern": [{"@CAPEC_ID": "112"}]})
    for budget in range(len(text) - 1, 350, -150):
        shown, info = truncate_text(text, budget)
        if info["mode"] == "fallback":
            continue
        assert not (set(info["dropped"]) | set(info["trimmed"])) & PROTECTED
        for key in ("Related_Weaknesses", "Taxonomy_Mappings", "Related_Attack_Patterns", "Description"):
            assert _sections(shown)[key] == _sections(text)[key]


def test_the_result_never_exceeds_the_budget():
    text = _capec()
    for budget in range(50, len(text), 97):
        shown, _info = truncate_text(text, budget)
        assert len(shown) <= budget


# -- mitigations are trimmed, not dropped, when that is enough -------------------------


def test_mitigations_are_trimmed_from_the_end_before_being_dropped():
    text = _capec()
    full = _sections(text)["Mitigations"]["Mitigation"]
    # Small enough that everything ahead of mitigations is gone, large enough for one of them.
    everything_else_gone = {k: v for k, v in _sections(text).items()
                            if k in ("@ID", "Description", "Related_Weaknesses")}
    budget = len(_entry(**everything_else_gone)) + len(json.dumps({"Mitigations": {"Mitigation": full[:1]}})) + 40

    shown, info = truncate_text(text, budget)

    assert info["trimmed"] == {"Mitigations": {"kept_items": 1}}
    assert "Mitigations" not in info["dropped"]
    assert _sections(shown)["Mitigations"]["Mitigation"] == full[:1]       # the first, whole


def test_mitigations_are_dropped_when_not_even_one_fits():
    text = _capec()
    shown, info = truncate_text(text, 300)
    if info["mode"] == "sections":
        assert "Mitigations" in info["dropped"]
        assert "Mitigations" not in _sections(shown)


def test_a_section_keeps_its_place_in_the_entry_when_trimmed():
    text = _capec()
    shown, _info = truncate_text(text, 1500)
    kept = list(_sections(shown))
    assert kept == [k for k in _sections(text) if k in kept]


# -- fallback -------------------------------------------------------------------------


def test_protected_sections_alone_over_budget_fall_back_to_a_plain_cut_and_say_so():
    text = _entry(Description="d" * 5000, Related_Weaknesses={"Related_Weakness": [{"@CWE_ID": "1"}]})
    shown, info = truncate_text(text, 1000)

    assert info["mode"] == "fallback"
    assert info["reason"] == "protected sections alone exceed the budget"
    assert shown == text[:1000]
    assert info["dropped"] == [] and info["trimmed"] == {}


def test_text_that_is_not_title_plus_json_falls_back():
    text = "just a long paragraph of prose " * 100
    shown, info = truncate_text(text, 500)
    assert info["mode"] == "fallback" and shown == text[:500]


# -- fidelity -------------------------------------------------------------------------


def test_surviving_sections_are_character_for_character_the_original():
    for text in (_capec(Description="café — naïve"),                       # escaped, as json.dumps writes it
                 "T " + json.dumps({"Description": "café", "References": ["r" * 900]}, ensure_ascii=False)):
        shown, info = truncate_text(text, len(text) - 100)
        assert info["mode"] == "sections"
        body = shown[shown.index("{") + 1 : -1]
        for piece in body.split('", "'):
            assert piece in text


def test_a_title_containing_a_brace_is_still_split_correctly():
    text = _entry("Weird {title} here", Description="d", References=["r" * 500])
    title, sections = split_entry(text)
    assert title == "Weird {title} here" and set(sections) == {"Description", "References"}


# -- rebuilding what the model saw ------------------------------------------------------


def test_the_shown_text_can_be_rebuilt_from_a_saved_record():
    text = _capec()
    shown, info = truncate_text(text, 900)

    assert shown_text(text, info) == shown
    assert shown_text(text, None) == text       # an uncut (or pre-1.5.0) record


def test_a_record_cut_under_other_rules_is_refused_not_guessed_at():
    import pytest

    with pytest.raises(ValueError, match="sections-v99"):
        shown_text("x", {"version": "sections-v99", "max_doc_chars": 10})
    assert TRUNCATION_VERSION == "sections-v2"


def test_record_shown_text_reads_the_field_off_a_record():
    from sira_cti.common import EnrichmentRecord, Source

    text = _capec()
    shown, info = truncate_text(text, 900)
    record = EnrichmentRecord(doc_id="CAPEC-999", source=Source.CAPEC, original_text=text, truncation=info)

    assert record_shown_text(record) == shown
    assert "REF-1" in record.original_text and "REF-1" not in record_shown_text(record)
