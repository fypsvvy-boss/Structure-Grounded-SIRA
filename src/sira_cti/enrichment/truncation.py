"""Section-aware truncation: what a model is shown when an entry is too long.

A local model has a small context window, so a long catalogue entry has to be
shortened before it goes into the prompt. Cutting at a fixed character count
looked harmless and was not: a CAPEC entry *ends* with its "Related
Weaknesses" list (the CWE ids it maps to), so a plain cut removed exactly the
part an id-grounding pipeline most needs, on 55 of the 64 over-long CAPECs,
while keeping pages of mitigation prose (measured 2026-10-09, see
``docs/proposals/module1-freeze.md``).

So the cut is made by **section** instead. A ``corpus_kb`` entry's text is
``"<title> <one JSON object>"``, and that object's top-level keys are the
entry's sections. When an entry is over budget, whole sections are removed in
a fixed order -- least useful for finding the entry first -- until it fits:

    references -> content history -> CVE affected-products tables ->
    applicable-platform detail -> consequences -> prerequisites ->
    examples -> mitigations

A CVE's affected-products table is not simply dropped: it is replaced by the
vendor and product names it mentions, once each and without versions
(``sections-v2``). The table is where a long CVE's length comes from, but the
names in it are exactly what an analyst searches by.

Mitigations are *trimmed* (leading items kept) rather than dropped outright
where that is enough. Sections the instruction does not name
(``OTHER_ORDER``: detection methods, execution flow, ...) come after
mitigations, also trimmed. Title, description, and the cross-catalogue links
(related weaknesses / attack patterns / taxonomy mappings, a CVE's CWE list)
are **never** removed. Only if those protected sections alone are over budget
does the function fall back to a plain character cut, and it says so.

Only the copy shown to the model is shortened. The record keeps the full
``original_text`` and the index is built from the full document; the record's
``truncation`` field states what was removed, and :func:`shown_text` rebuilds
the shown copy from a saved record, which is what "was this id copied from
the entry?" has to be measured against.

Backend-independent on purpose: a frontier model with a huge context gets the
same cut, so that the model is the only thing that differs between two
indexes.
"""

from __future__ import annotations

import json
from typing import Any, Optional

TRUNCATION_VERSION = "sections-v2"
"""Recorded with every cut. Change it whenever the rules below change, so a
saved record is never re-cut under rules it was not written with.

* ``sections-v1`` -- a CVE's affected-products table is dropped whole.
* ``sections-v2`` -- it is replaced by a list of vendor and product names
  (:func:`summarise_products`). Everything else is unchanged.
"""

_KNOWN_VERSIONS = ("sections-v1", "sections-v2")

PRODUCTS_SECTION = "configurations"
PRODUCTS_SUMMARY_KEY = "affected_products"
"""The key the summary appears under in the shown text. Not a key that exists
in corpus_kb, so a reader of a prompt can tell it is our summary."""

DROP_ORDER: tuple[tuple[str, tuple[str, ...], bool], ...] = (
    # (category, section keys, trim-instead-of-drop)
    ("references", ("References",), False),
    ("content_history", ("Content_History",), False),
    ("affected_products", ("configurations",), False),
    ("applicable_platforms", ("Applicable_Platforms",), False),
    ("consequences", ("Common_Consequences", "Consequences"), False),
    ("prerequisites", ("Prerequisites",), False),
    ("examples", ("Example_Instances", "Demonstrative_Examples", "Observed_Examples"), False),
    ("mitigations", ("Potential_Mitigations", "Mitigations"), True),
)

OTHER_ORDER: tuple[str, ...] = (
    # Not named in the drop order and not protected. Reached only when
    # everything above is gone and the entry is still too long.
    "Notes", "Indicators", "Resources_Required", "Skills_Required",
    "Modes_Of_Introduction", "Detection_Methods", "Execution_Flow",
)

PROTECTED: frozenset[str] = frozenset({
    "@ID", "@Name", "id", "cve_id",
    "Description", "Extended_Description", "descriptions", "description",
    "Related_Weaknesses", "Related_Attack_Patterns", "Taxonomy_Mappings",
    "weaknesses", "cwe_ids",        # a CVE's own CWE list is its "related weaknesses"
})


def split_entry(text: str) -> Optional[tuple[str, dict[str, Any]]]:
    """``(title, sections)`` for a ``"<title> <JSON object>"`` entry, else None.

    Works from the text alone (a saved record has no separate title). A title
    may itself contain a brace, so each ``" {"`` is tried in turn until the
    remainder parses as one JSON object.
    """
    start = text.find("{")
    while start != -1:
        try:
            obj = json.loads(text[start:])
        except json.JSONDecodeError:
            start = text.find("{", start + 1)
            continue
        if isinstance(obj, dict):
            return text[:start].rstrip(), obj
        return None
    return None


def _render(title: str, sections: dict[str, Any], ascii_only: bool = False) -> str:
    return f"{title} {json.dumps(sections, ensure_ascii=ascii_only)}".strip()


def summarise_products(configurations: Any) -> list[str]:
    """``["vendor product", ...]`` named in a CVE's affected-products table.

    The table is thousands of characters of CPE strings
    (``cpe:2.3:o:cisco:ios_xe:16.9.3:*:...``) that differ only in version.
    What an analyst searches for is the vendor and the product, so those are
    kept -- each pair once, in order of first appearance, versions discarded.
    Both NVD layouts are read (``criteria`` and the older ``cpe23Uri``).
    """
    seen: dict[str, None] = {}

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("criteria", "cpe23Uri") and isinstance(value, str):
                    parts = value.split(":")
                    if len(parts) > 4 and parts[0] == "cpe":
                        vendor, product = (
                            p.replace("\\", "").replace("_", " ").strip() for p in parts[3:5]
                        )
                        name = product if vendor in ("", "*", "-") or vendor == product else f"{vendor} {product}"
                        if name and name not in ("*", "-"):
                            seen.setdefault(name)
                else:
                    _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(configurations)
    return list(seen)


def _trim_section(value: Any, room: int, ascii_only: bool = False) -> Any:
    """The longest leading part of ``value`` whose JSON fits in ``room`` characters.

    Sections are a list, or a one-key wrapper around a list
    (``{"Mitigation": [...]}``); the list is cut from the end. Anything else
    cannot be trimmed and returns None (meaning: drop it).
    """
    if isinstance(value, dict) and len(value) == 1:
        (key, inner), = value.items()
        trimmed = _trim_section(inner, room - len(json.dumps({key: []})), ascii_only)
        return None if trimmed is None else {key: trimmed}
    if not isinstance(value, list):
        return None
    kept: list[Any] = []
    for item in value:
        if len(json.dumps(kept + [item], ensure_ascii=ascii_only)) > room:
            break
        kept.append(item)
    return kept or None


def truncate_text(
    text: str, max_chars: Optional[int], *, version: str = TRUNCATION_VERSION
) -> tuple[str, Optional[dict[str, Any]]]:
    """``(shown_text, info)``. ``info`` is None when nothing was cut.

    ``info`` is what goes on the record: ``mode`` (``"sections"`` or
    ``"fallback"``), the section keys ``dropped``, ``trimmed`` (with how many
    items were kept) and ``summarised`` (a CVE's product table replaced by
    its vendor/product names), and the character counts before and after.

    ``version`` exists only so a record saved under older rules can be
    rebuilt (:func:`shown_text`); new cuts always use the current one.
    """
    if version not in _KNOWN_VERSIONS:
        raise ValueError(f"unknown truncation rules {version!r}; this code knows {_KNOWN_VERSIONS}")
    if max_chars is None or len(text) <= max_chars:
        return text, None

    info: dict[str, Any] = {
        "version": version, "mode": "sections", "max_doc_chars": max_chars,
        "dropped": [], "trimmed": {}, "summarised": {}, "full_chars": len(text),
    }
    if version == "sections-v1":
        del info["summarised"]      # the field did not exist; keep v1 records comparable

    def _fallback(reason: str) -> tuple[str, dict[str, Any]]:
        shown = text[:max_chars]
        info.update(mode="fallback", reason=reason, dropped=[], trimmed={}, shown_chars=len(shown))
        if "summarised" in info:
            info["summarised"] = {}
        return shown, info

    parsed = split_entry(text)
    if parsed is None:
        return _fallback("entry is not a title followed by one JSON object")
    title, sections = parsed
    sections = dict(sections)
    # corpus_kb mixes two spellings of non-ASCII characters (written out, or
    # as \uXXXX escapes). Use whichever this entry uses, so every section that
    # survives is character-for-character what the full entry says.
    ascii_only = _render(title, sections, True) == text

    def render(secs: dict[str, Any]) -> str:
        return _render(title, secs, ascii_only)

    plan = [(key, trim) for _cat, keys, trim in DROP_ORDER for key in keys]
    plan += [(key, True) for key in OTHER_ORDER]
    # A section this module has never heard of is neither protected nor
    # ordered. Dropping it last (before the fallback) keeps the promise that
    # protected sections survive, without guessing where it ranks.
    plan += [(key, True) for key in sections if key not in PROTECTED and key not in dict(plan)]
    original_order = list(parsed[1])

    def put_back(secs: dict[str, Any], key: str, value: Any, *, at: str) -> dict[str, Any]:
        """``secs`` plus ``key``, placed where section ``at`` was in the full entry."""
        secs = {**secs, key: value}
        where = {k: original_order.index(k) for k in secs if k in original_order}
        where[key] = original_order.index(at)
        where.setdefault(PRODUCTS_SUMMARY_KEY, original_order.index(PRODUCTS_SECTION)
                         if PRODUCTS_SECTION in original_order else 0)
        return {k: secs[k] for k in sorted(secs, key=where.__getitem__)}

    for key, trim in plan:
        if len(render(sections)) <= max_chars:
            break
        if key not in sections:
            continue
        value = sections.pop(key)
        if key == PRODUCTS_SECTION and version != "sections-v1":
            # Not dropped outright: the version table goes, the names stay,
            # as many as fit in the room the table has just freed.
            names = summarise_products(value)
            placeholder = dict(sections)
            placeholder[PRODUCTS_SUMMARY_KEY] = None
            room = max_chars - (len(render(placeholder)) - len("null"))
            kept = _trim_section(names, room, ascii_only)
            if kept:
                sections = put_back(sections, PRODUCTS_SUMMARY_KEY, kept, at=key)
                info["summarised"][key] = {
                    "as": PRODUCTS_SUMMARY_KEY, "products": len(names), "kept": len(kept),
                }
                continue
        if trim:
            # Room left for this section once everything else is accounted for.
            placeholder = dict(sections)
            placeholder[key] = None
            room = max_chars - (len(render(placeholder)) - len("null"))
            kept = _trim_section(value, room, ascii_only)
            if kept is not None:
                # Re-insert at its original position so the entry reads in order.
                sections = put_back(sections, key, kept, at=key)
                items = kept[next(iter(kept))] if isinstance(kept, dict) else kept
                info["trimmed"][key] = {"kept_items": len(items)}
                continue
        info["dropped"].append(key)

    shown = render(sections)
    if len(shown) > max_chars:
        return _fallback("protected sections alone exceed the budget")
    info["shown_chars"] = len(shown)
    return shown, info


def shown_text(original_text: str, truncation: Optional[dict[str, Any]]) -> str:
    """Rebuild what the model saw, from a saved record's text and ``truncation``.

    ``truncation is None`` means the model saw the whole entry -- true of
    every record written before truncation existed.
    """
    if not truncation:
        return original_text
    version = truncation.get("version")
    if version not in _KNOWN_VERSIONS:
        raise ValueError(
            f"record was cut under truncation rules {version!r}; this code knows "
            f"{_KNOWN_VERSIONS} and cannot rebuild what the model saw"
        )
    shown, _info = truncate_text(original_text, truncation.get("max_doc_chars"), version=version)
    return shown


def record_shown_text(record: Any) -> str:
    """What the model saw for a saved :class:`EnrichmentRecord`.

    This, not ``record.original_text``, is the text to search when asking
    "did the model copy this id from the entry?" -- an id in a section that
    was cut off is one the model had to produce for itself.
    """
    return shown_text(record.original_text, getattr(record, "truncation", None))
