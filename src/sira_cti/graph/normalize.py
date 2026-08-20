"""Canonicalising the identifiers an LLM proposes.

An open-weight model asked for ATT&CK techniques will return ``T1110.001``,
``t1110/001``, ``ATT&CK T1110``, ``Technique T1110.1``, ``CWE 307``,
``cwe-307``, and ``CAPEC-49`` — often several forms in one reply. Validation
must not reject a real technique because the model wrote a slash instead of a
dot, and must not accept ``T99999`` because it looks well-formed.

This module answers only "is this well-formed, and what is its canonical
spelling"; :mod:`sira_cti.graph.ontology` answers "does it exist".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Namespace(str, Enum):
    ATTACK = "attack"
    CWE = "cwe"
    CAPEC = "capec"


class NodeType(str, Enum):
    TECHNIQUE = "technique"
    SUBTECHNIQUE = "subtechnique"
    TACTIC = "tactic"
    MITIGATION = "mitigation"
    GROUP = "group"
    SOFTWARE = "software"
    DATA_SOURCE = "data_source"
    CAMPAIGN = "campaign"
    WEAKNESS = "weakness"
    WEAKNESS_CATEGORY = "weakness_category"
    WEAKNESS_VIEW = "weakness_view"
    ATTACK_PATTERN = "attack_pattern"


@dataclass(frozen=True)
class ParsedID:
    """A syntactically valid structural identifier."""

    canonical: str
    namespace: Namespace
    node_type: NodeType

    @property
    def is_subtechnique(self) -> bool:
        return self.node_type is NodeType.SUBTECHNIQUE

    @property
    def parent_id(self) -> Optional[str]:
        """``T1110.001`` -> ``T1110``. ``None`` for everything else.

        Note this is *syntactic* parenthood, which only ATT&CK encodes in its
        identifiers. CWE and CAPEC hierarchy lives in ``ChildOf`` relations
        and must be read from the graph instead.
        """
        if self.is_subtechnique:
            return self.canonical.split(".")[0]
        return None


# Order matters: TA#### must be tried before T####, and DS#### before S####.
_ATTACK_PATTERNS: list[tuple[re.Pattern[str], NodeType, str]] = [
    (re.compile(r"^TA(\d{4})$"), NodeType.TACTIC, "TA{0:0>4}"),
    (re.compile(r"^DS(\d{4})$"), NodeType.DATA_SOURCE, "DS{0:0>4}"),
    (re.compile(r"^T(\d{4})[.\-/](\d{1,3})$"), NodeType.SUBTECHNIQUE, "T{0:0>4}.{1:0>3}"),
    (re.compile(r"^T(\d{4})$"), NodeType.TECHNIQUE, "T{0:0>4}"),
    (re.compile(r"^M(\d{4})$"), NodeType.MITIGATION, "M{0:0>4}"),
    (re.compile(r"^G(\d{4})$"), NodeType.GROUP, "G{0:0>4}"),
    (re.compile(r"^C(\d{4})$"), NodeType.CAMPAIGN, "C{0:0>4}"),
    (re.compile(r"^S(\d{4})$"), NodeType.SOFTWARE, "S{0:0>4}"),
]

_CWE_PATTERN = re.compile(r"^CWE[\s\-_:]*(\d{1,4})$", re.IGNORECASE)
_CAPEC_PATTERN = re.compile(r"^CAPEC[\s\-_:]*(\d{1,4})$", re.IGNORECASE)

# Prose an LLM prepends: "ATT&CK technique T1110", "MITRE ATT&CK: T1110".
_PROSE_PREFIX = re.compile(
    r"^(mitre\s*)?(att&ck|attack|att\s*&\s*ck)?[\s:\-]*"
    r"(technique|sub[\s\-]?technique|tactic|mitigation|group|software|weakness|"
    r"attack[\s\-]pattern|pattern|id)?[\s:\-]*",
    re.IGNORECASE,
)

# Any structural ID embedded in free text, for scanning model prose.
_EMBEDDED = re.compile(
    r"\b(?:TA\d{4}|DS\d{4}|T\d{4}(?:[.\-/]\d{1,3})?|M\d{4}|G\d{4}|S\d{4}|"
    r"CWE[\s\-_:]*\d{1,4}|CAPEC[\s\-_:]*\d{1,4})\b",
    re.IGNORECASE,
)


def parse_structural_id(text: str) -> Optional[ParsedID]:
    """Parse one identifier. Returns ``None`` if the string is not well-formed.

    A bare number never parses: ``"307"`` is ambiguous between CWE-307 and
    CAPEC-307, and treating it as either would let the model smuggle in
    unqualified guesses.
    """
    if not text:
        return None

    raw = text.strip().strip(".,;:()[]\"'")
    if not raw:
        return None

    cleaned = _PROSE_PREFIX.sub("", raw).strip().strip(".,;:()[]\"'")
    for candidate in (cleaned, raw):
        parsed = _match_id(candidate)
        if parsed is not None:
            return parsed
    return None


def _match_id(candidate: str) -> Optional[ParsedID]:
    if not candidate:
        return None

    m = _CWE_PATTERN.match(candidate)
    if m:
        return ParsedID(f"CWE-{int(m.group(1))}", Namespace.CWE, NodeType.WEAKNESS)

    m = _CAPEC_PATTERN.match(candidate)
    if m:
        return ParsedID(f"CAPEC-{int(m.group(1))}", Namespace.CAPEC, NodeType.ATTACK_PATTERN)

    upper = candidate.upper().replace(" ", "")
    for pattern, node_type, template in _ATTACK_PATTERNS:
        m = pattern.match(upper)
        if m:
            return ParsedID(template.format(*m.groups()), Namespace.ATTACK, node_type)
    return None


def extract_structural_ids(text: str) -> list[ParsedID]:
    """Find every structural identifier in a block of free text, in order, deduped.

    Used when a model ignores the requested JSON format and answers in prose.
    """
    seen: set[str] = set()
    out: list[ParsedID] = []
    for match in _EMBEDDED.finditer(text or ""):
        parsed = parse_structural_id(match.group(0))
        if parsed and parsed.canonical not in seen:
            seen.add(parsed.canonical)
            out.append(parsed)
    return out


def looks_structural(text: str) -> bool:
    """Cheap check used to route a proposed term to the graph filter."""
    return parse_structural_id(text) is not None


# An attempt at an identifier, well-formed or not. Either an explicit namespace
# word ("CWE-abc", "CAPEC 12x"), a prose lead-in ("MITRE thing"), or an ATT&CK
# letter prefix sitting directly on a digit ("T99", "S3"). The digit is what
# keeps ordinary vocabulary out: "medium" starts with the mitigation prefix M
# and "local" is all letters, but neither puts a digit where an ID would.
_ID_SHAPED = re.compile(
    r"^(?:mitre|att&ck|att\s*&\s*ck)\b"
    r"|^(?:cwe|capec|cve)\b"
    r"|^(?:TA|DS|T|M|G|S|C)[\-_:]?\d",
    re.IGNORECASE,
)


def is_id_shaped(text: str) -> bool:
    """Whether ``text`` was *plausibly an attempt* at a structural identifier.

    Distinct from :func:`looks_structural`, which asks whether the attempt
    *succeeded*. The gap between the two is the interesting one for RQ4::

        looks_structural("CWE-307")  -> True    valid identifier
        looks_structural("CWE-abc")  -> False   but is_id_shaped -> True
        looks_structural("heap-based") -> False and is_id_shaped -> False

    Corpus-side enrichment routes on that gap. An open-weight model
    routinely mislabels ordinary vocabulary as ``kind="structural"`` --
    observed in the first real Qwen2.5-7B run, which tagged ``heap-based``,
    ``zzip_get32``, ``local`` and ``medium`` as structural. Those never
    reached for an identifier at all, so scoring them as ``MALFORMED_ID``
    would book a form-filling slip as an identifier hallucination and
    inflate the RQ4 rate. ``CWE-abc`` genuinely did reach for one and missed;
    that is real RQ4 signal and must stay ``MALFORMED_ID``.
    """
    if not text:
        return False
    raw = text.strip().strip(".,;:()[]\"'")
    if not raw:
        return False
    cleaned = _PROSE_PREFIX.sub("", raw).strip()
    return bool(_ID_SHAPED.match(raw) or (cleaned and _ID_SHAPED.match(cleaned)))
