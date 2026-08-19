"""Parsers turning MITRE's published files into ontology nodes and edges.

Three source formats, one output shape:

* **ATT&CK** — STIX 2.1 bundle from ``github.com/mitre/cti``
  (``enterprise-attack/enterprise-attack.json``)
* **CWE** — ``cwec_latest.xml`` from ``cwe.mitre.org`` (``.xml`` or ``.zip``)
* **CAPEC** — ``capec_latest.xml`` from ``capec.mitre.org`` (``.xml`` or ``.zip``)

Two behaviours worth knowing about before you trust a validation result:

1. **Deprecated and revoked entries are loaded, not skipped.** They exist in
   the file and the LLM will propose them. Loading them lets the graph tool
   distinguish "never existed" from "no longer current" — the difference
   matters for RQ4, and revoked techniques additionally carry a pointer to
   their replacement.
2. **XML namespaces are matched on local name.** MITRE bumps the namespace
   URI with each schema version (``cwe-6`` -> ``cwe-7``), and hard-coding it
   makes the loader fail silently on the next release.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from .normalize import Namespace, NodeType, parse_structural_id


class Status(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


class EdgeType(str, Enum):
    SUBTECHNIQUE_OF = "subtechnique_of"   # T1110.001 -> T1110
    CHILD_OF = "child_of"                 # CWE/CAPEC hierarchy
    IN_TACTIC = "in_tactic"               # technique -> TA####
    MEMBER_OF = "member_of"               # CWE -> category/view
    MAPS_TO = "maps_to"                   # cross-namespace (CWE<->CAPEC, CAPEC->ATT&CK)
    REVOKED_BY = "revoked_by"             # old ID -> replacement ID


@dataclass
class OntologyNode:
    node_id: str
    namespace: Namespace
    node_type: NodeType
    name: str = ""
    description: str = ""
    status: Status = Status.ACTIVE
    revoked_by: Optional[str] = None
    aliases: list[str] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def is_usable(self) -> bool:
        """Whether this node may be allowed into a retrieval query."""
        return self.status is Status.ACTIVE


@dataclass(frozen=True)
class OntologyEdge:
    src: str
    dst: str
    edge_type: EdgeType


@dataclass
class LoadResult:
    nodes: list[OntologyNode] = field(default_factory=list)
    edges: list[OntologyEdge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def extend(self, other: "LoadResult") -> "LoadResult":
        self.nodes.extend(other.nodes)
        self.edges.extend(other.edges)
        self.warnings.extend(other.warnings)
        return self


# -- helpers -------------------------------------------------------------------------


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _find_all(elem: ET.Element, *path: str) -> Iterator[ET.Element]:
    """Namespace-agnostic descent by local name, e.g. ``_find_all(root, "Weaknesses", "Weakness")``."""
    current: list[ET.Element] = [elem]
    for step in path:
        nxt: list[ET.Element] = []
        for node in current:
            nxt.extend(c for c in node if _localname(c.tag) == step)
        current = nxt
    yield from current


def _first_text(elem: ET.Element, name: str) -> str:
    for child in elem:
        if _localname(child.tag) == name:
            return "".join(child.itertext()).strip()
    return ""


def _read_xml(path: str | Path) -> ET.Element:
    """Parse an XML catalogue, transparently handling MITRE's ``.zip`` distribution."""
    path = Path(path)
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
            if not names:
                raise ValueError(f"{path}: zip contains no .xml file")
            with zf.open(names[0]) as fh:
                return ET.parse(fh).getroot()
    return ET.parse(path).getroot()


# -- ATT&CK --------------------------------------------------------------------------

_STIX_TYPE_MAP: dict[str, NodeType] = {
    "attack-pattern": NodeType.TECHNIQUE,       # refined to SUBTECHNIQUE below
    "x-mitre-tactic": NodeType.TACTIC,
    "course-of-action": NodeType.MITIGATION,
    "intrusion-set": NodeType.GROUP,
    "malware": NodeType.SOFTWARE,
    "tool": NodeType.SOFTWARE,
    "x-mitre-data-source": NodeType.DATA_SOURCE,
    "campaign": NodeType.CAMPAIGN,
}


def _attack_external_id(obj: dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") in {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}:
            ext = ref.get("external_id")
            if ext:
                return ext
    return None


def load_attack_stix(path: str | Path, *, domains: Optional[Iterable[str]] = None) -> LoadResult:
    """Load an ATT&CK STIX 2.1 bundle.

    ``domains`` optionally filters on ``x_mitre_domains``
    (e.g. ``{"enterprise-attack"}``). Default loads everything in the file.
    """
    result = LoadResult()
    with Path(path).open(encoding="utf-8") as fh:
        bundle = json.load(fh)

    objects = bundle.get("objects", bundle if isinstance(bundle, list) else [])
    domain_filter = set(domains) if domains else None

    stix_to_ext: dict[str, str] = {}
    tactic_shortnames: dict[str, str] = {}   # x_mitre_shortname -> TA####

    for obj in objects:
        stix_type = obj.get("type")
        node_type = _STIX_TYPE_MAP.get(stix_type)
        if node_type is None:
            continue
        if domain_filter and obj.get("x_mitre_domains"):
            if not domain_filter.intersection(obj["x_mitre_domains"]):
                continue

        ext_id = _attack_external_id(obj)
        if not ext_id:
            continue

        parsed = parse_structural_id(ext_id)
        if parsed is None:
            result.warnings.append(f"unparseable ATT&CK external_id: {ext_id!r}")
            continue

        if stix_type != "attack-pattern" and parsed.node_type is not node_type:
            # Legacy collision, not a parsing failure: early ATT&CK releases
            # minted mitigations (course-of-action) with the same T#### id as
            # a technique, before M#### mitigation IDs existed. ~200 of these
            # remain in the catalogue purely for backward-compatible URLs. Our
            # ID space treats T#### as technique-namespace (normalize.py), so
            # letting one in here would let it silently occupy — and on a
            # longer description, overwrite via add_node's tie-break — the
            # real technique's node_id.
            result.warnings.append(
                f"skipped legacy {stix_type} {ext_id!r} ({obj.get('name')!r}): "
                f"id belongs to {parsed.node_type.value}-namespace, not {node_type.value}"
            )
            continue

        if obj.get("revoked"):
            status = Status.REVOKED
        elif obj.get("x_mitre_deprecated"):
            status = Status.DEPRECATED
        else:
            status = Status.ACTIVE

        node = OntologyNode(
            node_id=parsed.canonical,
            namespace=Namespace.ATTACK,
            node_type=parsed.node_type if stix_type == "attack-pattern" else node_type,
            name=obj.get("name", ""),
            description=(obj.get("description") or "").strip(),
            status=status,
            aliases=list(obj.get("x_mitre_aliases") or obj.get("aliases") or []),
            attrs={
                "stix_id": obj.get("id"),
                "platforms": obj.get("x_mitre_platforms", []),
                "domains": obj.get("x_mitre_domains", []),
                "detection": obj.get("x_mitre_detection", ""),
            },
        )
        result.nodes.append(node)
        if obj.get("id"):
            stix_to_ext[obj["id"]] = parsed.canonical
        if stix_type == "x-mitre-tactic" and obj.get("x_mitre_shortname"):
            tactic_shortnames[obj["x_mitre_shortname"]] = parsed.canonical

    # Second pass: edges, now that STIX-ID -> external-ID is fully known.
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            ext_id = _attack_external_id(obj)
            if not ext_id:
                continue
            parsed = parse_structural_id(ext_id)
            if parsed is None:
                continue
            for phase in obj.get("kill_chain_phases") or []:
                if phase.get("kill_chain_name") not in {
                    "mitre-attack",
                    "mitre-mobile-attack",
                    "mitre-ics-attack",
                }:
                    continue
                tactic_id = tactic_shortnames.get(phase.get("phase_name", ""))
                if tactic_id:
                    result.edges.append(
                        OntologyEdge(parsed.canonical, tactic_id, EdgeType.IN_TACTIC)
                    )

        elif obj.get("type") == "relationship":
            src = stix_to_ext.get(obj.get("source_ref", ""))
            dst = stix_to_ext.get(obj.get("target_ref", ""))
            if not src or not dst:
                continue
            rel = obj.get("relationship_type")
            if rel == "subtechnique-of":
                result.edges.append(OntologyEdge(src, dst, EdgeType.SUBTECHNIQUE_OF))
            elif rel == "revoked-by":
                result.edges.append(OntologyEdge(src, dst, EdgeType.REVOKED_BY))

    # Attach the replacement ID directly to revoked nodes, so validate() can
    # tell the caller what to use instead in a single lookup.
    replacements = {e.src: e.dst for e in result.edges if e.edge_type is EdgeType.REVOKED_BY}
    for node in result.nodes:
        if node.node_id in replacements:
            node.revoked_by = replacements[node.node_id]
            node.status = Status.REVOKED

    return result


# -- CWE -----------------------------------------------------------------------------

_CWE_ABSTRACTION_TO_TYPE = {
    "pillar": NodeType.WEAKNESS,
    "class": NodeType.WEAKNESS,
    "base": NodeType.WEAKNESS,
    "variant": NodeType.WEAKNESS,
    "compound": NodeType.WEAKNESS,
}


def _status_from_attr(value: str) -> Status:
    v = (value or "").strip().lower()
    if v in {"deprecated", "obsolete"}:
        return Status.DEPRECATED
    return Status.ACTIVE


def load_cwe_xml(path: str | Path) -> LoadResult:
    """Load the CWE catalogue (weaknesses, categories, views, and CAPEC links)."""
    result = LoadResult()
    root = _read_xml(path)

    for weakness in _find_all(root, "Weaknesses", "Weakness"):
        cwe_id = weakness.get("ID")
        if not cwe_id:
            continue
        node_id = f"CWE-{int(cwe_id)}"
        abstraction = (weakness.get("Abstraction") or "").lower()
        result.nodes.append(
            OntologyNode(
                node_id=node_id,
                namespace=Namespace.CWE,
                node_type=_CWE_ABSTRACTION_TO_TYPE.get(abstraction, NodeType.WEAKNESS),
                name=weakness.get("Name", ""),
                description=_first_text(weakness, "Description"),
                status=_status_from_attr(weakness.get("Status", "")),
                attrs={
                    "abstraction": weakness.get("Abstraction", ""),
                    "structure": weakness.get("Structure", ""),
                },
            )
        )

        for rel in _find_all(weakness, "Related_Weaknesses", "Related_Weakness"):
            if (rel.get("Nature") or "").lower() == "childof" and rel.get("CWE_ID"):
                result.edges.append(
                    OntologyEdge(node_id, f"CWE-{int(rel.get('CWE_ID'))}", EdgeType.CHILD_OF)
                )

        for rel in _find_all(weakness, "Related_Attack_Patterns", "Related_Attack_Pattern"):
            if rel.get("CAPEC_ID"):
                result.edges.append(
                    OntologyEdge(node_id, f"CAPEC-{int(rel.get('CAPEC_ID'))}", EdgeType.MAPS_TO)
                )

    for container, singular, node_type in (
        ("Categories", "Category", NodeType.WEAKNESS_CATEGORY),
        ("Views", "View", NodeType.WEAKNESS_VIEW),
    ):
        for elem in _find_all(root, container, singular):
            raw_id = elem.get("ID")
            if not raw_id:
                continue
            node_id = f"CWE-{int(raw_id)}"
            result.nodes.append(
                OntologyNode(
                    node_id=node_id,
                    namespace=Namespace.CWE,
                    node_type=node_type,
                    name=elem.get("Name", ""),
                    description=_first_text(elem, "Summary") or _first_text(elem, "Objective"),
                    status=_status_from_attr(elem.get("Status", "")),
                )
            )
            for member in _find_all(elem, "Relationships", "Has_Member"):
                if member.get("CWE_ID"):
                    result.edges.append(
                        OntologyEdge(f"CWE-{int(member.get('CWE_ID'))}", node_id, EdgeType.MEMBER_OF)
                    )
            for member in _find_all(elem, "Members", "Has_Member"):
                if member.get("CWE_ID"):
                    result.edges.append(
                        OntologyEdge(f"CWE-{int(member.get('CWE_ID'))}", node_id, EdgeType.MEMBER_OF)
                    )

    return result


# -- CAPEC ---------------------------------------------------------------------------


def load_capec_xml(path: str | Path) -> LoadResult:
    """Load the CAPEC catalogue, including its ATT&CK taxonomy mappings.

    The ATT&CK mappings are the cheapest available CAPEC -> ATT&CK bridge and
    complete the CVE -> CWE -> CAPEC -> ATT&CK spine the proposal describes.
    """
    result = LoadResult()
    root = _read_xml(path)

    for pattern in _find_all(root, "Attack_Patterns", "Attack_Pattern"):
        raw_id = pattern.get("ID")
        if not raw_id:
            continue
        node_id = f"CAPEC-{int(raw_id)}"
        result.nodes.append(
            OntologyNode(
                node_id=node_id,
                namespace=Namespace.CAPEC,
                node_type=NodeType.ATTACK_PATTERN,
                name=pattern.get("Name", ""),
                description=_first_text(pattern, "Description"),
                status=_status_from_attr(pattern.get("Status", "")),
                attrs={"abstraction": pattern.get("Abstraction", "")},
            )
        )

        for rel in _find_all(pattern, "Related_Attack_Patterns", "Related_Attack_Pattern"):
            if (rel.get("Nature") or "").lower() == "childof" and rel.get("CAPEC_ID"):
                result.edges.append(
                    OntologyEdge(node_id, f"CAPEC-{int(rel.get('CAPEC_ID'))}", EdgeType.CHILD_OF)
                )

        for rel in _find_all(pattern, "Related_Weaknesses", "Related_Weakness"):
            if rel.get("CWE_ID"):
                result.edges.append(
                    OntologyEdge(node_id, f"CWE-{int(rel.get('CWE_ID'))}", EdgeType.MAPS_TO)
                )

        for mapping in _find_all(pattern, "Taxonomy_Mappings", "Taxonomy_Mapping"):
            if (mapping.get("Taxonomy_Name") or "").upper() != "ATTACK":
                continue
            entry = _first_text(mapping, "Entry_ID")
            if not entry:
                continue
            # CAPEC writes ATT&CK entries without the "T" prefix: "1110.001".
            parsed = parse_structural_id(entry if entry[:1].isalpha() else f"T{entry}")
            if parsed:
                result.edges.append(OntologyEdge(node_id, parsed.canonical, EdgeType.MAPS_TO))
            else:
                result.warnings.append(f"{node_id}: unparseable ATT&CK taxonomy entry {entry!r}")

    return result


def load_all(
    *,
    attack_path: Optional[str | Path | Iterable[str | Path]] = None,
    cwe_path: Optional[str | Path] = None,
    capec_path: Optional[str | Path] = None,
    domains: Optional[Iterable[str]] = None,
) -> LoadResult:
    """Load whichever sources are provided into one result.

    ``attack_path`` accepts either a single bundle or a list of bundles —
    the ATT&CK STIX data is split one file per domain (enterprise/mobile/ICS),
    and CTIConnect's snapshot spans all three. Loading only the enterprise
    file leaves every mobile- and ICS-only technique unresolvable, which
    shows up as ``not_in_graph`` for terms that are perfectly real.
    """
    combined = LoadResult()
    for path in _as_path_list(attack_path):
        combined.extend(load_attack_stix(path, domains=domains))
    if cwe_path:
        combined.extend(load_cwe_xml(cwe_path))
    if capec_path:
        combined.extend(load_capec_xml(capec_path))
    return combined


def _as_path_list(value: Optional[str | Path | Iterable[str | Path]]) -> list[str | Path]:
    """Normalise a single path or an iterable of paths to a list, dropping ``None``."""
    if value is None:
        return []
    if isinstance(value, (str, Path)):
        return [value]
    return list(value)
