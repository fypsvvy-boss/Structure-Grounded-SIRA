"""Zone 3 — the ontology graph tool. Shared by Modules 1 and 2.

This is the component under test. RQ1 asks whether grounding proposed
vocabulary against a real graph transfers from Wikipedia's flat categories to
this hierarchical, multi-relational ontology; RQ4 asks how much work the
grounding is actually doing. Both questions are answered by
:meth:`OntologyGraph.validate`, so its failure modes need to be precise
rather than merely correct-on-average.

Four rejection modes, deliberately kept distinct:

===================  ===========================================================
``MALFORMED_ID``     Not a well-formed identifier at all (``T99``, ``CWE-abc``)
``NOT_IN_GRAPH``     Well-formed but absent — the pure hallucination case
``REVOKED``          Existed, superseded; ``replacement_id`` names the successor
``DEPRECATED``       Existed, withdrawn without a replacement
===================  ===========================================================

Collapsing the last two into ``NOT_IN_GRAPH`` would make an LLM working from
stale training data look identical to one inventing identifiers outright.
Those are different findings, and the distinction is free to record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional

import networkx as nx

from ..common.schemas import RejectReason
from .loaders import EdgeType, LoadResult, OntologyEdge, OntologyNode, Status, load_all
from .normalize import Namespace, NodeType, ParsedID, parse_structural_id


class RevokedPolicy(str, Enum):
    """How :meth:`OntologyGraph.validate` treats a REVOKED term.

    ``REJECT`` (default) is the README/RQ4 baseline: a revoked term fails
    validation, and ``replacement_id`` names what it should have been. Under
    ``REPAIR``, the same term is accepted with ``canonical_id`` rewritten to
    the replacement — useful when the pipeline would rather silently correct
    stale-training-data mistakes than lose them at the retrieval stage. See
    :class:`ValidationResult` for how the repair is still recorded rather
    than disappearing from the RQ4 dataset.
    """

    REJECT = "reject"
    REPAIR = "repair"


@dataclass
class ValidationResult:
    """The answer the graph tool gives about one proposed term."""

    valid: bool
    input_term: str
    canonical_id: Optional[str] = None
    node: Optional[OntologyNode] = None
    reject_reason: Optional[RejectReason] = None
    replacement_id: Optional[str] = None
    repaired: bool = False
    """True iff ``revoked_policy="repair"`` rewrote a REVOKED term into its
    replacement. ``valid`` is True and ``reject_reason`` is still REVOKED in
    that case — the repair happened *because* the term was revoked, and that
    is exactly the signal the RQ4 rejection log must not lose just because
    the term went on to validate. (Downstream, ``ProposedTerm`` cannot carry
    both ``accepted=True`` and a ``reject_reason`` under its current
    invariant — recording this in an ``EnrichmentRecord`` needs a schemas.py
    change; see the summary.)"""

    def __bool__(self) -> bool:
        return self.valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "input_term": self.input_term,
            "canonical_id": self.canonical_id,
            "reject_reason": self.reject_reason.value if self.reject_reason else None,
            "replacement_id": self.replacement_id,
            "repaired": self.repaired,
            "name": self.node.name if self.node else None,
        }


class OntologyGraph:
    """A queryable CVE/CWE/CAPEC/ATT&CK ontology backed by ``networkx``."""

    def __init__(self) -> None:
        self.g: nx.MultiDiGraph = nx.MultiDiGraph()
        self._nodes: dict[str, OntologyNode] = {}
        self._name_index: dict[str, str] = {}      # lowercased name/alias -> node id
        self.warnings: list[str] = []
        self._dangling_edges: list[OntologyEdge] = []

    # -- construction -------------------------------------------------------------

    @classmethod
    def from_load_result(cls, result: LoadResult) -> "OntologyGraph":
        graph = cls()
        graph.warnings.extend(result.warnings)
        for node in result.nodes:
            graph.add_node(node)
        for edge in result.edges:
            graph.add_edge(edge)
        return graph

    @classmethod
    def from_files(
        cls,
        *,
        attack_path: Optional[str | Path | Iterable[str | Path]] = None,
        cwe_path: Optional[str | Path] = None,
        capec_path: Optional[str | Path] = None,
        domains: Optional[Iterable[str]] = None,
    ) -> "OntologyGraph":
        """``attack_path`` may be a single STIX bundle or a list of them — pass
        one path per domain (enterprise/mobile/ICS) to load the full ATT&CK
        matrix, as CTIConnect's snapshot spans all three."""
        return cls.from_load_result(
            load_all(
                attack_path=attack_path,
                cwe_path=cwe_path,
                capec_path=capec_path,
                domains=domains,
            )
        )

    def add_node(self, node: OntologyNode) -> None:
        existing = self._nodes.get(node.node_id)
        if existing is not None:
            # ATT&CK bundles can list the same technique across domains. Keep
            # the richer entry rather than letting load order decide.
            if len(node.description) <= len(existing.description):
                return
        self._nodes[node.node_id] = node
        self.g.add_node(
            node.node_id,
            namespace=node.namespace.value,
            node_type=node.node_type.value,
            name=node.name,
            status=node.status.value,
        )
        for label in [node.name, *node.aliases]:
            if label:
                self._name_index.setdefault(label.strip().lower(), node.node_id)

    def add_edge(self, edge: OntologyEdge) -> None:
        if edge.src not in self._nodes or edge.dst not in self._nodes:
            # Cross-catalogue references routinely point at entries from a
            # source that was not loaded (CAPEC -> ATT&CK when only CAPEC was
            # given). Record rather than crash; surfaced via `stats()`.
            self._dangling_edges.append(edge)
            return
        self.g.add_edge(edge.src, edge.dst, key=edge.edge_type.value, edge_type=edge.edge_type.value)

    # -- lookup -------------------------------------------------------------------

    def __contains__(self, node_id: str) -> bool:
        return node_id in self._nodes

    def __len__(self) -> int:
        return len(self._nodes)

    def resolve(self, identifier: str) -> Optional[OntologyNode]:
        """Look up a node by identifier (in any spelling) or by exact name."""
        parsed = parse_structural_id(identifier)
        if parsed is not None:
            return self._nodes.get(parsed.canonical)
        return self._nodes.get(self._name_index.get((identifier or "").strip().lower(), ""))

    # -- the validation step under test -------------------------------------------

    def validate(
        self,
        term: str,
        *,
        allow_deprecated: bool = False,
        revoked_policy: RevokedPolicy | str = RevokedPolicy.REJECT,
    ) -> ValidationResult:
        """Adjudicate one LLM-proposed structural term.

        ``allow_deprecated`` exists for the RQ4 ablation: a deprecated
        technique's text is still in the corpus, so admitting it may help
        recall even though it is not current guidance. Off by default.

        ``revoked_policy`` (``graph.revoked_policy`` in config) is
        ``"reject"`` by default — a revoked term fails, naming
        ``replacement_id``. Under ``"repair"`` it is accepted instead, with
        ``canonical_id``/``node`` rewritten to the replacement; see
        :class:`ValidationResult.repaired` for how that repair still shows up
        in the RQ4 log. A revoked node with no recorded replacement cannot be
        repaired and is rejected regardless of policy.
        """
        policy = RevokedPolicy(revoked_policy)
        parsed: Optional[ParsedID] = parse_structural_id(term)
        if parsed is None:
            return ValidationResult(
                valid=False, input_term=term, reject_reason=RejectReason.MALFORMED_ID
            )

        node = self._nodes.get(parsed.canonical)
        if node is None:
            return ValidationResult(
                valid=False,
                input_term=term,
                canonical_id=parsed.canonical,
                reject_reason=RejectReason.NOT_IN_GRAPH,
            )

        if node.status is Status.REVOKED:
            replacement = self._nodes.get(node.revoked_by) if node.revoked_by else None
            if policy is RevokedPolicy.REPAIR and replacement is not None:
                return ValidationResult(
                    valid=True,
                    input_term=term,
                    canonical_id=replacement.node_id,
                    node=replacement,
                    reject_reason=RejectReason.REVOKED,
                    replacement_id=replacement.node_id,
                    repaired=True,
                )
            return ValidationResult(
                valid=False,
                input_term=term,
                canonical_id=parsed.canonical,
                node=node,
                reject_reason=RejectReason.REVOKED,
                replacement_id=node.revoked_by,
            )

        if node.status is Status.DEPRECATED and not allow_deprecated:
            return ValidationResult(
                valid=False,
                input_term=term,
                canonical_id=parsed.canonical,
                node=node,
                reject_reason=RejectReason.DEPRECATED,
            )

        return ValidationResult(
            valid=True, input_term=term, canonical_id=parsed.canonical, node=node
        )

    def validate_many(
        self,
        terms: Iterable[str],
        *,
        allow_deprecated: bool = False,
        revoked_policy: RevokedPolicy | str = RevokedPolicy.REJECT,
    ) -> list[ValidationResult]:
        return [
            self.validate(t, allow_deprecated=allow_deprecated, revoked_policy=revoked_policy)
            for t in terms
        ]

    # -- neighbourhood (used to expand a validated term) ---------------------------

    def _typed_out(self, node_id: str, edge_type: EdgeType) -> list[str]:
        if node_id not in self.g:
            return []
        return [
            dst
            for _, dst, key in self.g.out_edges(node_id, keys=True)
            if key == edge_type.value
        ]

    def _typed_in(self, node_id: str, edge_type: EdgeType) -> list[str]:
        if node_id not in self.g:
            return []
        return [
            src
            for src, _, key in self.g.in_edges(node_id, keys=True)
            if key == edge_type.value
        ]

    def parents(self, node_id: str) -> list[str]:
        """Hierarchical parents: ATT&CK ``subtechnique-of`` or CWE/CAPEC ``ChildOf``.

        Falls back to the *syntactic* parent (``ParsedID.parent_id``, e.g.
        ``T1110.002`` -> ``T1110``) when a sub-technique has no
        ``subtechnique-of`` edge at all. Revocation prunes a node's
        relationships along with everything else, leaving it graph-orphaned
        even though its ID still names its parent. This exists for audit-log
        readability only — :meth:`validate` never calls ``parents()``, so the
        fallback cannot change which terms pass validation.
        """
        subtechnique_of = self._typed_out(node_id, EdgeType.SUBTECHNIQUE_OF)
        if not subtechnique_of and node_id in self._nodes:
            # Only for nodes the graph actually loaded — never invent a
            # parent for an ID that was never a real node to begin with.
            parsed = parse_structural_id(node_id)
            if parsed is not None and parsed.is_subtechnique and parsed.parent_id in self._nodes:
                subtechnique_of = [parsed.parent_id]
        return subtechnique_of + self._typed_out(node_id, EdgeType.CHILD_OF)

    def children(self, node_id: str) -> list[str]:
        return self._typed_in(node_id, EdgeType.SUBTECHNIQUE_OF) + self._typed_in(
            node_id, EdgeType.CHILD_OF
        )

    def siblings(self, node_id: str) -> list[str]:
        out: list[str] = []
        for parent in self.parents(node_id):
            out.extend(c for c in self.children(parent) if c != node_id)
        return sorted(set(out))

    def tactics_for(self, node_id: str) -> list[str]:
        """Parent tactics of a technique; falls back to the parent technique's tactics."""
        tactics = self._typed_out(node_id, EdgeType.IN_TACTIC)
        if tactics:
            return tactics
        for parent in self._typed_out(node_id, EdgeType.SUBTECHNIQUE_OF):
            tactics.extend(self._typed_out(parent, EdgeType.IN_TACTIC))
        return sorted(set(tactics))

    def mapped(self, node_id: str) -> list[str]:
        """Cross-namespace links (CWE <-> CAPEC, CAPEC -> ATT&CK), both directions."""
        return sorted(
            set(self._typed_out(node_id, EdgeType.MAPS_TO) + self._typed_in(node_id, EdgeType.MAPS_TO))
        )

    def context(self, node_id: str) -> dict[str, Any]:
        """Everything Modules 1 and 2 need about a validated node, in one call."""
        node = self._nodes.get(node_id)
        if node is None:
            return {}
        return {
            "id": node.node_id,
            "name": node.name,
            "namespace": node.namespace.value,
            "node_type": node.node_type.value,
            "status": node.status.value,
            "parents": self.parents(node_id),
            "children": self.children(node_id),
            "siblings": self.siblings(node_id),
            "tactics": self.tactics_for(node_id),
            "mapped": self.mapped(node_id),
        }

    def expansion_terms(self, node_id: str, *, include_siblings: bool = False) -> list[str]:
        """Vocabulary to add to ``q_exp`` once a term validates.

        Siblings are off by default: they are plausible-but-different
        techniques, and admitting them dilutes the discriminative weight BM25
        gives rare terms. Turn them on only as a measured ablation.
        """
        node = self._nodes.get(node_id)
        if node is None:
            return []
        terms = [node.node_id]
        if node.name:
            terms.append(node.name)
        for parent_id in self.parents(node_id):
            parent = self._nodes.get(parent_id)
            if parent and parent.name:
                terms.extend([parent.node_id, parent.name])
        if include_siblings:
            for sib_id in self.siblings(node_id):
                sib = self._nodes.get(sib_id)
                if sib and sib.name:
                    terms.append(sib.name)
        seen: set[str] = set()
        return [t for t in terms if not (t.lower() in seen or seen.add(t.lower()))]

    # -- reporting ----------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        by_namespace: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for node in self._nodes.values():
            by_namespace[node.namespace.value] = by_namespace.get(node.namespace.value, 0) + 1
            by_type[node.node_type.value] = by_type.get(node.node_type.value, 0) + 1
            by_status[node.status.value] = by_status.get(node.status.value, 0) + 1

        by_edge: dict[str, int] = {}
        for _, _, key in self.g.edges(keys=True):
            by_edge[key] = by_edge.get(key, 0) + 1

        return {
            "nodes": len(self._nodes),
            "edges": self.g.number_of_edges(),
            "nodes_by_namespace": by_namespace,
            "nodes_by_type": by_type,
            "nodes_by_status": by_status,
            "edges_by_type": by_edge,
            "dangling_edges": len(self._dangling_edges),
            "warnings": len(self.warnings),
        }

    def ids(self, namespace: Optional[Namespace] = None, active_only: bool = True) -> list[str]:
        return sorted(
            n.node_id
            for n in self._nodes.values()
            if (namespace is None or n.namespace is namespace)
            and (not active_only or n.is_usable)
        )
