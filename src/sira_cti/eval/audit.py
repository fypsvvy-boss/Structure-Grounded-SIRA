"""Module 4 -- auditing the enrichment record (RQ4, and the denominators of RQ1).

Reads an enrichment JSONL (Module 1's corpus-side output today, Module 2's
query-side output later -- same record shape) and counts what was proposed,
accepted and rejected, and why.

Three rates that must not be confused
-------------------------------------
``EnrichmentRecord.rejection_rate()`` counts *every* rejected structural
term, including ones the ontology graph accepted and the document-frequency
gate then removed. It is not the graph-validation rejection rate the README
asks for, so this module reports the three separately:

* ``total_rejection_rate``      rejected / proposed, over all terms
* ``structural_rejection_rate`` rejected / proposed, over structural terms,
                                for any reason (what ``rejection_rate()``
                                measures, pooled over records)
* ``graph_rejection_rate``      structural terms the **graph** refused /
                                structural terms proposed

Every rate is pooled over the terms of all records (micro-averaged), and is
``None`` -- not zero -- when nothing was proposed.

Reasons are classified by their string value, so this file needs no edit
when the frozen ``RejectReason`` gains a member: a reason that is neither a
graph failure nor a corpus-statistics failure (the proposed
``already_in_document``, ``docs/proposals/already-in-document-gate.md``) is
counted under its own name in ``other`` and is never folded into either.

What these numbers cannot show -- see :data:`CAVEATS`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from ..common.schemas import EnrichmentRecord, ProposedTerm, RejectReason, TermKind, read_jsonl
from ..graph.normalize import parse_structural_id

GRAPH_REASONS = frozenset({"not_in_graph", "deprecated", "revoked", "malformed_id"})
"""The ontology graph said no. Mirrors ``schemas._GRAPH_FAILURES`` by value."""

CORPUS_STAT_REASONS = frozenset({"too_common", "not_in_index"})
"""A document-frequency / index-membership gate said no; the graph did not object."""

GRAPH, CORPUS_STATS, OTHER = "graph", "corpus_stats", "other"

CAVEATS = (
    "Graph validation checks that an identifier exists and is current, not that it is relevant to "
    "the document or query it was proposed for (docs/04_OPEN_QUESTIONS.md question 8). A low "
    "graph-rejection rate is not evidence of good proposals.",
    "The too_common gate cannot reject an ATT&CK identifier: those ids have document frequency 0 in "
    "the base corpus (question 1). Survival rates are not comparable across catalogues.",
    "Rates depend on the model that produced the proposals; always read them with the by_model breakdown.",
    "A term the model labelled structural but that was not an identifier attempt is recorded as "
    "colloquial with no trace of the original label, so the mislabel rate is not recoverable here.",
)


def classify_reason(reason: Optional[RejectReason | str]) -> Optional[str]:
    """``"graph"`` | ``"corpus_stats"`` | ``"other"``; ``None`` for an accepted term."""
    if reason is None:
        return None
    value = reason.value if isinstance(reason, RejectReason) else str(reason)
    if value in GRAPH_REASONS:
        return GRAPH
    if value in CORPUS_STAT_REASONS:
        return CORPUS_STATS
    return OTHER


def catalogue_of(term: ProposedTerm) -> str:
    """Which catalogue a structural term's id belongs to: ``attack`` / ``cwe`` / ``capec``.

    ``"other"`` for anything the normalizer does not place (a malformed id,
    a CVE id) -- the same rule as ``corpus_side.summarize_by_source``, so
    the two reports agree.
    """
    parsed = parse_structural_id(term.structural_id or "")
    return parsed.namespace.value if parsed is not None else "other"


def _rate(numerator: int, denominator: int) -> Optional[float]:
    return numerator / denominator if denominator else None


class _Counts:
    """Running totals for one slice of the proposals."""

    def __init__(self) -> None:
        self.proposed = 0
        self.accepted = 0
        self.by_reason: dict[str, int] = {}
        self.structural_proposed = 0
        self.structural_accepted = 0
        self.structural_by_reason: dict[str, int] = {}
        self.repaired = 0

    def add(self, term: ProposedTerm) -> None:
        reason = term.reject_reason.value if term.reject_reason is not None else None
        self.proposed += 1
        if term.accepted:
            self.accepted += 1
        else:
            self.by_reason[reason] = self.by_reason.get(reason, 0) + 1
        if term.kind is TermKind.STRUCTURAL:
            self.structural_proposed += 1
            if term.accepted:
                self.structural_accepted += 1
            else:
                self.structural_by_reason[reason] = self.structural_by_reason.get(reason, 0) + 1
            if term.repaired_from_id is not None:
                self.repaired += 1

    @staticmethod
    def _split(by_reason: dict[str, int]) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {GRAPH: {}, CORPUS_STATS: {}, OTHER: {}}
        for reason, n in sorted(by_reason.items()):
            out[classify_reason(reason)][reason] = n
        return out

    def to_dict(self) -> dict[str, Any]:
        rejected = self.proposed - self.accepted
        structural = self._split(self.structural_by_reason)
        graph_rejected = sum(structural[GRAPH].values())
        stale = self.repaired + self.structural_by_reason.get("revoked", 0)
        return {
            "proposed": self.proposed,
            "accepted": self.accepted,
            "rejected": rejected,
            "rejected_by_reason": dict(sorted(self.by_reason.items())),
            "rejected_by_class": {k: sum(v.values()) for k, v in self._split(self.by_reason).items()},
            "total_rejection_rate": _rate(rejected, self.proposed),
            "structural": {
                "proposed": self.structural_proposed,
                "accepted": self.structural_accepted,
                "repaired": self.repaired,
                "graph_rejected": graph_rejected,
                "graph_rejected_by_reason": structural[GRAPH],
                "corpus_stats_rejected": sum(structural[CORPUS_STATS].values()),
                "corpus_stats_rejected_by_reason": structural[CORPUS_STATS],
                "other_rejected": sum(structural[OTHER].values()),
                "other_rejected_by_reason": structural[OTHER],
                "structural_rejection_rate": _rate(
                    self.structural_proposed - self.structural_accepted, self.structural_proposed
                ),
                "graph_rejection_rate": _rate(graph_rejected, self.structural_proposed),
                "hallucination_rate": _rate(self.structural_by_reason.get("not_in_graph", 0), self.structural_proposed),
                "staleness_rate": _rate(stale, self.structural_proposed),
            },
        }


def audit_records(records: Iterable[EnrichmentRecord]) -> dict[str, Any]:
    """Counts and rates overall, and broken down three ways.

    * ``by_source``    the type of the document (or ``query``) proposed for
    * ``by_model``     the model that proposed
    * ``by_catalogue`` structural terms only, by the catalogue of the
                       proposed id (``attack`` / ``cwe`` / ``capec`` / ``other``)

    ``hallucination_rate`` is ``not_in_graph`` alone -- a well-formed id
    that never existed -- and ``staleness_rate`` is revoked plus repaired,
    matching ``EnrichmentRecord.staleness_rate()``.
    """
    overall = _Counts()
    slices: dict[str, dict[str, _Counts]] = {"by_source": {}, "by_model": {}, "by_catalogue": {}}
    docs: dict[str, dict[str, int]] = {"by_source": {}, "by_model": {}}
    n_records = 0
    n_without_proposals = 0

    def bump(table: dict[str, _Counts], key: str, term: ProposedTerm) -> None:
        table.setdefault(key, _Counts()).add(term)

    for rec in records:
        n_records += 1
        n_without_proposals += not rec.proposed_terms
        source, model = rec.source.value, rec.model or "(unknown)"
        docs["by_source"][source] = docs["by_source"].get(source, 0) + 1
        docs["by_model"][model] = docs["by_model"].get(model, 0) + 1
        for term in rec.proposed_terms:
            overall.add(term)
            bump(slices["by_source"], source, term)
            bump(slices["by_model"], model, term)
            if term.kind is TermKind.STRUCTURAL:
                bump(slices["by_catalogue"], catalogue_of(term), term)

    out: dict[str, Any] = {
        "records": n_records,
        "records_without_proposals": n_without_proposals,
        **overall.to_dict(),
    }
    for name, table in slices.items():
        out[name] = {
            key: ({"records": docs[name][key]} if name in docs else {}) | counts.to_dict()
            for key, counts in sorted(table.items())
        }
        # A source or model whose records proposed nothing still exists.
        for key in sorted(docs.get(name, {}).keys() - table.keys()):
            out[name][key] = {"records": docs[name][key]} | _Counts().to_dict()
    out["caveats"] = list(CAVEATS)
    return out


def audit_file(path: str | Path, *, reader: Callable[[str | Path], Iterable[EnrichmentRecord]] = read_jsonl) -> dict[str, Any]:
    """:func:`audit_records` over one enrichment JSONL, with its path recorded."""
    return {"path": str(path)} | audit_records(reader(path))
