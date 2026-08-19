"""Shared data contract for SIRA-CTI.

Modules 1 and 2 both *emit* an :class:`EnrichmentRecord`; Module 3 *consumes*
it; Module 4 *audits* it. Changing anything in this file requires agreement
from all four module owners (see README, "Contributing Conventions").

Design note (RQ4)
-----------------
Rejected terms are never dropped. A term that fails graph validation, or that
is too common to be discriminative, stays in ``proposed_terms`` with
``accepted=False`` and a populated ``reject_reason``. That rejection log *is*
the dataset for RQ4 (robustness / hallucination audit). Code that filters
this list for retrieval must do so at read time, not by discarding at write
time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

SCHEMA_VERSION = "1.1.0"


class Source(str, Enum):
    """Which corpus (or which side of the pipeline) a record came from."""

    CVE = "cve"
    CWE = "cwe"
    CAPEC = "capec"
    ATTACK = "attack"
    REPORT = "report"
    # Added to the README contract: Module 2 emits the same record shape for
    # an analyst query, and none of the five corpus values fit. Flagged for
    # four-owner sign-off.
    QUERY = "query"


class TermKind(str, Enum):
    """What sort of vocabulary the LLM proposed."""

    COLLOQUIAL = "colloquial"
    SYMPTOM = "symptom"
    PRODUCT = "product"
    MISSPELLING = "misspelling"
    STRUCTURAL = "structural"


class RejectReason(str, Enum):
    """Why a proposed term was not allowed into the index or the query.

    The first three are the original README set. The remaining three were
    added deliberately: an LLM proposing a *deprecated* or *revoked* ATT&CK
    technique is a different failure mode from proposing one that never
    existed, and collapsing them into ``NOT_IN_GRAPH`` would hide a genuinely
    interesting RQ4 result.
    """

    NOT_IN_GRAPH = "not_in_graph"
    TOO_COMMON = "too_common"
    NOT_IN_INDEX = "not_in_index"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    MALFORMED_ID = "malformed_id"


@dataclass
class TokenUsage:
    """Prompt/completion token counts for one or more LLM calls."""

    prompt: int = 0
    completion: int = 0

    @property
    def total(self) -> int:
        return self.prompt + self.completion

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            prompt=self.prompt + other.prompt,
            completion=self.completion + other.completion,
        )

    def to_dict(self) -> dict[str, int]:
        return {"prompt": self.prompt, "completion": self.completion}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TokenUsage":
        return cls(prompt=int(d.get("prompt", 0)), completion=int(d.get("completion", 0)))


@dataclass
class ProposedTerm:
    """One piece of vocabulary the LLM suggested, plus its adjudication.

    Three fields, three distinct facts, all of which can differ from one
    another for a repaired structural term:

    * ``term``             what the LLM literally wrote, sloppiness included
                            (``"t1562/001"``)
    * ``structural_id``    what actually enters the query, post-repair
                            (``"T1685"``)
    * ``repaired_from_id`` the canonical pre-repair identifier
                            (``"T1562.001"``), set only when
                            ``OntologyGraph.validate(..., revoked_policy="repair")``
                            rewrote a REVOKED term rather than rejecting it

    Invariants (enforced at construction):

    * ``kind == STRUCTURAL``     -> ``structural_id`` set, ``graph_validated`` is a bool
    * ``kind != STRUCTURAL``     -> ``structural_id`` is None, ``graph_validated`` is None
    * ``accepted``               -> ``reject_reason`` is None
    * ``not accepted``           -> ``reject_reason`` is set
    * ``repaired_from_id`` set   -> ``kind == STRUCTURAL``, ``accepted`` is True,
                                     and it differs from ``structural_id``

    A repaired term stays in ``accepted_terms`` (the accepted/rejected
    partition is what lets Module 4 compute rejection rates without a third
    state), but ``repaired_from_id`` keeps the fact that it needed repair
    from disappearing into an ordinary accept. See
    :meth:`EnrichmentRecord.staleness_rate`.
    """

    term: str
    kind: TermKind
    structural_id: Optional[str] = None
    graph_validated: Optional[bool] = None
    doc_freq: Optional[int] = None
    accepted: bool = False
    reject_reason: Optional[RejectReason] = None
    repaired_from_id: Optional[str] = None

    def __post_init__(self) -> None:
        self.kind = TermKind(self.kind)
        if self.reject_reason is not None:
            self.reject_reason = RejectReason(self.reject_reason)

        if not self.term or not self.term.strip():
            raise ValueError("ProposedTerm.term must be a non-empty string")

        if self.kind is TermKind.STRUCTURAL:
            if self.structural_id is None:
                raise ValueError("structural terms require a structural_id")
            if not isinstance(self.graph_validated, bool):
                raise ValueError("structural terms require graph_validated to be True or False")
        else:
            if self.structural_id is not None:
                raise ValueError(f"non-structural term {self.term!r} must not carry a structural_id")
            if self.graph_validated is not None:
                raise ValueError(f"non-structural term {self.term!r} must have graph_validated=None")

        if self.accepted and self.reject_reason is not None:
            raise ValueError(f"accepted term {self.term!r} must not carry a reject_reason")
        if not self.accepted and self.reject_reason is None:
            raise ValueError(f"rejected term {self.term!r} must carry a reject_reason")

        if self.repaired_from_id is not None:
            if self.kind is not TermKind.STRUCTURAL:
                raise ValueError(f"non-structural term {self.term!r} must not carry a repaired_from_id")
            if not self.accepted:
                raise ValueError(f"repaired_from_id on {self.term!r} requires accepted=True")
            if self.repaired_from_id == self.structural_id:
                raise ValueError(
                    f"repaired_from_id on {self.term!r} must differ from structural_id "
                    f"({self.structural_id!r}) -- otherwise nothing was repaired"
                )

        if self.doc_freq is not None and self.doc_freq < 0:
            raise ValueError("doc_freq must be >= 0")

    # -- convenience constructors -------------------------------------------------

    @classmethod
    def accept(
        cls,
        term: str,
        kind: TermKind,
        *,
        structural_id: Optional[str] = None,
        doc_freq: Optional[int] = None,
    ) -> "ProposedTerm":
        kind = TermKind(kind)
        return cls(
            term=term,
            kind=kind,
            structural_id=structural_id,
            graph_validated=True if kind is TermKind.STRUCTURAL else None,
            doc_freq=doc_freq,
            accepted=True,
            reject_reason=None,
        )

    @classmethod
    def repair(
        cls,
        term: str,
        *,
        structural_id: str,
        repaired_from_id: str,
        doc_freq: Optional[int] = None,
    ) -> "ProposedTerm":
        """A structural term whose REVOKED id was rewritten to its replacement.

        Accepted, ``graph_validated=True``, no ``reject_reason`` — same shape
        as :meth:`accept` for everything downstream that only looks at the
        accepted/rejected partition — but ``repaired_from_id`` records the
        canonical id it was rewritten from, so the RQ4 staleness signal is
        not lost just because the term went on to validate.
        """
        return cls(
            term=term,
            kind=TermKind.STRUCTURAL,
            structural_id=structural_id,
            graph_validated=True,
            doc_freq=doc_freq,
            accepted=True,
            reject_reason=None,
            repaired_from_id=repaired_from_id,
        )

    @classmethod
    def reject(
        cls,
        term: str,
        kind: TermKind,
        reason: RejectReason,
        *,
        structural_id: Optional[str] = None,
        doc_freq: Optional[int] = None,
    ) -> "ProposedTerm":
        kind = TermKind(kind)
        graph_validated: Optional[bool] = None
        if kind is TermKind.STRUCTURAL:
            # A structural term rejected for a graph-side reason failed validation;
            # one rejected on corpus statistics passed the graph but failed the
            # index/DF filter. That distinction matters for the RQ4 ablation.
            graph_validated = RejectReason(reason) not in _GRAPH_FAILURES
            if structural_id is None:
                structural_id = term
        return cls(
            term=term,
            kind=kind,
            structural_id=structural_id,
            graph_validated=graph_validated,
            doc_freq=doc_freq,
            accepted=False,
            reject_reason=RejectReason(reason),
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["reject_reason"] = self.reject_reason.value if self.reject_reason else None
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProposedTerm":
        return cls(
            term=d["term"],
            kind=TermKind(d["kind"]),
            structural_id=d.get("structural_id"),
            graph_validated=d.get("graph_validated"),
            doc_freq=d.get("doc_freq"),
            accepted=bool(d.get("accepted", False)),
            reject_reason=RejectReason(d["reject_reason"]) if d.get("reject_reason") else None,
            repaired_from_id=d.get("repaired_from_id"),
        )


_GRAPH_FAILURES = {
    RejectReason.NOT_IN_GRAPH,
    RejectReason.DEPRECATED,
    RejectReason.REVOKED,
    RejectReason.MALFORMED_ID,
}


@dataclass
class EnrichmentRecord:
    """One document's (Module 1) or one query's (Module 2) enrichment result."""

    doc_id: str
    source: Source
    original_text: str
    proposed_terms: list[ProposedTerm] = field(default_factory=list)
    llm_calls: int = 0
    tokens: TokenUsage = field(default_factory=TokenUsage)
    latency_ms: int = 0
    model: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.source = Source(self.source)
        if not self.doc_id:
            raise ValueError("EnrichmentRecord.doc_id must be non-empty")

    # -- views --------------------------------------------------------------------

    @property
    def accepted_terms(self) -> list[ProposedTerm]:
        """The terms that are actually allowed to shape the index or the query."""
        return [t for t in self.proposed_terms if t.accepted]

    @property
    def rejected_terms(self) -> list[ProposedTerm]:
        """The RQ4 dataset."""
        return [t for t in self.proposed_terms if not t.accepted]

    @property
    def repaired_terms(self) -> list[ProposedTerm]:
        """Accepted terms whose id was rewritten from a revoked one."""
        return [t for t in self.proposed_terms if t.repaired_from_id is not None]

    @property
    def structural_terms(self) -> list[ProposedTerm]:
        return [t for t in self.proposed_terms if t.kind is TermKind.STRUCTURAL]

    def rejection_rate(self, structural_only: bool = True) -> Optional[float]:
        """Graph-validation rejection rate (README, Evaluation > Metrics).

        Returns ``None`` when there is nothing to measure, rather than 0.0 —
        an empty proposal set is not the same as a perfect one.
        """
        pool = self.structural_terms if structural_only else self.proposed_terms
        if not pool:
            return None
        return sum(1 for t in pool if not t.accepted) / len(pool)

    def staleness_rate(self) -> Optional[float]:
        """Share of structural terms the model got out-of-date, not wrong.

        Counts both repaired terms (accepted after a revoked-id rewrite) and
        outright REVOKED rejections — together, "the model's training data
        was stale" as distinct from "the model hallucinated"
        (``NOT_IN_GRAPH``). ``None`` when there are no structural terms,
        mirroring :meth:`rejection_rate`.
        """
        pool = self.structural_terms
        if not pool:
            return None
        stale = sum(
            1
            for t in pool
            if t.repaired_from_id is not None or t.reject_reason is RejectReason.REVOKED
        )
        return stale / len(pool)

    def expansion_query(self) -> str:
        """The ``q_exp`` half of ``score(d) = BM25(q_orig,d) + w*BM25(q_exp,d)``."""
        return " ".join(t.term for t in self.accepted_terms)

    # -- serialisation ------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "source": self.source.value,
            "original_text": self.original_text,
            "proposed_terms": [t.to_dict() for t in self.proposed_terms],
            "llm_calls": self.llm_calls,
            "tokens": self.tokens.to_dict(),
            "latency_ms": self.latency_ms,
            "model": self.model,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EnrichmentRecord":
        return cls(
            doc_id=d["doc_id"],
            source=Source(d["source"]),
            original_text=d.get("original_text", ""),
            proposed_terms=[ProposedTerm.from_dict(t) for t in d.get("proposed_terms", [])],
            llm_calls=int(d.get("llm_calls", 0)),
            tokens=TokenUsage.from_dict(d.get("tokens", {})),
            latency_ms=int(d.get("latency_ms", 0)),
            model=d.get("model", ""),
            schema_version=d.get("schema_version", SCHEMA_VERSION),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json(cls, s: str) -> "EnrichmentRecord":
        return cls.from_dict(json.loads(s))


# -- JSONL helpers ------------------------------------------------------------------
# Enrichment output is JSONL: one record per line, append-safe, streamable by
# Module 4 without loading the whole corpus into memory.


def write_jsonl(records: Iterable[EnrichmentRecord], path: str | Path, append: bool = False) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("a" if append else "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(rec.to_json() + "\n")
            n += 1
    return n


def read_jsonl(path: str | Path) -> Iterator[EnrichmentRecord]:
    with Path(path).open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield EnrichmentRecord.from_json(line)
            except Exception as exc:  # noqa: BLE001 - want the line number in the message
                raise ValueError(f"{path}:{line_no}: malformed enrichment record: {exc}") from exc
