"""Module 1 — offline corpus-side enrichment.

For each CVE/CWE/CAPEC/ATT&CK entry: prompt the frozen LLM for vocabulary an
analyst might search for that is absent from the entry's own text, parse the
reply strictly, validate structural proposals against the ontology graph
(:mod:`sira_cti.graph.ontology`), apply the document-frequency filter, and
emit one :class:`~sira_cti.common.schemas.EnrichmentRecord` per document.

Pipeline, per document::

    prompt -> client.generate() -> parse_json_loose() (reused from llm.py)
           -> strict shape check           [malformed -> raise, never []]
           -> kind routing                 [demote a mislabelled "structural"]
           -> graph.validate() for kind=="structural" terms
           -> DF filter (too_common) over everything that survived so far

Rejected terms are kept, never dropped -- the rejection log is the RQ4
dataset (README, schemas.py). A reply that fails to parse, or doesn't match
the expected shape, raises :class:`MalformedReplyError` rather than
degrading into an empty term list: an LLM that "proposed nothing" and a
pipeline that "couldn't understand the reply" are different RQ4-relevant
outcomes, and this module must never make the second one look like the
first.

Resumability lives in :func:`run_corpus_enrichment`, not here: it reads the
existing output JSONL once to build a done-set, and every subsequent write is
a single-record, immediately-flushed append (``write_jsonl(..., append=True)``)
so a crash loses at most the document in flight. A document whose reply is
malformed is never marked done, so it is retried on the next run rather than
silently skipped -- see the module docstring above for why that must not
collapse into "no proposals".
"""

from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..common.llm import LLMClient, LLMError, parse_json_loose
from ..common.schemas import (
    EnrichmentRecord,
    ProposedTerm,
    RejectReason,
    RejectStage,
    TermKind,
    TokenUsage,
    read_jsonl,
    write_jsonl,
)
from ..graph.normalize import is_id_shaped, looks_structural, parse_structural_id
from ..graph.ontology import OntologyGraph, RevokedPolicy
from ..index.corpus import CorpusDocument
from ..index.df_stats import Combine, DFLookup
from .prompts.corpus_side import PROMPT_VERSION, SYSTEM_PROMPT, build_prompt
from .truncation import TRUNCATION_VERSION, truncate_text

_VALID_KINDS = {k.value for k in TermKind}


class MalformedReplyError(RuntimeError):
    """The LLM's reply could not be trusted as a list of proposals.

    Raised instead of returning ``[]`` -- see the module docstring. Callers
    must record this as an explicit failure, not swallow it into a record.

    ``raw`` carries the model's reply verbatim. Without it the failure log
    says only "could not parse", which cannot distinguish a reply cut off by
    the token cap from one the model simply formatted badly -- and those have
    different fixes (raise ``enrichment.max_new_tokens`` vs. constrain
    decoding). ``truncated`` is the backend's own account of why generation
    stopped, when it gives one.
    """

    def __init__(self, message: str, *, raw: str = "", truncated: bool = False) -> None:
        super().__init__(message)
        self.raw = raw
        self.truncated = truncated


# -- reply parsing (structural validation is a separate step, below) ---------------


@dataclass(frozen=True)
class Proposal:
    """One element of the model's reply, after shape validation only.

    Deliberately not a :class:`ProposedTerm`: nothing here has been
    adjudicated yet, and ``claimed_name`` is a *claim*, not a fact. Keeping
    the two types apart is what stops an unchecked name reaching the index.
    """

    term: str
    kind: str
    claimed_name: Optional[str] = None


def _extract_proposals(parsed: object) -> list[Proposal]:
    """Strictly validate the *shape* of an already-JSON-parsed reply.

    Expects a list of ``{"term": str, "kind": <TermKind value>}``, with an
    optional ``"name"`` carrying the title the model believes a structural id
    has (prompt ``corpus-v4``). Anything else -- wrong top-level type, a
    non-object item, a blank term, an unrecognised kind -- raises
    :class:`MalformedReplyError` for the whole reply. A genuinely empty reply
    (``[]``) is not malformed and returns ``[]`` unchanged: the model
    proposing nothing is a legitimate outcome, just not one this function
    should ever manufacture on its own.

    ``"id"`` is accepted as a synonym for ``"term"``. The v4 prompt asks for
    ``term``, but a model told to emit an identifier and a name writes
    ``{"id": ..., "name": ...}`` often enough that treating it as a malformed
    reply would throw away whole documents over a key spelling -- and that
    loss would land disproportionately on the structural proposals this
    experiment is about.

    A **missing or blank ``name`` is not a shape error.** It is carried
    through as ``claimed_name=None`` and adjudicated as a name mismatch
    later, which keeps the failure in the RQ4 dataset with a reason attached
    instead of discarding the document that produced it.
    """
    if not isinstance(parsed, list):
        raise MalformedReplyError(f"expected a JSON array, got {type(parsed).__name__}: {parsed!r}")

    out: list[Proposal] = []
    for i, item in enumerate(parsed):
        if not isinstance(item, dict):
            raise MalformedReplyError(f"item {i} is not an object: {item!r}")
        term = item.get("term")
        if not isinstance(term, str) or not term.strip():
            term = item.get("id")
        kind = item.get("kind")
        if not isinstance(term, str) or not term.strip():
            raise MalformedReplyError(f"item {i} has no usable 'term': {item!r}")
        if kind not in _VALID_KINDS:
            raise MalformedReplyError(f"item {i} has an unrecognised 'kind' {kind!r}: {item!r}")
        claimed = item.get("name")
        claimed = claimed.strip() if isinstance(claimed, str) and claimed.strip() else None
        out.append(Proposal(term=term.strip(), kind=kind, claimed_name=claimed))
    return out


# -- kind routing (before the graph gate) -------------------------------------------

# Where a mislabelled "structural" proposal is sent instead. TermKind has no
# "unknown" member and adding one would change the frozen EnrichmentRecord
# contract (four-owner sign-off, see docs/02_MODULE1_STATE.md), so this reuses
# the existing catch-all: COLLOQUIAL is defined in the prompt as "an informal
# name an analyst might type", which is what these terms actually are.
_MISLABELLED_STRUCTURAL_KIND = TermKind.COLLOQUIAL


def _route_kind(kind: TermKind, term_text: str) -> TermKind:
    """Correct a ``kind="structural"`` label the model put on a non-identifier.

    Qwen2.5-7B mislabels routinely: the first real run tagged ``heap-based``,
    ``zzip_get32``, ``local`` and ``medium`` as structural. Routing on the
    model's own label sent those to the graph gate, which correctly found no
    identifier and rejected them as ``MALFORMED_ID``.

    That conflates two different failures, and the conflation is expensive
    because the rejection log *is* the RQ4 dataset (see the module docstring):

    * the model **reached for an identifier and got it wrong** (``CWE-abc``,
      ``T99``) -- a real hallucination, real RQ4 signal, still ``MALFORMED_ID``;
    * the model **filled in the wrong form field** on ordinary vocabulary --
      not a hallucination at all, and booking it as one inflates the headline
      RQ4 rate with a schema-compliance slip.

    :func:`~sira_cti.graph.normalize.is_id_shaped` separates the two. A term
    that never reached for an identifier is relabelled and judged on its
    merits like any other vocabulary -- which is also how ``zzip_get32``
    (a real zziplib symbol, document frequency 0 in the base index, so
    maximally discriminative) stops being discarded over a label.

    Deliberately one-way: this only ever *demotes* STRUCTURAL. A term the
    model labelled colloquial is left alone even if it parses as an
    identifier, because promoting it would put an unvalidated id into the
    structural pool and quietly change what RQ4 counts.
    """
    if kind is not TermKind.STRUCTURAL:
        return kind
    if looks_structural(term_text) or is_id_shaped(term_text):
        return kind
    return _MISLABELLED_STRUCTURAL_KIND


# -- structural adjudication (graph gate) -------------------------------------------


def _adjudicate_structural(
    term: str,
    graph: OntologyGraph,
    *,
    allow_deprecated: bool,
    revoked_policy: RevokedPolicy | str,
    claimed_name: Optional[str] = None,
    name_match_min_overlap: Optional[float] = None,
    name_scorer: str = "v1",
    name_match_min_jaccard: float = 0.6,
) -> ProposedTerm:
    """Validate one structural proposal: stage 1 existence, then stage 2 name.

    ``term`` is normalised through ``normalize.py``'s parser as part of
    ``graph.validate()`` itself -- ``MALFORMED_ID`` *is* the "did not even
    parse" outcome, already a first-class :class:`RejectReason`. This
    function only re-parses when a repair occurs, to recover the pre-repair
    canonical id: :class:`~sira_cti.graph.ontology.ValidationResult`
    overwrites ``canonical_id`` with the replacement and does not carry the
    original alongside it.

    **Stage order is existence first, then name**, and it is not
    interchangeable. An id that does not exist has no official title to
    compare against, so running the name check first would report
    ``NAME_MISMATCH`` for pure hallucinations and merge the two most
    different RQ4 findings -- "this id is invented" and "this id is real but
    the model does not know what it is" -- under one reason.

    ``name_match_min_overlap=None`` disables stage 2 entirely, which is how
    the corpus-v3 behaviour stays reproducible for the model-to-model
    comparison rather than being overwritten by it.
    """
    result = graph.validate(term, allow_deprecated=allow_deprecated, revoked_policy=revoked_policy)

    if not result.valid:
        return ProposedTerm.reject(
            term,
            TermKind.STRUCTURAL,
            result.reject_reason,
            structural_id=result.canonical_id or term,
            claimed_name=claimed_name,
            official_name=result.node.name if result.node else None,
        )

    # The node the id resolved to -- for a repair, that is the *replacement*,
    # so the name is checked against what would actually enter the index.
    official_name = result.node.name if result.node else None
    scored_by: Optional[str] = None

    if name_match_min_overlap is not None:
        check = graph.check_name(
            result.canonical_id,
            claimed_name,
            min_overlap=name_match_min_overlap,
            scorer=name_scorer,
            min_jaccard=name_match_min_jaccard,
        )
        official_name = check.official_name
        scored_by = check.scorer
        if not check.matches:
            return ProposedTerm.reject(
                term,
                TermKind.STRUCTURAL,
                RejectReason.NAME_MISMATCH,
                structural_id=result.canonical_id,
                claimed_name=check.claimed_name,
                official_name=official_name,
                name_scorer=scored_by,
            )

    if result.repaired:
        pre_repair = parse_structural_id(term)
        repaired_from = pre_repair.canonical if pre_repair is not None else term
        return ProposedTerm.repair(
            term,
            structural_id=result.canonical_id,
            repaired_from_id=repaired_from,
            claimed_name=claimed_name,
            official_name=official_name,
            name_scorer=scored_by,
        )

    return ProposedTerm.accept(
        term,
        TermKind.STRUCTURAL,
        structural_id=result.canonical_id,
        claimed_name=claimed_name,
        official_name=official_name,
        name_scorer=scored_by,
    )


# -- document-frequency gate (everyone who survived the graph gate) -----------------


def _indexable_text(term: ProposedTerm) -> str:
    """What would actually be injected into the index for this term."""
    return term.structural_id if term.kind is TermKind.STRUCTURAL else term.term


def _df_combine(term: ProposedTerm) -> Combine:
    """Which per-token DF combine rule this term is judged under.

    Structural identifiers get ``"min"``, everything else ``"max"``. The
    reasoning, and the measured numbers behind it, are in
    :data:`sira_cti.index.df_stats.Combine`. In one line: ``CWE-307``
    analyzes to ``["cwe", "307"]``, and ``cwe`` is a constant shared by every
    identifier in the catalogue, so judging a CWE by its most common token
    judges every CWE identically and rejects all of them -- while one-token
    ATT&CK ids bypass the gate entirely. The identity of a structural id
    lives in its number, so the number is what the gate reads.
    """
    return "min" if term.kind is TermKind.STRUCTURAL else "max"


def _apply_df_filter(term: ProposedTerm, df_lookup: DFLookup, *, df_max_ratio: float) -> ProposedTerm:
    """Downgrade an accepted/repaired term to ``TOO_COMMON`` if it isn't discriminative.

    Only corpus-side's own gate (``too_common``) applies here. ``NOT_IN_INDEX``
    is Module 2's query-side gate (configs/default.yaml: "query-side terms
    must already exist in the enriched index") -- there is no enriched index
    yet for a corpus-side term to be absent from, so this function never
    produces that reason. A term already rejected at the graph stage is
    passed through untouched: DF only matters once a term is otherwise going
    to enter the index.
    """
    if not term.accepted:
        return term

    doc_freq = df_lookup.doc_freq(_indexable_text(term), combine=_df_combine(term))
    ratio = doc_freq / df_lookup.total_docs if df_lookup.total_docs else 0.0

    if ratio > df_max_ratio:
        return ProposedTerm.reject(
            term.term,
            term.kind,
            RejectReason.TOO_COMMON,
            structural_id=term.structural_id,
            doc_freq=doc_freq,
            claimed_name=term.claimed_name,
            official_name=term.official_name,
            name_scorer=term.name_scorer,
        )

    if term.repaired_from_id is not None:
        return ProposedTerm.repair(
            term.term,
            structural_id=term.structural_id,
            repaired_from_id=term.repaired_from_id,
            doc_freq=doc_freq,
            claimed_name=term.claimed_name,
            official_name=term.official_name,
            name_scorer=term.name_scorer,
        )
    return ProposedTerm.accept(
        term.term,
        term.kind,
        structural_id=term.structural_id,
        doc_freq=doc_freq,
        claimed_name=term.claimed_name,
        official_name=term.official_name,
        name_scorer=term.name_scorer,
    )


# -- measurement-only annotations (never change accept/reject) ----------------------

_TRAILING_NUMBER = re.compile(r"^(.*?)(\d+)$")

MIN_COUNTING_RUN = 3
"""How many consecutive ids make a run.

Two in a row is ordinary: ``T1110.001`` and ``T1110.002`` are genuine
siblings an analyst would reasonably want together. Three or more in an
unbroken sequence is the signature of a model walking the number line, and in
the 2026-10-07 14B run every such sequence was one (``CWE-73`` through
``CWE-81`` on a Spyware entry, ``T1056.005`` through ``T1056.009`` of which
none exist).
"""


def _run_key(canonical_id: str) -> Optional[tuple[str, int]]:
    """Split an id into the part that names a series and the number within it.

    ``CWE-307`` -> ``("CWE-", 307)``; ``T1110`` -> ``("T", 1110)``;
    ``T1056.004`` -> ``("T1056.", 4)``. Sub-techniques key on their parent, so
    ``T1056.004`` and ``T1057.004`` are not mistaken for neighbours -- they
    share a number but belong to different series.
    """
    m = _TRAILING_NUMBER.match(canonical_id or "")
    if m is None:
        return None
    return m.group(1), int(m.group(2))


def flag_counting_runs(terms: Iterable[ProposedTerm], *, min_run: int = MIN_COUNTING_RUN) -> int:
    """Mark structural ids that sit in a run of consecutive numbers. Returns the count.

    Measurement only -- it sets ``in_counting_run`` and touches nothing else.
    Enumeration is not grounds for rejection here because some of it is
    legitimate (a technique's real sub-techniques are consecutive by
    construction), and the project does not yet know the split. Recording the
    flag is what makes that answerable; gating on it would foreclose the
    question. See ``docs/04_OPEN_QUESTIONS.md`` question 8.

    Rejected proposals are included: the invented tail of a run (``T1056.005``
    onward) is the most informative part of it, and excluding rejects would
    show the run stopping exactly where the graph started catching it.
    """
    series: dict[str, dict[int, list[ProposedTerm]]] = {}
    for t in terms:
        if t.kind is not TermKind.STRUCTURAL or not t.structural_id:
            continue
        parsed = parse_structural_id(t.structural_id)
        if parsed is None:
            continue  # a malformed id has no place on the number line
        key = _run_key(parsed.canonical)
        if key is None:
            continue
        prefix, number = key
        series.setdefault(prefix, {}).setdefault(number, []).append(t)

    flagged = 0
    for by_number in series.values():
        numbers = sorted(by_number)
        start = 0
        for i in range(1, len(numbers) + 1):
            if i < len(numbers) and numbers[i] == numbers[i - 1] + 1:
                continue
            if i - start >= min_run:
                for n in numbers[start:i]:
                    for t in by_number[n]:
                        t.in_counting_run = True
                        flagged += 1
            start = i
    return flagged


def annotate_graph_distance(
    terms: Iterable[ProposedTerm], doc: CorpusDocument, graph: OntologyGraph
) -> Optional[str]:
    """Record each structural id's hop distance from the document's own node.

    Returns the anchor node id used, or ``None`` when the document is not an
    ontology node at all -- which is every CVE, since CVEs are corpus
    documents with no entry in ATT&CK/CWE/CAPEC. In that case every distance
    stays ``None``, and the report must say "not measurable" rather than
    reading the absence as "unrelated".

    Reported, never filtered on. The whole point of corpus-side enrichment is
    to add the links an entry's own data lacks, so the ids at a large
    distance include both the model's worst guesses *and* the genuinely new
    connections that would justify the method. Those cannot be separated by
    distance alone, so distance does not get a veto.
    """
    anchor_node = graph.resolve(doc.doc_id)
    if anchor_node is None:
        return None
    for t in terms:
        if t.kind is not TermKind.STRUCTURAL or not t.structural_id:
            continue
        t.graph_distance = graph.distance(anchor_node.node_id, t.structural_id)
    return anchor_node.node_id


REPAIR_MAX_HOPS = 2
"""How far from the source document a repair candidate may sit.

The bound is what makes a repair evidence rather than a search. Scored
against all ~4,500 titles, most claimed names match *something*; scored
against the few dozen nodes within two hops of the entry, a match means the
model named a real neighbour and attached the wrong number to it.
"""


def repair_candidates(
    term: ProposedTerm,
    doc: CorpusDocument,
    graph: OntologyGraph,
    df_lookup: DFLookup,
    *,
    df_max_ratio: float,
    min_jaccard: float = 0.6,
    max_hops: int = REPAIR_MAX_HOPS,
) -> list[tuple[str, float, int]]:
    """Real ids near ``doc`` whose official name matches what the model *said*.

    ``(node_id, score, hops)``, best score first. Empty unless ``term`` is a
    ``name_mismatch`` with a claimed name and ``doc`` is an ontology node --
    so never for a CVE, which has no neighbourhood to search.

    The rejected id itself is never a candidate. The document's own id *can*
    be (the model reciting the entry's title beside a different number is a
    recurring pattern), and the index build skips it when the repair ablation
    is on (``index.build_enriched.repaired_ids``): an entry's own id reaching
    the index by way of the LLM is the thing prompt ``corpus-v3`` was written
    to stop.

    A candidate must also clear the same document-frequency bar as any
    accepted structural id, so that switching the repair ablation on cannot
    index something the ordinary pipeline would have refused.
    """
    if term.reject_reason is not RejectReason.NAME_MISMATCH or not term.claimed_name:
        return []
    anchor = graph.resolve(doc.doc_id)
    if anchor is None:
        return []
    nearby = graph.within(anchor.node_id, max_hops)
    nearby.pop(term.structural_id, None)
    out: list[tuple[str, float, int]] = []
    for node_id, score in graph.name_candidates(
        term.claimed_name, nearby, min_jaccard=min_jaccard
    ):
        doc_freq = df_lookup.doc_freq(node_id, combine="min")
        ratio = doc_freq / df_lookup.total_docs if df_lookup.total_docs else 0.0
        if ratio <= df_max_ratio:
            out.append((node_id, score, nearby[node_id]))
    return out


def annotate_repairs(
    terms: Iterable[ProposedTerm],
    doc: CorpusDocument,
    graph: OntologyGraph,
    df_lookup: DFLookup,
    *,
    df_max_ratio: float,
    min_jaccard: float = 0.6,
) -> int:
    """Set ``repaired_to`` on name mismatches with exactly one candidate. Returns the count.

    Measurement only: the term stays rejected with ``reject_reason`` still
    ``name_mismatch``. Exactly one, because two candidates means the claimed
    name does not identify an id -- recording the better-scoring one would
    present a guess as a recovery. Ambiguous cases are left unset and can be
    listed from the saved records with ``scripts/rescore_enrichment.py``.
    """
    repaired = 0
    for t in terms:
        candidates = repair_candidates(
            t, doc, graph, df_lookup, df_max_ratio=df_max_ratio, min_jaccard=min_jaccard
        )
        if len(candidates) == 1:
            t.repaired_to = candidates[0][0]
            repaired += 1
    return repaired


# -- one document ---------------------------------------------------------------------


def truncate_document(
    doc: CorpusDocument, max_doc_chars: Optional[int]
) -> tuple[CorpusDocument, Optional[dict[str, object]]]:
    """``(doc as shown to the model, what was removed)``.

    Section-aware (``enrichment/truncation.py``): whole sections go, least
    useful first, and the description and cross-catalogue links never do. The
    second value is ``None`` when the entry fits and is otherwise what gets
    stored on the record as ``truncation``. Only the copy shown to the model
    is shortened; the record keeps the full ``original_text`` and the index is
    built from the full document.
    """
    shown, info = truncate_text(doc.text, max_doc_chars)
    return (doc if info is None else replace(doc, text=shown)), info


def _ask_for_proposals(
    doc: CorpusDocument,
    client: LLMClient,
    *,
    max_terms: int,
    json_retries: int,
    max_doc_chars: Optional[int] = None,
) -> tuple[list[Proposal], int]:
    """Call the model and parse its reply, retrying a parse failure with a nudge.

    Returns ``(proposals, attempts)``. Raises :class:`MalformedReplyError`
    carrying the last raw reply once the retries are spent, and
    :class:`LLMError` if the backend reports that the prompt did not fit its
    context -- a reply to a prompt the model only partly saw is not a result.
    """
    shown, _info = truncate_document(doc, max_doc_chars)
    last_exc: Optional[MalformedReplyError] = None
    for attempt in range(json_retries + 1):
        prompt = build_prompt(shown, max_terms=max_terms, nudge=attempt > 0)
        raw = client.generate(prompt, system=SYSTEM_PROMPT, tag="corpus_enrich")
        if getattr(client, "last_context_overflow", False):
            raise LLMError(
                f"{doc.doc_id}: prompt plus reply cap exceeds the model's context "
                f"(num_ctx={getattr(client, 'num_ctx', None)}); lower enrichment.max_doc_chars"
            )
        try:
            return _extract_proposals(parse_json_loose(raw)), attempt + 1
        except (ValueError, MalformedReplyError) as exc:
            last_exc = MalformedReplyError(
                f"{doc.doc_id}: {exc}",
                raw=raw,
                truncated=bool(getattr(client, "last_truncated", False)),
            )
    assert last_exc is not None
    raise last_exc


def adjudicate_proposals(
    proposals: Iterable[Proposal],
    doc: CorpusDocument,
    graph: OntologyGraph,
    df_lookup: DFLookup,
    *,
    df_max_ratio: float,
    allow_deprecated: bool = False,
    revoked_policy: RevokedPolicy | str = RevokedPolicy.REJECT,
    name_match_min_overlap: Optional[float] = None,
    name_scorer: str = "v1",
    name_match_min_jaccard: float = 0.6,
) -> list[ProposedTerm]:
    """Everything after the model call: route -> graph -> name -> DF -> annotate.

    Split out from :func:`propose_terms` so that a saved run can be
    re-adjudicated without calling the model again
    (:func:`readjudicate_record`). The model's reply is the expensive,
    unrepeatable part of a run; every gate after it is a pure function of
    that reply, the graph and the index, and should be re-runnable for free.

    The last step annotates ``in_counting_run``, ``graph_distance`` and
    ``repaired_to`` across the whole document's proposals at once. All three
    are measurements and run after adjudication so that nothing they record
    can influence it.
    """
    terms: list[ProposedTerm] = []
    for proposal in proposals:
        kind = _route_kind(TermKind(proposal.kind), proposal.term)
        if kind is TermKind.STRUCTURAL:
            pt = _adjudicate_structural(
                proposal.term,
                graph,
                allow_deprecated=allow_deprecated,
                revoked_policy=revoked_policy,
                claimed_name=proposal.claimed_name,
                name_match_min_overlap=name_match_min_overlap,
                name_scorer=name_scorer,
                name_match_min_jaccard=name_match_min_jaccard,
            )
        else:
            pt = ProposedTerm.accept(proposal.term, kind)
        terms.append(_apply_df_filter(pt, df_lookup, df_max_ratio=df_max_ratio))

    flag_counting_runs(terms)
    annotate_graph_distance(terms, doc, graph)
    annotate_repairs(
        terms, doc, graph, df_lookup, df_max_ratio=df_max_ratio,
        min_jaccard=name_match_min_jaccard,
    )
    return terms


def propose_terms(
    doc: CorpusDocument,
    client: LLMClient,
    graph: OntologyGraph,
    df_lookup: DFLookup,
    *,
    max_terms: int,
    df_max_ratio: float,
    allow_deprecated: bool = False,
    revoked_policy: RevokedPolicy | str = RevokedPolicy.REJECT,
    name_match_min_overlap: Optional[float] = None,
    name_scorer: str = "v1",
    name_match_min_jaccard: float = 0.6,
    json_retries: int = 0,
    max_doc_chars: Optional[int] = None,
) -> list[ProposedTerm]:
    """The per-document pipeline: prompt -> parse -> :func:`adjudicate_proposals`.

    Raises :class:`MalformedReplyError` if the reply cannot be trusted. Every
    model call goes through ``client.generate()`` (the instrumented wrapper) --
    never a direct call -- and JSON extraction reuses ``parse_json_loose``
    rather than a second parser.
    """
    proposals, _attempts = _ask_for_proposals(
        doc, client, max_terms=max_terms, json_retries=json_retries, max_doc_chars=max_doc_chars
    )
    return adjudicate_proposals(
        proposals[:max_terms],
        doc,
        graph,
        df_lookup,
        df_max_ratio=df_max_ratio,
        allow_deprecated=allow_deprecated,
        revoked_policy=revoked_policy,
        name_match_min_overlap=name_match_min_overlap,
        name_scorer=name_scorer,
        name_match_min_jaccard=name_match_min_jaccard,
    )


def readjudicate_record(
    record: EnrichmentRecord,
    graph: OntologyGraph,
    df_lookup: DFLookup,
    *,
    df_max_ratio: float,
    allow_deprecated: bool = False,
    revoked_policy: RevokedPolicy | str = RevokedPolicy.REJECT,
    name_match_min_overlap: Optional[float] = None,
    name_scorer: str = "v1",
    name_match_min_jaccard: float = 0.6,
) -> EnrichmentRecord:
    """Re-run every gate on a saved record's proposals. No model call.

    Each stored term keeps what the model literally wrote (``term``) and what
    it claimed (``claimed_name``), which is all the gates ever saw of the
    reply -- so a new scorer, threshold or graph snapshot can be applied to
    an old run and the result is exactly what that run would have produced.
    Cost fields (``llm_calls``, ``tokens``, ``latency_ms``, ``model``) are
    carried over untouched: they describe the model call that was made, and
    re-adjudicating makes none.

    The stored ``kind`` is the kind *after* routing. Routing only ever demotes
    a mislabelled "structural", and a demoted term is routed the same way
    again, so replaying from it is lossless. A term recording that the reply
    never parsed (``llm_json_error``) was never a proposal and is passed
    through as it is.
    """
    doc = CorpusDocument(
        doc_id=record.doc_id, source=record.source, title="", text=record.original_text
    )
    failures = [
        t for t in record.proposed_terms if t.reject_reason is RejectReason.LLM_JSON_ERROR
    ]
    proposals = [
        Proposal(term=t.term, kind=t.kind.value, claimed_name=t.claimed_name)
        for t in record.proposed_terms
        if t.reject_reason is not RejectReason.LLM_JSON_ERROR
    ]
    terms = adjudicate_proposals(
        proposals,
        doc,
        graph,
        df_lookup,
        df_max_ratio=df_max_ratio,
        allow_deprecated=allow_deprecated,
        revoked_policy=revoked_policy,
        name_match_min_overlap=name_match_min_overlap,
        name_scorer=name_scorer,
        name_match_min_jaccard=name_match_min_jaccard,
    )
    return EnrichmentRecord(
        doc_id=record.doc_id,
        source=record.source,
        original_text=record.original_text,
        proposed_terms=failures + terms,
        llm_calls=record.llm_calls,
        tokens=record.tokens,
        latency_ms=record.latency_ms,
        model=record.model,
        truncation=record.truncation,
    )


# -- the resumable, (optionally) concurrent driver -----------------------------------


@dataclass
class EnrichmentRunSummary:
    """What :func:`run_corpus_enrichment` did, for the CLI to print."""

    total_docs: int = 0
    already_done: int = 0
    processed: int = 0
    failed: int = 0
    json_failures: int = 0
    """Documents whose reply never parsed. Under
    ``record_json_failures=True`` these are *also* counted in ``processed``,
    because a record was written for them -- the two numbers answer different
    questions ("how many documents are now done" vs. "how many of those are
    done only in the sense that we gave up")."""
    elapsed_s: float = 0.0
    failures: list[tuple[str, str]] = field(default_factory=list)  # (doc_id, error)
    llm_calls: int = 0
    tokens: TokenUsage = field(default_factory=TokenUsage)
    """Calls and tokens of the records written by *this* invocation (a resume
    does not re-count what an earlier one already paid for). ``tokens.thinking``
    is kept apart from ``tokens.completion``."""


def _append_failure(path: Path, doc_id: str, error: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"doc_id": doc_id, "error": error, "ts": time.time()}) + "\n")


def _append_raw(path: Path, doc_id: str, exc: MalformedReplyError) -> None:
    """Save the unparseable reply in full, beside the run.

    The ``ProposedTerm`` that marks the failure can only hold a truncated
    copy (it is a search term, not a log line), and the interesting part of a
    broken reply is often where it broke -- which may be past the truncation.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "doc_id": doc_id,
                    "error": str(exc),
                    "raw": exc.raw,
                    "raw_chars": len(exc.raw),
                    "truncated_by_token_cap": exc.truncated,
                    "ts": time.time(),
                },
                ensure_ascii=False,
            )
            + "\n"
        )


_RAW_TERM_CHARS = 200


def _json_failure_term(exc: MalformedReplyError) -> ProposedTerm:
    """The single rejected term that stands for "this reply never parsed".

    Carrying the raw reply as the ``term`` is deliberate. The alternative --
    a fixed placeholder string -- would make every parse failure identical in
    the RQ4 dataset, when what the model actually emitted is the evidence
    (``CAPEC-587``'s reply lost one opening brace mid-array; a reply cut off
    by the token cap looks nothing like that). It can never reach the index:
    ``accepted=False``, and the index build reads accepted terms only.
    """
    snippet = " ".join((exc.raw or "").split())[:_RAW_TERM_CHARS]
    return ProposedTerm.reject(
        snippet or "<empty reply>",
        TermKind.COLLOQUIAL,
        RejectReason.LLM_JSON_ERROR,
        stage=RejectStage.PARSE,
    )


class ResumeMismatchError(RuntimeError):
    """An existing output file was written under different settings.

    Raised instead of appending. A JSONL holding replies made under two
    prompts, two models or two truncation rules looks like one run and cannot
    be untangled afterwards (open question 2).
    """


_RESUME_TOP_LEVEL = ("prompt_version", "model", "config_hash", "sampling", "concurrency")
_MISSING = object()


def check_resume(
    output_path: Path, current: dict[str, object], *, allow_code_change: bool = False
) -> dict[str, object]:
    """Refuse to append to ``output_path`` unless its manifest matches ``current``.

    Returns the previous manifest. The code version (``code.code_commit``) is
    compared too, when this session knows its own: a different commit means
    the documents already in the file and the ones about to be added were
    produced by different programs. ``allow_code_change`` waives that one
    check and nothing else -- for a fix that is known not to touch what a
    reply looks like.

    ``current`` is the manifest this session would write. Compared: prompt
    version, model, config hash, sampling, concurrency, and every entry of
    ``gates`` (name scorer and thresholds, decoding mode, reply cap,
    truncation budget and rules). A key an older manifest never recorded is
    only acceptable when the current value is "off" (``None``) -- except
    ``concurrency``, which older manifests simply did not have.
    """
    manifest_path = output_path.with_suffix(output_path.suffix + ".manifest.json")
    if not manifest_path.exists():
        raise ResumeMismatchError(
            f"{output_path} already holds records but has no manifest beside it, so there is "
            "no way to check they were made with the current settings. Use a new --output."
        )
    previous = json.loads(manifest_path.read_text(encoding="utf-8"))
    differences: list[str] = []

    def _compare(label: str, old: object, new: object, *, tolerate_missing: bool = False) -> None:
        if old is _MISSING:
            if tolerate_missing or new is None:
                return
            old = "(not recorded)"
        if old != new:
            differences.append(f"  {label}: the file was written with {old!r}, this run would use {new!r}")

    for key in _RESUME_TOP_LEVEL:
        _compare(key, previous.get(key, _MISSING), current.get(key), tolerate_missing=key == "concurrency")
    old_gates = previous.get("gates") or {}
    new_gates = current.get("gates") or {}
    for key in sorted(new_gates):  # type: ignore[arg-type]
        _compare(f"gates.{key}", old_gates.get(key, _MISSING), new_gates[key])  # type: ignore[index, union-attr]

    new_code = current.get("code")
    if isinstance(new_code, dict) and not allow_code_change:
        old_code = previous.get("code")
        old_commit = old_code.get("code_commit") if isinstance(old_code, dict) else None
        if old_commit != new_code.get("code_commit"):
            differences.append(
                f"  code: the file was written by commit {str(old_commit)[:12] if old_commit else '(not recorded)'}, "
                f"this is commit {str(new_code.get('code_commit'))[:12]}"
                "  (pass --allow-code-change only if the change cannot affect a reply)"
            )

    if differences:
        raise ResumeMismatchError(
            f"Refusing to resume into {output_path}: its settings differ from this run's.\n"
            + "\n".join(differences)
            + "\nMixing them would put two different experiments in one file. Either restore the "
            "original settings (config, model, flags) or start a new file with a different --output."
        )
    return previous


def _truncation_summary(docs: list[CorpusDocument], max_doc_chars: int) -> dict[str, object]:
    """Which documents the model saw shortened, for the manifest."""
    cut: list[str] = []
    fallback: list[str] = []
    for d in docs:
        info = truncate_document(d, max_doc_chars)[1]
        if info is None:
            continue
        cut.append(d.doc_id)
        if info["mode"] == "fallback":
            fallback.append(d.doc_id)
    return {
        "max_doc_chars": max_doc_chars,
        "version": TRUNCATION_VERSION,
        "truncated_docs": sorted(cut),
        "fallback_docs": sorted(fallback),
    }


def _write_manifest(
    output_path: Path,
    *,
    prompt_version: str,
    model: str,
    config_hash: Optional[str],
    kinds: list[str],
    sampling: Optional[dict[str, object]],
    gates: Optional[dict[str, object]] = None,
    llm: Optional[dict[str, object]] = None,
    usage: Optional[dict[str, object]] = None,
    truncation: Optional[dict[str, object]] = None,
    concurrency: Optional[int] = None,
    code: Optional[dict[str, object]] = None,
    code_previous: Optional[list[object]] = None,
    write: bool = True,
) -> dict[str, object]:
    manifest: dict[str, object] = {
        "prompt_version": prompt_version,
        "model": model,
        "config_hash": config_hash,
        "kinds": kinds,
        "sampling": sampling,
        "concurrency": concurrency,
        # Which gates were switched on. The config hash alone no longer
        # settles this: --model and the name-check threshold can both be
        # overridden per run, by design, so that the comparison between two
        # runs isn't confounded by an edited config file.
        "gates": gates or {},
        "created_at": time.time(),
    }
    # Only present when the caller supplied them, so a manifest from a plain
    # Ollama run keeps the shape it always had.
    if llm:
        # Backend settings that shape the reply but are not gates: provider,
        # thinking configuration, seed (and whether it was honoured), pricing.
        manifest["llm"] = llm
    if code:
        # Which commit produced this file, and whether the working tree
        # matched it. See common/repro.py:code_version.
        manifest["code"] = code
    if code_previous:
        # Earlier code versions that also wrote into this file (a resume made
        # with --allow-code-change). Never dropped, so the file's history is
        # readable from its manifest alone.
        manifest["code_previous"] = code_previous
    if usage:
        manifest["usage"] = usage
    if truncation:
        truncated = list(truncation.get("truncated_docs", []))  # type: ignore[arg-type]
        manifest["truncation"] = {**truncation, "truncated_count": len(truncated)}
    if write:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.with_suffix(output_path.suffix + ".manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
    return manifest


def run_corpus_enrichment(
    docs: Iterable[CorpusDocument],
    *,
    client_factory: Callable[[], LLMClient],
    graph: OntologyGraph,
    df_lookup: DFLookup,
    output_path: str | Path,
    max_terms: int = 12,
    df_max_ratio: float = 0.10,
    allow_deprecated: bool = False,
    revoked_policy: RevokedPolicy | str = RevokedPolicy.REJECT,
    name_match_min_overlap: Optional[float] = None,
    name_scorer: str = "v1",
    name_match_min_jaccard: float = 0.6,
    json_retries: int = 0,
    record_json_failures: bool = False,
    max_new_tokens: Optional[int] = None,
    json_mode: Optional[str] = None,
    max_doc_chars: Optional[int] = None,
    concurrency: int = 1,
    prompt_version: str = PROMPT_VERSION,
    config_hash: Optional[str] = None,
    corpus_kinds: Optional[list[str]] = None,
    sampling: Optional[dict[str, object]] = None,
    llm_settings: Optional[dict[str, object]] = None,
    code_version: Optional[dict[str, object]] = None,
    allow_code_change: bool = False,
    dry_run: bool = False,
    on_record: Optional[Callable[[EnrichmentRecord], None]] = None,
) -> EnrichmentRunSummary:
    """Run corpus-side enrichment over ``docs``, resuming from ``output_path``.

    ``client_factory`` is called once per worker (not once per document) --
    concurrency uses a thread per worker, and ``LLMClient``/``CallLog``
    scoping (``common/llm.py``) is not safe to share across threads (a
    ``CallLog`` fans every call out to every currently-open scope; two
    threads sharing one client would cross-attribute each other's token and
    latency counts). Giving each worker its own client/``CallLog`` avoids
    that entirely rather than working around it. ``concurrency=1`` (the
    default) never touches the thread pool at all.

    ``dry_run=True`` runs the full pipeline (so ``--dry-run`` in the CLI is a
    real cost/latency preview) but writes nothing to disk.

    ``record_json_failures=True`` turns an unparseable reply into a written
    record (one rejected term, ``reject_reason=llm_json_error``) instead of
    leaving the document unwritten. The default is False because "unwritten
    means retry next time" is the right behaviour for a transient failure --
    a dropped connection, a model still loading. It is the wrong behaviour
    for a deterministic one: at ``temperature=0`` the same prompt returns the
    same broken reply forever, so the document can never be finished and the
    run can never report completion. ``json_retries`` (with the nudge in
    ``prompts/corpus_side.py``) is tried first; this is what happens when
    that also fails.

    ``max_new_tokens`` and ``json_mode`` are **recorded, not applied** --
    ``client_factory`` owns how the client is built, and taking them here as
    well would give two places the power to set them and no way to tell which
    one won. They are parameters so the manifest can state what the run
    actually used, which is the thing a reader of the JSONL needs.

    ``sampling`` describes how ``docs`` was chosen (e.g. ``{"method":
    "per_kind", "per_kind": 10, "seed": 42}``) and is recorded in the
    manifest as-is. Without it, a JSONL of 40 documents cannot say whether
    it is the first 40 or a stratified 40, and conclusions drawn from the
    two are not interchangeable.

    ``max_doc_chars`` *is* applied: a document longer than this is shown to
    the model cut to that many characters (the record and the index keep the
    full text). The manifest lists which documents were cut, so "the model
    saw all of it" is never assumed.

    ``code_version`` (``common.repro.code_version()``) is recorded in the
    manifest as ``code`` and, on a resume, its ``code_commit`` must equal the
    one already there unless ``allow_code_change`` is set -- in which case the
    earlier version is kept under ``code_previous``.

    ``llm_settings`` is recorded in the manifest as-is under ``"llm"`` --
    the backend facts a reader needs that are not gates (provider, thinking
    configuration, seed and whether it was honoured). ``None`` writes nothing.
    """
    output_path = Path(output_path)
    docs = list(docs)
    summary = EnrichmentRunSummary(total_docs=len(docs))

    done: set[str] = set()
    if output_path.exists():
        for rec in read_jsonl(output_path):
            done.add(rec.doc_id)
    summary.already_done = len(done)

    pending = [d for d in docs if d.doc_id not in done]

    # One client up front: its model name is part of what a resume is checked
    # against, and the sequential path below reuses it.
    first_client = client_factory()
    model_name = first_client.model

    code_previous: list[object] = []

    def _manifest(*, write: bool, with_usage: bool) -> dict[str, object]:
        return _write_manifest(
            output_path,
            code=code_version,
            code_previous=code_previous,
            prompt_version=prompt_version,
            model=model_name,
            config_hash=config_hash,
            kinds=corpus_kinds or [],
            sampling=sampling,
            concurrency=concurrency,
            gates={
                "name_match_min_overlap": name_match_min_overlap,
                "name_scorer": name_scorer if name_match_min_overlap is not None else None,
                "name_match_min_jaccard": name_match_min_jaccard,
                "json_retries": json_retries,
                "record_json_failures": record_json_failures,
                "max_new_tokens": max_new_tokens,
                "json_mode": json_mode,
                "max_doc_chars": max_doc_chars,
                "truncation_version": TRUNCATION_VERSION if max_doc_chars is not None else None,
                "df_max_ratio": df_max_ratio,
                "allow_deprecated": allow_deprecated,
                "revoked_policy": str(revoked_policy),
            },
            # Over every document in the run, not just this invocation's, so
            # a resumed run's manifest is still complete.
            truncation=(
                None if max_doc_chars is None else _truncation_summary(docs, max_doc_chars)
            ),
            llm=llm_settings,
            usage=(
                {"llm_calls": summary.llm_calls, "tokens": summary.tokens.to_dict()}
                if llm_settings and with_usage else None
            ),
            write=write,
        )

    if not dry_run and pending:
        if done:
            # Appending to someone's earlier work: only under identical settings.
            previous = check_resume(
                output_path, _manifest(write=False, with_usage=False),
                allow_code_change=allow_code_change,
            )
            code_previous.extend(previous.get("code_previous") or [])  # type: ignore[arg-type]
            old_code = previous.get("code")
            if old_code and old_code != code_version and old_code not in code_previous:
                code_previous.append(old_code)
            # Rewritten now, so the change of code is on record even if this
            # session dies before it finishes a document.
            _manifest(write=True, with_usage=False)
        else:
            # Written before the first document, not only at the end, so a
            # run that dies part-way still leaves the manifest a resume needs.
            _manifest(write=True, with_usage=False)

    started = time.perf_counter()

    def _process_one(
        doc: CorpusDocument, client: LLMClient
    ) -> tuple[Optional[EnrichmentRecord], Optional[str], Optional[MalformedReplyError]]:
        before = len(client.log.records)
        json_error: Optional[MalformedReplyError] = None
        try:
            terms = propose_terms(
                doc,
                client,
                graph,
                df_lookup,
                max_terms=max_terms,
                df_max_ratio=df_max_ratio,
                allow_deprecated=allow_deprecated,
                revoked_policy=revoked_policy,
                name_match_min_overlap=name_match_min_overlap,
                name_scorer=name_scorer,
                name_match_min_jaccard=name_match_min_jaccard,
                json_retries=json_retries,
                max_doc_chars=max_doc_chars,
            )
        except MalformedReplyError as exc:
            if not record_json_failures:
                return None, f"{type(exc).__name__}: {exc}", exc
            # Write the document as permanently failed rather than leaving it
            # for a resume that would reproduce the same reply.
            json_error = exc
            terms = [_json_failure_term(exc)]
        except LLMError as exc:
            return None, f"{type(exc).__name__}: {exc}", None

        calls = client.log.records[before:]
        tokens = TokenUsage()
        for c in calls:
            tokens = tokens + c.tokens
        record = EnrichmentRecord(
            doc_id=doc.doc_id,
            source=doc.source,
            original_text=doc.text,
            proposed_terms=terms,
            llm_calls=len(calls),
            tokens=tokens,
            latency_ms=sum(c.latency_ms for c in calls),
            model=client.model,
            truncation=truncate_document(doc, max_doc_chars)[1],
        )
        return record, None, json_error

    def _handle(
        doc: CorpusDocument,
        record: Optional[EnrichmentRecord],
        error: Optional[str],
        json_error: Optional[MalformedReplyError] = None,
    ) -> None:
        if json_error is not None:
            summary.json_failures += 1
            if not dry_run:
                _append_raw(
                    output_path.with_suffix(output_path.suffix + ".raw_failures.jsonl"),
                    doc.doc_id,
                    json_error,
                )
        if error is not None:
            summary.failed += 1
            summary.failures.append((doc.doc_id, error))
            if not dry_run:
                failures_path = output_path.with_suffix(output_path.suffix + ".failures.jsonl")
                _append_failure(failures_path, doc.doc_id, error)
            return
        summary.processed += 1
        assert record is not None
        summary.llm_calls += record.llm_calls
        summary.tokens = summary.tokens + record.tokens
        if not dry_run:
            write_jsonl([record], output_path, append=True)
        if on_record is not None:
            on_record(record)

    if concurrency <= 1:
        client = first_client
        for doc in pending:
            record, error, json_error = _process_one(doc, client)
            _handle(doc, record, error, json_error)
    else:
        local = threading.local()
        model_holder: list[str] = []
        lock = threading.Lock()

        def _worker(
            doc: CorpusDocument,
        ) -> tuple[
            CorpusDocument,
            Optional[EnrichmentRecord],
            Optional[str],
            Optional[MalformedReplyError],
        ]:
            client = getattr(local, "client", None)
            if client is None:
                client = client_factory()
                local.client = client
                with lock:
                    if not model_holder:
                        model_holder.append(client.model)
            record, error, json_error = _process_one(doc, client)
            return doc, record, error, json_error

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            for doc, record, error, json_error in pool.map(_worker, pending):
                _handle(doc, record, error, json_error)

    summary.elapsed_s = time.perf_counter() - started

    if not dry_run and summary.processed:
        _manifest(write=True, with_usage=True)

    return summary


# -- summarising a finished (or in-progress) run -------------------------------------


def summarize(output_path: str | Path) -> dict[str, object]:
    """Accept/reject counts by ``reject_reason``, plus repair/staleness counts.

    Reads the JSONL rather than tracking counters during the run, so it can
    also summarise a previous run's output without re-enriching anything.
    """
    n_accepted = 0
    n_rejected = 0
    by_reason: dict[str, int] = {}
    n_repaired = 0
    staleness_num = 0
    staleness_den = 0

    for rec in read_jsonl(output_path):
        n_accepted += len(rec.accepted_terms)
        n_rejected += len(rec.rejected_terms)
        for t in rec.rejected_terms:
            reason = t.reject_reason.value if t.reject_reason else "unknown"
            by_reason[reason] = by_reason.get(reason, 0) + 1
        n_repaired += len(rec.repaired_terms)
        pool = rec.structural_terms
        staleness_den += len(pool)
        staleness_num += sum(
            1 for t in pool if t.repaired_from_id is not None or t.reject_reason is RejectReason.REVOKED
        )

    return {
        "accepted": n_accepted,
        "rejected": n_rejected,
        "rejected_by_reason": by_reason,
        "repaired": n_repaired,
        "staleness_rate": (staleness_num / staleness_den) if staleness_den else None,
    }


def summarize_by_source(output_path: str | Path) -> dict[str, dict[str, object]]:
    """The same counts as :func:`summarize`, split by the *source document's* type.

    Answers a different question from the whole-file totals: not "how often
    are proposals rejected" but "does what the model proposes depend on what
    it is reading". In particular ``structural_proposed_by_namespace`` shows
    which catalogue each structural proposal came from (``attack``, ``cwe``,
    ``capec``, or ``other`` for anything the normalizer doesn't place, such as
    a CVE id) -- so a run with zero ATT&CK proposals shows *which* source
    documents produced none, rather than one undifferentiated zero.
    """
    out: dict[str, dict[str, object]] = {}
    for rec in read_jsonl(output_path):
        s = out.setdefault(
            rec.source.value,
            {
                "docs": 0,
                "proposed": 0,
                "accepted": 0,
                "rejected_by_reason": {},
                "structural_proposed_by_namespace": {},
                "structural_accepted_by_namespace": {},
            },
        )
        s["docs"] += 1
        s["proposed"] += len(rec.proposed_terms)
        s["accepted"] += len(rec.accepted_terms)
        for t in rec.rejected_terms:
            reasons = s["rejected_by_reason"]
            reasons[t.reject_reason.value] = reasons.get(t.reject_reason.value, 0) + 1
        for t in rec.structural_terms:
            parsed = parse_structural_id(t.structural_id)
            ns = parsed.namespace.value if parsed is not None else "other"
            proposed = s["structural_proposed_by_namespace"]
            proposed[ns] = proposed.get(ns, 0) + 1
            if t.accepted:
                accepted = s["structural_accepted_by_namespace"]
                accepted[ns] = accepted.get(ns, 0) + 1
    return out
