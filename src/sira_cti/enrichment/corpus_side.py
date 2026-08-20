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
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..common.llm import LLMClient, LLMError, parse_json_loose
from ..common.schemas import (
    EnrichmentRecord,
    ProposedTerm,
    RejectReason,
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

_VALID_KINDS = {k.value for k in TermKind}


class MalformedReplyError(RuntimeError):
    """The LLM's reply could not be trusted as a list of proposals.

    Raised instead of returning ``[]`` -- see the module docstring. Callers
    must record this as an explicit failure, not swallow it into a record.
    """


# -- reply parsing (structural validation is a separate step, below) ---------------


def _extract_proposals(parsed: object) -> list[tuple[str, str]]:
    """Strictly validate the *shape* of an already-JSON-parsed reply.

    Expects a list of ``{"term": str, "kind": <TermKind value>}``. Anything
    else -- wrong top-level type, a non-object item, a blank term, an
    unrecognised kind -- raises :class:`MalformedReplyError` for the whole
    reply. A genuinely empty reply (``[]``) is not malformed and returns
    ``[]`` unchanged: the model proposing nothing is a legitimate outcome,
    just not one this function should ever manufacture on its own.
    """
    if not isinstance(parsed, list):
        raise MalformedReplyError(f"expected a JSON array, got {type(parsed).__name__}: {parsed!r}")

    out: list[tuple[str, str]] = []
    for i, item in enumerate(parsed):
        if not isinstance(item, dict):
            raise MalformedReplyError(f"item {i} is not an object: {item!r}")
        term = item.get("term")
        kind = item.get("kind")
        if not isinstance(term, str) or not term.strip():
            raise MalformedReplyError(f"item {i} has no usable 'term': {item!r}")
        if kind not in _VALID_KINDS:
            raise MalformedReplyError(f"item {i} has an unrecognised 'kind' {kind!r}: {item!r}")
        out.append((term.strip(), kind))
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
) -> ProposedTerm:
    """Validate one structural proposal against the graph.

    ``term`` is normalised through ``normalize.py``'s parser as part of
    ``graph.validate()`` itself -- ``MALFORMED_ID`` *is* the "did not even
    parse" outcome, already a first-class :class:`RejectReason`. This
    function only re-parses when a repair occurs, to recover the pre-repair
    canonical id: :class:`~sira_cti.graph.ontology.ValidationResult`
    overwrites ``canonical_id`` with the replacement and does not carry the
    original alongside it.
    """
    result = graph.validate(term, allow_deprecated=allow_deprecated, revoked_policy=revoked_policy)

    if result.repaired:
        pre_repair = parse_structural_id(term)
        repaired_from = pre_repair.canonical if pre_repair is not None else term
        return ProposedTerm.repair(term, structural_id=result.canonical_id, repaired_from_id=repaired_from)

    if result.valid:
        return ProposedTerm.accept(term, TermKind.STRUCTURAL, structural_id=result.canonical_id)

    return ProposedTerm.reject(
        term, TermKind.STRUCTURAL, result.reject_reason, structural_id=result.canonical_id or term
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
        )

    if term.repaired_from_id is not None:
        return ProposedTerm.repair(
            term.term, structural_id=term.structural_id, repaired_from_id=term.repaired_from_id, doc_freq=doc_freq
        )
    return ProposedTerm.accept(term.term, term.kind, structural_id=term.structural_id, doc_freq=doc_freq)


# -- one document ---------------------------------------------------------------------


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
) -> list[ProposedTerm]:
    """The full per-document pipeline: prompt -> strict parse -> graph gate -> DF gate.

    Raises :class:`MalformedReplyError` if the reply cannot be trusted. Every
    model call goes through ``client.generate()`` (the instrumented wrapper) --
    never a direct call -- and JSON extraction reuses ``parse_json_loose``
    rather than a second parser.
    """
    prompt = build_prompt(doc, max_terms=max_terms)
    raw = client.generate(prompt, system=SYSTEM_PROMPT, tag="corpus_enrich")
    try:
        parsed = parse_json_loose(raw)
        proposals = _extract_proposals(parsed)
    except ValueError as exc:
        raise MalformedReplyError(f"{doc.doc_id}: {exc}") from exc

    terms: list[ProposedTerm] = []
    for term_text, kind_str in proposals[:max_terms]:
        kind = _route_kind(TermKind(kind_str), term_text)
        if kind is TermKind.STRUCTURAL:
            pt = _adjudicate_structural(
                term_text, graph, allow_deprecated=allow_deprecated, revoked_policy=revoked_policy
            )
        else:
            pt = ProposedTerm.accept(term_text, kind)
        terms.append(_apply_df_filter(pt, df_lookup, df_max_ratio=df_max_ratio))
    return terms


# -- the resumable, (optionally) concurrent driver -----------------------------------


@dataclass
class EnrichmentRunSummary:
    """What :func:`run_corpus_enrichment` did, for the CLI to print."""

    total_docs: int = 0
    already_done: int = 0
    processed: int = 0
    failed: int = 0
    elapsed_s: float = 0.0
    failures: list[tuple[str, str]] = field(default_factory=list)  # (doc_id, error)


def _append_failure(path: Path, doc_id: str, error: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"doc_id": doc_id, "error": error, "ts": time.time()}) + "\n")


def _write_manifest(
    output_path: Path, *, prompt_version: str, model: str, config_hash: Optional[str], kinds: list[str]
) -> None:
    manifest = {
        "prompt_version": prompt_version,
        "model": model,
        "config_hash": config_hash,
        "kinds": kinds,
        "created_at": time.time(),
    }
    output_path.with_suffix(output_path.suffix + ".manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )


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
    concurrency: int = 1,
    prompt_version: str = PROMPT_VERSION,
    config_hash: Optional[str] = None,
    corpus_kinds: Optional[list[str]] = None,
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
    started = time.perf_counter()
    model_name = ""

    def _process_one(doc: CorpusDocument, client: LLMClient) -> tuple[Optional[EnrichmentRecord], Optional[str]]:
        before = len(client.log.records)
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
            )
        except (MalformedReplyError, LLMError) as exc:
            return None, f"{type(exc).__name__}: {exc}"

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
        )
        return record, None

    def _handle(doc: CorpusDocument, record: Optional[EnrichmentRecord], error: Optional[str]) -> None:
        if error is not None:
            summary.failed += 1
            summary.failures.append((doc.doc_id, error))
            if not dry_run:
                failures_path = output_path.with_suffix(output_path.suffix + ".failures.jsonl")
                _append_failure(failures_path, doc.doc_id, error)
            return
        summary.processed += 1
        assert record is not None
        if not dry_run:
            write_jsonl([record], output_path, append=True)
        if on_record is not None:
            on_record(record)

    if concurrency <= 1:
        client = client_factory()
        model_name = client.model
        for doc in pending:
            record, error = _process_one(doc, client)
            _handle(doc, record, error)
    else:
        local = threading.local()
        model_holder: list[str] = []
        lock = threading.Lock()

        def _worker(doc: CorpusDocument) -> tuple[CorpusDocument, Optional[EnrichmentRecord], Optional[str]]:
            client = getattr(local, "client", None)
            if client is None:
                client = client_factory()
                local.client = client
                with lock:
                    if not model_holder:
                        model_holder.append(client.model)
            record, error = _process_one(doc, client)
            return doc, record, error

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            for doc, record, error in pool.map(_worker, pending):
                _handle(doc, record, error)
        model_name = model_holder[0] if model_holder else ""

    summary.elapsed_s = time.perf_counter() - started

    if not dry_run and summary.processed:
        _write_manifest(
            output_path,
            prompt_version=prompt_version,
            model=model_name,
            config_hash=config_hash,
            kinds=corpus_kinds or [],
        )

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
