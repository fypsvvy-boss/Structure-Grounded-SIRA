"""Module 4 -- reading and validating the run files Module 3 writes.

Module 3's runner (``scripts/run_retrieval.py`` on the ``sarthak`` branch,
described in ``docs/05_MODULE3_STATE.md``) writes three files per run:

* ``<run>``                 six-column TREC run:
                            ``<query id> Q0 <doc id> <rank> <score> <system>``
* ``<run>.costs.jsonl``     one cost row per question (:mod:`sira_cti.eval.cost`)
* ``<run>.manifest.json``   ``system``, ``settings``, ``index_manifest``,
                            ``config_hash``, ``queries_path``, ...

This module depends on those **file formats only**. It imports nothing from
``sira_cti.retrieval``: that package is on an unmerged branch, and a harness
that scores a system by importing it could not score a run produced
anywhere else.

Nothing here raises on bad content. Every problem becomes an :class:`Issue`
so one pass reports everything wrong with a file, and the caller decides
whether an ``error`` is fatal. A malformed line is reported and skipped,
never repaired.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

ERROR = "error"
WARNING = "warning"

_MAX_EXAMPLES = 5


@dataclass(frozen=True)
class Issue:
    severity: str   # ERROR | WARNING
    code: str
    message: str
    where: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"severity": self.severity, "code": self.code, "message": self.message, "where": self.where}


class IssueLog:
    """Collects problems by code; reports a count and the first few examples of each."""

    def __init__(self, where: str = "") -> None:
        self.where = where
        self._found: dict[tuple[str, str], list[str]] = {}

    def add(self, severity: str, code: str, detail: str) -> None:
        self._found.setdefault((severity, code), []).append(detail)

    def issues(self) -> list[Issue]:
        out = []
        for (severity, code), details in self._found.items():
            shown = "; ".join(details[:_MAX_EXAMPLES])
            more = f" (+{len(details) - _MAX_EXAMPLES} more)" if len(details) > _MAX_EXAMPLES else ""
            out.append(Issue(severity, code, f"{len(details)}x: {shown}{more}", self.where))
        return out


def errors(issues: Iterable[Issue]) -> list[Issue]:
    return [i for i in issues if i.severity == ERROR]


@dataclass(frozen=True)
class RunHit:
    doc_id: str
    rank: int
    score: float


@dataclass
class Run:
    path: str
    system: Optional[str] = None
    rankings: dict[str, list[RunHit]] = field(default_factory=dict)
    manifest: Optional[dict[str, Any]] = None
    issues: list[Issue] = field(default_factory=list)

    @property
    def query_ids(self) -> set[str]:
        return set(self.rankings)

    def doc_rankings(self) -> dict[str, list[str]]:
        """``query id -> doc ids in rank order``, the shape the metrics take."""
        return {q: [h.doc_id for h in hits] for q, hits in self.rankings.items()}


def sidecar(run_path: str | Path, suffix: str) -> Path:
    """``runs/sira.trec`` + ``.costs.jsonl`` -> ``runs/sira.trec.costs.jsonl``."""
    run_path = Path(run_path)
    return run_path.with_suffix(run_path.suffix + suffix)


_MANIFEST_KEYS = ("system", "settings", "index_manifest", "config_hash")


def read_run_manifest(run_path: str | Path, log: Optional[IssueLog] = None) -> Optional[dict[str, Any]]:
    log = log if log is not None else IssueLog(str(run_path))
    path = sidecar(run_path, ".manifest.json")
    if not path.exists():
        log.add(WARNING, "no_manifest", f"{path.name} not found -- this run's provenance is unknown")
        return None
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        log.add(ERROR, "malformed_manifest", f"{path.name}: {exc}")
        return None
    if not isinstance(manifest, dict):
        log.add(ERROR, "malformed_manifest", f"{path.name}: not a JSON object")
        return None
    for key in _MANIFEST_KEYS:
        if manifest.get(key) in (None, ""):
            log.add(WARNING, "manifest_field_missing", key)
    return manifest


def read_run(
    path: str | Path,
    *,
    known_query_ids: Optional[Iterable[str]] = None,
    known_doc_ids: Optional[Iterable[str]] = None,
) -> Run:
    """Parse one TREC run and its manifest, checking it as it goes.

    Errors (the run cannot be trusted as written):

    ``malformed_line``     not six columns, or a rank/score that is not a number
    ``duplicate_doc``      a document listed twice for one question
    ``duplicate_rank``     two documents at one rank for one question
    ``rank_gap``           a question's ranks are not exactly ``1..n``
    ``score_order``        a lower-ranked document has a higher score
    ``mixed_systems``      more than one system tag in the file
    ``unknown_doc``        a doc id that is not in the corpus (needs ``known_doc_ids``)
    ``empty_run``          no usable line at all
    ``manifest_system_mismatch``  the manifest names a different system

    Warnings (worth knowing, not wrong in themselves):

    ``missing_query``      a question in the qrels with no line in the run --
                           scored as zero by :mod:`sira_cti.eval.metrics`
    ``extra_query``        a question in the run but not in the qrels -- ignored
                           (expected when a run over all questions is scored
                           on one split)
    ``no_manifest`` / ``manifest_field_missing``
    """
    path = Path(path)
    log = IssueLog(str(path))
    run = Run(path=str(path))

    systems: dict[str, int] = {}
    raw: dict[str, list[RunHit]] = {}
    with path.open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            cols = line.split()
            if len(cols) != 6:
                log.add(ERROR, "malformed_line", f"line {line_no}: {len(cols)} columns, expected 6")
                continue
            query_id, _q0, doc_id, rank_s, score_s, system = cols
            try:
                rank = int(rank_s)
                score = float(score_s)
            except ValueError:
                log.add(ERROR, "malformed_line", f"line {line_no}: rank {rank_s!r} / score {score_s!r} not numeric")
                continue
            if rank < 1 or not math.isfinite(score):
                log.add(ERROR, "malformed_line", f"line {line_no}: rank {rank} / score {score_s} out of range")
                continue
            systems[system] = systems.get(system, 0) + 1
            raw.setdefault(query_id, []).append(RunHit(doc_id, rank, score))

    if not raw:
        log.add(ERROR, "empty_run", "no usable ranked line")
    if len(systems) > 1:
        log.add(ERROR, "mixed_systems", ", ".join(f"{s} ({n} lines)" for s, n in sorted(systems.items())))
    if systems:
        run.system = max(sorted(systems), key=lambda s: systems[s])

    known_docs = set(known_doc_ids) if known_doc_ids is not None else None
    for query_id, hits in raw.items():
        seen_docs: set[str] = set()
        kept: list[RunHit] = []
        for hit in hits:
            if hit.doc_id in seen_docs:
                log.add(ERROR, "duplicate_doc", f"{query_id}: {hit.doc_id}")
                continue
            seen_docs.add(hit.doc_id)
            kept.append(hit)
            if known_docs is not None and hit.doc_id not in known_docs:
                log.add(ERROR, "unknown_doc", f"{query_id}: {hit.doc_id}")

        kept.sort(key=lambda h: h.rank)
        ranks = [h.rank for h in kept]
        if len(set(ranks)) != len(ranks):
            log.add(ERROR, "duplicate_rank", query_id)
        elif ranks != list(range(1, len(ranks) + 1)):
            log.add(ERROR, "rank_gap", f"{query_id}: ranks {ranks[0]}..{ranks[-1]} over {len(ranks)} lines")
        if any(later.score > earlier.score for earlier, later in zip(kept, kept[1:])):
            log.add(ERROR, "score_order", query_id)
        run.rankings[query_id] = kept

    if known_query_ids is not None:
        known = set(known_query_ids)
        for query_id in sorted(known - run.query_ids):
            log.add(WARNING, "missing_query", query_id)
        for query_id in sorted(run.query_ids - known):
            log.add(WARNING, "extra_query", query_id)

    run.manifest = read_run_manifest(path, log)
    if run.manifest and run.system and run.manifest.get("system") not in (None, "", run.system):
        log.add(ERROR, "manifest_system_mismatch", f"run says {run.system!r}, manifest says {run.manifest['system']!r}")

    run.issues = log.issues()
    return run


def _settings(run: Run) -> Mapping[str, Any]:
    settings = (run.manifest or {}).get("settings")
    return settings if isinstance(settings, dict) else {}


def check_consistency(runs: Sequence[Run], *, config_hash: Optional[str] = None) -> list[Issue]:
    """Checks across runs -- are these systems actually comparable?

    ``duplicate_system`` (error)        two run files carry the same system name
    ``config_hash_mismatch`` (error)    the runs were produced under different configs
    ``config_hash_differs_from_eval`` (warning)  the config now on disk is not the
                                        one the runs were produced under
    ``queries_path_mismatch`` (warning) the runs read different query files
    ``k_mismatch`` (warning)            the runs kept different numbers of results
    ``query_set_mismatch`` (warning)    the runs do not cover the same questions
    """
    log = IssueLog("across runs")

    by_system: dict[str, list[str]] = {}
    for run in runs:
        by_system.setdefault(run.system or "(unnamed)", []).append(run.path)
    for system, paths in sorted(by_system.items()):
        if len(paths) > 1:
            log.add(ERROR, "duplicate_system", f"{system}: {', '.join(paths)}")

    def disagreement(values: dict[str, Any]) -> Optional[str]:
        """The values that were stated, spelled out, if they are not all the same."""
        present = {name: v for name, v in values.items() if v not in (None, "")}
        if len({json.dumps(v, sort_keys=True) for v in present.values()}) > 1:
            return ", ".join(f"{name}={v}" for name, v in sorted(present.items()))
        return None

    names = {run.path: run.system or run.path for run in runs}
    hashes = {names[r.path]: (r.manifest or {}).get("config_hash") for r in runs}
    if (detail := disagreement(hashes)) is not None:
        log.add(ERROR, "config_hash_mismatch", detail)
    elif config_hash is not None:
        differing = sorted(name for name, h in hashes.items() if h not in (None, "", config_hash))
        if differing:
            log.add(WARNING, "config_hash_differs_from_eval", f"eval config {config_hash}; runs: {', '.join(differing)}")

    if (detail := disagreement({names[r.path]: (r.manifest or {}).get("queries_path") for r in runs})):
        log.add(WARNING, "queries_path_mismatch", detail)
    if (detail := disagreement({names[r.path]: _settings(r).get("k") for r in runs})):
        log.add(WARNING, "k_mismatch", detail)

    if runs:
        union = set().union(*(r.query_ids for r in runs))
        for run in runs:
            missing = len(union - run.query_ids)
            if missing:
                log.add(WARNING, "query_set_mismatch", f"{names[run.path]} lacks {missing} question(s) other runs have")

    return log.issues()
