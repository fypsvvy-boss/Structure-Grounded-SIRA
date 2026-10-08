"""Module 4 -- cost and latency per question (RQ3).

Reads the ``<run>.costs.jsonl`` sidecar Module 3 writes next to every run
(``docs/05_MODULE3_STATE.md`` on the ``sarthak`` branch), one row per
question::

    {"query_id": "rcm-001", "system": "sira_cti",
     "retrieval_calls": 1, "retrieval_ms": 12,
     "llm_calls": 1, "tokens": {"prompt": 812, "completion": 143},
     "llm_latency_ms": 1904, "expansion_terms": ["CWE-307", ...]}

File format only -- nothing is imported from ``sira_cti.retrieval``.

Online and offline cost are different things and are never added together
-------------------------------------------------------------------------
*Online* cost is what answering one question costs: the rows above.
*Offline* cost is corpus-side enrichment (Module 1) -- paid once per corpus,
before any question exists, and independent of how many questions are later
asked. :func:`offline_enrichment_cost` reports it on its own, and
:func:`amortise` divides it over a stated number of questions for anyone who
wants that figure; neither is ever folded into a per-question number here.

What the latency figures do and do not mean
-------------------------------------------
``total_ms`` is ``retrieval_ms + llm_latency_ms``. For SIRA-CTI, Module 3
copies the LLM half from the query-side enrichment record, which a separate
batch run produced: it is summed model time, not measured end-to-end wall
clock, and it excludes retry back-off (``common/llm.py`` times each attempt
on its own). A question whose enrichment reply was malformed has no record
at all, so its tokens are missing rather than zero. These are properties of
the inputs; :data:`CAVEATS` carries them into every results file.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from ..common.schemas import read_jsonl
from .runs import ERROR, WARNING, Issue, IssueLog, sidecar

CAVEATS = (
    "LLM latency for SIRA-CTI is copied by Module 3 from the query-side enrichment record: "
    "summed model time from a separate batch run, not end-to-end wall clock, and excluding retry back-off.",
    "A question or document whose enrichment reply was malformed has no enrichment record, "
    "so its LLM calls and tokens are absent from these figures rather than counted.",
    "Corpus-side enrichment is an offline, one-off cost. It is reported separately and is "
    "not included in any per-question figure.",
)

FIELDS = (
    "retrieval_calls",
    "retrieval_ms",
    "llm_calls",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "llm_latency_ms",
    "total_ms",
)


@dataclass(frozen=True)
class QueryCost:
    query_id: str
    system: str
    retrieval_calls: int = 0
    retrieval_ms: float = 0.0
    llm_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    llm_latency_ms: float = 0.0
    expansion_terms: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def total_ms(self) -> float:
        return self.retrieval_ms + self.llm_latency_ms


def _number(row: Mapping[str, Any], key: str) -> float:
    value = row[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{key}={value!r} is not a non-negative number")
    return value


def read_costs(path: str | Path) -> tuple[dict[str, QueryCost], list[Issue]]:
    """Parse a ``.costs.jsonl`` sidecar. Returns ``(query id -> cost, issues)``.

    Errors: ``malformed_cost_row`` (not an object, a missing field, a
    negative or non-numeric value), ``duplicate_cost_row`` (a question
    listed twice -- the first row is kept), ``mixed_systems``.
    """
    path = Path(path)
    log = IssueLog(str(path))
    costs: dict[str, QueryCost] = {}
    systems: set[str] = set()
    with path.open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("not a JSON object")
                tokens = row["tokens"]
                if not isinstance(tokens, dict):
                    raise ValueError("'tokens' is not an object")
                cost = QueryCost(
                    query_id=str(row["query_id"]),
                    system=str(row.get("system", "")),
                    retrieval_calls=int(_number(row, "retrieval_calls")),
                    retrieval_ms=_number(row, "retrieval_ms"),
                    llm_calls=int(_number(row, "llm_calls")),
                    prompt_tokens=int(_number(tokens, "prompt")),
                    completion_tokens=int(_number(tokens, "completion")),
                    llm_latency_ms=_number(row, "llm_latency_ms"),
                    expansion_terms=len(row.get("expansion_terms") or []),
                )
            except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
                detail = f"missing {exc}" if isinstance(exc, KeyError) else str(exc)
                log.add(ERROR, "malformed_cost_row", f"line {line_no}: {detail}")
                continue
            if cost.query_id in costs:
                log.add(ERROR, "duplicate_cost_row", cost.query_id)
                continue
            costs[cost.query_id] = cost
            systems.add(cost.system)
    if len(systems) > 1:
        log.add(ERROR, "mixed_systems", ", ".join(sorted(systems)))
    return costs, log.issues()


def read_costs_for_run(run_path: str | Path) -> tuple[Optional[dict[str, QueryCost]], list[Issue]]:
    """The costs sidecar of a run, or ``None`` with a warning if there is none."""
    path = sidecar(run_path, ".costs.jsonl")
    if not path.exists():
        return None, [Issue(WARNING, "no_costs", f"{path.name} not found -- no cost figures for this run", str(run_path))]
    return read_costs(path)


# -- distributions --------------------------------------------------------------------


def percentile(values: Sequence[float], p: float) -> Optional[float]:
    """Nearest-rank percentile: the smallest value with at least ``p``% of the data at or below it.

    ``sorted(values)[ceil(p/100 * n) - 1]``. Always one of the observed
    values (no interpolation), which is the honest choice for a latency
    tail measured on a few hundred questions.
    """
    if not 0 < p <= 100:
        raise ValueError(f"p must be in (0, 100], got {p}")
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(math.ceil(p / 100 * len(ordered)) - 1, 0)]


def median(values: Sequence[float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def distribution(values: Sequence[float]) -> dict[str, Optional[float]]:
    return {
        "mean": sum(values) / len(values) if values else None,
        "median": median(values),
        "p95": percentile(values, 95),
        "total": sum(values) if values else None,
    }


def summarise_costs(costs: Mapping[str, QueryCost], *, query_ids: Optional[Iterable[str]] = None) -> dict[str, Any]:
    """Per-question mean / median / p95 / total of every cost field.

    With ``query_ids`` (the questions being scored), only those are counted,
    and the ones with no cost row are listed under ``missing`` -- they are
    left out of the statistics, never counted as free.
    """
    wanted = sorted(costs) if query_ids is None else sorted(set(query_ids))
    rows = [costs[q] for q in wanted if q in costs]
    out: dict[str, Any] = {
        "n": len(rows),
        "missing": [q for q in wanted if q not in costs],
    }
    for name in FIELDS:
        out[name] = distribution([getattr(r, name) for r in rows])
    return out


def efficiency(quality: Mapping[str, Optional[float]], cost_summary: Mapping[str, Any]) -> dict[str, dict[str, Optional[float]]]:
    """Quality per unit of cost, for each metric (RQ3).

    ``quality`` is ``metric -> mean``; ``cost_summary`` is
    :func:`summarise_costs` output over the same questions.

    * ``per_llm_call``  mean metric / mean LLM calls per question
    * ``per_1k_tokens`` mean metric / (mean total tokens per question / 1000)
    * ``per_second``    mean metric / (mean ``total_ms`` per question / 1000)

    A ratio whose denominator is zero is ``None``, not infinity: plain BM25
    makes no LLM call, and "infinitely efficient per call" is not a result.
    """

    def ratio(value: Optional[float], denominator: Optional[float]) -> Optional[float]:
        return value / denominator if value is not None and denominator else None

    def mean_of(name: str, scale: float = 1.0) -> Optional[float]:
        m = cost_summary.get(name, {}).get("mean")
        return m / scale if m is not None else None

    calls, tokens_k, seconds = mean_of("llm_calls"), mean_of("total_tokens", 1000.0), mean_of("total_ms", 1000.0)
    return {
        name: {
            "per_llm_call": ratio(value, calls),
            "per_1k_tokens": ratio(value, tokens_k),
            "per_second": ratio(value, seconds),
        }
        for name, value in quality.items()
    }


# -- offline (corpus-side) cost, kept apart -------------------------------------------


def offline_enrichment_cost(path: str | Path) -> dict[str, Any]:
    """What an enrichment JSONL cost to produce, read from its own records.

    For corpus-side enrichment this is the offline, one-off cost. Also
    reports the sidecar manifest (prompt version, model, config hash,
    sampling) and how many documents failed -- those left no record, so
    their cost is not in these totals.
    """
    path = Path(path)
    calls: list[float] = []
    prompt: list[float] = []
    completion: list[float] = []
    latency: list[float] = []
    models: dict[str, int] = {}
    for rec in read_jsonl(path):
        calls.append(rec.llm_calls)
        prompt.append(rec.tokens.prompt)
        completion.append(rec.tokens.completion)
        latency.append(rec.latency_ms)
        models[rec.model] = models.get(rec.model, 0) + 1

    failures_path = sidecar(path, ".failures.jsonl")
    failures = 0
    if failures_path.exists():
        failures = sum(1 for line in failures_path.read_text(encoding="utf-8").splitlines() if line.strip())

    manifest_path = sidecar(path, ".manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else None

    return {
        "scope": "offline",
        "path": str(path),
        "records": len(calls),
        "failed_without_record": failures,
        "models": dict(sorted(models.items())),
        "manifest": manifest,
        "llm_calls": distribution(calls),
        "prompt_tokens": distribution(prompt),
        "completion_tokens": distribution(completion),
        "total_tokens": distribution([p + c for p, c in zip(prompt, completion)]),
        "llm_latency_ms": distribution(latency),
    }


def amortise(offline: Mapping[str, Any], n_queries: int) -> dict[str, Any]:
    """An offline cost spread over ``n_queries`` questions -- reported beside, not inside, online cost."""
    if n_queries < 1:
        raise ValueError(f"n_queries must be >= 1, got {n_queries}")

    def share(name: str) -> Optional[float]:
        total = offline[name]["total"]
        return total / n_queries if total is not None else None

    return {
        "n_queries": n_queries,
        "llm_calls": share("llm_calls"),
        "total_tokens": share("total_tokens"),
        "llm_latency_ms": share("llm_latency_ms"),
    }
