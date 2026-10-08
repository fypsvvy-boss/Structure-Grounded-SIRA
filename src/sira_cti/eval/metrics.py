"""Module 4 -- retrieval quality metrics (RQ2), with uncertainty.

Recall@k and NDCG@k per question, means over any grouping of questions, a
bootstrap confidence interval for a mean, and a paired randomisation test
for the difference between two systems on the same questions.

Pure standard library and fully deterministic: every random draw comes from
a ``random.Random`` seeded by the caller, so a results file can be
reproduced exactly from its inputs and its recorded seed.

Definitions (they match ``trec_eval``'s ``recall_<k>`` and ``ndcg_cut_<k>``):

* ``recall@k`` -- relevant documents in the top ``k``, divided by *all*
  relevant documents of the question;
* ``ndcg@k``   -- ``DCG@k / IDCG@k`` with linear gain (the relevance grade)
  and a ``log2(rank + 1)`` discount; the ideal ranking is the question's
  relevant documents in decreasing grade.

Two deliberate differences from running ``trec_eval`` on the same files:

* **Rankings are taken in the order the system returned them.** ``trec_eval``
  re-sorts by score and breaks ties on doc id, discarding the rank column;
  rank-fused lists (synthesis, the agent baseline) do contain ties.
  :mod:`sira_cti.eval.runs` checks that rank and score agree.
* **A question the system returned nothing for scores zero.** ``trec_eval``
  averages over the questions present in the run, which would let a system
  improve its mean by failing to answer.

A question with no relevant document in the qrels is skipped, as in
``trec_eval``: every metric here is undefined for it.
"""

from __future__ import annotations

import itertools
import math
import random
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence

DEFAULT_METRICS = ("recall@1", "recall@10", "recall@100", "ndcg@10")

PerQuery = dict[str, dict[str, float]]
"""``query id -> metric name -> value``."""


def parse_metric(name: str) -> tuple[str, int]:
    """``"recall@10"`` -> ``("recall", 10)``. The names are ``eval.metrics`` in the config."""
    kind, sep, cutoff = name.strip().lower().partition("@")
    if sep and kind in ("recall", "ndcg") and cutoff.isdigit() and int(cutoff) >= 1:
        return kind, int(cutoff)
    raise ValueError(f"unknown metric {name!r}; expected recall@<k> or ndcg@<k>")


def _relevant(grades: Mapping[str, int]) -> dict[str, int]:
    return {doc_id: grade for doc_id, grade in grades.items() if grade > 0}


def recall_at_k(ranking: Sequence[str], grades: Mapping[str, int], k: int) -> float:
    relevant = _relevant(grades)
    if not relevant:
        raise ValueError("recall is undefined for a question with no relevant document")
    return len(set(ranking[:k]) & relevant.keys()) / len(relevant)


def ndcg_at_k(ranking: Sequence[str], grades: Mapping[str, int], k: int) -> float:
    relevant = _relevant(grades)
    if not relevant:
        raise ValueError("NDCG is undefined for a question with no relevant document")
    dcg = sum(relevant.get(doc_id, 0) / math.log2(rank + 1) for rank, doc_id in enumerate(ranking[:k], start=1))
    ideal = sorted(relevant.values(), reverse=True)[:k]
    idcg = sum(grade / math.log2(rank + 1) for rank, grade in enumerate(ideal, start=1))
    return dcg / idcg


_METRIC_FUNCTIONS = {"recall": recall_at_k, "ndcg": ndcg_at_k}


def per_query_metrics(
    rankings: Mapping[str, Sequence[str]],
    qrels: Mapping[str, Mapping[str, int]],
    metrics: Sequence[str] = DEFAULT_METRICS,
) -> PerQuery:
    """Score every question in ``qrels``; one missing from ``rankings`` scores zero."""
    parsed = [(name, *parse_metric(name)) for name in metrics]
    out: PerQuery = {}
    for query_id, grades in qrels.items():
        if not _relevant(grades):
            continue
        ranking = rankings.get(query_id, ())
        out[query_id] = {name: _METRIC_FUNCTIONS[kind](ranking, grades, k) for name, kind, k in parsed}
    return out


def mean(values: Sequence[float]) -> Optional[float]:
    """Arithmetic mean, or ``None`` for no values -- an empty group is not a zero."""
    return sum(values) / len(values) if values else None


# -- uncertainty ----------------------------------------------------------------------


def bootstrap_ci(
    values: Sequence[float], *, n_resamples: int = 1000, alpha: float = 0.05, seed: int = 42
) -> tuple[Optional[float], Optional[float]]:
    """Percentile-bootstrap confidence interval for the mean of ``values``.

    Resamples the questions with replacement ``n_resamples`` times and takes
    the ``alpha/2`` and ``1 - alpha/2`` quantiles of the resampled means
    (sorted means ``m``: ``m[floor(alpha/2 * B)]`` and
    ``m[ceil((1 - alpha/2) * B) - 1]``). ``(None, None)`` for no values.
    """
    if n_resamples < 1:
        raise ValueError(f"n_resamples must be >= 1, got {n_resamples}")
    if not 0.0 < alpha < 1.0:
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")
    n = len(values)
    if n == 0:
        return None, None
    rng = random.Random(seed)
    means = sorted(sum(values[rng.randrange(n)] for _ in range(n)) / n for _ in range(n_resamples))
    lo = min(int(math.floor(alpha / 2 * n_resamples)), n_resamples - 1)
    hi = max(int(math.ceil((1 - alpha / 2) * n_resamples)) - 1, 0)
    return means[lo], means[hi]


@dataclass(frozen=True)
class RandomisationResult:
    mean_diff: Optional[float]   # mean(a) - mean(b) over the paired questions
    p_value: Optional[float]     # two-sided
    n: int
    method: str                  # "exact" | "monte_carlo" | "none"

    def to_dict(self) -> dict[str, Any]:
        return {"mean_diff": self.mean_diff, "p_value": self.p_value, "n": self.n, "method": self.method}


_EPS = 1e-12


def paired_randomisation_test(
    a: Sequence[float], b: Sequence[float], *, n_resamples: int = 10000, seed: int = 42
) -> RandomisationResult:
    """Two-sided paired randomisation (sign-flip) test on per-question scores.

    Null hypothesis: the two systems are interchangeable on every question,
    so each paired difference ``a_i - b_i`` is as likely to carry either
    sign. The p-value is the share of sign assignments whose absolute mean
    difference is at least the observed one.

    When all ``2**n`` assignments number no more than ``n_resamples`` they
    are enumerated and the p-value is exact. Otherwise ``n_resamples``
    random assignments are drawn and ``p = (hits + 1) / (n_resamples + 1)``,
    which counts the observed assignment so the estimate is never zero.
    """
    if len(a) != len(b):
        raise ValueError(f"paired test needs equal-length score lists, got {len(a)} and {len(b)}")
    if n_resamples < 1:
        raise ValueError(f"n_resamples must be >= 1, got {n_resamples}")
    diffs = [x - y for x, y in zip(a, b)]
    n = len(diffs)
    if n == 0:
        return RandomisationResult(None, None, 0, "none")

    observed = sum(diffs) / n
    threshold = abs(observed) - _EPS

    if 2**n <= n_resamples:
        hits = sum(
            1
            for signs in itertools.product((1, -1), repeat=n)
            if abs(sum(s * d for s, d in zip(signs, diffs)) / n) >= threshold
        )
        return RandomisationResult(observed, hits / 2**n, n, "exact")

    rng = random.Random(seed)
    hits = 0
    for _ in range(n_resamples):
        total = sum(d if rng.random() < 0.5 else -d for d in diffs)
        if abs(total / n) >= threshold:
            hits += 1
    return RandomisationResult(observed, (hits + 1) / (n_resamples + 1), n, "monte_carlo")


# -- aggregation ----------------------------------------------------------------------


def _summarise_group(
    per_query: PerQuery, query_ids: Sequence[str], metrics: Sequence[str], *, n_resamples: int, alpha: float, seed: int
) -> dict[str, Any]:
    out: dict[str, Any] = {"n": len(query_ids)}
    for name in metrics:
        values = [per_query[q][name] for q in query_ids]
        lo, hi = bootstrap_ci(values, n_resamples=n_resamples, alpha=alpha, seed=seed)
        out[name] = {"mean": mean(values), "ci_low": lo, "ci_high": hi}
    return out


def summarise(
    per_query: PerQuery,
    *,
    groupings: Optional[Mapping[str, Mapping[str, str]]] = None,
    metrics: Sequence[str] = DEFAULT_METRICS,
    n_resamples: int = 1000,
    alpha: float = 0.05,
    seed: int = 42,
) -> dict[str, Any]:
    """Means with confidence intervals: overall, and within each grouping.

    ``groupings`` maps a grouping name to ``query id -> group`` -- for
    example ``{"task": {...}, "category": {...}}``. The result has
    ``"overall"`` plus ``"by_<name>"`` for each. A question absent from a
    grouping's mapping is collected under ``"(unknown)"`` rather than
    dropped, so the groups of a grouping always sum to the overall count.
    """
    query_ids = sorted(per_query)
    kwargs = {"n_resamples": n_resamples, "alpha": alpha, "seed": seed}
    out: dict[str, Any] = {"overall": _summarise_group(per_query, query_ids, metrics, **kwargs)}
    for name, mapping in (groupings or {}).items():
        groups: dict[str, list[str]] = {}
        for q in query_ids:
            groups.setdefault(mapping.get(q, "(unknown)"), []).append(q)
        out[f"by_{name}"] = {
            group: _summarise_group(per_query, ids, metrics, **kwargs) for group, ids in sorted(groups.items())
        }
    return out


def compare(
    per_query_a: PerQuery,
    per_query_b: PerQuery,
    *,
    metrics: Sequence[str] = DEFAULT_METRICS,
    n_resamples: int = 10000,
    seed: int = 42,
) -> dict[str, dict[str, Any]]:
    """The paired test for each metric, over the questions both systems were scored on."""
    shared = sorted(per_query_a.keys() & per_query_b.keys())
    return {
        name: paired_randomisation_test(
            [per_query_a[q][name] for q in shared],
            [per_query_b[q][name] for q in shared],
            n_resamples=n_resamples,
            seed=seed,
        ).to_dict()
        for name in metrics
    }


def group_of(metadata: Mapping[str, Mapping[str, Any]], key: str) -> dict[str, str]:
    """``query id -> metadata[key]`` for the rows that have it (see ``summarise``)."""
    return {q: str(row[key]) for q, row in metadata.items() if row.get(key) not in (None, "")}


def metric_names(names: Optional[Iterable[str]]) -> tuple[str, ...]:
    """Validate a configured metric list; ``None`` means the defaults."""
    out = tuple(n.strip().lower() for n in names) if names else DEFAULT_METRICS
    for n in out:
        parse_metric(n)
    return out
