"""Module 4 -- evaluation, cost analysis and the enrichment audit.

Consumes files only: CTIConnect QA rows, the TREC run / costs / manifest
files Module 3's runner writes, and enrichment JSONL. Nothing here imports
``sira_cti.retrieval`` or calls a model.
"""

from .audit import audit_file, audit_records, classify_reason
from .cost import QueryCost, amortise, efficiency, offline_enrichment_cost, read_costs, summarise_costs
from .cticonnect import (
    Benchmark,
    BlockedItem,
    QAItem,
    load_qa,
    read_metadata,
    read_qrels,
    split_dev_test,
    write_benchmark,
)
from .metrics import (
    DEFAULT_METRICS,
    bootstrap_ci,
    ndcg_at_k,
    paired_randomisation_test,
    per_query_metrics,
    recall_at_k,
    summarise,
)
from .report import evaluate, render_markdown, write_results
from .runs import Issue, Run, check_consistency, read_run

__all__ = [
    "audit_file",
    "audit_records",
    "classify_reason",
    "QueryCost",
    "amortise",
    "efficiency",
    "offline_enrichment_cost",
    "read_costs",
    "summarise_costs",
    "Benchmark",
    "BlockedItem",
    "QAItem",
    "load_qa",
    "read_metadata",
    "read_qrels",
    "split_dev_test",
    "write_benchmark",
    "DEFAULT_METRICS",
    "bootstrap_ci",
    "ndcg_at_k",
    "paired_randomisation_test",
    "per_query_metrics",
    "recall_at_k",
    "summarise",
    "evaluate",
    "render_markdown",
    "write_results",
    "Issue",
    "Run",
    "check_consistency",
    "read_run",
]
