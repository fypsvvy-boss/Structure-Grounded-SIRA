"""Shared builders for the Module 4 (evaluation) tests.

Kept apart from ``helpers.py`` (Module 1's, which Module 3's branch also
edits) so the three sets of tests cannot collide in a merge.

``tests/fixtures/cticonnect/qa/`` is a hand-written miniature of CTIConnect's
``data/`` directory -- same layout, same row fields, one or two rows per
task -- whose gold ids point at the entries in ``tests/fixtures/corpus_kb``.
(The directory is not called ``data`` because ``.gitignore`` ignores every
directory of that name.)

The run-file writers here produce the three files Module 3's runner writes
(``docs/05_MODULE3_STATE.md``), from plain data: the evaluation code is
tested against the documented file formats, never against Module 3's
classes.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from helpers import CORPUS_KB_FIXTURE, FIXTURES

from sira_cti.index import load_corpus

QA_FIXTURE = FIXTURES / "cticonnect" / "qa"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "configs" / "default.yaml"


def fixture_doc_ids() -> set[str]:
    return {doc.doc_id for doc in load_corpus(CORPUS_KB_FIXTURE)}


def load_script(name: str):
    """Import ``scripts/<name>.py`` as a module, so a test can call its ``main(argv)``."""
    spec = importlib.util.spec_from_file_location(f"scripts_{name}", REPO_ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeOverlapRetriever:
    """A stand-in retrieval system: rank entries by how many words they share with the question.

    No index, no model, no randomness. Ties break on doc id, so the same
    question always gives the same list.
    """

    name = "fake_overlap"

    def __init__(self) -> None:
        self._docs = {doc.doc_id: self._words(doc.text) for doc in load_corpus(CORPUS_KB_FIXTURE)}

    @staticmethod
    def _words(text: str) -> set[str]:
        return set(re.findall(r"[a-z0-9]+", text.lower()))

    def retrieve(self, query: str, k: int = 100) -> list[tuple[str, float]]:
        words = self._words(query)
        scored = [(doc_id, float(len(words & doc_words))) for doc_id, doc_words in self._docs.items()]
        ranked = sorted((s for s in scored if s[1] > 0), key=lambda s: (-s[1], s[0]))
        return ranked[:k]


def cost_row(query_id: str, system: str, *, llm_calls: int = 0, prompt: int = 0, completion: int = 0,
             llm_latency_ms: int = 0, retrieval_calls: int = 1, retrieval_ms: int = 10,
             expansion_terms: Sequence[str] = ()) -> dict[str, Any]:
    """One line of ``<run>.costs.jsonl``, in the shape Module 3 documents."""
    return {
        "query_id": query_id,
        "system": system,
        "retrieval_calls": retrieval_calls,
        "retrieval_ms": retrieval_ms,
        "llm_calls": llm_calls,
        "tokens": {"prompt": prompt, "completion": completion},
        "llm_latency_ms": llm_latency_ms,
        "expansion_terms": list(expansion_terms),
    }


def write_module3_run(
    path: Path,
    system: str,
    rankings: Mapping[str, Sequence[tuple[str, float]]],
    *,
    costs: Optional[Sequence[Mapping[str, Any]]] = None,
    manifest: Optional[Mapping[str, Any]] = None,
    config_hash: str = "test-hash",
) -> Path:
    """Write a TREC run plus its ``.costs.jsonl`` and ``.manifest.json`` sidecars.

    ``manifest`` entries override the defaults. ``costs=None`` writes no
    costs sidecar; a test that needs the manifest absent deletes it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for query_id, hits in rankings.items():
            for rank, (doc_id, score) in enumerate(hits, start=1):
                fh.write(f"{query_id} Q0 {doc_id} {rank} {score:.6f} {system}\n")

    if costs is not None:
        with path.with_suffix(path.suffix + ".costs.jsonl").open("w", encoding="utf-8") as fh:
            for row in costs:
                fh.write(json.dumps(row) + "\n")

    body: dict[str, Any] = {
        "system": system,
        "queries_path": "queries.all.jsonl",
        "enrichment_path": None,
        "index_dir": "indexes/base",
        "index_manifest": {"kind": "base", "config_hash": config_hash},
        "settings": {"k": 100, "k1": 0.9, "b": 0.4},
        "totals": {"questions": len(rankings)},
        "config_hash": config_hash,
        "created_at": 0.0,
    }
    body.update(manifest or {})
    path.with_suffix(path.suffix + ".manifest.json").write_text(json.dumps(body, indent=2), encoding="utf-8")
    return path
