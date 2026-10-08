"""Module 4 -- CTIConnect QA rows as a retrieval benchmark.

CTIConnect ships question/answer rows, not a retrieval test collection: there
is no query file and there are no qrels. This module derives both, so the
same questions can be handed to every retrieval system and scored with one
harness:

* a **query file** in the shape Module 3's runner reads
  (``docs/05_MODULE3_STATE.md`` on the ``sarthak`` branch): JSONL, one
  ``{"id": ..., "query": ...}`` per line;
* **TREC qrels** (``<query id> 0 <doc id> <relevance>``), where the relevant
  documents of a question are the knowledge-base entries its
  ``ground_truth`` names;
* a **metadata** file keeping ``task`` / ``category`` / ``eval_type`` per
  question, so results can be broken down the way the benchmark is organised.

Scoring a question by whether its gold *entry* is retrieved is this project's
reframing. CTIConnect itself scores the identifiers in a generated answer
(precision / recall / F1); that difference belongs in the write-up.

Row shape assumed (CTIConnect README; **verify against the cloned repo** --
``data/README.md`` calls this the project's highest-impact unknown)::

    {"id": "rcm-001", "task": "rcm", "category": "entity_linking",
     "eval_type": "single_id_match", "question": "...", "answer": "...",
     "ground_truth": {"target_type": "cwe", "target_id": "CWE-384",
                      "valid_target_ids": [...]},          # optional list
     "source": {"source_type": "cve", "source_id": "CVE-2018-1000519"}}

A row that does not fit is never guessed at. A structurally broken row raises
with its file and line; a row this module cannot turn into qrels is kept as a
:class:`BlockedItem` with the reason, and is left out of the query file and
the qrels.

Multi-document synthesis is blocked on purpose
-----------------------------------------------
CSC / TAP / MLA rows carry ``eval_type: "judge"``: a free-text answer scored
by an LLM judge, over vendor reports that are not in the index Module 1
builds (``corpus.kinds`` is cve/cwe/capec/mitre). There is no gold document
to put in a qrels file, and the README's "entity/answer coverage" metric has
no agreed definition yet. Until the team decides one, those rows are reported
as blocked (``BLOCKED_SYNTHESIS``) and no number is produced for them.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

Qrels = dict[str, dict[str, int]]
"""``query id -> doc id -> relevance grade`` (grades here are always 1)."""

SCOREABLE_EVAL_TYPES = ("single_id_match", "id_set_match")
JUDGE_EVAL_TYPE = "judge"
SYNTHESIS_CATEGORY = "multi_doc_synthesis"

BLOCKED_SYNTHESIS = "synthesis_scoring_undefined"
BLOCKED_EVAL_TYPE = "unsupported_eval_type"
BLOCKED_NO_GOLD = "no_gold_target"

SPLITS = ("all", "dev", "test")

# Mirrors sira_cti.index.corpus._canonical_id, so a gold id and the doc id of
# the entry it names are spelled the same way. "mitre" is corpus_kb's name
# for the ATT&CK file; "attack" is the name the rest of this project uses.
_ID_PREFIX = {"cve": "CVE-", "cwe": "CWE-", "capec": "CAPEC-"}
_ATTACK_TYPES = {"attack", "mitre", "technique"}


@dataclass(frozen=True)
class QAItem:
    """One question that can be scored as retrieval."""

    query_id: str
    query: str
    task: str
    category: str
    eval_type: str
    gold_ids: tuple[str, ...]
    target_type: str = ""
    source_type: str = ""
    source_id: str = ""

    def query_row(self) -> dict[str, str]:
        """One line of the query file Module 3's runner reads."""
        return {"id": self.query_id, "query": self.query}

    def metadata_row(self, split: str) -> dict[str, Any]:
        return {
            "id": self.query_id,
            "task": self.task,
            "category": self.category,
            "eval_type": self.eval_type,
            "target_type": self.target_type,
            "gold_ids": list(self.gold_ids),
            "source_type": self.source_type,
            "source_id": self.source_id,
            "split": split,
        }


@dataclass(frozen=True)
class BlockedItem:
    """A question that is in the benchmark but cannot be scored here, and why."""

    query_id: str
    task: str
    category: str
    eval_type: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.query_id,
            "task": self.task,
            "category": self.category,
            "eval_type": self.eval_type,
            "reason": self.reason,
        }


@dataclass
class Benchmark:
    items: list[QAItem] = field(default_factory=list)
    blocked: list[BlockedItem] = field(default_factory=list)

    def qrels(self, items: Optional[Iterable[QAItem]] = None) -> Qrels:
        return {i.query_id: {d: 1 for d in i.gold_ids} for i in (self.items if items is None else items)}


def canonical_doc_id(target_type: str, raw: str) -> str:
    """Spell a gold id the way :mod:`sira_cti.index.corpus` spells doc ids.

    An unrecognised ``target_type`` leaves the id as written rather than
    guessing a prefix for it.
    """
    raw = str(raw).strip()
    kind = (target_type or "").strip().lower()
    if kind in _ATTACK_TYPES:
        return f"T{raw}" if raw[:1].isdigit() else raw
    prefix = _ID_PREFIX.get(kind)
    if prefix is None or raw.upper().startswith(prefix):
        return raw
    return f"{prefix}{raw}"


def _gold_ids(ground_truth: Mapping[str, Any]) -> tuple[str, ...]:
    """``target_id`` plus any ``valid_target_ids``, canonicalised, deduped, in order."""
    target_type = str(ground_truth.get("target_type") or "")
    raw: list[Any] = []
    for key in ("target_id", "valid_target_ids"):
        value = ground_truth.get(key)
        if isinstance(value, (list, tuple)):
            raw.extend(value)
        elif value not in (None, ""):
            raw.append(value)
    ids = [canonical_doc_id(target_type, r) for r in raw if str(r).strip()]
    return tuple(dict.fromkeys(ids))


def _require_token(value: str, what: str, where: str) -> None:
    # TREC run and qrels files are whitespace-separated columns.
    if not value or any(ch.isspace() for ch in value):
        raise ValueError(f"{where}: {what} {value!r} must be non-empty and contain no whitespace")


def load_qa(qa_dir: str | Path) -> Benchmark:
    """Read every ``<category>/<task>.jsonl`` under CTIConnect's ``data/`` directory.

    Files are read in sorted path order and rows in file order, so the result
    does not depend on the filesystem. ``task`` and ``category`` default to
    the file stem and its directory name when a row omits them.
    """
    qa_dir = Path(qa_dir)
    files = sorted(qa_dir.glob("*/*.jsonl"))
    if not files:
        raise FileNotFoundError(f"no <category>/<task>.jsonl files under {qa_dir}")

    bench = Benchmark()
    seen: dict[str, str] = {}
    for path in files:
        with path.open(encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                where = f"{path}:{line_no}"
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{where}: malformed QA row: {exc}") from exc
                if not isinstance(row, dict):
                    raise ValueError(f"{where}: a QA row must be a JSON object")

                query_id = str(row.get("id") or "")
                _require_token(query_id, "question id", where)
                if query_id in seen:
                    raise ValueError(f"{where}: duplicate question id {query_id!r} (first seen at {seen[query_id]})")
                seen[query_id] = where

                task = str(row.get("task") or path.stem)
                category = str(row.get("category") or path.parent.name)
                eval_type = str(row.get("eval_type") or "")

                def blocked(reason: str) -> None:
                    bench.blocked.append(BlockedItem(query_id, task, category, eval_type, reason))

                if eval_type == JUDGE_EVAL_TYPE or category == SYNTHESIS_CATEGORY:
                    blocked(BLOCKED_SYNTHESIS)
                    continue
                if eval_type not in SCOREABLE_EVAL_TYPES:
                    blocked(BLOCKED_EVAL_TYPE)
                    continue

                question = row.get("question")
                if not isinstance(question, str) or not question.strip():
                    raise ValueError(f"{where}: question {query_id!r} has no 'question' text")

                ground_truth = row.get("ground_truth") or {}
                if not isinstance(ground_truth, dict):
                    raise ValueError(f"{where}: 'ground_truth' must be an object")
                gold = _gold_ids(ground_truth)
                if not gold:
                    blocked(BLOCKED_NO_GOLD)
                    continue
                for doc_id in gold:
                    _require_token(doc_id, "gold id", where)

                source = row.get("source") if isinstance(row.get("source"), dict) else {}
                bench.items.append(
                    QAItem(
                        query_id=query_id,
                        query=question,
                        task=task,
                        category=category,
                        eval_type=eval_type,
                        gold_ids=gold,
                        target_type=str(ground_truth.get("target_type") or ""),
                        source_type=str(source.get("source_type") or ""),
                        source_id=str(source.get("source_id") or ""),
                    )
                )
    return bench


# -- dev/test split -------------------------------------------------------------------


def split_dev_test(items: Iterable[QAItem], *, seed: int, dev_fraction: float = 0.2) -> dict[str, str]:
    """Assign every question to ``"dev"`` or ``"test"``; returns ``query id -> split``.

    ``w`` and the field boosts are tuned on dev, and only test is reported,
    so the split has to be fixed before any system is run and identical on
    every machine. Stratified by task (each task gives the same share to
    dev). Within a task, questions are ordered by a hash of ``(seed, id)``
    and the first ``dev_fraction`` of them go to dev -- so a question's place
    in that order depends only on the seed and its own id, never on file
    order or on which other tasks are present.
    """
    if not 0.0 <= dev_fraction <= 1.0:
        raise ValueError(f"dev_fraction must be in [0, 1], got {dev_fraction}")

    by_task: dict[str, list[str]] = {}
    for item in items:
        by_task.setdefault(item.task, []).append(item.query_id)

    assignment: dict[str, str] = {}
    for task, ids in by_task.items():
        ordered = sorted(ids, key=lambda qid: (hashlib.sha256(f"{seed}:{qid}".encode("utf-8")).hexdigest(), qid))
        n_dev = int(len(ordered) * dev_fraction + 0.5)
        for i, qid in enumerate(ordered):
            assignment[qid] = "dev" if i < n_dev else "test"
    return assignment


# -- files ----------------------------------------------------------------------------


def write_queries(items: Iterable[QAItem], path: str | Path) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for item in items:
            fh.write(json.dumps(item.query_row(), ensure_ascii=False) + "\n")
            n += 1
    return n


def write_qrels(qrels: Qrels, path: str | Path) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for query_id, docs in qrels.items():
            for doc_id, grade in docs.items():
                fh.write(f"{query_id} 0 {doc_id} {grade}\n")
                n += 1
    return n


def read_qrels(path: str | Path) -> Qrels:
    qrels: Qrels = {}
    with Path(path).open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            cols = line.split()
            if len(cols) != 4:
                raise ValueError(f"{path}:{line_no}: a qrels line has 4 columns, got {len(cols)}")
            query_id, _, doc_id, grade = cols
            try:
                rel = int(grade)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: relevance {grade!r} is not an integer") from exc
            docs = qrels.setdefault(query_id, {})
            if doc_id in docs:
                raise ValueError(f"{path}:{line_no}: duplicate qrels entry for ({query_id}, {doc_id})")
            docs[doc_id] = rel
    return qrels


def read_metadata(path: str | Path) -> dict[str, dict[str, Any]]:
    """``query id -> metadata row`` from the ``metadata.jsonl`` written below."""
    out: dict[str, dict[str, Any]] = {}
    with Path(path).open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if "id" not in row:
                raise ValueError(f"{path}:{line_no}: a metadata row needs 'id'")
            out[str(row["id"])] = row
    return out


def _count(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


def write_benchmark(
    bench: Benchmark,
    out_dir: str | Path,
    *,
    seed: int,
    dev_fraction: float = 0.2,
    qa_dir: Optional[str | Path] = None,
    config_hash: Optional[str] = None,
    known_doc_ids: Optional[Iterable[str]] = None,
) -> dict[str, Any]:
    """Write the query files, qrels, metadata and a manifest; return the manifest.

    For each of ``all`` / ``dev`` / ``test``: ``queries.<split>.jsonl`` and
    ``qrels.<split>.trec``. Plus ``metadata.jsonl`` (every scoreable question
    with its split), ``blocked.jsonl`` and ``manifest.json``.

    ``known_doc_ids`` (the corpus's doc ids), when given, is used only to
    *report* gold ids that name no document in the corpus. They stay in the
    qrels: a gold entry no system can retrieve is a miss for every system,
    and dropping it would raise every recall figure.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    assignment = split_dev_test(bench.items, seed=seed, dev_fraction=dev_fraction)

    by_split = {
        "all": list(bench.items),
        "dev": [i for i in bench.items if assignment[i.query_id] == "dev"],
        "test": [i for i in bench.items if assignment[i.query_id] == "test"],
    }
    for split, items in by_split.items():
        write_queries(items, out_dir / f"queries.{split}.jsonl")
        write_qrels(bench.qrels(items), out_dir / f"qrels.{split}.trec")

    with (out_dir / "metadata.jsonl").open("w", encoding="utf-8") as fh:
        for item in bench.items:
            fh.write(json.dumps(item.metadata_row(assignment[item.query_id]), ensure_ascii=False) + "\n")
    with (out_dir / "blocked.jsonl").open("w", encoding="utf-8") as fh:
        for b in bench.blocked:
            fh.write(json.dumps(b.to_dict(), ensure_ascii=False) + "\n")

    gold_not_in_corpus: Optional[list[dict[str, str]]] = None
    if known_doc_ids is not None:
        known = set(known_doc_ids)
        gold_not_in_corpus = [
            {"id": i.query_id, "gold_id": d} for i in bench.items for d in i.gold_ids if d not in known
        ]

    source_manifest = None
    if qa_dir is not None and (Path(qa_dir) / "manifest.json").exists():
        source_manifest = json.loads((Path(qa_dir) / "manifest.json").read_text(encoding="utf-8"))

    manifest = {
        "kind": "cticonnect_eval",
        "qa_dir": str(qa_dir) if qa_dir is not None else None,
        "cticonnect_manifest": source_manifest,
        "seed": seed,
        "dev_fraction": dev_fraction,
        "questions": {split: len(items) for split, items in by_split.items()},
        "questions_by_task": {split: _count(i.task for i in items) for split, items in by_split.items()},
        "questions_by_category": _count(i.category for i in bench.items),
        "multi_gold_questions": sum(1 for i in bench.items if len(i.gold_ids) > 1),
        "blocked": len(bench.blocked),
        "blocked_by_reason": _count(b.reason for b in bench.blocked),
        "blocked_by_task": _count(b.task for b in bench.blocked),
        "gold_not_in_corpus": gold_not_in_corpus,
        "config_hash": config_hash,
        "created_at": time.time(),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
