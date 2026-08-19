"""Loads CTIConnect's structured knowledge base as the corpus this project indexes.

``data/CTIConnect/corpus_kb/{cve,cwe,capec,mitre}.jsonl`` is CTIConnect's own
retrieval corpus (see its ``MANIFEST.json``: "used as the retrieval corpus for
Entity Linking and Entity Attribution tasks"). CTIConnect's own baseline
loader (``data/CTIConnect/baselines/_shared/kb.py``) canonicalises each row's
id to ``CVE-…`` / ``CWE-…`` / ``CAPEC-…`` / ``T####[.###]`` and embeds
``title + contents`` (``contents`` is a JSON-*string* blob, kept as raw text).
We mirror that convention exactly rather than invent our own — a differently
keyed index would silently break Module 4's evaluation against CTIConnect's
qrels, and mirroring ``T####`` also happens to match ``normalize.py`` for
free. We don't import CTIConnect's package directly: it's an external,
gitignored clone, not a stable dependency of this project.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

from ..common.schemas import Source

_ID_FIELD = {"cve": "cve_id", "cwe": "cwe_id", "capec": "capec_id", "mitre": "mitre_id"}
_ID_PREFIX = {"cwe": "CWE-", "capec": "CAPEC-"}  # cve/mitre ids already prefixed/bare
_SOURCE = {"cve": Source.CVE, "cwe": Source.CWE, "capec": Source.CAPEC, "mitre": Source.ATTACK}

KINDS = tuple(_ID_FIELD)


@dataclass(frozen=True)
class CorpusDocument:
    """One corpus_kb entry, ready to enrich or index.

    ``text`` is ``title + contents`` exactly as CTIConnect's own baselines
    embed it — ``contents`` is a JSON-encoded string (descriptions, CVSS
    metrics, mitigations, ...), deliberately left unparsed. BM25 tokenizes
    through the JSON syntax without issue, and re-serialising it would only
    risk diverging from what CTIConnect's other baselines see.
    """

    doc_id: str
    source: Source
    title: str
    text: str


def _canonical_id(kind: str, raw: str) -> str:
    raw = str(raw)
    if kind == "cve":
        return raw if raw.upper().startswith("CVE-") else f"CVE-{raw}"
    if kind == "mitre":
        return raw if raw.upper().startswith("T") else f"T{raw}"
    prefix = _ID_PREFIX[kind]
    return raw if raw.upper().startswith(prefix) else f"{prefix}{raw}"


def load_kb(kb_dir: str | Path, kind: str, *, limit: Optional[int] = None) -> Iterator[CorpusDocument]:
    """Stream one knowledge base's entries as :class:`CorpusDocument`."""
    if kind not in _ID_FIELD:
        raise ValueError(f"unknown corpus kind {kind!r}; valid: {list(_ID_FIELD)}")
    path = Path(kb_dir) / f"{kind}.jsonl"
    id_field = _ID_FIELD[kind]
    n = 0
    with path.open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: malformed corpus_kb row: {exc}") from exc
            raw_id = row.get(id_field) or row.get("id")
            title = row.get("title", "") or ""
            contents = row.get("contents", "") or ""
            yield CorpusDocument(
                doc_id=_canonical_id(kind, raw_id),
                source=_SOURCE[kind],
                title=title,
                text=f"{title} {contents}".strip(),
            )
            n += 1
            if limit is not None and n >= limit:
                return


def load_corpus(
    kb_dir: str | Path, kinds: Iterable[str] = KINDS, *, limit: Optional[int] = None
) -> Iterator[CorpusDocument]:
    """Stream every requested knowledge base in turn.

    ``limit``, if given, caps the *total* documents yielded across all kinds
    (cheap iteration for ``--limit N`` in the CLI scripts), not each kind.
    """
    n = 0
    for kind in kinds:
        for doc in load_kb(kb_dir, kind):
            yield doc
            n += 1
            if limit is not None and n >= limit:
                return
