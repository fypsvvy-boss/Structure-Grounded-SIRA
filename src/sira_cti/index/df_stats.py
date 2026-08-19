"""Document-frequency lookups the corpus-side ``too_common`` filter consumes.

DF is read from the already-built **base** (unenriched) index via Pyserini's
``LuceneIndexReader`` -- not reimplemented as a standalone Python token
count. Two reasons this must be reader-backed:

1. **Consistency with what actually happens at retrieval time.**
   ``df_max_ratio``'s whole point is "is this term discriminative under the
   same tokenizer that will score queries" -- a hand-rolled Python tokenizer
   can silently disagree with Lucene's analyzer (stemming, stopwords,
   casing: confirmed empirically -- the default analyzer keeps ``T1110.001``
   as one token but splits ``CWE-307`` into ``["cwe", "307"]``), producing a
   DF number that describes a term shape that doesn't exist at query time.
2. **It's free.** The base index (this package's other half,
   :mod:`sira_cti.index.build_base`) already exists before corpus-side
   enrichment can run -- see ``scripts/build_index.py``'s staged ordering.
   A standalone counter would have to duplicate Lucene's analyzer to be
   correct anyway, at the cost of a second, divergence-prone implementation.

This creates a hard two-pass ordering, made explicit rather than hidden:
base index -> DF stats (read from it) -> enrichment -> enriched index.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class DFLookup(Protocol):
    """What the ``too_common`` filter needs. :class:`LuceneDFLookup` (real
    index) and tests' fake implementations both satisfy this."""

    @property
    def total_docs(self) -> int: ...

    def doc_freq(self, term: str) -> int: ...


class LuceneDFLookup:
    """Wraps a Pyserini ``LuceneIndexReader`` over the base index."""

    def __init__(self, index_dir: str | Path) -> None:
        from pyserini.index.lucene import LuceneIndexReader  # heavy, JVM-backed; import on use

        self._reader = LuceneIndexReader(str(index_dir))
        self._total_docs = int(self._reader.stats()["documents"])

    @property
    def total_docs(self) -> int:
        return self._total_docs

    def doc_freq(self, term: str) -> int:
        """Highest single-token document frequency once ``term`` is analyzed.

        A multi-word candidate ("password guessing") is only as
        discriminative as its most common constituent token -- one common
        word floods BM25 matches regardless of how rare the rest of the
        phrase is, so the filter judges by the worst offender, not an
        average. ``analyzer=None`` on the second call does a literal
        posting-list lookup with no re-analysis, since the token has
        already been through the index's own analyzer once via
        :meth:`analyze`.
        """
        tokens = self._reader.analyze(term)
        if not tokens:
            return 0
        return max(self._reader.get_term_counts(tok, analyzer=None)[0] or 0 for tok in tokens)


def too_common(term: str, lookup: DFLookup, *, df_max_ratio: float) -> bool:
    """Whether ``term``'s document frequency exceeds ``df_max_ratio`` of the corpus."""
    if lookup.total_docs == 0:
        return False
    return (lookup.doc_freq(term) / lookup.total_docs) > df_max_ratio
