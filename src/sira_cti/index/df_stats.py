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
from typing import Callable, Iterable, Literal, Protocol, runtime_checkable

Combine = Literal["max", "min"]
"""How a multi-token term's per-token document frequencies collapse to one number.

The analyzer decides how many tokens a term has, and it is not consistent
across the three catalogues: Anserini's default analyzer keeps ``T1110.001``
as one token but splits ``CWE-307`` into ``["cwe", "307"]``. So the combine
rule is not a detail -- it decides whether the ``too_common`` gate applies the
same standard to ATT&CK and CWE. The caller picks it because the right rule
depends on what kind of term it is:

``"max"`` -- judge by the *most* common token. Correct for ordinary
    multi-word vocabulary: "remote attacker" is only as discriminative as the
    stem ``attack`` (DF 3989 / 6044 here), because one very common word floods
    BM25 matches however rare the rest of the phrase is.

``"min"`` -- judge by the *least* common token. Correct for structural
    identifiers, where the namespace prefix is a corpus-wide constant carrying
    no identity and the numeric component carries all of it. Under ``"max"``
    every CWE identifier scores DF(``cwe``) = 2974/6044 = 0.492 -- *identical*
    for CWE-331 (whose own number appears in 7 documents) and CWE-119 (108),
    ~5x any sane ``df_max_ratio``, so every CWE is rejected unconditionally
    while one-token ATT&CK ids score 0 and pass unconditionally. That is a
    tokenization artifact masquerading as a filtering decision, and RQ1 is
    measured on exactly this survival rate. See ``docs/04_OPEN_QUESTIONS.md``
    question 1.
"""

_COMBINERS: dict[str, Callable[[Iterable[int]], int]] = {"max": max, "min": min}


@runtime_checkable
class DFLookup(Protocol):
    """What the ``too_common`` filter needs. :class:`LuceneDFLookup` (real
    index) and tests' fake implementations both satisfy this."""

    @property
    def total_docs(self) -> int: ...

    def doc_freq(self, term: str, *, combine: Combine = "max") -> int: ...


class LuceneDFLookup:
    """Wraps a Pyserini ``LuceneIndexReader`` over the base index."""

    def __init__(self, index_dir: str | Path) -> None:
        from pyserini.index.lucene import LuceneIndexReader  # heavy, JVM-backed; import on use

        self._reader = LuceneIndexReader(str(index_dir))
        self._total_docs = int(self._reader.stats()["documents"])

    @property
    def total_docs(self) -> int:
        return self._total_docs

    def doc_freq(self, term: str, *, combine: Combine = "max") -> int:
        """Document frequency of ``term``, combined across its analyzed tokens.

        ``analyzer=None`` on the second call does a literal posting-list
        lookup with no re-analysis, since the token has already been through
        the index's own analyzer once via :meth:`analyze`.

        See :data:`Combine` for why the caller, not this method, picks the
        rule.
        """
        tokens = self._reader.analyze(term)
        if not tokens:
            return 0
        dfs = [self._reader.get_term_counts(tok, analyzer=None)[0] or 0 for tok in tokens]
        return _COMBINERS[combine](dfs)


def too_common(term: str, lookup: DFLookup, *, df_max_ratio: float, combine: Combine = "max") -> bool:
    """Whether ``term``'s document frequency exceeds ``df_max_ratio`` of the corpus."""
    if lookup.total_docs == 0:
        return False
    return (lookup.doc_freq(term, combine=combine) / lookup.total_docs) > df_max_ratio
