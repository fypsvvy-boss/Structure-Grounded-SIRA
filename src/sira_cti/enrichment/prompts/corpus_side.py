"""The corpus-side enrichment prompt (Module 1).

Kept in its own module — not inline in ``corpus_side.py``'s control flow —
so Module 2 can mirror this file's shape for ``prompts/query_side.py``
without untangling prompt text from pipeline logic, and so a prompt change
is a one-file diff.

``PROMPT_VERSION`` is not part of the frozen :class:`EnrichmentRecord`
contract (schemas.py has no such field, and changing that contract needs
four-owner sign-off — see ``common/schemas.py``'s module docstring). Instead
the enrichment driver writes it to a sidecar manifest next to the output
JSONL, which is enough to keep records from different prompt versions
separable without touching the frozen shape.
"""

from __future__ import annotations

from ...index.corpus import CorpusDocument

PROMPT_VERSION = "corpus-v1"

_KIND_GUIDE = """\
- "colloquial": an informal name an analyst might type ("brute force login")
- "symptom": an observable effect, not a technique name ("account lockouts spiking")
- "product": a product, vendor, or platform name relevant to this entry
- "misspelling": a common misspelling or alternate spelling of a term above
- "structural": a formal identifier from the ATT&CK / CWE / CAPEC catalogues
  (e.g. "T1110.001", "CWE-307", "CAPEC-49") -- write it in its own natural
  spelling; do not invent an ID you are not confident exists"""

SYSTEM_PROMPT = f"""You are helping build a search index for cyber threat intelligence.

You will be shown one catalogue entry (a CVE, CWE, CAPEC, or ATT&CK record). \
Propose vocabulary a security analyst might search for that would find this \
entry, but that does NOT already appear in its text. Do not restate words \
already present in the entry -- the index already has those for free.

Every proposed term has a "kind":
{_KIND_GUIDE}

Reply with ONLY a JSON array, no prose before or after it. Each element is an \
object with exactly two keys: "term" (string) and "kind" (one of the five \
values above). If you have nothing to add, reply with an empty array: []

Example reply:
[
  {{"term": "password spraying", "kind": "colloquial"}},
  {{"term": "T1110.003", "kind": "structural"}},
  {{"term": "account lockout", "kind": "symptom"}}
]"""


def build_prompt(doc: CorpusDocument, *, max_terms: int) -> str:
    """The user turn for one document. ``SYSTEM_PROMPT`` carries the fixed
    instructions; this carries the one thing that varies per call."""
    return (
        f"Catalogue entry ({doc.source.value}, id {doc.doc_id}):\n"
        f"{doc.text}\n\n"
        f"Propose at most {max_terms} terms."
    )
