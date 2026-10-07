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

PROMPT_VERSION = "corpus-v4"
"""Version history (``corpus-v2`` was a reverted experiment, see
``docs/experiments/prompt-corpus-v2.md``, so its name is not reused):

* ``corpus-v1`` -- the user turn opened with ``Catalogue entry (cwe, id CWE-1321)``.
* ``corpus-v3`` -- the same prompt with the document's id removed from that
  header. The stratified run showed every structural id proposed on a CWE or
  ATT&CK entry was that entry's own id, read off this header, because
  ``corpus_kb`` text does not contain it -- a transcription the graph then
  "validated". Whether an entry should be searchable by its own id is a
  retrieval decision for Module 3, not something to get by asking the LLM to
  copy it. Decision 2 in ``docs/proposals/already-in-document-gate.md``.
  (A CVE's id is still visible: ``corpus_kb`` puts it in the CVE's title.)
* ``corpus-v4`` -- v3 plus a required ``"name"`` on every structural
  proposal: the model must state the official title it believes the id has.
  The 2026-10-07 qwen2.5:14b run showed the graph's existence check passing
  runs of consecutive ids (CWE-512 "Spyware" -> CWE-73..81, all nine
  accepted), because on a dense integer namespace "does this id exist" is
  almost always yes. The claimed title is the evidence an existence check
  cannot ask for. See ``docs/proposals/name-id-consistency.md``.

  **Deliberately neutral wording.** The prompt asks for the title as one more
  field to fill in; it does not warn that the title will be checked, or that a
  wrong one loses the proposal. Warning the model would change how freely it
  proposes ids, which is the thing RQ4 is trying to measure -- the gate would
  then be reporting its own deterrent effect rather than the model's
  unprompted error rate.
"""

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
object with the keys "term" (string) and "kind" (one of the five values \
above). When "kind" is "structural", add a third key "name": the official \
title that identifier has in its catalogue. If you have nothing to add, \
reply with an empty array: []

Example reply:
[
  {{"term": "password spraying", "kind": "colloquial"}},
  {{"term": "T1110.003", "kind": "structural", "name": "Password Spraying"}},
  {{"term": "account lockout", "kind": "symptom"}}
]"""


REPLY_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "term": {"type": "string"},
            "kind": {
                "type": "string",
                "enum": ["colloquial", "symptom", "product", "misspelling", "structural"],
            },
            "name": {"type": "string"},
        },
        "required": ["term", "kind"],
    },
}
"""The reply shape, as a JSON Schema for constrained decoding.

Lives beside the prompt because it *is* the prompt's last paragraph, stated
again in a form the decoder can enforce. Two settings were measured on
CAPEC-587, the one document the 14B run could never finish:

======================  =============================================
unconstrained           a valid-looking array with one element's
                        opening brace missing -- identical on every
                        retry at temperature 0
``format: "json"``      valid JSON, but a single **object**: one
                        proposal where twelve were asked for
this schema             twelve proposals, both models, first attempt
======================  =============================================

``name`` is deliberately **not** in ``required``. A model that cannot name an
id should be able to leave the field out and have that recorded as a name
mismatch; forcing the key would make it invent a title to satisfy the
grammar, turning "I don't know" into a hallucination the pipeline then books
against the model.
"""

JSON_RETRY_NUDGE = """

Your previous reply could not be parsed as JSON. Reply again with ONLY the \
JSON array -- no prose, no code fence, no trailing comma, and an opening \
brace on every element."""
"""Appended to the user turn for one retry after a parse failure.

At temperature 0 the same prompt returns the same reply byte for byte, so a
bare retry is guaranteed to fail identically -- the prompt has to change for
the second attempt to mean anything. Which also means the retry is not a
clean second sample of the same distribution, so a document rescued by a
nudge is counted separately in the run report rather than silently folded in
with the documents that parsed first time.
"""


def build_prompt(doc: CorpusDocument, *, max_terms: int, nudge: bool = False) -> str:
    """The user turn for one document. ``SYSTEM_PROMPT`` carries the fixed
    instructions; this carries the one thing that varies per call."""
    return (
        f"Catalogue entry ({doc.source.value}):\n"
        f"{doc.text}\n\n"
        f"Propose at most {max_terms} terms."
        + (JSON_RETRY_NUDGE if nudge else "")
    )
