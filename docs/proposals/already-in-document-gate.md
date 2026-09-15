# Proposal: reject terms that just repeat the document's own words

**Status: Module 1 approved (2026-09-15) — awaiting Modules 2, 3 and 4.**
**Needs:** agreement to add one new value to `RejectReason` in
`src/sira_cti/common/schemas.py` — the frozen contract Modules 1–4 all share.
**Opened by:** Module 1, 2026-09-15. **Background:** `docs/04_OPEN_QUESTIONS.md`
question 7 (full measurement detail there — this doc is the decision request).

If you own Module 2, 3, or 4: skip to **"What this changes for you"** and
**"Decision needed"** near the bottom. You don't need to read the measurement
section to make the call, but it's there if you want it.

---

## The problem, in one sentence

Module 1 asks an LLM to propose search terms that are *missing* from a
document's own text — and measured on a real 20-document run, 61% of the
terms it proposed (and **100%** of the formal ID terms, like `CWE-307`) were
words already sitting in that same document's text.

## Why that's a real problem, not just noise

A term that's already in the document is already indexed and already
findable by a plain keyword search. Adding it to our "expansion" vocabulary
costs a `max_terms_per_doc` slot and real tokens, and gets it **zero** extra
recall. Worse, for the structural IDs specifically: CTIConnect's CVE records
often embed their own CWE number in the text, so the model is reading
`CWE-119` off the page and handing it back — and the ontology graph then
"validates" it. That validation is real (the ID does exist), but it isn't
testing what RQ1 needs it to test. RQ1 asks whether grounding proposals
against the real graph produces more valid, discriminative vocabulary than
proposing without grounding. If the grounded proposals are mostly
transcriptions of text already on the page, a high validity rate is
measuring the model's ability to copy, not the mechanism the whole project
is about.

## We already tried the cheap fix, twice, and it didn't work

The prompt has said "Do NOT restate words already present in the entry"
since the very first version. The model ignores it. We then wrote a second,
much more forceful prompt (`corpus-v2` — full text in
`docs/experiments/prompt-corpus-v2.md`) that spelled out a concrete test,
showed a worked bad example, and repeated the instruction next to the
document text. Same 20 documents, same model:

```
                                   v1        v2
  redundant share of accepted   61.1%     59.5%   <- barely moved
  genuinely-new terms indexed      51        30   <- 41% WORSE
```

The model complied with the letter of v2 (it proposed fewer terms overall)
without complying with the intent (it kept copying at almost the same
rate) — it just got more cautious across the board. Two rounds of evidence
say prompting alone will not fix this for this model. That's why this is
now a request to build an enforced gate instead.

## What's being proposed

**One new value on `RejectReason`:** `ALREADY_IN_DOCUMENT = "already_in_document"`.

That's the only frozen-contract change. Everything else below is Module 1's
own implementation, which needs no sign-off — it's included so the decision
isn't made blind.

### Where it slots into the existing pipeline

`corpus_side.py`'s `propose_terms()` already runs proposals through two
gates in order — graph validation, then the `too_common` document-frequency
filter. This would be a third gate, run **before** the DF filter (a term
that's just copied isn't "too common," it's not new vocabulary *at all*,
which is the more fundamental reason to reject it — but this ordering is
itself part of what's being asked for sign-off; say so if you'd rather it be
last):

```
prompt -> strict parse -> kind routing -> graph gate (structural terms)
       -> NEW: already-in-document gate         <- proposed insertion point
       -> too_common (DF) gate
```

### The detection rule (already specified, already used for the measurement above)

Not a simple substring/set check — that overstates redundancy, because e.g.
`CWE-331` analyzes to two tokens (`cwe`, `331`) that can occur far apart in a
document without the phrase `CWE-331` ever appearing together:

- **Structural terms:** reject if the term's canonical form appears
  literally in the document's raw text (after stripping punctuation).
- **Everything else:** reject if the term's analyzed token sequence appears
  as a **contiguous run** in the document's own analyzed tokens (same Lucene
  analyzer already used everywhere else in this pipeline, via
  `LuceneIndexReader.analyze()`).

This is exactly the check that produced the 61.1%/100% numbers above, so
adopting it doesn't change what's already been measured — it just enforces
what's already been observed. It is now a saved script,
`scripts/measure_redundancy.py`, which reproduces those numbers exactly.

**This rule on its own is not enough** — see the next section.

## Update after the stratified run (2026-09-15)

The numbers above came from CVE documents only. A second run took 10 random
documents of each type (CVE, CWE, CAPEC, ATT&CK). It showed that the rule
above misses most of the copying on the three non-CVE types, because the model
copies identifiers from two places the rule doesn't look:

```
  document type   structural ids proposed   where each one came from
  cve             10                        written in the text ("CWE-79")     <- rule catches
  cwe              5                        the document's own id              <- rule misses
  attack           4                        the document's own id              <- rule misses
  capec            3                        a bare number in the JSON text     <- rule misses
                                            ("@CWE_ID": "120" -> CWE-120)
```

Across all three runs so far: **47 of 48 structural ids were copies.** Zero
ATT&CK or CAPEC ids were proposed for any document other than that entry
itself — even though 3 of the 10 sampled CAPEC entries list ATT&CK mappings in
their own text.

So for structural terms the detection rule becomes two checks, both reported
under the one proposed reason `already_in_document`:

1. **the id is written in the text** (the original rule — `CWE-79`);
2. **the id is named by a labelled id field in the entry's own JSON.** The
   catalogue comes from the field name, never guessed from a bare number:

   | field | becomes | note |
   |---|---|---|
   | `"@CWE_ID": "120"` | `CWE-120` | |
   | `"@CAPEC_ID": "444"`, `"@Exclude_ID": "515"` | `CAPEC-444`, `CAPEC-515` | both are CAPEC references |
   | `"Entry_ID": "1027"` | `T1027` | **only** inside an `"@Taxonomy_Name": "ATTACK"` mapping |

   The ATT&CK condition matters: WASC and OWASP mappings use `Entry_ID` too
   (e.g. `"Entry_ID": "07"`), and a looser "any quoted number" rule would have
   matched those. `@ID` (the entry's own id) is deliberately not in the list —
   see the next section. Checked across all 615 CAPEC entries: the extracted
   ATT&CK ids match the `ATTACK`-labelled mappings exactly, with no leaks. In
   `corpus_kb` only CAPEC entries carry these fields.

An earlier draft of this section had a third check ("the document's own id")
and a looser version of check 2 ("the number appears anywhere as a quoted
value"). Module 1 dropped the first and tightened the second — see below.

### The document's own id — decided by Module 1, no gate check needed

Up to prompt `corpus-v1`, the document's own id reached the model through the
**prompt header** (`"Catalogue entry (cwe, id CWE-1321)"`), not through the
document text:
`corpus_kb` stores CWE/CAPEC/ATT&CK entries as title + JSON body, without the
id. That cuts both ways:

- **For rejecting it:** proposing an entry's own id is a transcription, and the
  graph "validating" it tests nothing RQ1 cares about. Counting it as a
  successful grounded proposal inflates exactly the number RQ1 reports.
- **Against rejecting it:** because the id is *not* in the indexed text,
  injecting it genuinely makes the entry findable by its own id. Measured on the
  base index: a search for `CWE-1321` or `CWE-378` does not return that entry
  anywhere in the top 1,000; `T1437` returns no hits at all; `CAPEC-14` finds
  its own entry at rank 306. Rejecting the own id removes real retrieval value.

**Decision (Module 1, 2026-09-15): take the id out of the prompt header, and
leave "should an entry be searchable by its own id" to Module 3.** This is a
Module 1 prompt change, so it needs no sign-off, and it is already done: prompt
`corpus-v3` opens with `Catalogue entry (cwe):` and no id.

Why this over the other two options:

- **The LLM is an unreliable way to make ids searchable.** It proposed its own
  id for only 5 of 10 CWE entries and 4 of 10 ATT&CK entries. If entries should
  be findable by id, adding the id at indexing time covers all 6,044 entries,
  every time, for zero tokens.
- **Keeping it accepted** would count a transcription as a successful grounded
  proposal — inflating exactly the number RQ1 reports.
- **Rejecting it** records the copy honestly, but keeps paying tokens to watch
  the model copy something we already know it will copy.

This decouples "is the id searchable" (a retrieval design choice, Module 3's)
from "did the model infer something" (an RQ1 measurement, Module 1's). One
limit: a CVE's own id is still visible to the model, because `corpus_kb` puts
it in the CVE's title — and CVE ids are not graph nodes anyway (open question
6).

**Result, same 40 documents re-run under `corpus-v3`:** own-id proposals went
from 9 to 0, with no drop in overall output. ATT&CK entries then proposed no
identifiers at all. The only two identifiers not copied from anywhere
(`CWE-1321` -> `CWE-134`, `CWE-835` -> `CWE-362`) exist but are wrong for their
entries, and the graph accepted them — that is a separate problem from this
proposal, logged as open question 8. It does not change this proposal: copies
are still the large majority of structural proposals, and the gate still
catches all the ones that remain.

### What Module 1 would implement once this is approved (no further sign-off needed)

- A new `_already_in_document(term, doc_text, analyzer) -> bool` in
  `corpus_side.py`, ported from the reference functions in
  `scripts/measure_redundancy.py` (`contains_contiguous`,
  `already_in_document_structural`, `labelled_ids_in_text`) together with
  tests — the script already reports what the gate *would* reject
  ("under the approved gate rule"), so the gate's effect can be checked
  against it exactly.
- `DFLookup` (`index/df_stats.py`) gains an `analyze(text) -> list[str]`
  method — it already wraps a `LuceneIndexReader`, which already has this;
  it's just not exposed on the protocol yet. Internal to Module 1, not a
  contract change.
- Per the project's standing rule, rejected terms are **kept in the log**,
  not dropped — the redundancy rate itself becomes a measurable, citable
  number, which is arguably a small finding of its own for the write-up
  ("open-weight model X copies Y% of proposed identifiers from source text").

---

## What this changes for you

**Module 2 (query-side enrichment).** This gate is Module 1-specific by
design — it compares a proposed term against the *document* it was proposed
for, and query-side enrichment has no source document, only the analyst's
question. **You almost certainly don't need this logic**, but you do need to
know the new `RejectReason` value exists so your own rejection-handling code
(if any) doesn't choke on an enum value it's never seen. If your enrichment
records also end up copying words from the query back at itself, that's a
different, separate question — flag it if you see it, don't assume this
covers it.

**Module 3 (retrieval).** No code changes implied. You consume
`accepted_terms` for the expansion field either way; this just means fewer,
and more genuinely-new, terms land there than would otherwise. Might move
your recall numbers versus what you'd see on the current (unfiltered)
enriched index — worth knowing before you tune `w`.

Separately, and true today regardless of this decision: **a CWE, CAPEC or
ATT&CK entry's own id is not in its indexed text.** In the base (plain-BM25
baseline) index, searching `CWE-1321` doesn't return the `CWE-1321` entry in
the top 1,000, and `T1437` returns nothing. This matches how CTIConnect's own
baselines index the corpus (title + contents), so it may be the intended
setup for comparability — but entity-linking questions that name an id will
behave very differently depending on it, so decide it deliberately.

**Module 4 (evaluation).** `RejectReason` currently has six values
(`not_in_graph`, `too_common`, `not_in_index`, `deprecated`, `revoked`,
`malformed_id`); this would make seven. `EnrichmentRecord.rejection_rate()`
already counts whichever reasons are present with no code change needed on
your end — but if you've built anything that special-cases the six current
reasons by name (a chart legend, a fixed-width table, a switch statement),
that needs the seventh added.

---

## Decision needed

**What is being signed off:** a new `RejectReason` value
`already_in_document`, and a gate in Module 1 that applies it — before the DF
filter — using the rule above (contiguous analyzed tokens for ordinary terms;
checks 1 and 2 for structural ids).

**One reason to prefer the gate over filtering silently at index-build time**
(option 2 in question 7), beyond keeping the RQ4 log honest: Module 3 builds
the expansion query from `accepted_terms`. If copies were dropped later, in
`build_enriched.py`, then `accepted_terms` would list terms that are not
actually in the index, and every module reading the shared record would be
working from a false list. Rejecting at the gate keeps "accepted" and "indexed"
meaning the same thing.

**A wording precision:** "zero extra recall" above means a copied term adds no
*new way to find* its document. Depending on how Module 3 scores the expansion
field (question 4), a copied term can still move that document up the ranking.
That doesn't change the case for the gate — the expansion field is meant to
hold new vocabulary, not a second copy of the old — but it is the accurate
claim.

| Owner | Decision | Date | Notes |
|---|---|---|---|
| Module 1 | **Approve**, with check 2 limited to labelled id fields (as now written) | 2026-09-15 | Own-id question resolved separately by prompt change, see above |
| Module 2 | *pending* | | |
| Module 3 | *pending* | | Also: decide whether entries should be searchable by their own id |
| Module 4 | *pending* | | |

To respond: fill in your row (approve / approve with changes — say what /
reject — and if rejecting, which alternative from `04_OPEN_QUESTIONS.md`
question 7 Module 1 should pursue instead).

Once all four have weighed in, Module 1 will implement the `schemas.py`
change plus the gate itself, re-run the saved samples under it, and log the
before/after in `docs/03_STATUS_LOG.md` — the same way the DF-combine and
kind-routing gate fixes were logged on 2026-08-20.
