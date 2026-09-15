# Proposal: reject terms that just repeat the document's own words

**Status: DRAFT — awaiting sign-off from all four module owners.**
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
what's already been observed.

### What Module 1 would implement once this is approved (no further sign-off needed)

- A new `_already_in_document(term, doc_text, analyzer) -> bool` in
  `corpus_side.py`.
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

**Module 4 (evaluation).** `RejectReason` currently has six values
(`not_in_graph`, `too_common`, `not_in_index`, `deprecated`, `revoked`,
`malformed_id`); this would make seven. `EnrichmentRecord.rejection_rate()`
already counts whichever reasons are present with no code change needed on
your end — but if you've built anything that special-cases the six current
reasons by name (a chart legend, a fixed-width table, a switch statement),
that needs the seventh added.

---

## Decision needed

Please respond (in this file, a PR comment, or however the team's doing
sign-off) with one of:

- [ ] **Approve as specified** — value name `already_in_document`, gate runs
      before the DF filter.
- [ ] **Approve with changes** — say what (alternate name, different gate
      ordering, different detection rule, etc.)
- [ ] **Reject** — and if so, which of the other two options from
      `04_OPEN_QUESTIONS.md` question 7 should Module 1 pursue instead
      (silent filtering at index time, which hides this from the RQ4 log; or
      something else)?

Once all four have weighed in, Module 1 will implement the `schemas.py`
change plus the gate itself, re-run the archived 20-document sample under
it, and log the before/after in `docs/03_STATUS_LOG.md` — the same way the
DF-combine and kind-routing gate fixes were logged on 2026-08-20.
