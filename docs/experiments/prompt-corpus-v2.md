# Experiment: corpus-v2 prompt (redundancy reduction) — FAILED, reverted

**Date:** 2026-08-20 · **Model:** qwen2.5:7b · **Sample:** same 20 CVE documents
as the corpus-v1 baseline · **Outcome: rejected, prompt reverted to corpus-v1.**

## What it was testing

`04_OPEN_QUESTIONS.md` question 7: 61.1% of accepted enrichment terms, and 100%
of structural identifiers, were already present verbatim in the document's own
text. corpus-v1 already contained the instruction "Do NOT restate words already
present in the entry" and the model ignored it. This experiment asked whether a
much more forceful prompt could fix that before spending a schema sign-off round
on an enforced gate.

## Three changes from v1

1. **Made the constraint operational rather than a bare negation.** A single
   concrete per-term test — "Could an analyst who has NEVER SEEN this entry type
   this term, and expect to find it?" — instead of "do not restate".
2. **Demonstrated the failure instead of describing it.** Added a `BAD reply`
   block to the worked example, showing terms copied out of the entry and
   labelled worthless. v1 showed only a good reply.
3. **Repeated the constraint in the user turn**, adjacent to the entry text,
   rather than only in the system prompt.

Plus a structural-specific instruction: if the entry already cites an
identifier, propose a *different* one (the ATT&CK technique that exploits the
weakness, a related CAPEC pattern, a broader/narrower CWE) or none at all.

## Result: it did not work

```
                                   v1        v2
  terms proposed                  223       148
  accepted                        131        74
  redundant share of accepted   61.1%     59.5%     <- the target metric
  GENUINELY NEW terms indexed      51        30     <- what actually matters
  structural accepted               17         3
  structural already in doc      17/17      2/3
  malformed_id                       1         3
  completion tokens               3935      2586
```

**The target metric moved 1.6 percentage points — noise.** Meanwhile total output
collapsed by a third and genuinely-new terms fell 51 -> 30. v2 is *strictly
worse*: it made the model more cautious across the board without making it less
redundant.

The likely cause of the volume collapse is the added "Fewer, genuinely-absent
terms are better than many restated ones" line, which the model appears to have
read as "propose less" rather than "propose better".

## New failure mode introduced

`malformed_id` rose 1 -> 3, all of one shape:

```
  'CWE-331: Use of Inadequate Randomness'
  'CWE-310: Inadequate Entropy Sources'
  'CWE-125 buffer overflow'
```

Told to reason about *which* CWE to propose, the model started writing the
identifier together with its title. Note these are **genuinely
normalizer-recoverable**, unlike the original five mislabels:
`parse_structural_id` returns `None` for all three, but the existing
`extract_structural_ids` finds `CWE-331`, `CWE-310` and `CWE-125` correctly.
If any future prompt encourages descriptive identifier forms, the adjudicator
should fall back to `extract_structural_ids` when `parse_structural_id` fails on
an ID-shaped term. Logged so it is not rediscovered.

## Conclusion

Prompting is not the lever for question 7. The recommendation in that question
flips from "prompt-iterate first" to **option 1 — enforce it as a gate**, which
needs a new `RejectReason` (`already_in_document`) and therefore four-owner
sign-off on the frozen contract.

Do not simply retry a stronger wording: the model complied with the *letter* of
v2 (it proposed less) without complying with its *intent* (it kept copying).

## The exact v2 prompt, for the record

### System prompt

```text
You are helping build a search index for cyber threat intelligence.

You will be shown one catalogue entry (a CVE, CWE, CAPEC, or ATT&CK record). The entry's own words are ALREADY in the search index. Your job is to add the words that are missing from it.

So there is exactly one test every term must pass:

  Could an analyst who has NEVER SEEN this entry type this term,
  and expect to find it?

If the term is already written in the entry, it fails -- the index has it for free, and repeating it adds nothing. Copying identifiers, product names or phrases out of the entry is the single most common mistake on this task. Before you output each term, look back at the entry and check it is not there.

Prefer: what practitioners call this informally, what a user would observe without knowing the cause, related identifiers the entry does NOT cite, vendor/product names implied but not written, common misspellings.

Every proposed term has a "kind":
- "colloquial": an informal name an analyst might type ("brute force login")
- "symptom": an observable effect, not a technique name ("account lockouts spiking")
- "product": a product, vendor, or platform name relevant to this entry
- "misspelling": a common misspelling or alternate spelling of a term above
- "structural": a formal identifier from the ATT&CK / CWE / CAPEC catalogues
  (e.g. "T1110.001", "CWE-307", "CAPEC-49") -- write it in its own natural
  spelling; do not invent an ID you are not confident exists.
  If the entry already cites an identifier, that one is worthless to propose.
  Propose a *different* one the entry does not cite -- the ATT&CK technique
  this weakness is exploited by, a related CAPEC attack pattern, a broader or
  narrower CWE -- or propose none at all.

Reply with ONLY a JSON array, no prose before or after it. Each element is an object with exactly two keys: "term" (string) and "kind" (one of the five values above). Fewer, genuinely-absent terms are better than many restated ones. If you have nothing to add, reply with an empty array: []

Worked example. Suppose the entry reads:
  "Improper Restriction of Excessive Authentication Attempts (CWE-307).
   The product does not implement sufficient measures to prevent multiple
   failed authentication attempts within a short time frame."

GOOD reply -- none of these appear in the entry above:
[
  {"term": "password spraying", "kind": "colloquial"},
  {"term": "T1110.003", "kind": "structural"},
  {"term": "account lockout", "kind": "symptom"}
]

BAD reply -- every one of these is copied from the entry, so all are worthless:
[
  {"term": "CWE-307", "kind": "structural"},
  {"term": "authentication attempts", "kind": "colloquial"},
  {"term": "failed authentication", "kind": "symptom"}
]
```

### User turn template

```text
Catalogue entry (cve, id <DOC_ID>):
<ENTRY TEXT>

Propose at most 12 terms that are NOT written anywhere in the entry above. Re-read the entry and drop any term you find in it, including any identifier it already cites. Fewer is better than restated.
```
