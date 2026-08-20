# Open Questions & Known Issues

> Decisions that are NOT yet made, or made but not yet documented as deliberate.
> These need a human call, not a silent default. Each affects the research
> validity, not just code cleanliness.

---

## 1. ~~How is document frequency computed for multi-token structural IDs?~~ RESOLVED 2026-08-20

**Decision: for structural identifiers the DF gate reads the *rarest* of the
identifier's analyzed tokens. Everything else keeps the existing *most common*
token rule.** Implemented as an explicit `combine` argument on
`DFLookup.doc_freq` (`src/sira_cti/index/df_stats.py`), chosen per term by
`_df_combine()` in `corpus_side.py`. Both rules and the reasoning are documented
on the `Combine` type itself, so the choice is visible at the call site.

### What was actually wrong (this was live, not hypothetical)

A search index does not store words the way you type them. It chops text into
pieces first — that step is the **analyzer**. Anserini's default analyzer chops
`CWE-307` into two pieces, `cwe` and `307`, because the hyphen looks like a
separator. It leaves `T1110.001` as one piece, because dots do not split.

The `too_common` gate asks "how many documents contain this term?" (its
**document frequency**, or DF) and rejects anything above `df_max_ratio`
(currently 0.10, i.e. 10% of the corpus). For a term that chopped into several
pieces, the old rule took the DF of the *most common* piece.

Measured on the real base index (`indexes/base`, 6,044 documents):

```
CWE-331   -> ['cwe'(2974), '331'(7)]    took 2974  = 49.2%  REJECTED
CWE-310   -> ['cwe'(2974), '310'(6)]    took 2974  = 49.2%  REJECTED
CWE-287   -> ['cwe'(2974), '287'(41)]   took 2974  = 49.2%  REJECTED
CWE-119   -> ['cwe'(2974), '119'(108)]  took 2974  = 49.2%  REJECTED
CWE-787   -> ['cwe'(2974), '787'(92)]   took 2974  = 49.2%  REJECTED
T1110.001 -> ['t1110.001'(0)]           took 0     =  0.0%  passes
CAPEC-49  -> ['capec'(92), '49'(15)]    took 92    =  1.5%  passes
```

Read the third column: **every CWE identifier scored exactly the same number**,
because the gate was always reading `cwe` and never the digits. `cwe` appears in
2,974 of 6,044 documents — about five times the threshold. So **every CWE
identifier was rejected as `too_common`, unconditionally, regardless of which
CWE it was**, including ones whose own number appears in 6 documents. Meanwhile
ATT&CK identifiers stayed one piece, scored 0, and passed unconditionally.

This is not a threshold that could be re-tuned. 49.2% is a constant: lower the
threshold and nothing changes; raise it past 0.492 and the gate stops filtering
anything at all.

### Why the fix is "rarest token"

For an identifier, the namespace prefix (`cwe`, `capec`) is a constant shared by
every entry in that catalogue and carries no identity — the number carries all
of it. Reading the rarest token reads the number.

The old max rule stays for ordinary vocabulary, where it is correct: `remote
attacker` analyzes to `['remot'(1103), 'attack'(3989)]` and deserves to die on
`attack`, because one very common word floods BM25 matches however rare the rest
of the phrase is.

The gate still bites on identifiers — a CWE genuinely cited across the corpus
has a high DF *on its number* and is still rejected. This is a correction, not
an exemption. (Exempting graph-validated identifiers entirely was considered and
rejected: it would have removed a real signal.)

### Measured effect

Replaying the first real run's recorded proposals through the new gate, with no
new LLM calls so nothing but the gate logic differs: all five CWE identifiers
flip from `too_common` to accepted, at their true DFs of 7, 6, 6, 41, 108 and 92.

### Still true, and it belongs in the write-up

The ATT&CK-vs-CWE/CAPEC tokenization asymmetry is a property of the analyzer, not
something this fix removes. Two things follow that Module 4 should state
explicitly rather than let a reader assume:

- ATT&CK identifiers have DF **0** in the base corpus — they do not appear in it
  at all. The `too_common` gate therefore *cannot* reject an ATT&CK identifier,
  under either rule. Any RQ1 comparison of survival rates across catalogues is
  comparing a filter that can fire against one that cannot.
- Reading the rarest token is a close approximation of the true phrase
  frequency, not the phrase frequency itself. For `CWE-331` the number `331`
  appears in 7 documents; how many of those 7 have it adjacent to `cwe` is not
  checked. In this corpus the two are near-identical, because a bare `331` is
  rare on its own. A true positional phrase lookup was considered and judged not
  worth the extra machinery — but the approximation should be named in the
  write-up, not hidden.

`tests/test_index_build.py` pins the analyzer's actual behaviour
(`analyze("CWE-307") == ["cwe","307"]`, `analyze("T1110.001") == ["t1110.001"]`)
so a future Lucene/Anserini upgrade that changes tokenization fails loudly here
instead of quietly skewing RQ1.

---

## 2. Prompt versioning doesn't compose with resumability (affects RQ4 data integrity)

**The situation:** `PROMPT_VERSION` is recorded once per output file in a sidecar
`<output>.manifest.json` (chosen to avoid a schema sign-off round). But
`run_corpus_enrichment()` is resumable — a resume skips already-done docs.

**The problem:** if the prompt changes between an initial run and a resume, one
JSONL ends up holding records produced under two different prompt versions, under
a single manifest claiming one version. Since the rejection log is the RQ4
dataset, that's silent provenance contamination that can't be untangled later.

**Proposed fix (no schema change needed):** on resume, compare the current prompt
hash against the manifest's; if they differ, refuse to append and require a new
output path (or an explicit `--force`). Cheap to add now while the corpus is
small and nothing's lost.

---

## 3. ~~`malformed_id` rejections — genuine or normalizer-fixable?~~ RESOLVED 2026-08-20

**Answer: neither. All five were the model putting the wrong `kind` label on
ordinary vocabulary.** The normalizer is not at fault and needs no change.

### What the five actually were

| term | document | is it an identifier? |
|---|---|---|
| `heap-based` | CVE-2017-5974, CVE-2017-5975 | no — a description of a bug class |
| `zzip_get32` | CVE-2017-5974 | no — a real zziplib function name |
| `local` | CVE-2017-5975 | no — a CVSS metric value |
| `medium` | CVE-2017-5975 | no — a CVSS metric value |

None is a format variant of a real identifier, so the normalizer was right to
refuse all of them. But none is a fabricated identifier either. What happened is
that the model tagged them `kind: "structural"` — the label that means "this is
a formal ATT&CK/CWE/CAPEC identifier". The pipeline routed on that self-declared
label, sent them to the graph gate, and the graph gate correctly found no
identifier and returned `MALFORMED_ID`.

### Why it mattered enough to fix

**It corrupted the RQ4 headline number.** RQ4 asks how often the model
hallucinates an invalid identifier, and the rejection log is the dataset that
answers it. In this run Qwen2.5-7B fabricated **zero** identifiers — but the log
recorded 5 `malformed_id`. Anyone reading it later sees five hallucinations that
never occurred. A form-filling slip was being booked as a hallucination.

**It threw away a good term.** `zzip_get32` is a real symbol from the software
the CVE is about, and has DF 0 in the base index — maximally discriminative,
exactly the vocabulary enrichment exists to add. It was discarded over a label.

### The fix

`is_id_shaped()` in `src/sira_cti/graph/normalize.py` asks a new question:
*was this even an attempt at an identifier?* — separate from
`looks_structural()`, which asks whether the attempt *succeeded*. The gap
between them is what matters:

```
looks_structural("CWE-307")    True    valid identifier          -> graph gate
looks_structural("CWE-abc")    False   but is_id_shaped -> True  -> MALFORMED_ID
looks_structural("heap-based") False   and is_id_shaped -> False -> relabelled
```

`_route_kind()` in `corpus_side.py` uses that gap. A `structural` label on
something that never reached for an identifier is demoted to `colloquial` and
judged on its merits like any other vocabulary. A term that *did* reach for an
identifier and missed (`CWE-abc`, `T99`) stays `MALFORMED_ID` — that is the real
RQ4 hallucination signal and it is preserved exactly.

The routing is deliberately **one-way**: it only ever demotes `structural`, never
promotes into it. Promoting a term the model called colloquial would put an
unvalidated identifier into the structural pool and silently change RQ4's
denominator.

`colloquial` is the demotion target because `TermKind` has no `unknown` member and
adding one would be a frozen-contract change requiring four-owner sign-off. The
prompt defines `colloquial` as "an informal name an analyst might type", which is
what these terms genuinely are.

### Measured effect (replay, no new LLM calls)

`malformed_id` 5 -> 0. `zzip_get32` accepted at DF 0. `heap-based`, `local` and
`medium` fall through to `too_common` at DF 684, 810 and 1910 — still rejected,
but for the true reason.

### Known limitation, accepted deliberately

`is_id_shaped` is a shape test, so real security jargon that happens to look like
an identifier — `S3 bucket`, `C2 server` — reads as ID-shaped and would still be
recorded as `malformed_id` if the model labels it structural. This is the
conservative direction (it keeps them out of the index rather than letting them
in unvalidated) and neither appeared in the real run, but it is a known source of
a small `malformed_id` overcount. See question 6 for the related CVE case.

---

## 4. (Handoff to Module 3) expansion-field length normalization

Not a Module 1 action, but flag it in the Module 1→3 handoff so Student 3 decides
knowingly: BM25 length-normalization is per-field in Lucene, and the `expansion`
field is short. So `BM25(q_exp, d)` against the expansion field isn't scaled like
the contents field. Module 3 must decide explicitly whether `q_orig` searches
contents-only or contents+expansion, and how the two-field scoring maps onto
SIRA's `score(d) = BM25(q_orig,d) + w·BM25(q_exp,d)`. This is a fidelity question
against the paper's formula and should be a deliberate call, not inherited by
default.

---

## 5. (Low priority) subprocess interpreter bug

`src/sira_cti/index/build_base.py` calls the pyserini indexer subprocess as
`python` by name. On this machine conda's Python got picked instead of the venv's.
Should use `sys.executable`. Masked by the `.venv/bin/python` explicit-path
workaround, so low urgency, but it's a real portability bug.

---

## 6. (New, opened 2026-08-20) Should a CVE identifier count as "structural"?

`is_id_shaped` deliberately treats `CVE-2017-5974` as ID-shaped, so a CVE
identifier the model labels `structural` is still recorded as `malformed_id`
rather than being demoted to ordinary vocabulary.

That was the conservative default, not a decision. The tension: the ontology
graph covers ATT&CK, CWE and CAPEC only — it has no CVE nodes, so a CVE
identifier can never be graph-validated and will always fail the structural
path. But a CVE identifier is also an excellent, highly discriminative search
term that enrichment arguably should be adding.

Three options, none taken yet:

1. leave it — CVE stays ID-shaped, and `malformed_id` quietly accumulates CVE
   identifiers that were never hallucinations;
2. demote CVE identifiers to ordinary vocabulary, so they face the DF gate and
   can enter the index on merit;
3. give CVE its own validation path (an existence check against the NVD/CVE
   feed rather than the ontology graph).

Option 2 is cheapest and probably right, but it touches what RQ4 counts, so it
needs a deliberate call. Note this interacts with Module 2: query-side
enrichment is specified to *avoid* guessing a specific CVE identifier, so
whatever is decided here should be consistent with that.


---

## 7. (New, opened 2026-08-20 — HIGH, affects RQ1 directly) Enrichment is largely re-proposing text the document already contains

**Measured on the 20-document run under the fixed gates: 80 of 131 accepted
terms (61.1%) already appear verbatim in the document's own text. For structural
identifiers it is 17 of 17 — 100%.**

Measurement method (be precise about this, a loose check overstates it): a
structural id counts as present if its literal canonical form appears in the raw
text after stripping punctuation; a phrase counts as present only if its analyzed
token sequence appears as a *contiguous run* in the document's analyzed tokens.
A set-membership check instead of a contiguous one inflates the number, because
`CWE-331` analyzes to `["cwe","331"]` and both tokens can occur far apart.

Breakdown by kind:

```
  structural :  17/17  already present (100%)
     symptom :  16/18  already present  (89%)
  colloquial :  26/40  already present  (65%)
     product :  21/55  already present  (38%)
 misspelling :   0/1   already present   (0%)
```

### Why this is the most serious finding so far

A term already in the document's `contents` is **already indexed and already
retrievable**. Injecting it into the `expansion` field adds no new way to reach
the document. It consumes one of the `max_terms_per_doc` (12) slots, costs
completion tokens, and contributes nothing to recall.

For the thesis specifically: **every single structural identifier the model
proposed was one already written in the CVE's own text.** CTIConnect's CVE
records embed their CWE mapping, so the model is reading `CWE-119` off the page
and handing it back. The ontology graph then validates it — correctly, but the
grounding is confirming a copy, not catching a leap of inference. RQ1 asks
whether graph-grounded proposals are more valid and discriminative than
ungrounded ones; if the grounded proposals are transcriptions, a high validity
rate measures the model's ability to copy, not the mechanism under test.

The prompt already says "Do NOT restate words already present in the entry — the
index already has those for free" (`prompts/corpus_side.py`). The model ignores
it, and **nothing in the pipeline enforces it.**

### Options

1. **Enforce it as a gate.** Reject a term whose analyzed tokens already appear
   contiguously in the document's own text. Cleanest and matches the stated
   intent. Needs a new `RejectReason` (`already_in_document`) = frozen-contract
   change = four-owner sign-off. Keeping these in the rejection log rather than
   dropping them is consistent with the project's "never silently drop" rule and
   would itself be a publishable measurement.
2. **Filter silently at index-injection time** (`build_enriched.py`) rather than
   at adjudication. No schema change, but it hides a real model behaviour from
   the RQ4 log — against the spirit of the project's conventions.
3. **Prompt-iterate first.** Cheapest experiment: the instruction exists and is
   being ignored, so try strengthening it (few-shot negative example, or feeding
   the model an explicit "words already present" list to avoid) and re-measure
   before building any gate.

### Option 3 was tried on 2026-08-20 and FAILED — recommendation is now option 1

A `corpus-v2` prompt was written and run against the same 20 documents. It made
the constraint operational rather than a bare negation, demonstrated the failure
with a `BAD reply` example, repeated it in the user turn, and told the model to
propose a *different* identifier when the entry already cites one. Full text and
analysis: `docs/experiments/prompt-corpus-v2.md`.

```
                                   v1        v2
  redundant share of accepted   61.1%     59.5%     <- target metric: unmoved
  GENUINELY NEW terms indexed      51        30     <- got worse
  structural accepted               17         3
  malformed_id                       1         3
```

The target metric moved 1.6 points (noise) while genuinely-new output fell by
41%. The model complied with the *letter* of the instruction — it proposed
fewer terms — without complying with its *intent*: it kept copying. The prompt
was reverted to `corpus-v1`.

**Do not retry this with stronger wording.** v1 already contained the
instruction, v2 made it about as forceful as a prompt can be, and the copying
rate barely moved. Two rounds of evidence say the model will not self-police
here.

**Recommendation: option 1 — enforce it as a gate.** This needs a new
`RejectReason` (`already_in_document`) on the frozen contract, so it needs
four-owner sign-off. Keep the rejected terms in the log rather than dropping
them, per the project's standing rule; the redundancy rate is itself a
publishable measurement about what an open-weight model does on this task.

Implementation note for whoever builds it: the check must be a **contiguous
analyzed-token match** (or a literal substring match for identifiers), not set
membership — `CWE-331` analyzes to `["cwe","331"]` and both tokens occur
separately in most CVE records, so a set check reports false redundancy. The
measurement code used for both runs is the reference.

### Related, same run

- **The model proposed zero ATT&CK and zero CAPEC identifiers** across 20
  documents. All 19 structural proposals were CWE (18) plus one CVE. Structural
  terms were only 19 of 223 proposals (8.5%) overall. The graph-grounding
  mechanism under test is barely being exercised, and the ATT&CK half of the
  ontology not at all. This may be a property of CVE source documents
  specifically — see the sampling caveat below — but it needs checking before
  any RQ1 claim about "the ATT&CK/CWE/CAPEC ontology" as a whole.
- **Sampling caveat: all 20 documents were CVEs.** `load_corpus(..., limit=20)`
  takes the first N in load order, and those are all CVE records. Nothing in this
  run says anything about how enrichment behaves on CWE, CAPEC or ATT&CK source
  documents. **Any RQ1 comparison across catalogues needs a stratified sample,
  not a prefix.** Worth adding a `--stratify` or per-kind limit to
  `scripts/enrich_corpus.py`.
