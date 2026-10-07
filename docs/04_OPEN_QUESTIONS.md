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

*Second instance, 2026-09-15 (`corpus-v3` run):* `'Mitre mobile attack'` — the
`"mitre-mobile-attack"` kill-chain name copied from `T1470`'s own text, labelled
structural — was recorded as `malformed_id`, because `_ID_SHAPED` treats any
string *starting with* `mitre` or `att&ck` as an identifier attempt. A tighter
rule would require an id-like token after the prefix (`MITRE ATT&CK T1110`
yes, `Mitre mobile attack` no). Not changed yet: it alters what RQ4 counts, and
at one case in 40 documents it can wait for a deliberate change with its own
before/after.

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

## 5. ~~(Low priority) subprocess interpreter bug~~ NOT A BUG — corrected 2026-09-15

~~`src/sira_cti/index/build_base.py` calls the pyserini indexer subprocess as
`python` by name.~~ It doesn't, and never did: it has run
`sys.executable -m pyserini.index.lucene` since its first commit (`988709b`), so
the subprocess always uses whichever Python launched the script. The conda Python
seen on this machine must have come from starting the script itself with a bare
`python` — which the "always use `.venv/bin/python`" rule in `01_ENVIRONMENT.md`
already covers. Nothing to fix.

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

### Sign-off requested 2026-09-15 — see `docs/proposals/already-in-document-gate.md`

The recommendation below (option 1) has been written up as a formal decision
request for all four owners: exact `RejectReason` value, where the gate slots
into `corpus_side.py`, the detection rule, and what it changes for each
module. Nothing in `schemas.py` has been touched — that document *is* the
sign-off request, not a pre-emptive implementation. Update this section once
a decision comes back.

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
  `scripts/enrich_corpus.py`. — *Done 2026-09-15 (`--per-kind`); see below.*

### Stratified run, 2026-09-15 — the finding holds on every document type, and is worse than it looked

10 randomly sampled documents of each type (`corpus_stratified.jsonl`, seed 42).
Full numbers are in the `03_STATUS_LOG.md` entry of the same date. For this
question, three things:

**1. Every structural identifier was copied — on all four document types.** The
headline rule above only catches ids written literally in the text, and on CWE,
CAPEC and ATT&CK documents it scored structural terms 0/5, 0/3 and 0/3 already
present, which looks like the problem is CVE-only. It isn't. Classifying each
structural proposal by where it could have come from
(`scripts/measure_redundancy.py`):

```
  cve     10/10  literal      "CWE-79" is written in the CVE's own text
  cwe      5/5   own id       proposed CWE-1321 for the CWE-1321 entry
  attack   4/4   own id       proposed T1437 for the T1437 entry
  capec    3/3   bare number  text has "@CWE_ID": "120"; proposed CWE-120
```

The own-id case comes from the prompt, not the document: `corpus_kb` rows for
these types hold the title and a JSON body but not the id, and the prompt header
supplies it (`"Catalogue entry (cwe, id CWE-1321)"`). The bare-number case is the
CAPEC JSON writing related ids without their prefix. Across all three runs to
date, **47 of 48 structural proposals were copies**; the one exception is
`CWE-125` for `CVE-2018-6484` (v2 prompt), a record that cites no CWE, and
whether that is the correct CWE has not been checked.

**2. The redundancy check proposed for the gate needs to cover these.** As first
written, the proposal's detection rule (literal id, contiguous tokens) would let
every own-id and bare-number copy through. The proposal has been amended; see its
"Update after the stratified run" section, which also raises the harder question
of whether the prompt header should give the model the id at all.

**3. The zero-ATT&CK result was not a sampling artifact, and not missing
information.** ATT&CK ids appear only on ATT&CK documents, only as their own id.
3 of the 10 sampled CAPEC entries contain explicit ATT&CK taxonomy mappings in
their own text (e.g. `CAPEC-267` -> `"Entry_ID": "1027"`) and the model proposed
none of them. So the grounding mechanism under test has still not been shown a
single cross-catalogue proposal from this model.

**Answered 2026-10-07: model.** `qwen2.5:14b` on the same 40 documents, same
prompt, proposed 37 ATT&CK ids on ATT&CK entries (7B: 0) and 125 structural ids
overall (7B: 14). Cross-catalogue proposals did appear on CAPEC entries, but 24
of their 27 came from labelled mapping fields in the entry's own JSON, so
genuine cross-catalogue inference is still rare (clearest case: `CWE-1321` ->
`CAPEC-448`). And see question 8: much of the increase is sequential
enumeration, not inference. Original reasoning preserved below.

Prompt or model? The live prompt (`corpus-v1`) only defines what a structural id
*is*; it never asks for related ids from other catalogues. But the reverted
`corpus-v2` prompt did ask explicitly — "propose the ATT&CK technique this
weakness is exploited by, a related CAPEC attack pattern" — and across 20 CVE
documents it returned 7 structural ids, **all CWE, zero ATT&CK, zero CAPEC**.
That points at the model rather than the wording, with one caveat: v2 also
suppressed output overall (see `docs/experiments/prompt-corpus-v2.md`), so it is
not a clean test. This is now closer to the centre of RQ1 than the redundancy
rate is: if Qwen2.5-7B does not make cross-catalogue links, the graph gate has
nothing to catch during development, and the frontier model reserved for the
final run may behave completely differently — meaning development-time
measurements of the gate would not predict final-run behaviour at all.

### Decisions and the `corpus-v3` run, 2026-09-15

Module 1 approved the gate (structural check limited to literal ids and
labelled id fields) and removed the document's own id from the prompt header
(`corpus-v3`). Proposal: `docs/proposals/already-in-document-gate.md`, now
awaiting Modules 2/3/4. Re-running the same 40 documents under `corpus-v3`: the
own-id copies went from 9 to 0; ATT&CK entries then proposed no identifiers at
all, and the only two identifiers not copied from anywhere were both wrong —
which is question 8.

---

## 8. (Opened 2026-09-15 — **PARTLY ANSWERED 2026-10-07**) The graph gate accepts identifiers that are real but irrelevant

> **Update, 2026-10-07.** Half of this is now addressed and shipped behind a
> config switch: a **name-ID consistency check** (`docs/proposals/name-id-consistency.md`).
> Asking the model to state what each id *is* and checking that against MITRE's
> title cut structural acceptance on the 14B from 109/125 (87%) to 56/157 (36%),
> and cut accepted counting-run ids from 33/38 to 7/51. It catches the
> motivating case directly: `CWE-835` -> `CWE-362` with the model reciting
> CWE-835's own title.
>
> **What remains open is the other half**, and it is the harder half: the name
> check asks whether the model knows what an id *is*, not whether that id is
> *relevant to this document*. `CWE-79` proposed for a spyware entry **with its
> correct title** passes both gates. `graph_distance` is now recorded per
> proposal to inform that decision, and is deliberately not a gate — see below
> for why the `CAPEC-24` case makes a distance gate unsafe.
>
> One number that needs a human call: **33 of the 69 name-mismatch rejections
> are within 2 hops of the document**, so the check discards structurally
> plausible ids. For retrieval the id is what gets indexed, so those would have
> helped recall; for RQ1's claim about grounding they are not evidence of
> grounding, since the model did not know what it had proposed. Which of those
> two framings the project uses is a supervisor question, not a Module 1 one.

**What happened.** In the `corpus-v3` stratified run, the model made its first
two structural proposals that were not copied from the entry or the prompt:

```
  CWE-1321 Prototype Pollution  -> proposed CWE-134 Use of Externally-Controlled Format String
  CWE-835  Infinite Loop        -> proposed CWE-362 Race Condition
```

Both ids exist, so both were accepted. Both are wrong for their entry: neither
is a parent, child or sibling, and the only ancestor each pair shares is a CWE
Pillar (`CWE-664`, `CWE-691`), the very top of the hierarchy.

**Why it matters.** The grounding step under test (`OntologyGraph.validate()`)
answers one question: does this identifier exist, and is it current? That catches
invented ids (`T9999`) and stale ones (revoked/deprecated). It cannot catch a real
id attached to the wrong document — and on the evidence so far, that is the
error this model makes when it isn't copying. Qwen2.5-7B has fabricated **zero**
non-existent ontology ids: `not_in_graph` is 0 in all five saved runs (125
documents). So during development the gate's
existence check has had nothing to reject, while the one kind of wrong
identifier that did appear sailed through. An RQ1 result of "graph-grounded
proposals are ~100% valid" would be true and would not mean what a reader
assumes.

It also means copied identifiers and wrong identifiers look identical in the
current rejection log — both are accepted and `graph_validated=True`.

**Options — not decided.**

1. **Report it, don't gate it.** Keep validation as existence-only, and measure
   relatedness offline (graph distance between the proposed id and the entry, or
   the ids the entry cites) as a write-up metric. No code or contract change.
2. **Add a relatedness gate.** Reject a structural id that is not within *k*
   hops of an anchor: the entry itself where it is a graph node (CWE, CAPEC,
   ATT&CK entries), or the ids the entry cites (a CVE's CWE). The graph tool
   already exposes parents/children/siblings/mapped links, so this is cheap to
   build — but it needs a new `RejectReason` (four-owner sign-off), a choice of
   *k*, and a guard against it rejecting correct-but-distant links (a CAPEC
   pattern legitimately mapping to an ATT&CK technique is one "mapped" hop, not
   hierarchy distance).
3. **Treat it as model-scale noise.** Two cases at n=40 is thin. Re-check with a
   larger open-weight model before designing anything — if a bigger model stops
   making these, option 1 is enough.

### Option 3 was tried on 2026-10-07 (`qwen2.5:14b`) — it is worse at scale, not noise

The larger model proposes 125 structural ids where the 7B proposed 14. Of the 83
that are not copied from anywhere, **29 are adjacent (+1) to another id proposed
for the same document** — the model enumerates consecutive numbers:

```
  CWE-512  Spyware  -> CWE-73,74,75,76,77,78,79,80,81   all 9 ACCEPTED by the graph
  T1056.001         -> T1056.002/.003/.004 (real siblings) then .005-.009 (don't exist)
  T1430.001         -> C0023,C0024,C0025,C0026
```

Consecutive CWE numbers almost always exist, so the existence check waves them
through: `CWE-512` is Spyware and `CWE-79` is cross-site scripting. The five
`not_in_graph` rejections in that run are simply where a counting run ran off
the end of a sub-technique range.

**This inverts how the RQ1 number must be read.** "Graph-validated proposal
rate" rose with model size while proposal *quality* fell. A validity rate that
goes up when the model starts enumerating is not measuring grounding; reporting
it without a relatedness measure alongside would be misleading.

### Measured 2026-10-07: distance does separate enumeration from real siblings

`graph_distance` (schema 1.2.0) is now recorded per proposal: hops from the
document's own ontology node to the proposed id, over hierarchy *and*
cross-catalogue mapping edges, direction ignored. Applied to the seven counting
runs the 14B produced, it splits them cleanly — and in doing so it rescues one
run that the counting-run flag wrongly accuses:

```
  CWE-512  Spyware                 -> CWE-73 .. CWE-81    all dist=4   enumeration
  T1003.006 DCSync                 -> T1113, T1114, T1115 all dist=4   enumeration
  CWE-1169 SEI CERT C Concurrency  -> CWE-481 .. CWE-486  dist=3-4     enumeration
  CWE-940  Improper Verification   -> CWE-346             dist=1       genuine sibling
                                      CWE-347 .. CWE-349  dist=3       then drifts
  T1056.001 Keylogging             -> T1056.002/.003/.004 dist=2       genuine siblings
                                      T1056.005 .. .009   not in graph  ran off the end
  CAPEC-24 Filter Failure thru...  -> CWE-118, CWE-119,
                                      CWE-120             all dist=1   GENUINE
  T1430.001 Remote Device Mgmt     -> C0023 .. C0026       unreachable  campaign ids
```

**`CAPEC-24` is the important row.** Three consecutive CWE numbers, so the
counting-run detector flags it — but `CAPEC-24` is "Filter Failure through
Buffer Overflow" and `CWE-118`/`119`/`120` are the buffer-bounds weaknesses it
genuinely maps to, one hop away. MITRE assigned related CWE numbers
sequentially, so consecutive numbering and real sibling-hood are **correlated**
in CWE. Neither signal is sufficient alone:

- the counting-run flag alone over-accuses (it would condemn `CAPEC-24`);
- distance alone under-accuses (`CWE-940 -> CWE-346` is one hop and fine, while
  `CWE-347..349` are three hops and were dragged along by the counting).

**Counting run _and_ distance >= 3 is the enumeration signature.** That is the
pair to report, and it is a direct argument for keeping both as measurements
rather than promoting either to a gate: a gate on the flag alone would reject
correct cross-catalogue mappings, which are precisely the links corpus-side
enrichment exists to add.

One oddity worth knowing: ATT&CK campaign nodes (`C00xx`) come out of the
loader with no edges at all, so their distance is `None` rather than large.
`None` means "cannot be placed", never "unrelated" — do not let the two blur in
a table.

**Revised recommendation: option 1 now, option 2 seriously considered.**
Measure relatedness (graph distance from the proposed id to an anchor — the
entry itself, or the ids it cites) and report it next to validity; that needs no
contract change and can be added to `scripts/measure_redundancy.py`'s sibling
script. Then decide on gating. Note the distance measure must treat `mapped`
cross-namespace links as near (a CAPEC->ATT&CK mapping is one hop by design) and
should *not* punish real siblings: `T1056.001 -> T1056.002` is a legitimate
neighbour, while `CWE-512 -> CWE-79` is nine hops of nothing. Worth putting to
the supervisor with these numbers: an existence-only check may simply be the
wrong definition of "grounding" for a hierarchical ontology.

---

## 9. ~~A document whose reply won't parse can never be finished~~ RESOLVED 2026-10-07

**Decision: constrain decoding with the reply schema; keep a nudged retry and,
after that, write the document off as `reject_reason=llm_json_error`.**
Implemented. The contract change rides in
`docs/proposals/name-id-consistency.md`.

### What was wrong

`CAPEC-587` broke the 2026-10-07 `qwen2.5:14b` run — 39 of 40 documents
finished. By design, a document whose reply doesn't parse is **not** written,
so a resume retries it. That is right for a transient failure (a dropped
connection, a model still loading). It is wrong for a deterministic one: at
`temperature=0` the same prompt returns the same bytes forever, so that
document could never be completed and the run could never report "all done".

### It was not truncation

Worth checking before assuming the token cap, because the config had a cap in
it that nothing was reading. Re-running that one document and logging the raw
completion:

```
no cap, no json mode   245 completion tokens, 724 chars, done_reason="stop"
cap 512, no json mode  245 completion tokens, 724 chars, done_reason="stop"
```

Identical, well under 512, and Ollama's own stop reason is `stop`, not
`length`. The reply even ends with a well-formed `]`. The actual defect is one
element's opening brace missing mid-array:

```
  {"term": "same origin policy bypass", "kind": "colloquial"},
   "frame busting evasion", "kind": "colloquial"},        <- no {"term":
```

A formatting slip, not a length problem. `parse_json_loose` cannot repair it
and should not try — a parser that guesses at broken replies is how an earlier
bug turned object replies into empty arrays and made parse failures look like
"the model proposed nothing".

### The fix, and the two things that looked like the fix

| `format` sent to Ollama | result on CAPEC-587 |
|---|---|
| absent | brace missing; identical on every retry |
| `"json"` | valid JSON, but a **single object** — one proposal where twelve were asked for |
| the reply schema | 12 proposals, both models, first attempt |

**Plain `format: "json"` is the wrong tool and would have been the obvious
choice.** It only promises *valid* JSON, and one object is valid JSON; it
biases the model towards `{...}` and guts a run instead of failing it. Sending
a JSON Schema (`prompts/corpus_side.py:REPLY_SCHEMA`, selected by
`enrichment.json_mode: schema`) pins the shape as well.

Cost: grammar-constrained sampling runs roughly 3x slower — `qwen2.5:7b` takes
~50s/document under the schema against ~17s unconstrained. If that becomes the
bottleneck, run unconstrained first and fall back to the schema only on a parse
failure; the unconstrained path parsed 39 of 40 documents, so the grammar would
run about once per run instead of forty times.

### And a backstop, because decoding is not a guarantee

`enrichment.json_retries: 1` retries once with an explicit nudge appended to
the user turn — the prompt *has* to change, since an identical prompt at
temperature 0 returns identical bytes, which also means the retry is not a
clean second sample and is counted separately in the run report. If that also
fails, `record_json_failures` writes the document with one rejected term
carrying `reject_reason=llm_json_error` and the raw reply as its `term`, with
the full reply in `<output>.raw_failures.jsonl`.

Two deliberate choices there. The raw reply is the term, rather than a fixed
placeholder, because *what the model actually emitted* is the evidence and a
placeholder would make every parse failure identical in the RQ4 dataset. And
recording failures is **off by default** in `run_corpus_enrichment` — only
determinism justifies giving up on a document, so the caller has to say so.

### Also fixed in passing: `enrichment.max_new_tokens` was read by nothing

It sat in the config for six weeks while every reply was generated unbounded.
It now reaches Ollama as `options.num_predict`. Ollama accepts and silently
ignores generation settings sent at the top level of the request, which is the
same trap `temperature`/`seed` have — see `01_ENVIRONMENT.md`.

---

## 10. (Opened 2026-10-07) Is the grounding effect a trend across model size, or two points?

**Open. Needs a decision about spending money, so it is a supervisor question,
not a Module 1 one.**

We have two model sizes and they disagree in an awkward way: the 7B invents
almost nothing and proposes almost nothing, the 14B proposes ten times as much
and invents in a specific, structured way (counting runs). Two points cannot
tell a trend from a quirk of one checkpoint. A third, larger model is the
obvious next step, and it is **not possible on this machine**:

| model | weights at 4-bit | fits in 16 GiB? |
|---|---|---|
| `qwen2.5:7b` | ~4.7 GB | yes |
| `qwen2.5:14b` | ~9.0 GB | yes, tightly |
| `qwen2.5:32b` | ~20 GB | **no** |

A 3-bit 32B quantisation is ~16 GB, which still leaves nothing for the OS, and
quantising harder to fit would confound "bigger model" with "more damaged
model" — the opposite of a clean comparison. So the third point needs a
frontier API, which this project reserves for the final benchmark run
(`01_ENVIRONMENT.md`, model policy).

**What it would cost**, measured from the actual token counts of the
`corpus-v4` 7B run (834 prompt + 216 completion tokens per document, averaged
over the sample):

| scope | prompt tokens | completion tokens | at $0.80/$4 per M | at $3/$15 per M |
|---|---|---|---|---|
| the 40-document sample | 33k | 8.6k | ~$0.06 | ~$0.23 |
| the full 6,044-document corpus | 5.0M | 1.3M | ~$9 | ~$35 |

(Those two price columns are representative mid-tier and frontier rates —
**check current list prices before quoting these to anyone**. The token counts
are measured and will not change.)

Time, not cost, is the real argument for the sample: an API run at
concurrency 4–8 finishes 40 documents in a few minutes, against ~35 minutes
locally for the 7B under schema decoding.

**Module 1's recommendation:** spend the ~$0.25 on the 40-document sample now,
on the same seed-42 documents, and keep the full-corpus run for the benchmark.
The question "does an existence check get weaker as models get stronger" is
load-bearing for the write-up, and answering it on two local checkpoints is
answering it on one data point and a hunch. Needs sign-off because the model
policy says development is open-weight only.
