# Proposal: make the model say what an ID *is*, and check it

**Status: Module 1 implemented behind a config switch (2026-10-07) — awaiting
Modules 2, 3 and 4 on the contract change.**
**Needs:** agreement to add to `src/sira_cti/common/schemas.py` (the frozen
contract Modules 1–4 share):

- two new `RejectReason` values — `NAME_MISMATCH`, `LLM_JSON_ERROR`
- one new enum — `RejectStage` (`parse` / `graph` / `name` / `df`)
- five new optional fields on `ProposedTerm` — `claimed_name`,
  `official_name`, `rejected_at_stage`, `in_counting_run`, `graph_distance`
- **added 2026-10-08, same sign-off round:** two more optional fields —
  `name_scorer` (which scorer version made the name verdict) and `repaired_to`
  (the id a name-mismatched proposal was probably meant to be; measurement
  only). See "Amendment" at the end.
- `SCHEMA_VERSION` 1.1.0 → 1.3.0 (1.2.0 was the first five fields; it was
  never signed off, so there is one decision to make, not two)

**All of it is additive.** No existing field changes name, type or meaning, and
a 1.1.0 record loads into the 1.2.0 dataclass unchanged (there is a test:
`test_v1_1_0_records_without_the_new_fields_load_cleanly`). But new enum values
are still a contract change — Module 4 switching on `RejectReason` will meet
values it has never seen — so it needs the four-way call.

**Opened by:** Module 1, 2026-10-07. **Background:**
`docs/04_OPEN_QUESTIONS.md` question 8.

If you own Module 2, 3 or 4: read **"The problem"**, then skip to **"What this
changes for you"** and **"Decision needed"**.

---

## The problem

SIRA's grounding step checks a proposed term against a real category graph.
In the original paper that graph is Wikipedia's categories, and a Wikipedia
category's identifier **is its name** — `Category:Phishing`. So one lookup
answers two questions at once: does this category exist, and is it about the
right thing?

MITRE identifiers are integers. `CWE-79`. `T1056.004`. The name lives
somewhere else entirely. And the number space is *dense*: CWE has roughly 940
active entries packed into the range 1–1425. So "does `CWE-74` exist?" is
nearly always yes, no matter why the model wrote it.

On 2026-10-07 we ran 40 documents through `qwen2.5:14b`. On the entry for
**CWE-512, "Spyware"**, the model proposed:

```
CWE-73, CWE-74, CWE-75, CWE-76, CWE-77, CWE-78, CWE-79, CWE-80, CWE-81
```

All nine exist. All nine were **accepted** by the graph. `CWE-79` is
cross-site scripting. None of them is about spyware. The model was counting,
and the existence check cannot tell counting apart from knowing.

It happened seven times in that one run. 38 of the 125 structural ids proposed
(30%) sat in a run of three or more consecutive numbers; 34 of those were not
copied from the document:

```
CWE-512   Spyware                      -> CWE-73 .. CWE-81       (9 ids, all accepted)
CWE-1169  SEI CERT C ... Concurrency   -> CWE-481 .. CWE-486     (6 ids)
CWE-940   Improper Verification of ... -> CWE-346 .. CWE-349     (4 ids)
T1056.001 Keylogging                   -> T1056.002 .. T1056.009 (.002-.004 real,
                                                                  .005-.009 invented)
T1430.001 Remote Device Management ... -> C0023 .. C0026         (campaign ids)
T1003.006 DCSync                       -> T1113, T1114, T1115
CAPEC-24  Filter Failure through ...   -> CWE-118, CWE-119, CWE-120
```

**Why this is a research finding and not just a bug.** The headline RQ1 number
is "share of graph-grounded proposals that validate". Going from the 7B to the
14B, that number *rose* — 12/14 to 109/125 — while the proposals got
**worse**. A validity rate that improves when a model starts enumerating is
not measuring grounding. Reporting it without something alongside it would be
misleading, and it is the kind of thing an examiner asks about.

So the claim this project can defend is narrower and more interesting than the
one we started with:

> An existence check is sufficient grounding for a named category namespace
> like Wikipedia's, and insufficient for a dense integer namespace like
> MITRE's. Transferring SIRA's grounding to CTI requires checking the
> identifier's *meaning*, not just its existence — and the cheapest way to get
> at meaning is to make the model commit to the identifier's name and check
> that.

## What's being proposed

**Ask for the name; check it against MITRE's.**

The prompt (`corpus-v4`) now requires a `"name"` on every structural proposal:

```json
{"term": "T1110.003", "kind": "structural", "name": "Password Spraying"}
```

`OntologyGraph.check_name()` compares that claim to the node's official title
and aliases. A mismatch is rejected as `NAME_MISMATCH`.

It caught a real error on the first two documents of the smoke test:

```
CVE-2012-4687 -> CWE-310, claimed "Insufficiently Protected Credentials"
                 official  "Cryptographic Issues"            REJECTED
```

That is CWE-522's title on CWE-310's number. The existing pipeline accepted
it, because `CWE-310` exists.

### How the comparison works

Titles are compared on **content words**, using the overlap coefficient
(shared words ÷ the shorter title's word count), with a threshold from config
(`enrichment.name_match_min_overlap`, default `0.5`).

Why the shorter title and not both? Because MITRE titles are long and formal
while the name anyone actually uses is short:

```
CWE-79 official: "Improper Neutralization of Input During Web Page
                  Generation ('Cross-site Scripting')"
model says:      "Cross-site Scripting"                      <- correct
```

Dividing by the longer title scores that 0.3 and calls a correct answer a
mismatch. Dividing by the shorter one scores it 1.0.

Words that open a large share of all CWE titles — `improper`, `insufficient`,
`incorrect`, `missing` — are dropped along with ordinary English stopwords, so
two unrelated weaknesses cannot match on catalogue house style.

**Known weakness, measured rather than patched.** The same arithmetic means a
one-word claim passes on one shared word. The alternative (requiring two
shared words) would reject genuinely one-word titles — `CWE-512` really is
just "Spyware". So the check keeps the generous rule and
`scripts/report_enrichment.py` reports how many passes rest on a single shared
word, as a caveat on the number rather than a hidden flaw in it.

### Where it actually fails: inside a formulaic family

The 7B run (`corpus-v4`, 40 documents) caught four wrong titles and **let two
through**. Both escapes are the same failure:

```
CWE-74 proposed, claimed "...used in an SQL Command ('SQL Injection')"
       official      "...in Output Used by a Downstream Component ('Injection')"   overlap 0.67  PASSED
CWE-89 proposed, claimed "...used in an OS Command ('OS Command Injection')"
       official      "...used in an SQL Command ('SQL Injection')"                 overlap 0.83  PASSED
```

The model is off by one entry *within the injection family*, and CWE's titles
in that family are near-identical sentences. Measured on the real catalogue,
the official titles of CWE-78 and CWE-89 score **0.83 against each other** — so
at any threshold that admits a correct answer, each family member passes as any
other. By contrast the four it caught were cross-family confusions, where the
score is 0.00:

```
CWE-29   claimed CWE-119's title       overlap 0.00  REJECTED
CWE-1230 claimed CWE-119's title       overlap 0.00  REJECTED
CWE-173  claimed CWE-20's title        overlap 0.00  REJECTED
CWE-362  claimed CWE-835's title       overlap 0.20  REJECTED
```

**So the honest characterisation of this check is: it catches cross-family
confusions and misses within-family neighbours.** That is still a real gain —
`CWE-362` on a CWE-835 document is exactly question 8's "real but irrelevant"
case, and corpus-v3 accepted it — but the claim in the write-up has to be the
narrow one.

### Two candidate fixes, measured offline, one of which does not work

Both `claimed_name` and `official_name` are stored on every proposal, so a
better scorer can be tested by re-scoring saved runs with **no model calls at
all**. Done for the 7B run:

1. **Weight title words by rarity across the catalogue (IDF).** *Does not
   work.* Verdicts changed: **zero**. CWE-74 moves 0.67 → 0.62, CWE-89 0.83 →
   0.79, both still pass. The reason is that the injection family shares its
   *rare* words too — `neutralization`, `special`, `elements` — while the
   distinguishing words (`sql`, `os`, `downstream`) are one or two tokens out
   of eight. Worth recording as a negative result, because it is the obvious
   thing to try.

2. **Compare against the parenthesised short name, with a symmetric score.**
   *Works, on this evidence.* CWE titles carry their common name in
   parentheses, and those are discriminative where the long titles are not:

   ```
   claimed "SQL Injection"        vs CWE-74's "Injection"              jaccard 0.50
   claimed "OS Command Injection" vs CWE-89's "SQL Injection"          jaccard 0.25
   claimed "Cross-site Scripting" vs CWE-79's "Cross-site Scripting"   jaccard 1.00
   ```

   Both escapes drop to the threshold or below while the correct answer stays
   at 1.00. Note the symmetric measure is what makes this work, and it only
   becomes safe *because* the short name is short — a symmetric score against
   the full official title would reject "Cross-site Scripting" as a 0.3 match,
   which is why the current check uses the asymmetric one.

   **This needs a loader change, not just a scorer change:** the CWE loader
   does not currently extract those short names, so `node.aliases` is empty for
   every CWE. `check_name()` already scores against aliases, so populating them
   from the parenthesised title (and from CWE's `Alternate_Terms` element) would
   feed this check without touching its logic.

**Module 1's recommendation:** ship the overlap check as written — it is the
specified design, it works on cross-family errors, and its failure mode is now
measured rather than hypothetical — then do the alias extraction as a separate,
testable change and re-score the saved runs offline to confirm before re-running
anything. Not folded into this proposal because changing the scorer mid-run
would make the 7B/14B comparison incomparable.

A third idea was tested and **rejected**: scoring the claimed name against
every title in the ontology and requiring the proposed id to be the best match.
It does flag both escapes, but it is contaminated by short titles — the ATT&CK
data source `DS0017` is named "Command", which scores 1.00 against any claim
mentioning a command, so it "wins" against the real answer. It amplifies the
one-word weakness above instead of fixing it.

### Stage order: existence first, then name

```
parse -> graph (exists? current?) -> name (is it what the model said?) -> df (discriminative?)
```

Not interchangeable. An id that does not exist has no official title to
compare against, so checking names first would report every pure
hallucination as a `NAME_MISMATCH` and merge the two most distinct RQ4
findings — "this id is invented" and "this id is real and the model doesn't
know what it is". `rejected_at_stage` records which gate fired, so the
ablation ("how much is the name check doing that the existence check wasn't")
is answerable directly from the JSONL.

A `NAME_MISMATCH` term keeps `graph_validated=True`. That is deliberate and it
is the whole point: the record says, truthfully, *this identifier exists and
the model still didn't know what it was*.

### Two things that are measured and never gated

**`in_counting_run`** — true when an id sits in a run of ≥3 consecutive
numbers from the same series within one document's proposals. It changes no
verdict. Some enumeration is legitimate (a technique's real sub-techniques
*are* consecutive by construction), and we don't yet know the split; gating on
it would foreclose the question that the flag exists to answer.

**`graph_distance`** — hops from the document's own ontology node to the
proposed id, over hierarchy and cross-catalogue mapping edges, direction
ignored. Null when either end isn't a graph node, which is every CVE.

Measured on the seven counting runs the 14B produced, the two flags together
do something neither does alone:

```
CWE-512  Spyware                -> CWE-73 .. CWE-81  all 4 hops   enumeration
T1003.006 DCSync                -> T1113/4/5         all 4 hops   enumeration
T1056.001 Keylogging            -> .002/.003/.004    2 hops       real siblings
CAPEC-24 Filter Failure thru... -> CWE-118/119/120   all 1 hop    GENUINE
```

`CAPEC-24` is why neither becomes a gate. Three consecutive CWE numbers trip
the counting-run flag, but they are the buffer-bounds weaknesses that attack
pattern genuinely maps to. MITRE numbered related weaknesses sequentially, so
"consecutive" and "actually related" are correlated in CWE. A gate on the flag
alone would reject correct cross-catalogue mappings — exactly the links
enrichment exists to add. **Counting run _and_ distance >= 3** is the
enumeration signature; either one alone is wrong.

Distance is **reported, never filtered on**, and this is a deliberate
reversal of question 8's option 2. Corpus-side enrichment exists to add the
links an entry's own data lacks. The distant ids therefore contain both the
model's worst guesses *and* the genuinely novel connections that would justify
the whole method — and distance alone cannot separate them. A distance filter
would reject exactly the proposals that make the technique worth having, and
would make the recall improvement look like it came from grounding when it
really came from only ever proposing near neighbours.

### The second new reason: `LLM_JSON_ERROR`

Separate problem, same sign-off round. One document in the 14B run
(`CAPEC-587`) produced a reply that would not parse — an array with one
element's opening brace missing. Unparsed documents are deliberately left
unwritten so a resume retries them. But at `temperature=0` the same prompt
returns the same bytes forever, so that document could never be finished and
the run could never report completion.

Diagnosed on 2026-10-07, and it was **not** truncation: Ollama reported
`done_reason="stop"` at 245 completion tokens with no cap in force, and the
reply ended with a well-formed `]`. It is a formatting slip mid-array.

Fixed properly by constrained decoding — the fix and its two false starts are
worth recording because the obvious one is wrong:

| setting | result on CAPEC-587 |
|---|---|
| unconstrained | one element's opening brace missing; identical on every retry |
| Ollama `format: "json"` | valid JSON, but a single **object** — one proposal where twelve were asked for |
| Ollama `format: <JSON Schema>` | 12 proposals, both models, first attempt |

So enrichment now sends the reply schema (`REPLY_SCHEMA` in
`prompts/corpus_side.py`). `LLM_JSON_ERROR` remains as the backstop: after one
retry with an explicit nudge, an unparseable document is written as a single
rejected term carrying the raw reply, with the full reply saved to
`<output>.raw_failures.jsonl`. It can never reach the index — the index build
reads accepted terms only — and it keeps the failure in the RQ4 dataset
instead of throwing it away.

## What this changes for you

**Module 2 (query-side).** You emit the same `EnrichmentRecord`. Nothing
breaks if you ignore all of this: every new field is optional, and
`name_match_min_overlap: null` reproduces the old adjudication exactly. If you
*do* want the name check on query-side proposals, `OntologyGraph.check_name()`
is in the shared graph tool, already tested. Worth considering — an analyst's
query is shorter than a catalogue entry, so a model proposing ids from it has
even less to go on.

**Module 3 (retrieval).** No change to what you read. `expansion_query()`
still returns accepted terms only, and a `NAME_MISMATCH` or `LLM_JSON_ERROR`
term is not accepted. The change you will notice is that **fewer structural
ids reach the expansion field** — if that moves your recall numbers, the
`--no-name-check` flag on `scripts/enrich_corpus.py` regenerates the old
behaviour for a clean A/B.

**Module 4 (audit).** This is mostly for you, and it is the part to check:

- Two new `RejectReason` values will appear. If you switch on the enum, add
  cases or you will hit an unhandled branch.
- `rejected_at_stage` lets you attribute rejections to gates without
  hard-coding the reason→stage mapping yourself.
- `graph_validated=True` on a rejected term is now a normal, meaningful state
  (name mismatch). Any code reading `graph_validated` as a proxy for
  `accepted` will now be wrong.
- `in_counting_run` and `graph_distance` are new measurement surfaces that may
  be more interesting for RQ4 than the rejection rate itself.
- The `llm_json_error` term inflates "terms proposed" by one per failed
  document. It is identifiable by its reason; exclude it if your denominator
  needs to be real proposals.

## Decision needed

1. **Add `NAME_MISMATCH` and `LLM_JSON_ERROR` to `RejectReason`, `RejectStage`,
   and the five optional `ProposedTerm` fields** — schema 1.2.0. Yes / no /
   changes.
2. **Should the name check be on by default?** Module 1's recommendation: yes
   for the final benchmark run, and keep `--no-name-check` so the
   existence-only ablation stays one flag away. The ablation is arguably the
   most defensible RQ1 result the project has — "existence-only vs
   existence+meaning, same model, same documents".
3. **Module 2: do you want it query-side too?** If yes it should be the same
   threshold from the same config key, or the two sides stop being comparable.

| Owner | Decision | Date | Notes |
|---|---|---|---|
| Module 1 | **Approve** (implemented, default on, ablation flag kept); amended 2026-10-08 to 1.3.0 | 2026-10-07 | `name_scorer` + `repaired_to` added — see Amendment |
| Module 2 | *pending* | | Also: name check on query-side proposals? |
| Module 3 | *pending* | | Expect fewer structural ids in the expansion field |
| Module 4 | *pending* | | Two new reasons + `graph_validated=True` on rejects |

## Still open after this

- The name check asks whether the model knows what an id **is**. It does not
  ask whether that id is **relevant to this document**. `CWE-79` with the
  correct title "Cross-site Scripting", proposed for a spyware entry, passes
  both gates. That is question 8's remaining half, and `graph_distance` is the
  measurement that would inform it — deliberately not a gate yet.
- The prompt asks for the title **without warning that it will be checked**.
  That keeps the model's behaviour comparable to `corpus-v3` and measures its
  unprompted error rate. A warned prompt is a separate experiment, and would
  measure the deterrent rather than the error.

---

## Amendment, 2026-10-08: scorer versions and `repaired_to` (schema 1.3.0)

Everything below was measured **offline** on the saved `corpus-v4` runs —
`scripts/rescore_enrichment.py` re-runs every gate on the stored proposals with
no model call. Replaying under the original scorer reproduces every saved
verdict on both files, so the differences below are the scorer and nothing
else.

### `name_scorer` — a verdict is not comparable without it

There are now three scorers (`sira_cti.graph.ontology.NAME_SCORERS`), and each
term records which one decided it:

| | rule | reach |
|---|---|---|
| `v1` | overlap against the title (what this proposal describes above) | every node |
| `v2` | symmetric match on the entry's **short names** — the quoted name in a CWE title and CWE `Alternate_Terms`; falls back to v1 where there are none, recorded as `v2:v1-fallback` | 122 of 1,450 CWE nodes; no ATT&CK, no CAPEC |
| `v3` | symmetric match everywhere, plurals folded — *experimental* | every node |

The CWE loader now fills `node.aliases` with those short names (it was empty
for every CWE). v1 deliberately keeps ignoring them, so runs already on disk
replay exactly.

| structural ids | 7B v1 | 7B v2 | 7B v3 | 14B v1 | 14B v2 | 14B v3 |
|---|---|---|---|---|---|---|
| proposed | 14 | 14 | 14 | 157 | 157 | 157 |
| accepted | 6 | 4 | 4 | 56 | 54 | 46 |
| rejected at `graph` | 4 | 4 | 4 | 32 | 32 | 32 |
| rejected at `name` | 4 | 6 | 6 | 69 | 71 | 79 |
| name verdicts that fell back to v1 | – | 3 of 10 | – | – | 90 of 125 | – |
| counting-run ids accepted | 0 | 0 | 0 | 7 of 51 | 7 of 51 | 4 of 51 |

Verdicts that change, v1 → v2 (all four, both files):

```
7B   CWE-74   accepted -> name_mismatch   claimed CWE-89's title ('SQL Injection')         correct catch
7B   CWE-89   accepted -> name_mismatch   claimed CWE-78's title ('OS Command Injection')  correct catch
14B  CWE-416  accepted -> name_mismatch   "Double Free" for 'Use After Free'               correct catch
14B  CWE-415  accepted -> name_mismatch   "Double Free or Release of Same Resource"
                                          for 'Double Free'                                arguably a FALSE rejection
```

So v2 does what it was built for — both known within-family escapes are
caught — and its honest limit is reach, not accuracy: on the 14B it only had a
short name to work with for 35 of 125 verdicts.

v3 changes 10 verdicts on the 14B: the two above, six more wrong titles v2
cannot reach because the node has no short name (`CAPEC-423` claimed with
CAPEC-421's title; `CAPEC-424` with CAPEC-423's; `T1098` "Account
Manipulation" claimed as "Account Discovery"; `T1056.002`; `T1552`; `CWE-1230`),
and two that are **stale rather than wrong** — `T1046` claimed as "Network
Service Scanning", which was its title before MITRE renamed it to "Network
Service Discovery". A model whose training data predates a rename is a
different finding from a model that does not know the id, and v3 cannot tell
them apart.

### `repaired_to` — what the model probably meant

For a `name_mismatch`, the pipeline now looks for a real id **within 2 hops of
the source document** whose official name matches what the model *said*
(matched symmetrically, whatever scorer adjudicates — naming a candidate is a
stronger claim than not rejecting one). If there is **exactly one**, it is
recorded as `repaired_to`. The term stays rejected and `reject_reason` stays
`name_mismatch`. Two candidates means the name does not identify an id, so
nothing is recorded.

On the 14B run (v1 verdicts, to match the "33 within 2 hops" figure above):

```
69 name mismatches
  33 with the proposed id within 2 hops of the document
       9 repair cleanly      2 ambiguous      22 match nothing nearby
  13 clean repairs in all (4 more where the proposed id itself was further out)
       2 are the document's own id   -> recorded, never indexed
      11 would be indexed under the ablation flag
```

Examples of clean repairs: `CAPEC-24`: `CWE-119` claimed as "Integer Overflow
or Wraparound" → `CWE-190`; `CWE-1169`: `CWE-364` claimed as "Improper Locking"
→ `CWE-667`; `CAPEC-267` (7B): `CWE-173` claimed as "Improper Input
Validation" → `CWE-20`. The two ambiguous ones: "Dangling Pointer" matches both
`CWE-416` and `CWE-825`; "Credential Access: Credentials in Files" matches both
`T1552.001` and the tactic `TA0006`.

Two cautions. Repairs scoring 1.00 are exact title matches and look right; the
three scoring 0.67–0.80 are weaker, and one of them lands on a *tactic*
(`T1005` claimed as "Credential Access: Credential Dumping" → `TA0006`), which
is a category, not a technique. And a CVE document has no ontology node, so
nothing on a CVE is ever repaired.

**`enrichment.index_repaired_ids` (default `false`)** makes
`scripts/build_index.py --stage enriched` also index `repaired_to` ids. That is
the retrieval ablation for Modules 3 and 4: does indexing what the model
*meant* beat indexing nothing? The default index is byte-for-byte what it was
before the flag existed (there is a test).

### What this adds for each owner

- **Module 2:** `check_name(..., scorer=...)`, `name_candidates()` and
  `within()` are on the shared `OntologyGraph`; interfaces are listed in
  `docs/proposals/module1-freeze.md`.
- **Module 3:** one new flag you may flip for an ablation; nothing changes
  unless you do.
- **Module 4:** group name verdicts by `name_scorer` before comparing them — a
  `v2:v1-fallback` verdict is a v1 verdict. `repaired_to` on a rejected term is
  a new RQ4 category: *knew the concept, wrote the wrong number*.
