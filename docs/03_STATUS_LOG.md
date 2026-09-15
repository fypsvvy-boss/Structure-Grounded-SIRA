# Status Log

> Rolling log — newest entry at the top. Update this at the end of every working
> session so the next session (human or AI) picks up exactly where this one left
> off. Keep entries short and factual.

---

## Current headline

**2026-09-15 (later): prompt `corpus-v3` — the document's own id removed from the
prompt — confirms the own-id copies came from the header (9 -> 0), and exposes
what the model does when it has nothing to copy: almost nothing, and wrong.**
ATT&CK entries produced no identifiers at all; CWE entries produced two, and
both were real CWEs that have nothing to do with the entry (Prototype Pollution
-> Format String; Infinite Loop -> Race Condition). The graph gate accepted both,
because it checks that an id *exists*, not that it *fits*. See the log entry
below and new open question 8.

**2026-09-15: first stratified run (10 documents of each type) — the model has
not made a single cross-catalogue inference.** Every structural identifier it
proposed on every document type was copied from what it was shown: 22 of 22 in
this run, 47 of 48 across all three runs to date. On CWE and ATT&CK documents it
hands back the document's *own* id, which the prompt header supplies. The
redundancy check as written in the question-7 proposal misses those copies, so
the proposal has been amended before it goes out. Full numbers in the log entry
below and in `04_OPEN_QUESTIONS.md` question 7.

**2026-09-15: the question 7 sign-off request is written and waiting on the
other three owners.** `docs/proposals/already-in-document-gate.md` — read
it before implementing anything in that area. Nothing in `schemas.py` has
changed; this is the request, not the implementation.

**Phase 1 / Module 1: two gate bugs found and fixed after the first real LLM run
(2026-08-20). Both were distorting RQ1/RQ4 rather than merely being untidy.**
`04_OPEN_QUESTIONS.md` questions 1 and 3 are now RESOLVED — read those two
sections before touching the enrichment gates, they carry the measurements.

In one line each:
1. **Every CWE identifier was being rejected as `too_common`, always**, because
   the DF gate scored `CWE-307` by its `cwe` token (49.2% of the corpus) instead
   of its number. ATT&CK ids bypassed the gate entirely. Fixed.
2. **`malformed_id` was counting form-filling slips as hallucinations**, inflating
   the RQ4 headline metric. The model had fabricated zero identifiers; the log
   said 5. Fixed.

**Data regenerated.** The old 5-record file (adjudicated under the broken gates)
is archived as `indexes/enrichment/corpus.jsonl.pre-gatefix` — keep it, it is the
only surviving record of the old behaviour and the "before" half of the evidence.
A fresh 20-document run and the enriched index now exist.

**⚠️ New and more serious: see `04_OPEN_QUESTIONS.md` question 7.** 61% of
accepted enrichment terms — and **100% of structural identifiers** — are words
already present in the document's own text, so they add no retrieval value. This
matters more than either gate bug.

Immediate priorities: (1) question 7 needs an enforced gate — prompting was
tried and failed, and the gate needs four-owner sign-off for a new
`RejectReason`, so start that conversation, (2) stratify the corpus sample (every
result so far is CVE-only), (3) investigate the zero ATT&CK/CAPEC proposals.

## Log

### Decisions on the question 7 proposal, and the `corpus-v3` prompt run
**Decisions (Module 1, 2026-09-15).** (1) Approve the `already_in_document`
gate, with its structural check limited to ids written in the text or named by
a labelled id field (`@CWE_ID`, `@CAPEC_ID`, `@Exclude_ID`, and `Entry_ID` only
inside an `ATTACK` taxonomy mapping) — the looser "any quoted number" version
would have matched WASC/OWASP codes like `"Entry_ID": "07"`. Still needs Modules
2/3/4. (2) Remove the document's own id from the prompt header; whether entries
should be searchable by their own id goes to Module 3. Both recorded in the
proposal, which now has a per-owner sign-off table.

**Changes.** Prompt `corpus-v3` (`"Catalogue entry (cwe):"`, no id; `corpus-v2`
is the reverted experiment's name so it is not reused). `enrich_corpus.py` now
records `PROMPT_VERSION` from the prompt module, and the
`enrichment.corpus_prompt_version` config key is gone — closes the latent bug
logged earlier. `measure_redundancy.py`: check tightened as above, plus a second
headline line for what the approved gate rule would reject. Four existing tests
used to pick documents by spotting "id T1110" in the prompt; they now key on the
document text instead (assertions unchanged), and one new test pins that the
prompt carries no id. 169 -> 170 tests.

**Run.** Same 40 documents as the `corpus-v1` stratified run (seed 42), output
`indexes/enrichment/corpus_stratified_v3.jsonl`. 40 docs, 0 failed, 695.5s
(slower than v1's 411.5s; nothing in the change explains that, most likely machine
load — not investigated). 419 terms: 210 accepted, 209 rejected — `too_common:
207`, `malformed_id: 2`.

```
  structural ids proposed            corpus-v1    corpus-v3
  cve     (literal copies)                10            9   (8 CWE + 1 CVE id, also in the text)
  cwe     (own id, from header)            5            0
          (not copied from anywhere)       0            2   <- both wrong, see below
  attack  (own id, from header)            4            0
  capec   (labelled-field copies)          3            2   (CWE-173; T1195.001)
```

**1. The own-id copies came from the header.** Removing it took them from 9 to
0, with no drop in overall output (437 -> 419 terms proposed). ATT&CK entries
now propose **no** identifiers at all; CWE entries propose two.

**2. The only two identifiers not copied from anywhere were both wrong.**

```
  CWE-1321 Prototype Pollution  -> CWE-134 Use of Externally-Controlled Format String
  CWE-835  Infinite Loop        -> CWE-362 Race Condition
```

Neither is a parent, child or sibling of its entry; the only ancestor each pair
shares is a CWE **Pillar** (`CWE-664`, `CWE-691`) — the top level of the
hierarchy, about as unrelated as two weaknesses in the same catalogue get. Both
passed the graph gate as valid, because validation checks that an id exists.
This is new open question 8: once the model stops copying, the error it makes is
"real but irrelevant", and existence checking cannot see it.

**3. First ATT&CK id ever proposed for a non-ATT&CK entry** — `T1195.001` for
`CAPEC-538` — but copied from that entry's own ATT&CK taxonomy mapping.

**4. Two `malformed_id`, neither a hallucinated ontology id.** `CVE-2024-34359`
for `CVE-2024-4897` is a CVE id that appears in the CVE's own text (question
6). `'Mitre mobile attack'` for `T1470` is the `"mitre-mobile-attack"`
kill-chain name copied from the entry and labelled structural; it was not
demoted to colloquial because `is_id_shaped()` treats anything *starting with*
"mitre" as an identifier attempt (`_ID_SHAPED` in `graph/normalize.py`). Same
class as question 3's known limitation — a small `malformed_id` overcount. Not
changed mid-experiment; noted under question 3.

**Redundancy** (headline rule): 55.6% -> 62.4% of accepted terms. Removing
identifiers from CWE/ATT&CK changed the denominators and n=10 per type is small;
treat as noise, not as the prompt making copying worse.

**⚠️ Live-file hazard.** `index.enrichment_path` is still `corpus.jsonl`, which
was written with `corpus-v1`. Running `enrich_corpus.py` without `--output` now
resumes into it under `corpus-v3` — two prompt versions in one file (question 2).
Always pass `--output` until question 2's guard exists. `indexes/enriched` is
still built from the v1 file.

### Stratified sample: 10 documents of each type
Command:
`.venv/bin/python scripts/enrich_corpus.py --per-kind 10 --output indexes/enrichment/corpus_stratified.jsonl`
(seed 42 from `eval.seed`, recorded in the manifest's new `sampling` field).
Result: **40 docs, 0 failed**, 411.5s (~10.3s/doc at concurrency 2). 437 terms:
225 accepted, 212 rejected — `too_common: 211`, `deprecated: 1`. Prompt
`corpus-v1`, gates unchanged since the 2026-08-20 fixes. Base index is the full
6,044 documents, so DF numbers are real.

**What was built for this** (all Module 1-internal, no contract change):
`sample_corpus()` in `index/corpus.py` (seeded random N per type; each type draws
from its own generator so dropping a type doesn't reshuffle the others);
`--per-kind` / `--seed` on `scripts/enrich_corpus.py`; a `sampling` field in the
enrichment manifest; `summarize_by_source()` printed at the end of every run; and
`scripts/measure_redundancy.py`, the question-7 measurement saved as a script. It
reproduces the logged v1 and v2 numbers exactly (80/131 with every per-kind cell
matching; 44/74). 160 -> 169 tests.

**By source document type:**

```
            docs  proposed  accepted   structural proposed    already in own text*
  cve         10       108        52   cwe 10                 48/52  (92%)
  capec       10       120        71   cwe 2, capec 1         42/71  (59%)
  attack      10       105        53   attack 4               25/53  (47%)
  cwe         10       104        49   cwe 5                  10/49  (20%)
                                                              ----------------
                                                              125/225 (55.6%)
  * headline rule from question 7 (literal id / contiguous tokens)
```

**Finding 1 — every structural proposal was a copy, on every document type.**
`measure_redundancy.py` now also classifies each structural proposal by where it
could have come from:

```
  cve     literal=10       CWE-79 etc. written in the CVE's own text
  cwe     own_id=5         CWE-1321 proposed for the CWE-1321 entry
  attack  own_id=4         T1437 proposed for the T1437 entry
  capec   bare_number=3    "@CWE_ID": "120" in the JSON -> proposed CWE-120
  not_found (i.e. a possible genuine inference): none
```

Replayed over the earlier runs: v1 19/19 literal; v2 6 literal plus **one**
not found anywhere — `CWE-125` for `CVE-2018-6484`, whose record cites no CWE at
all. That single case is the only candidate genuine inference in 48 structural
proposals, and whether it is the *right* CWE has not been checked.

The `own_id` case is invisible to the headline redundancy rule, because
`corpus_kb` text for CWE/CAPEC/ATT&CK entries holds the title but not the id —
the id reaches the model only through the prompt header
(`prompts/corpus_side.py`: `"Catalogue entry (cwe, id CWE-1321)"`). So question
7's 100%-of-structural figure was not a CVE quirk: it holds across all four
types, and the proposal's detection rule needed amending (done — see its
"Update after the stratified run" section).

**Finding 2 — the zero-ATT&CK result was not a sampling artifact.** ATT&CK ids
appear only on ATT&CK documents, and only as their own id. Nothing proposes an
ATT&CK technique for a CVE, CWE or CAPEC entry. It is also not missing
information: 3 of the 10 sampled CAPEC entries carry explicit ATT&CK taxonomy
mappings in their own text (`CAPEC-267` -> `"Entry_ID": "1027"`, `CAPEC-538` ->
`1195.001`, `CAPEC-654` -> `1056`, `1548.004`) and the model proposed none of
them, not even as copies. Whole corpus: 177 of 615 CAPEC entries carry such a
mapping. Documents with no structural proposal at all: cve 1/10, cwe 5/10,
attack 6/10, capec 7/10.

**Finding 3 — redundancy tracks how much text there is to copy.** CVE records
(median 1,390 chars, 9 of 10 cite a CWE in their text) are 92% redundant; CWE
entries (median 502 chars — `corpus_kb`'s CWE rows have no Description field)
are 20%. Do not read the overall 61% -> 56% change as the model improving: CVEs
alone went from 61% (the first 20 in file order, 2012–2018 records) to 92% (this
random 10, mostly 2024–2025). At 10–20 documents per cell these rates are not
yet stable — enough to see the pattern, not to quote a figure.

**Also:** one `deprecated` rejection is `T1470` proposing its own id — the
`corpus_kb` snapshot contains an entry ATT&CK v17.1 marks deprecated.
`too_common` is 211 of 212 rejections here; the `df_max_ratio` decision is still
open. `build_index.py --stage enriched` was **not** re-run: `indexes/enriched`
still reflects `corpus.jsonl` (v1, CVE-only), which is the live set.

### Question 7 sign-off request drafted
Wrote up the recommendation from the failed `corpus-v2` experiment (below) as
a formal decision request for all four module owners:
`docs/proposals/already-in-document-gate.md`. Covers: the exact
`RejectReason` value being proposed (`already_in_document`), where the new
gate would run in `corpus_side.py`'s pipeline (before the DF filter, flagged
as itself part of the decision), the detection rule (same contiguous-token
match used for the 61.1%/100% measurement, not a looser set check), and a
"what this changes for you" section per module — Module 2 almost certainly
doesn't need the gate logic itself (no source document to compare against on
the query side) but does need to know the enum value exists; Module 3 sees
fewer/more-genuinely-new expansion terms with no code change required; Module
4 gets a seventh `RejectReason` bucket, automatically counted by
`rejection_rate()` but worth checking against anything that special-cases the
current six by name.

No code changed. `schemas.py` is untouched pending the actual sign-off.

### Prompt iteration against question 7 — NEGATIVE RESULT, reverted
Tried `corpus-v2`, a much more forceful version of the "do not restate the
entry's own words" instruction, run against the same 20 documents as the v1
baseline. **It did not work and was reverted.**

```
                                   v1        v2
  terms proposed                  223       148
  accepted                        131        74
  redundant share of accepted   61.1%     59.5%   <- target metric: unmoved
  GENUINELY NEW terms indexed      51        30   <- 41% worse
  structural accepted               17         3
  malformed_id                       1         3
  completion tokens               3935      2586
```

The copying rate barely moved while total useful output fell by nearly half. The
model read the added "fewer is better than restated" line as "propose less"
rather than "propose better" — it complied with the letter and not the intent.
Since v1 already carried the instruction and v2 made it about as forceful as a
prompt can be, that is two rounds of evidence that **prompting is not the lever
for question 7**. Its recommendation flips to option 1, an enforced
`already_in_document` gate, which needs four-owner sign-off for a new
`RejectReason`.

Full experiment record, including the exact v2 prompt text so nobody rewrites
it from scratch: `docs/experiments/prompt-corpus-v2.md`.

**Side finding worth keeping.** v2's extra `malformed_id` cases were all shaped
`'CWE-331: Use of Inadequate Randomness'` — identifier plus its title. Unlike the
original five mislabels, these **are** normalizer-recoverable: `parse_structural_id`
returns `None` but the existing `extract_structural_ids` recovers `CWE-331`
correctly. If a future prompt ever encourages descriptive identifier forms, the
adjudicator should fall back to `extract_structural_ids` when
`parse_structural_id` fails on an ID-shaped term.

**Kept from this work even though the prompt was reverted:** the two tests that
hardcoded `"corpus-v1"` now compare against the `PROMPT_VERSION` constant
instead. They exist to check the manifest *records* the version, not what the
version is, and would have broken on every future prompt change.

**Latent bug spotted, not yet fixed:** `scripts/enrich_corpus.py` writes the
manifest's `prompt_version` from the *config* key `enrichment.corpus_prompt_version`,
not from `prompts/corpus_side.py:PROMPT_VERSION`. Change the prompt without
editing the config and the manifest silently records the wrong version — the same
provenance-contamination class as question 2. A comment now ties them together in
`configs/default.yaml`, but the real fix is to read the constant.

**Data:** v2's output is kept at `indexes/enrichment/corpus_v2.jsonl` as the
experiment's evidence. `indexes/enrichment/corpus.jsonl` (v1) remains the live
enrichment set and `indexes/enriched` is still built from it — unchanged and
still correct.


### Regenerated the corpus under the fixed gates — and found a bigger problem
Command: `.venv/bin/python scripts/enrich_corpus.py --limit 20` (fresh, not a
resume; old file archived as `corpus.jsonl.pre-gatefix`).
Result: **20 docs, 0 failed**, 251.6s (~12.6s/doc at concurrency 2; 24.6s/doc of
model time). 223 terms: **131 accepted (58.7%)**, 92 rejected —
`too_common: 90`, `deprecated: 1`, `malformed_id: 1`.
Enriched index then built: `indexes/enriched`, 6,044 docs.

**The gate fixes hold at scale.** 10 distinct CWE identifiers accepted at their
real document frequencies (4 to 108), where every one of them would have been
rejected before. `malformed_id` fell from 5-in-5-docs to 1-in-20-docs, and the
one remaining is `CVE-2018-6542` — a CVE identifier, i.e. exactly the case
question 6 was opened for, not a hallucination. **Qwen2.5-7B has still fabricated
zero ontology identifiers across 25 documents.**

**Verified the enriched index really works:** `CWE-331` searched against the
`expansion` field returns CVE-2012-4687 and four other enriched CVEs, a different
and better result set than the base index's contents-only match. Note
`LuceneSearcher.search()` queries `contents` only by default — to see expansion
terms you must pass `fields={EXPANSION_FIELD: 1.0}`. Forgetting that makes a
working enriched index look empty.

**The serious finding — question 7.** 80 of 131 accepted terms (61.1%) already
appear verbatim in their document's own text, including **17 of 17 structural
identifiers (100%)**. Those terms are already indexed and already retrievable;
injecting them adds nothing. CTIConnect CVE records embed their CWE mapping, so
the model is reading the identifier off the page and handing it back, and the
graph then validates a transcription rather than an inference. The prompt already
forbids this and is being ignored, with nothing enforcing it. Full analysis,
measurement method and options in `04_OPEN_QUESTIONS.md` question 7.

**Two more from the same run:**
- **Zero ATT&CK and zero CAPEC proposals** across 20 documents — all 19
  structural proposals were CWE (18) plus one CVE, and structural terms were only
  8.5% of all proposals. The mechanism under test is barely exercised.
- **The sample was 100% CVE documents.** `--limit N` takes the first N in load
  order and those are all CVEs. No conclusion about CWE/CAPEC/ATT&CK source
  documents can be drawn from this run. Cross-catalogue RQ1 work needs a
  stratified sample.

**`df_max_ratio` sensitivity** (now measurable, since the CWE artifact is gone —
90 `too_common` rejections against the 6,044-doc base index):

```
  0.10 (current) -> 131/223 accepted (58.7%)
  0.15           -> 153/223 (68.6%)
  0.25           -> 163/223 (73.1%)
  0.30           -> 179/223 (80.3%)
```

The far end looks correctly rejected: `remote attacker` / `network attack` /
`man-in-the-middle attack` all sit at 0.660. The borderline is arguable —
`denial of service` (0.141) is a real CTI search term that 0.10 cuts and 0.15
keeps. Not yet a decision; it should be tuned against retrieval metrics by
Module 3/4, not eyeballed here.

**Known gap in the kind-routing fix:** a demoted term is written to the JSONL as
`colloquial` with no trace that the model originally said `structural`, and
`CallRecord` (`common/llm.py`) stores no prompt or reply text. **The kind-mislabel
rate is therefore not measurable after the fact.** If prompt-iterating against it
matters, it needs a runtime counter on `EnrichmentRunSummary` (Module 1's own
dataclass, not the frozen contract) or a sidecar log next to the JSONL.


### Gate fixes: structural kind routing + structural DF (open questions 1 and 3)
Both found by inspecting the first real run's output. Neither was visible from
the code alone — the run's numbers are what exposed them.

**Question 3 — the 5 `malformed_id` rejections.** They were neither genuine
hallucinations nor normalizer-fixable format variants (the two options the
question posed). They were `heap-based` (x2), `zzip_get32`, `local` and `medium`
— ordinary vocabulary the model tagged `kind="structural"`. The normalizer was
right to refuse them; the model just filled in the wrong field. Because the
rejection log is the RQ4 dataset, this was booking a schema slip as an identifier
hallucination: **true hallucination count for that run was 0, the log said 5.**
Fix: new `is_id_shaped()` in `graph/normalize.py` + `_route_kind()` in
`corpus_side.py` demote a mislabelled `structural` to `colloquial`, while a term
that genuinely reached for an identifier and missed (`CWE-abc`, `T99`) still
records `MALFORMED_ID`. Routing only ever demotes, never promotes.

**Question 1 — DF for multi-token structural ids.** Measured on the real base
index (6,044 docs, `df_max_ratio` 0.10): the gate took the *most common* token of
a multi-token term, so every `CWE-*` scored DF(`cwe`) = 2974/6044 = **0.492** —
the same number for all of them, ~5x the threshold. **Every CWE identifier was
rejected unconditionally regardless of which CWE it was**, including ones whose
number appears in 6 documents; one-token `T1110.001` scored 0 and passed
unconditionally. Not tunable — 0.492 is a constant. Fix: `doc_freq` takes an
explicit `combine` argument; structural ids use `"min"` (the number carries the
identity, the prefix is a catalogue-wide constant), everything else keeps
`"max"`. The gate still rejects a genuinely common identifier — this is a
correction, not an exemption.

**Measured effect.** Replaying the recorded proposals through the new gates with
no new LLM calls, so only gate logic differs:

```
                  BEFORE -> AFTER
      ACCEPTED:      28  ->  35
    deprecated:       1  ->   1
  malformed_id:       5  ->   0
    too_common:      24  ->  22
```

11 terms changed verdict. All 5 CWE ids flipped `too_common` -> accepted at their
true DFs (7, 6, 6, 41, 108, 92). `zzip_get32` flipped `malformed_id` -> accepted
at DF 0 — a real zziplib symbol, maximally discriminative. `heap-based`, `local`
and `medium` flipped `malformed_id` -> `too_common`: still rejected, but now for
the true reason.

**Tests:** 145 -> 160, all still offline/StubClient. Includes a regression test
pinning the analyzer's actual tokenization (`CWE-307` -> two tokens, `T1110.001`
-> one), so a Lucene upgrade that changes it fails loudly instead of silently
skewing RQ1.

**Opened as a side effect:** question 6 — whether a CVE identifier should count
as structural. Left at the conservative default, not decided.

**Not changed:** the frozen `EnrichmentRecord` contract. Both fixes were designed
to avoid a schema sign-off round.


### First real Ollama run — `--limit 5`
Command: `.venv/bin/python scripts/enrich_corpus.py --limit 5`
Result: 5 docs, 0 already done, 5 processed, **0 failed**, 88.2s (~17.6s/doc).
Accept/reject (cumulative): accepted 28, rejected 30 — of which
`too_common: 24`, `malformed_id: 5`, `deprecated: 1`; repaired 0;
staleness_rate 0.000.

Reading of this run:
- **0 failed** is the important success — no `MalformedReplyError`, real replies
  parse at the record level. First time the OllamaClient path has actually
  executed (all prior testing was StubClient).
- **`malformed_id: 5`** — needs eyeballing. Determine whether these are genuine
  garbage IDs or valid-but-slightly-misformatted IDs the normalizer should have
  caught pre-validation. If the latter → normalizer bug, not a model problem.
- **`too_common: 24`** — NOT meaningful yet. DF pool is only ~5 docs, so almost
  everything reads as common. Re-derive `df_max_ratio` against a real-sized index.
- Numbers here supersede the earlier stubbed 4-accept/5-reject demo figure, which
  was never meaningful.

### Environment brought up
- venv confirmed clean (python.org 3.13, not conda). conda PATH trap documented
  in `01_ENVIRONMENT.md`; workaround = always call `.venv/bin/python` explicitly.
- Base index built successfully: `indexes/base`.
- Enriched-index step correctly errors until enrichment JSONL exists (ordering
  guard working as designed).

### Prior state (from Module 1 build handoff)
- Branch `module-1/corpus-enrichment`, 145 tests passing, all offline.
- Full detail in `02_MODULE1_STATE.md`.

---

## Next actions (living checklist)

- [x] Inspect the 5 `malformed_id` rejections. — Neither genuine nor
      normalizer-fixable: kind-mislabelling. Fixed.
- [x] Resolve the multi-token DF question. — Structural ids judged on their
      rarest token. `04_OPEN_QUESTIONS.md` q1.
- [x] Regenerate the enrichment JSONL under the fixed gates. — Done, 20 docs,
      old run archived as `corpus.jsonl.pre-gatefix`.
- [x] Build the enriched index. — Done, `indexes/enriched`, expansion-field
      retrieval verified.
- [x] Question 7, attempt 1: prompt iteration. — **Failed.** Redundancy 61.1% ->
      59.5% while genuinely-new terms fell 51 -> 30. Reverted to `corpus-v1`.
      See `docs/experiments/prompt-corpus-v2.md`.
- [ ] **Question 7 — get four-owner sign-off for an `already_in_document`
      `RejectReason`, then build the gate.** Highest priority; it undercuts RQ1
      more than either gate bug did, and prompting has been ruled out.
      **Sign-off request drafted 2026-09-15:**
      `docs/proposals/already-in-document-gate.md` — **Module 1 approved
      2026-09-15** (check 2 limited to labelled id fields); waiting on Module
      2/3/4 owners before Module 1 implements the gate.
- [x] Fix `scripts/enrich_corpus.py` to read `PROMPT_VERSION` from the prompt
      module rather than from config. — Done 2026-09-15, alongside `corpus-v3`
      (changing the version is exactly when the old way would have recorded the
      wrong one). The `enrichment.corpus_prompt_version` config key is removed.
- [x] **Stratify the corpus sample.** — Done 2026-09-15: `--per-kind`, 10 of
      each type, `corpus_stratified.jsonl`. See that log entry.
- [ ] Investigate why the model proposes **no ATT&CK or CAPEC identifiers**. —
      **Narrowed 2026-09-15:** not the sample (it holds across all four types)
      and not missing information (3/10 CAPEC entries carry ATT&CK mappings it
      ignores). What remains open is prompt vs. model. Evidence so far leans
      model: the reverted v2 prompt asked explicitly for the related ATT&CK
      technique / CAPEC pattern and got 7 ids back, all CWE. But v2 also
      suppressed output overall, so it is not a clean test. Next step that
      stays inside the model policy: re-run the same stratified sample with a
      larger open-weight model (e.g. `qwen2.5:14b`) to see whether the links
      appear with scale. A frontier model would answer it faster but is reserved
      for the final run (`01_ENVIRONMENT.md`), so using one here is a team call.
- [x] Decide whether the prompt header should keep giving the model the
      document's own id. — **Decided 2026-09-15 (Module 1): no.** Removed in
      prompt `corpus-v3`; whether entries are searchable by their own id is
      handed to Module 3 (next item). Reasoning in the proposal. Confirmed by
      re-running the 40-document sample: own-id copies 9 -> 0.
- [ ] **New — question 8:** the graph gate accepts ids that exist but don't fit
      the entry (`CWE-1321` Prototype Pollution -> `CWE-134` Format String).
      Recommendation: re-check with a larger open-weight model first, then decide
      between measuring relatedness offline and gating on it. Worth raising with
      the supervisor — a relatedness check is arguably what "grounding against a
      hierarchical ontology" should mean for RQ1.
- [ ] **Run the same 40 documents with `qwen2.5:14b`** (`ollama pull
      qwen2.5:14b`, ~9 GB) under `corpus-v3`, own `--output`. Answers "prompt or
      model" for the zero cross-catalogue ids and question 8 in one run.
- [ ] **Before the next default-path run:** `index.enrichment_path` still points
      at the `corpus-v1` file `corpus.jsonl`. Either implement question 2's
      version guard, or always pass `--output`.
- [ ] **Flag to Module 3:** a CWE/CAPEC/ATT&CK entry's own id is not in its
      indexed `contents` (title + JSON body only, the same as CTIConnect's own
      baselines). Measured on `indexes/base`: `CWE-1321` and `CWE-378` do not
      return their own entry in the top 1,000; `T1437` returns zero hits;
      `CAPEC-14` finds itself at rank 306. Included in the proposal's Module 3
      section so it reaches Student 3 either way.
- [ ] Decide `df_max_ratio` against retrieval metrics, not by eye. Sensitivity
      table is in the log entry above.
- [ ] Make the kind-mislabel rate observable (runtime counter or sidecar log).
- [ ] Fix prompt-versioning-vs-resume composition (`04_OPEN_QUESTIONS.md` q2).
- [ ] Decide `04_OPEN_QUESTIONS.md` q6 (CVE identifiers as structural) — now
      confirmed live, it is the only remaining `malformed_id` in the run.
- [x] ~~(Low priority) `build_base.py` subprocess should use `sys.executable`.~~
      — **Not a bug, corrected 2026-09-15:** `build_base.py` has invoked the
      indexer as `sys.executable -m pyserini.index.lucene` since its first commit
      (`988709b`). The conda Python seen earlier must have come from launching the
      script itself with a bare `python`, which the `.venv/bin/python` rule in
      `01_ENVIRONMENT.md` already covers.
