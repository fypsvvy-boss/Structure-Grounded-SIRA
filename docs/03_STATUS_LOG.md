# Status Log

> Rolling log — newest entry at the top. Update this at the end of every working
> session so the next session (human or AI) picks up exactly where this one left
> off. Keep entries short and factual.

---

## Current headline

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
- [ ] Fix `scripts/enrich_corpus.py` to read `PROMPT_VERSION` from the prompt
      module rather than from config, so the manifest cannot record a version the
      prompt does not have.
- [ ] **Stratify the corpus sample.** Every result so far is from CVE documents
      only. Add a per-kind limit to `scripts/enrich_corpus.py` and re-run before
      any cross-catalogue claim.
- [ ] Investigate why the model proposes **no ATT&CK or CAPEC identifiers**. Is
      it the source type (CVE docs), the prompt, or the model's CTI priors? This
      is close to the heart of RQ1.
- [ ] Decide `df_max_ratio` against retrieval metrics, not by eye. Sensitivity
      table is in the log entry above.
- [ ] Make the kind-mislabel rate observable (runtime counter or sidecar log).
- [ ] Fix prompt-versioning-vs-resume composition (`04_OPEN_QUESTIONS.md` q2).
- [ ] Decide `04_OPEN_QUESTIONS.md` q6 (CVE identifiers as structural) — now
      confirmed live, it is the only remaining `malformed_id` in the run.
- [ ] (Low priority) `build_base.py` subprocess should use `sys.executable`.
