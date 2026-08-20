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

**⚠️ `indexes/enrichment/corpus.jsonl` is now stale.** Its 5 records were
adjudicated under the old gates, so their verdicts are wrong. Do **not** just run
`--limit 20` — resume would skip those 5 and leave one file holding records from
two different gate versions, which is the same provenance contamination as
question 2 but for gate logic. Regenerate from scratch instead.

Immediate priorities: (1) regenerate the enrichment JSONL under the fixed gates,
(2) scale the run and re-read the `too_common` rate now that the CWE artifact is
gone, (3) build the enriched index.

## Log

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

- [x] Inspect the 5 `malformed_id` rejections; classify as genuine vs.
      normalizer-fixable. — Done: neither, they were kind-mislabelling. Fixed.
- [x] Resolve the multi-token DF question. — Done: structural ids judged on their
      rarest token. See `04_OPEN_QUESTIONS.md` question 1.
- [ ] **Regenerate `indexes/enrichment/corpus.jsonl` from scratch** under the
      fixed gates (archive the old one as before-evidence rather than deleting —
      it is the only record of what the old gates did). Do not resume onto it.
- [ ] Then run `--limit 20` and build the enriched index.
- [ ] Re-derive `df_max_ratio` against a real-sized base index. Still open, and
      now actually measurable: the old `too_common` rate was dominated by the CWE
      artifact, so any earlier reading of it was meaningless.
- [ ] Fix prompt-versioning-vs-resume composition (`04_OPEN_QUESTIONS.md` q2).
      Now more urgent than it looked — the gate fix just demonstrated the same
      failure mode for real, one file holding records from two logic versions.
- [ ] Decide `04_OPEN_QUESTIONS.md` question 6 (CVE identifiers as structural).
- [ ] (Low priority) `build_base.py` subprocess should use `sys.executable`, not
      bare `python`.
- [ ] Prompt-iterate against real Qwen output. Note the target has changed: the
      `malformed_id` rate is no longer the signal to watch, since those were
      mislabels. The signal now is how often the model mislabels `kind` at all —
      it was 5 terms across 5 documents, which is high.
