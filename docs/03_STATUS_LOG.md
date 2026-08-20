# Status Log

> Rolling log — newest entry at the top. Update this at the end of every working
> session so the next session (human or AI) picks up exactly where this one left
> off. Keep entries short and factual.

---

## Current headline

**Phase 1 / Module 1: core pipeline built and running against the real local LLM
for the first time.** Base index builds; corpus-side enrichment runs end-to-end
against Ollama + Qwen2.5-7B; enriched index build is unblocked (JSONL now exists).

Immediate priorities: (1) inspect the `malformed_id` rejections from the first
real run, (2) scale the run and re-read the `too_common` rate against a real-sized
DF pool, (3) resolve the multi-token DF question (see `04_OPEN_QUESTIONS.md`).

---

## Log

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

- [ ] Inspect the 5 `malformed_id` rejections in the JSONL; classify as genuine
      vs. normalizer-fixable. File a fix if it's the normalizer.
- [ ] Run `--limit 20` (skips the 5 done), then build the enriched index.
- [ ] Re-derive `df_max_ratio` against a real-sized base index; the `too_common`
      rate at `--limit 5` is not informative.
- [ ] Resolve the multi-token DF question (`04_OPEN_QUESTIONS.md`) — how DF is
      computed for `CWE-307` → `["cwe","307"]` vs. one-token `T1110.001`. Affects
      RQ1 fairness across catalogues. Make it a documented, deliberate choice.
- [ ] Fix prompt-versioning-vs-resume composition (`04_OPEN_QUESTIONS.md`).
- [ ] (Low priority) `build_base.py` subprocess should use `sys.executable`, not
      bare `python`.
- [ ] Prompt-iterate against real Qwen output if `malformed_id` rate stays high.
