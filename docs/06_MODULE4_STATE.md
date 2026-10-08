# Module 4 — Implementation State

> What Module 4 (evaluation + cost analysis) has built, the decisions behind it,
> and what it still needs from the other modules. Branch: `module4`.

---

## What's built

| Piece | File | What it is |
|---|---|---|
| CTIConnect adapter | `src/sira_cti/eval/cticonnect.py` | QA rows → query file (Module 3's `{"id", "query"}`), TREC qrels, metadata, seeded dev/test split |
| Metrics | `src/sira_cti/eval/metrics.py` | Recall@k, NDCG@k per question; means by task/category; bootstrap CI; paired randomisation test |
| Run reader | `src/sira_cti/eval/runs.py` | Reads and validates Module 3's TREC run + manifest; cross-run consistency checks |
| Cost | `src/sira_cti/eval/cost.py` | Reads `<run>.costs.jsonl`; mean/median/p95; quality per call / 1k tokens / second; offline corpus cost, separate |
| Audit | `src/sira_cti/eval/audit.py` | Rejections by reason, source type, catalogue, model; graph failures apart from DF failures |
| Assembly | `src/sira_cti/eval/report.py` | `evaluate()` → one results dict with provenance; Markdown tables |
| CLI | `scripts/run_eval.py` | `prepare` (benchmark files) and `score` (results) |

Tests: `tests/test_eval_*.py` (154: 153 pass, 1 skipped — the optional
cross-check against `pytrec_eval`, which is not installed on this machine).
All offline: hand-written fixtures under `tests/fixtures/cticonnect/qa`, run
files written as text in Module 3's documented format, a word-overlap fake
retriever. No index is built and no model is called.

**Not yet run on real data.** `data/` and `indexes/` were not on the machine
this was written on. The CTIConnect row shape the adapter assumes comes from
CTIConnect's README and has **not been checked against a clone** — do that
first (`data/README.md` already calls it the highest-impact unknown).

```bash
python scripts/run_eval.py prepare --output-dir runs/benchmark
# Module 3 runs each system over runs/benchmark/queries.<split>.jsonl
python scripts/run_eval.py score --qrels runs/benchmark/qrels.test.trec \
    --run runs/sira.trec --run runs/bm25.trec \
    --corpus-enrichment indexes/enrichment/corpus.jsonl --output-dir runs/results/test
```

---

## Decisions

### 1. Module 4 consumes Module 3's files, not its classes

`sira_cti.retrieval` is on an unmerged branch. The harness reads the three
files `scripts/run_retrieval.py` writes (TREC run, `.costs.jsonl`,
`.manifest.json`, as documented in `05_MODULE3_STATE.md`) and imports nothing
from that package; `test_the_eval_package_never_imports_module_3` pins it. A
run produced anywhere, by anything, can be scored.

### 2. Multi-document synthesis is blocked, not scored

CSC / TAP / MLA are `eval_type: "judge"` — free-text answers over vendor
reports that are not in the index. There is no gold document, and
"entity/answer coverage" has no agreed definition. `prepare` writes those rows
to `blocked.jsonl`; `score` reports them under `"blocked"` with no number.
**Needs a team/supervisor decision.**

### 3. Retrieval scoring is a reframing of the benchmark

CTIConnect scores identifiers in a generated answer (P/R/F1) and ships no
qrels. Here a question's relevant documents are the entries its `ground_truth`
names (`target_id` plus any `valid_target_ids`, all at grade 1). Say so in the
write-up. Open: if `valid_target_ids` are *alternative* acceptable answers,
Recall@k penalises a system for finding only one of them — check what the
field means in the real data.

### 4. Two departures from `trec_eval`, both deliberate

- A question with no lines in a run scores **zero** (`trec_eval` would drop it
  from the mean).
- Rankings are taken in the run's **rank order** (`trec_eval` re-sorts by score
  and breaks ties on doc id; RRF-fused lists have ties). `runs.py` errors if
  rank and score disagree.

Metrics are implemented in pure Python (no compiler needed on Windows) and
cross-checked against `pytrec_eval` when it is installed.

### 5. Gold ids missing from the corpus stay in the qrels

`prepare` lists them in the manifest (`gold_not_in_corpus`). Dropping them
would raise every system's recall.

### 6. Three rejection rates, never merged

`EnrichmentRecord.rejection_rate()` counts `too_common` rejections of valid
ids, so it is not the graph-validation rejection rate. The audit reports
`total_rejection_rate`, `structural_rejection_rate` and `graph_rejection_rate`
separately. Reasons are classified by string value, so a seventh reason
(`already_in_document`) appears in its own `other` bucket with no code change
and no edit to `schemas.py`.

### 7. Offline cost is separate

Corpus-side enrichment cost is read from the enrichment JSONL and reported in
its own section, with an amortised-per-question figure beside it. It is never
added to a per-question number.

### 8. The dev/test split is fixed before any run

Stratified by task, by a hash of `(seed, question id)`; seed defaults to
`eval.seed`. Tune `w` and the field boosts on `dev`, report `test`. The split
fraction (`--dev-fraction`, default 0.2) is recorded in the benchmark manifest.

---

## What Module 4 needs from the others

- **Module 3:** the agent's prompt version (`agent-v1`) is not in the run
  manifest; add it so it can be recorded. Confirm a cost row is written for
  every question, including ones that return nothing.
- **Modules 2 and 3 — cost gaps that the harness can only caveat:**
  SIRA's LLM latency is copied from an offline batch record (not end-to-end,
  no retry back-off); a question whose enrichment reply was malformed has no
  record, so its tokens vanish; nothing says which record carries the LLM call
  that writes synthesis sub-queries.
- **Module 2:** a sidecar manifest (prompt version, model, config hash) beside
  the query-side enrichment JSONL, like Module 1's.
- **Everyone:** the `id_boost` decision (`05_MODULE3_STATE.md`) — it changes
  what a fair baseline comparison is.

## Open items

- [ ] Clone CTIConnect and verify the row shape; run `prepare` on the real data.
- [ ] Decide synthesis scoring (decision 2).
- [ ] Relatedness measure beside validity (`04_OPEN_QUESTIONS.md` question 8) —
      coordinate with Module 1, who planned the same measurement.
- [ ] Hand-written 30–50 vague-query set, in the same query/qrels format.
- [ ] Ablation matrix runner (grounding, corpus enrichment, budget, `w`) once
      Modules 2 and 3 produce real runs.
- [ ] Module 4's row in `docs/proposals/already-in-document-gate.md` is still
      *pending*.
- [ ] No machine-readable ATT&CK pin in the config: `score` reads the version
      from the STIX bundles, or takes `--attack-version`.
