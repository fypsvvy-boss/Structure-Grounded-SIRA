# Module 1 — Implementation State

> What's built, how it's structured, and the design decisions behind it. This is
> the detailed reference for anyone working on or extending Module 1.

Branch: `module-1/corpus-enrichment` (main untouched).

---

## What's built

### A. Corpus-side enrichment
`src/sira_cti/enrichment/corpus_side.py` + `src/sira_cti/enrichment/prompts/corpus_side.py`

Per-document pipeline:
1. `client.generate()` (via the instrumented wrapper — never a direct model call)
2. `parse_json_loose()` — **reused from `llm.py`, not reimplemented.** (There was
   previously a greedy-bracket bug in a loose JSON parser that turned object
   replies like `{"terms":[...]}` into empty arrays, silently masking parse
   failures as legitimate "model proposed nothing". Do not reintroduce a second
   parser.)
3. Strict shape check → a malformed reply raises `MalformedReplyError` and the
   doc is **not written**. Resuming retries it, rather than a fake
   empty-proposals record ever contaminating the JSONL.
4. `graph.validate()` for structural terms (against the real ontology graph).
5. DF `too_common` gate.

`run_corpus_enrichment()` is:
- **Resumable** — JSONL keyed on `doc_id`, one flushed append per doc; a crash
  loses at most the doc in flight.
- **Optionally concurrent** — one `LLMClient`/`CallLog` per worker thread, because
  `CallLog.scope()` fans every call out to every open scope; sharing one client
  across threads would cross-attribute cost between concurrently-processed docs.

### B. Index build
`src/sira_cti/index/` — `corpus.py`, `df_stats.py`, `build_base.py`, `build_enriched.py`

- **`corpus.py`** loads `corpus_kb`, canonicalizing IDs to match CTIConnect's own
  baseline convention so the index stays doc-id-compatible with their qrels.
- **DF source:** read from the real base Lucene index (`LuceneDFLookup`), NOT a
  standalone counter. Reason: Anserini's default analyzer keeps `T1110.001` as
  one token but splits `CWE-307` into `["cwe","307"]`, so a hand-rolled tokenizer
  would silently disagree with query-time behaviour. Free, since the base index
  has to exist first anyway (it doubles as Module 3's plain-BM25 baseline).
- **Injection strategy:** a **separate `expansion` Lucene field**
  (`--fields expansion`), NOT appended-contents (corrupts stored raw text) and NOT
  term repetition (distorts BM25 length-normalization). Proven in
  `tests/test_index_build.py`: a term appearing nowhere in a doc's contents is
  retrieved via the expansion field, confirmed absent from the base index.
- **Ordering** (base → DF → enrichment → enriched) is explicit at the script
  layer: `build_enriched_index()` raises `FileNotFoundError` if the enrichment
  JSONL doesn't exist.

### C. Scripts
`scripts/enrich_corpus.py`, `scripts/build_index.py` — config-driven, `--limit N`,
`--dry-run`. `build_index.py --stage` is required with no `both` option,
deliberately, to keep ordering visible.

### Tests
145 tests pass (78 baseline → 145: +9 corpus loader, +29 enrichment pipeline,
+12 real-but-tiny Lucene index builds, +7 schema). All offline — `StubClient`
throughout, no network, no live LLM.

---

## The frozen enrichment-record contract (shared, do not change without 4-way sign-off)

Modules 1 & 2 emit this; Module 3 consumes it; Module 4 audits it.

```jsonc
{
  "doc_id": "CVE-2024-XXXXX",
  "source": "cve | cwe | capec | attack | report",
  "original_text": "...",
  "proposed_terms": [
    {
      "term": "brute force login",
      "kind": "colloquial | symptom | product | misspelling | structural",
      "structural_id": null,            // e.g. "T1110.001" or "CWE-307"
      "graph_validated": true,          // null if kind != "structural"
      "doc_freq": 412,
      "accepted": true,
      "reject_reason": null             // see RejectReason values below
    }
  ],
  "llm_calls": 1,
  "tokens": { "prompt": 812, "completion": 143 },
  "latency_ms": 1904,
  "model": "qwen2.5:7b"
}
```

`RejectReason` values: `not_in_graph`, `too_common`, `not_in_index`,
`deprecated`, `revoked`, `malformed_id`.

**Every rejected term is kept with its `reject_reason` — the rejection log IS the
RQ4 dataset.**

---

## Schema addition riding in this branch

The first commit on `module-1/corpus-enrichment` carries a schema change
(`repaired_from_id` / `staleness_rate`) that was sitting uncommitted in the
working tree. If this was signed off by all four owners, state that explicitly in
the PR body — a frozen-contract change inside a Module 1 branch is easy for a
downstream reviewer to skim past.

---

## Files new to `common/` (flag to the team)

- `src/sira_cti/common/repro.py` (new) — `config_hash` / `load_config`, used by
  both scripts for the "record the config hash" convention. New shared surface in
  `common/` — tell the other three so it doesn't get duplicated later.

---

## Config bug fixed in passing

`configs/default.yaml` had two top-level `enrichment:` blocks — PyYAML silently
keeps only the second, which would have dropped `max_terms_per_doc` /
`df_max_ratio` / etc. Merged into one block. (A separate stray
`eval.allow_deprecated` duplicate-in-spirit was left alone — harmless, nothing
reads it.)

---

## Prompt versioning

`PROMPT_VERSION` is NOT in the frozen `EnrichmentRecord` contract. It's recorded
in a sidecar `<output>.manifest.json` instead, to avoid a schema sign-off round.
**Known limitation — see `04_OPEN_QUESTIONS.md`:** this doesn't compose with
resumability (resume can mix records from two prompt versions under one manifest).
