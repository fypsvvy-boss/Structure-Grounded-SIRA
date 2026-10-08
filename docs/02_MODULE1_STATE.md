# Module 1 — Implementation State

> What's built, how it's structured, and the design decisions behind it. This is
> the detailed reference for anyone working on or extending Module 1.

Branch: `module-1/corpus-enrichment` (main untouched).

---

## What's built

### A. Corpus-side enrichment
`src/sira_cti/enrichment/corpus_side.py` + `src/sira_cti/enrichment/prompts/corpus_side.py`

Per-document pipeline (stage names match `RejectStage` in the contract):
1. `client.generate()` (via the instrumented wrapper — never a direct model call)
2. `parse_json_loose()` — **reused from `llm.py`, not reimplemented.** (There was
   previously a greedy-bracket bug in a loose JSON parser that turned object
   replies like `{"terms":[...]}` into empty arrays, silently masking parse
   failures as legitimate "model proposed nothing". Do not reintroduce a second
   parser.)
3. Strict shape check → a malformed reply raises `MalformedReplyError` and the
   doc is **not written**. Resuming retries it, rather than a fake
   empty-proposals record ever contaminating the JSONL.
4. **Kind routing** (`_route_kind`) — added 2026-08-20, see below.
5. **stage `graph`** — `graph.validate()` for structural terms (against the real
   ontology graph): does this id exist, and is it current?
6. **stage `name`** — `graph.check_name()`: does the title the model claimed for
   that id match MITRE's? Added 2026-10-07, see below.
7. **stage `df`** — `too_common` gate; **structural identifiers are scored on
   their rarest analyzed token, everything else on its most common one**, see
   below.
8. Measurement-only annotation of the whole document's proposals at once:
   `in_counting_run` and `graph_distance`. Runs *after* adjudication, so
   nothing it records can influence a verdict.

#### Name-ID consistency (step 6) — added 2026-10-07

Prompt `corpus-v4` requires a `"name"` on every structural proposal: the model
must state the official title it believes the id has. `check_name()` compares
that claim to the node's name and aliases on content words, using the overlap
coefficient against the *shorter* title (so "Cross-site Scripting" matches
CWE-79's full formal name), with the threshold in
`enrichment.name_match_min_overlap` (default 0.5). Mismatch →
`RejectReason.NAME_MISMATCH`.

Why this exists at all: SIRA grounds against Wikipedia categories, whose ids
*are* their names, so existence and meaning are one check. MITRE ids are
integers in a dense namespace — ~940 active CWEs inside 1..1425 — so existence
is nearly free and a model that counts upwards passes. `qwen2.5:14b` proposed
`CWE-73`..`CWE-81` for CWE-512 "Spyware" and the graph accepted all nine. Full
reasoning, measurements and the four-owner decision request:
`docs/proposals/name-id-consistency.md`; background in
`04_OPEN_QUESTIONS.md` question 8.

Three properties worth knowing:

- **Stage order is existence → name, and is not interchangeable.** A
  non-existent id has no official title, so checking names first would report
  every hallucination as a name mismatch and merge the two most distinct RQ4
  findings.
- **A `NAME_MISMATCH` term keeps `graph_validated=True`.** That is the finding,
  stated accurately: the id exists and the model still did not know what it was.
- **A missing `"name"` is a mismatch, not a parse error.** No claim is not
  evidence of knowledge, and passing it would restore existence-only behaviour
  on exactly the least confident proposals. The document is still written and
  the proposal still carries a reason, so it stays in the RQ4 dataset.

`name_match_min_overlap: null` (or `--no-name-check`) disables the stage and
reproduces `corpus-v3` adjudication exactly — that is the existence-only
ablation.

**Scorer versions (2026-10-08).** `enrichment.name_scorer` / `--name-scorer`
picks `v1` (above), `v2` (symmetric match on CWE short names — the quoted name
in the title plus `Alternate_Terms`, which the loader now puts in
`node.aliases`; falls back to v1 where a node has none and says so as
`v2:v1-fallback`) or `v3` (symmetric everywhere, experimental). Every name
verdict records its scorer in `name_scorer`. Measurements and the reasoning for
each are in the proposal's Amendment.

**Generation and adjudication are separate (2026-10-08).** `propose_terms` =
`_ask_for_proposals` (the model call) + `adjudicate_proposals` (every gate and
measurement). `readjudicate_record` replays the second half on a saved record,
and `scripts/rescore_enrichment.py` does it for a whole file — a new scorer,
threshold or graph snapshot applied to an old run with **no model calls**. It
replays under the original scorer first and reports any verdict that differs,
so drift in the graph or the index cannot pass as a scorer effect.

**Repair (2026-10-08, measurement only).** A `name_mismatch` gets
`repaired_to` when exactly one other real id within 2 hops of the document has
the title the model stated. The term stays rejected. Ambiguous matches are not
recorded. `enrichment.index_repaired_ids: true` makes the enriched index
include those ids (never a repair to the document's own id) — off by default,
there for Modules 3/4 to run as an ablation.

#### Measured, never gated (step 8)

- **`in_counting_run`** — true when an id sits in a run of ≥3 consecutive
  numbers from the same series inside one document's proposals. Threshold is 3
  because 2 is ordinary (`T1110.001`/`.002` are real siblings). Sub-techniques
  key on their parent, so `T1110.001` and `T1547.001` are not mistaken for
  neighbours. Rejected proposals are included on purpose: the invented tail of
  a run is its most informative part.
- **`graph_distance`** — hops from the document's own ontology node to the
  proposed id, over hierarchy *and* cross-catalogue mapping edges, direction
  ignored (a `maps_to` edge is recorded by whichever catalogue happened to
  write it down, so a directed distance would measure editorial accident).
  `None` when either end is not a graph node — which is **every CVE**, so
  "not measurable" must never be read as "unrelated".

Neither changes accept/reject, deliberately: enrichment exists to add the links
an entry's own data lacks, so the distant ids contain both the worst guesses
and the genuinely novel connections, and distance alone cannot separate them.

#### Kind routing (step 4)

The model self-declares a `kind` for every term it proposes, and the pipeline
routes on that label. Qwen2.5-7B mislabels routinely: the first real run tagged
`heap-based`, `zzip_get32`, `local` and `medium` as `kind="structural"` — the
label reserved for formal ATT&CK/CWE/CAPEC identifiers. All four went to the
graph gate and came back `MALFORMED_ID`.

That conflated two different failures, and the conflation is expensive because
the rejection log **is** the RQ4 dataset:

- the model *reached for an identifier and got it wrong* (`CWE-abc`, `T99`) —
  a real hallucination, real RQ4 signal;
- the model *filled in the wrong form field* on ordinary vocabulary — not a
  hallucination at all, and booking it as one inflates the headline RQ4 rate.

`graph/normalize.py:is_id_shaped()` separates them: it asks whether the term was
*plausibly an attempt* at an identifier, as opposed to `looks_structural()`,
which asks whether the attempt *succeeded*. A `structural` label on something
that was never an identifier attempt is demoted to `colloquial` and judged like
any other vocabulary; a botched identifier stays `MALFORMED_ID`.

Routing is **one-way — it only demotes, never promotes.** A term the model
labelled `colloquial` is left alone even if it parses as a valid identifier,
because promoting it would put an unvalidated id into the structural pool and
silently change RQ4's denominator.

`colloquial` is the demotion target because `TermKind` has no `unknown` member
and adding one is a frozen-contract change needing four-owner sign-off.

#### DF combine rule (step 6)

Anserini's analyzer splits `CWE-307` into `["cwe", "307"]` but keeps `T1110.001`
as one token. The gate used to score a multi-token term by its **most common**
token, which meant every CWE identifier was scored as DF(`cwe`) = 2974/6044 =
**0.492** — identical for every CWE, ~5x `df_max_ratio`, so *every CWE was
rejected unconditionally* while one-token ATT&CK ids scored 0 and passed
unconditionally.

`DFLookup.doc_freq` now takes an explicit `combine` argument (`"max"` | `"min"`),
picked per term by `_df_combine()`: `"min"` for structural identifiers (the
namespace prefix is a catalogue-wide constant; the number carries the identity),
`"max"` for everything else (a phrase is only as discriminative as its commonest
word). Full reasoning and measurements: `04_OPEN_QUESTIONS.md` question 1, and
the `Combine` docstring in `index/df_stats.py`.

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

Added 2026-09-15:
- **`enrich_corpus.py --per-kind N [--seed S]`** — a seeded random N of each
  document type, via `sample_corpus()` in `index/corpus.py`. Mutually exclusive
  with `--limit`. Each type draws from its own generator seeded by
  `(seed, kind)`, so a type's sample doesn't change when another type is added
  or dropped; the same seed always gives the same documents, which keeps sampled
  runs resumable. The manifest records how documents were chosen in a new
  `sampling` field (`{"method": "per_kind", ...}` or `{"method": "prefix", ...}`).
- **`enrich_corpus.py --model NAME`** (2026-10-07) — overrides `llm.model` for one
  run without editing the config (so the config hash stays comparable); the
  manifest records the model that actually ran.
- **`enrich_corpus.py --no-name-check` / `--name-overlap F`** (2026-10-07) — turn
  the name-ID consistency stage off, or move its threshold, for one run.
  `--no-name-check` is the existence-only ablation.
- **`scripts/report_enrichment.py`** (2026-10-07) — read-only per-run summary
  table: proposed/accepted, rejections by reason *and* by stage, structural ids
  split by where they could have been copied from, counting-run count, and the
  `graph_distance` distribution of accepted ids. Takes several JSONLs to compare
  models side by side, and `--counting-ids-from OLD.jsonl` to ask what a newer
  run did with the ids an older one proposed in counting runs. It recomputes
  `in_counting_run` rather than reading it, so it works on pre-1.2.0 files too.
- **`enrich_corpus.py --backend gemini`** (2026-10-08) — the frontier backend,
  for logged policy exceptions only (`06_POLICY_EXCEPTIONS.md`). Needs
  `--model`; optional `--thinking-level`, `--llm-seed`, `--price-in`,
  `--price-out`, `--cost-cap-usd`. Runs a two-call preflight on one document
  first. How-to and gotchas: `01_ENVIRONMENT.md`, "Gemini". The manifest gains
  an **`llm`** block (provider, SDK, thinking setting, seed sent and whether it
  was honoured, prices, preflight) and a **`usage`** block (calls and tokens,
  thinking separate).
- **Section-aware truncation** (2026-10-09) — `enrichment/truncation.py`.
  An over-long entry is shown to the model with whole sections removed in a
  fixed order; description and cross-catalogue links are never removed. The
  record gets a `truncation` field; `record_shown_text(record)` rebuilds what
  the model saw. `report_enrichment.py` and `measure_redundancy.py` now
  measure "copied from the entry" against that, not the full text.
- **Resume guard** (2026-10-09) — resuming into a file made under different
  settings raises `ResumeMismatchError`; the manifest is written before the
  first document and now records `concurrency`.
- **Context handling** (2026-10-08) — `llm.seed`, `llm.num_ctx` and
  `enrichment.max_doc_chars` in the config. Long documents are shortened for
  the model only (`truncate_document`); the manifest gains a **`truncation`**
  block listing them. Module 2 should send the same `seed`/`num_ctx` on the
  query side.
- **`scripts/bench_enrichment_speed.py`** (2026-10-08) — long-running speed
  benchmark for planning the full-corpus run: tokens per second early vs after
  30 minutes, and a per-source time estimate. Writes a timing log only.
- The manifest now carries a **`gates`** block (which checks were on, the
  decoding mode, the token cap), because `--model` and `--name-overlap` mean the
  config hash alone no longer identifies a run.
- **Per-source summary** — `summarize_by_source()` in `corpus_side.py`, printed at
  the end of every run: counts per source document type, including which
  catalogue each structural proposal belongs to.
- **`scripts/measure_redundancy.py`** — the question-7 "already in its own
  document" measurement, saved. Read-only, no LLM. Reproduces the v1/v2 numbers
  exactly, and adds a per-proposal classification of where each structural id
  could have been copied from (`literal` / `own_id` / `bare_number` /
  `not_found`). Its matching functions are the reference for the proposed
  `already_in_document` gate; they live in `scripts/` untested until that gate is
  approved and they move into `corpus_side.py` with tests.

### Tests
**349 tests pass** (+32 on 2026-10-09: 17 section-aware truncation, 11 resume guard, record `truncation` field, copy measured against the shown text, fallback and re-adjudication cases). 317 before that (+6 on 2026-10-08 latest: Ollama seed / `num_ctx` / overflow flag, document truncation, the overflow refusal). 311 before that on the merged `main` (+11 on 2026-10-08 later: 6 `GeminiClient` cases on a fake SDK,
`load_env_file`, 2 `TokenUsage.thinking` cases, 2 manifest `llm`/`usage` cases). Module 1 alone was 256 (+32 on 2026-10-08: scorer versions, CWE short-name loader,
`within`/`name_candidates`, offline re-adjudication, repair, the repair index
flag, schema 1.3.0). 224 before that (+54 on 2026-10-07: 6 LLM-wrapper generation settings,
13 name-check and distance cases on the graph, 24 pipeline cases for the name
stage / counting runs / distance / recorded parse failures, 7 schema 1.2.0
cases including the 1.1.0 backward-compatibility load, plus the manifest
`gates` check). 170 before that (+10 on 2026-09-15: 7 `sample_corpus`, 1 sampling manifest,
1 `summarize_by_source`, 1 "prompt carries no doc id"; four existing tests now
key their fake model replies on document text instead of the id). 160 before that (was 145 before the 2026-08-20 gate fixes: +5 `is_id_shaped`,
+7 kind-routing and structural-DF cases, +3 real-Lucene combine/tokenization
checks). Earlier count breakdown: 145 tests pass (78 baseline → 145: +9 corpus loader, +29 enrichment pipeline,
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
      "reject_reason": null,            // see RejectReason values below
      "repaired_from_id": null,

      // --- schema 1.2.0, all optional, all default to "not measured" ---
      "claimed_name": null,             // the title the model said this id has
      "official_name": null,            // MITRE's title for it
      "rejected_at_stage": null,        // parse | graph | name | df
      "in_counting_run": false,         // measurement only, never a verdict
      "graph_distance": null,           // hops from the document's own node

      // --- schema 1.3.0 ---
      "name_scorer": null,              // v1 | v2 | v2:v1-fallback | v3
      "repaired_to": null               // on a name_mismatch: the id it probably meant
    }
  ],
  "llm_calls": 1,
  "tokens": { "prompt": 812, "completion": 143 },
  // schema 1.4.0: a "thinking" model adds a third count, e.g.
  //   "tokens": { "prompt": 864, "completion": 208, "thinking": 679 }
  // The key is absent when it is 0 (every local Ollama record).
  "latency_ms": 1904,
  "model": "qwen2.5:7b",
  "schema_version": "1.5.0"
  // schema 1.5.0: present only when the entry was shortened for the model:
  //   "truncation": {"version": "sections-v1", "mode": "sections", "dropped": [...], "trimmed": {...}, ...}
  // original_text is always the FULL entry.
}
```

`RejectReason` values: `not_in_graph`, `too_common`, `not_in_index`,
`deprecated`, `revoked`, `malformed_id`, and (1.2.0) `name_mismatch`,
`llm_json_error`.

**Schema 1.5.0 (2026-10-09) adds the record-level `truncation` field; 1.4.0 (2026-10-08) adds `tokens.thinking`. Both are awaiting four-owner sign-off** —
`docs/proposals/thinking-tokens.md`. Cost for a thinking model is
`prompt` × input price + (`completion` + `thinking`) × output price.

**Schema 1.3.0 (1.2.0 from 2026-10-07, amended 2026-10-08) is awaiting four-owner sign-off** —
`docs/proposals/name-id-consistency.md`. Every addition is backward
compatible (a 1.1.0 record loads unchanged; there is a test for it), but new
enum values still reach Module 4's `RejectReason` switch, so it is a contract
change either way. Two states worth flagging to downstream readers:

- `graph_validated=True` on a **rejected** term is now normal and meaningful
  (name mismatch). Code that read `graph_validated` as a proxy for `accepted`
  is now wrong.
- a document whose reply never parsed is written with one rejected term
  carrying `reject_reason=llm_json_error` and the raw reply as its `term`. It
  inflates "terms proposed" by one per failed document; exclude it by reason if
  your denominator needs to be real proposals. It can never reach the index —
  `accepted=False`, and the index build reads accepted terms only.

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

- `GeminiClient` in `common/llm.py` and `load_env_file()` in `common/repro.py`
  (2026-10-08) — shared surface; Modules 2–4 can use them for their own
  approved frontier runs instead of writing a second backend.
- `src/sira_cti/common/repro.py` (new) — `config_hash` / `load_config`, used by
  both scripts for the "record the config hash" convention. New shared surface in
  `common/` — tell the other three so it doesn't get duplicated later.

---

## `enrichment.max_new_tokens` was dead config until 2026-10-07

It sat in `configs/default.yaml` being read by nothing: every reply was
generated unbounded. It now reaches Ollama as `options.num_predict` through
`common/llm.py`, which also grew `json_mode`/`json_schema` for constrained
decoding. Both live on the `LLMClient` base class rather than on one backend,
so a backend has to actively answer for them instead of silently ignoring a
config key — which is exactly how the cap went unread for six weeks.
`StubClient` records the resolved settings per call (`option_calls`), so a test
can assert that a config value actually reached the backend.

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
The script reads it straight from `prompts/corpus_side.py` (since 2026-09-15 —
it used to come from a config key that could drift out of step).

Versions: `corpus-v1` (original); `corpus-v2` (stronger "don't restate"
wording — reverted, `docs/experiments/prompt-corpus-v2.md`); `corpus-v3` — v1
with the document's own id removed from the user-turn header, so the model
can't copy an entry's id back as a "proposal"; **`corpus-v4` (live)** — v3 plus
a required `"name"` on every structural proposal. History and reasoning are in
the `PROMPT_VERSION` docstring and the two proposals under `docs/proposals/`.

v4's wording is **deliberately neutral**: it asks for the title as one more
field to fill in and does not warn that the title will be checked. Warning the
model would change how freely it proposes ids, and the gate would then be
measuring its own deterrent effect rather than the model's unprompted error
rate — which is what RQ4 is for.

`REPLY_SCHEMA` lives beside the prompt because it *is* the prompt's last
paragraph restated for a decoder to enforce. `name` is deliberately not in its
`required` list: a model that cannot name an id should be able to omit the
field and have that recorded as a mismatch, rather than being forced by the
grammar to invent a title.
**Known limitation — see `04_OPEN_QUESTIONS.md`:** this doesn't compose with
resumability (resume can mix records from two prompt versions under one manifest).
