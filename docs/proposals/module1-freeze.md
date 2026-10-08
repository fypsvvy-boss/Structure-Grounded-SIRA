# Module 1 freeze checklist — what gets locked for the full-corpus run

**Status: draft for the Module 1 owner, 2026-10-08. Nothing is frozen yet and
the full-corpus run has not been started.**
**Purpose:** agree the exact method before spending ~1–2 days of laptop time
enriching all 6,044 documents and building the enriched index, which completes
Phase 1.

---

## The one idea that makes this list short

A run has two halves, and only one of them is expensive.

- **Generation** — the model reads a document and replies. Slow, and cannot be
  redone without paying for it again.
- **Adjudication** — every gate after the reply (kind routing, graph check,
  name check, document-frequency check, the measurements). A pure function of
  the saved reply, the graph and the base index.
  `scripts/rescore_enrichment.py` re-runs all of it on a saved file with **no
  model calls**, in seconds, and replaying a saved run under its own settings
  reproduces every verdict exactly (checked on both `corpus-v4` files).

So the things that **must** be right before the run starts are the ones that
shape the reply. Everything else is frozen for the write-up's sake — one
method, stated once — but a wrong choice there costs seconds to correct, not
days.

## A. Frozen at generation — changing any of these means re-running the model

| what | proposed value | where it lives | note |
|---|---|---|---|
| model | **`qwen2.5:14b`** (see "Which model" below) | `--model` / `llm.model` | manifest records the one that ran |
| temperature | `0.0` | `llm.temperature` | |
| seed | **not sent today** | — | `OllamaClient` sends temperature only. At temperature 0 replies have been byte-identical across retries, but send an explicit seed before freezing so that is a setting rather than an observation |
| prompt | **`corpus-v4`** | `prompts/corpus_side.py:PROMPT_VERSION` | names required on structural ids; neutral wording (does not warn that names are checked) |
| reply schema | `REPLY_SCHEMA` (`name` optional) | `prompts/corpus_side.py` | |
| decoding mode | **`schema`** | `enrichment.json_mode` | fixed `CAPEC-587`; costs 1.5x on the 7B, nothing on the 14B (open question 11) |
| reply cap | `512` tokens | `enrichment.max_new_tokens` | no sampled reply has come near it (largest ~270) |
| terms per document | `12` | `enrichment.max_terms_per_doc` | it is in the prompt text, so it shapes the reply |
| JSON retry | `1`, with nudge | `enrichment.json_retries` | zero retries were needed in either `corpus-v4` run |
| unparseable reply | recorded as `llm_json_error` | `enrichment.record_json_failures: true` | so the run can finish |
| context handling | **UNDECIDED — blocker** | open question 12 | ~40 documents exceed the 4,096-token context and would be silently truncated |
| concurrency | **`1`** | `--concurrency 1` | 2 gives no speed-up on Ollama and doubles recorded latency (open question 11) |
| corpus | all four kinds, no sampling | `corpus.kinds`, no `--limit`/`--per-kind` | |
| output | a **new** file, e.g. `indexes/enrichment/corpus_full_v4_14b.jsonl` | `--output` | never the default `corpus.jsonl`, which holds `corpus-v1` records (open question 2) |

## B. Frozen for the write-up — re-derivable offline if a choice turns out wrong

| what | proposed value | where it lives | note |
|---|---|---|---|
| schema version | **`1.3.0`** | `common/schemas.py` | needs four-owner sign-off — `docs/proposals/name-id-consistency.md` |
| name check | on | `enrichment.name_match_min_overlap: 0.5` | `null` = the existence-only ablation |
| name scorer | **`v2`** | `enrichment.name_scorer` | currently `v1` in the config; change at freeze. See "Which scorer" |
| v2/v3 threshold | `0.6` | `enrichment.name_match_min_jaccard` | |
| DF gate | `df_max_ratio: 0.10`, `df_min_count: 1` | `enrichment.*` | rarest token for structural ids, commonest for phrases |
| deprecated / revoked ids | rejected | `graph.allow_deprecated: false`, `graph.revoked_policy: reject` | |
| repair | measured always; **not indexed** | `enrichment.index_repaired_ids: false` | Module 3/4 flip it for their ablation and rebuild the index — no re-enrichment |
| counting-run flag, graph distance | measured, never gated | — | |
| ontology snapshot | ATT&CK v17.1 (three domains), `cwec_latest`, `capec_latest` | `graph.*` | |
| base index | `indexes/base`, porter stemmer | `index.*` | DF statistics are read from it |

Still to come and **not** a blocker, for the same reason: the question-7
`already_in_document` gate (awaiting sign-off) is a gate after the reply, so it
can be applied to the finished full-corpus file offline.

## Blockers — must be closed before the run starts

1. **Context overflow (open question 12).** Decide: raise `num_ctx`, truncate
   long documents explicitly, or skip them. Recommended: explicit truncation to
   a character budget, with the count written to the manifest.
2. **Explicit seed** sent to Ollama (two-line change in the wrapper + a test).
3. **Schema 1.3.0 sign-off** from Modules 2, 3 and 4. The run can technically
   proceed without it, but Module 3 will be reading 1.3.0 records.
4. **Model choice** — below.

## Which model

The honest position: the two local models behave so differently that the
choice is a research decision, not a tuning one.

| on the 40-document sample, scorer v2 | `qwen2.5:7b` | `qwen2.5:14b` |
|---|---|---|
| structural ids proposed | 14 | 157 |
| structural ids accepted | 4 | 54 |
| …of which copied from the entry's own text | 4 (all of them) | 16 |
| rejected at `graph` / `name` | 4 / 6 | 32 / 71 |
| ids in a counting run | 0 | 51 |

The 7B proposes almost no identifiers, and every one that survives the gates
was copied off the page. An index enriched by it is, structurally,
close to the base index — the grounding mechanism this project tests barely
fires. The 14B exercises every gate. **Recommendation: `qwen2.5:14b` for the
Phase 1 index.** The third (frontier) point from open question 10 would say
whether that pattern is a trend; it is worth having before committing two days
of compute, and it is ~$0.25.

## Time and cost for the full corpus (6,044 documents)

Clean measurements (one request at a time, nothing else on Ollama, schema
decoding), from open question 11. Tokens from the `corpus-v4` runs: ~890 prompt
and ~205–260 completion per document.

| model | s/doc | full corpus | money |
|---|---|---|---|
| `qwen2.5:7b` | 12.7 | **~21 hours** | $0 (local) |
| `qwen2.5:14b` | 31.7 | **~53 hours (2.2 days)** | $0 (local) |
| frontier API, for reference | — | well under an hour at concurrency 4–8 | ~$9–35 (5.4M prompt + 1.4M completion tokens; check current prices) |

The run is resumable — one flushed line per document, so a crash, a sleep or a
closed lid loses at most the document in flight, and re-running the same
command continues. Practicalities for a 2-day local run: plugged in, sleep
disabled (`caffeinate -i`), **nothing else using Ollama** (a second model on
16 GB forces a reload cycle and wrecks both speed and the latency numbers),
and `--concurrency 1`.

Command, once frozen (do not run yet):

```bash
caffeinate -i .venv/bin/python scripts/enrich_corpus.py \
    --model qwen2.5:14b --name-scorer v2 --concurrency 1 \
    --output indexes/enrichment/corpus_full_v4_14b.jsonl
# then point index.enrichment_path at that file and:
.venv/bin/python scripts/build_index.py --stage enriched --config configs/default.yaml
```

## Which scorer

| | v1 | **v2** | v3 |
|---|---|---|---|
| 14B structural accepted | 56 | 54 | 46 |
| catches the known within-family escapes | no | yes (all 3 it can reach) | yes |
| known false rejections on the sample | 0 | 1 (`CWE-415`) | 1 + 2 stale-name |
| reach | every node | 122 CWE nodes; v1 elsewhere | every node |

**Recommendation: v2.** It is strictly v1 plus a targeted fix where MITRE gives
us short names, it reports honestly when it had none (`v2:v1-fallback`), and
its one false rejection is visible. v3 catches more, but on one 40-document
sample it also rejects names that are stale rather than wrong, and that
distinction deserves a look on more data before it becomes the method. Because
adjudication is offline, choosing v2 now does not close the door: v3 can be
applied to the finished full-corpus file in seconds.

## What Module 2 reuses, and the interfaces

All in `src/sira_cti/`, all covered by the offline test suite (256 tests).

**The graph tool** — `graph.OntologyGraph`

```python
graph = OntologyGraph.from_files(attack_path=..., cwe_path=..., capec_path=..., domains=...)

graph.validate(term, *, allow_deprecated=False, revoked_policy="reject") -> ValidationResult
    # .valid .canonical_id .node .reject_reason .replacement_id .repaired
graph.check_name(node_id, claimed_name, *, min_overlap=0.5, scorer="v1", min_jaccard=0.6) -> NameCheck
    # .matches .claimed_name .official_name .overlap .matched_against .scorer
graph.distance(src_id, dst_id, *, max_hops=6) -> int | None
graph.within(node_id, max_hops) -> dict[node_id, hops]
graph.name_candidates(claimed_name, node_ids, *, min_jaccard=0.6) -> list[(node_id, score)]
graph.resolve(identifier_or_exact_name) -> OntologyNode | None
graph.context(node_id) / parents / children / siblings / mapped / expansion_terms
```

`check_name` takes a **canonical** id (what `validate` returns), not a raw
term. Stage order is `validate` → `check_name`; a `NAME_MISMATCH` keeps
`graph_validated=True`.

**The adjudication pipeline** — `enrichment.corpus_side`

```python
Proposal(term, kind, claimed_name=None)            # one element of a model reply, unadjudicated
adjudicate_proposals(proposals, doc, graph, df_lookup, *, df_max_ratio,
                     name_match_min_overlap=None, name_scorer="v1",
                     name_match_min_jaccard=0.6, ...) -> list[ProposedTerm]
readjudicate_record(record, graph, df_lookup, ...) -> EnrichmentRecord   # no model call
flag_counting_runs(terms) / annotate_graph_distance(terms, doc, graph)
repair_candidates(term, doc, graph, df_lookup, *, df_max_ratio) -> list[(id, score, hops)]
```

Query-side caveats Module 2 should know before reusing these as they are:
`adjudicate_proposals` takes a `CorpusDocument` and uses `doc.doc_id` as the
anchor for `graph_distance` and repair — a query has no ontology node, so both
come out `None`/empty, exactly as they do for CVEs. And corpus-side only
applies `too_common`; `not_in_index` (query terms must exist in the enriched
index) is Module 2's own gate.

**The LLM wrapper** — `common.llm`: `max_new_tokens`, `json_mode`,
`json_schema` on every client; `OllamaClient.last_timings` /
`last_stop_reason`; `StubClient.option_calls` for tests. Use the same
`json_schema` mechanism and the same config keys, or the two sides of the
pipeline are not comparable (open question 11).

**The contract** — `common.schemas`, version 1.3.0: `ProposedTerm` fields
`claimed_name`, `official_name`, `rejected_at_stage`, `in_counting_run`,
`graph_distance`, `name_scorer`, `repaired_to`; reasons `name_mismatch`,
`llm_json_error`.

## Known loose ends that the freeze does *not* fix

- `expansion_query()` indexes an accepted structural term as the model
  *wrote* it (`cwe-287`), not its canonical id (`CWE-287`). Harmless here —
  the analyzer lower-cases and splits both the same way — but a model writing
  `t1110/001` would be indexed as two tokens while `T1110.001` is one. One
  occurrence of a non-canonical spelling in the 14B sample. Module 3's call.
- The config hash changed on 2026-10-08 (`86fee6d106b8` → `2514fd048115`)
  because the scorer and repair keys were added. They do not affect generation,
  and each manifest's `gates` block says what a run actually used — but hashes
  alone will not show that the `corpus-v4` sample runs and anything run after
  today are comparable.
- Open question 2 (resuming into a file written under a different prompt
  version) is still unguarded. Hence "a new `--output` file" above.
