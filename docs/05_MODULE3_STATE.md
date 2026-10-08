# Module 3 — Implementation State

> What Module 3 (retrieval engine + baselines) has built, the decisions behind
> it, and what it still needs from the other modules. Branch: `sarthak`.

---

## What's built

| Piece | File | What it is |
|---|---|---|
| Weighted retrieval engine | `src/sira_cti/retrieval/weighted_bm25.py` | `score(d) = BM25(q_orig,d) + w·BM25(q_exp,d)` as **one** Lucene query |
| Synthesis protocol | same file, `retrieve_synthesis()` | main query + up to `budget` sub-queries, evidence-blind, merged by RRF |
| Result types | `src/sira_cti/retrieval/types.py` | `RetrievalResult` (ranking + cost), `Retriever` protocol, TREC run writer |
| Baseline: plain BM25 | `retrieval/baselines/plain_bm25.py` | base index, contents only |
| Baseline: hybrid | `retrieval/baselines/hybrid.py` | dense bi-encoder + BM25, fixed mixing weight |
| Baseline: multi-round agent | `retrieval/baselines/multi_round_agent.py` | search → read → rewrite, one LLM call per extra round |
| Runner | `scripts/run_retrieval.py` | any system over a query file → TREC run + cost sidecar + manifest |

Tests: `tests/test_weighted_bm25.py` (28) and `tests/test_baselines.py` (16).
All offline — real tiny Lucene indexes over `tests/fixtures/corpus_kb`, a
word-hashing stand-in for the dense encoder, `StubClient` for the agent.
Suite total: 214.

**Not yet run on real data.** `data/` and `indexes/` are gitignored and were not
on the machine this was written on, so nothing here has touched the real
6,044-document corpus or a CTIConnect query. Every number below is a design
default, not a tuned value.

---

## Decisions

### 1. One retrieval call, exact

BM25 is a sum over query terms, so the formula is one bag-of-words query in
which each `q_exp` term carries boost `w`. The engine sends exactly that — a
boolean query of boosted term clauses — instead of running two searches and
adding the lists. Adding two top-k lists gives a document outside one list a
zero for that half, and it is two calls where SIRA claims one.
`test_one_call_scores_exactly_the_sum_of_the_two_halves` checks the single call
against the two halves scored separately.

### 2. Which fields each half searches — `04_OPEN_QUESTIONS.md` question 4

`BM25(q, d)` here means `Σ_fields boost_f · BM25_f(q, d)`, and **both halves
search both fields** (`contents` and `expansion`), each at boost 1.0:

- `q_orig` has to reach `expansion`, or corpus-side enrichment does nothing: that
  field holds the plain-language terms put there for the analyst's own words to
  match.
- `q_exp` has to reach `contents`, or a predicted `CWE-307` cannot find the CVEs
  that cite it.

The length-normalisation concern is real and not solved by this: `expansion` is
a few terms long, so a match there is scored against a much shorter field. The
per-field boosts are the knob (`retrieval.fields` in the config). **They are
untuned at 1.0** and should be set on the held-out slice alongside `w`.

### 3. Which enrichment terms enter the query

Read-time filtering, as `schemas.py` requires: accepted terms only, deduped. A
structural term contributes its `structural_id` (the post-repair id), not the
model's literal text — this differs from `EnrichmentRecord.expansion_query()`,
which joins `term`. `--no-grounding` also admits terms rejected for a graph
reason (`not_in_graph`, `deprecated`, `revoked`, `malformed_id`), which gives
the "without graph-grounding" ablation from the same records with no second LLM
pass. Corpus-statistics rejections (`too_common`, `not_in_index`) stay out
either way.

### 4. Should an entry be findable by its own id? — handed over by Module 1

**Built, switched off (`retrieval.id_boost: 0.0`). Needs a team decision.**
When above zero, an id named in the query — or a structural id in `q_exp` —
also matches the entry whose doc id it is, through an exact match on Lucene's
`id` field. No change to how the index is built.

Why it matters more than it looks: query-side enrichment predicts ids like
`CWE-307`, but the CWE-307 *entry* never contains "307". With `id_boost` off, a
correct structural prediction finds the CVEs citing that weakness and not the
weakness itself — which is the gold document for entity-linking questions.
Why it is off: CTIConnect's own baselines index title + contents with no id, so
turning it on for SIRA-CTI only is an advantage the baselines don't get, and
should be reported as such. The alternative is for Module 2 to add the node's
*name* to `q_exp` (`OntologyGraph.expansion_terms`), which matches the entry's
title with no special handling.

### 5. Synthesis is evidence-blind by construction

`retrieve_synthesis()` takes its sub-queries as an argument, fixed before the
first search. There is no callback through which retrieved text could reach a
model. The lists are merged by reciprocal rank fusion, because BM25 scores from
different queries are not on one scale.

### 6. Baselines share the engine

Plain BM25 is the weighted engine with the expansion half off, so the baseline
and the system under test cannot drift apart in tokenization or scoring. The
hybrid and agent baselines both use it as their sparse side, over the base
index.

The agent raises on an LLM backend failure instead of carrying on: with the
model unreachable it would otherwise produce plain-BM25 rankings labelled as the
agent's.

---

## What Module 3 needs from the others

- **Module 2:** query-side `EnrichmentRecord`s (`source="query"`) in one JSONL,
  with `doc_id` = the question id. For synthesis questions, the sub-queries and
  a record per sub-query id. Nothing here depends on how they are produced.
- **Module 4:** the query file format. The runner reads JSONL
  `{"id", "query"[, "sub_queries": [{"id", "query"}]]}`; converting CTIConnect's
  tasks into that is not done. Output is a standard six-column TREC run plus
  `<run>.costs.jsonl` (LLM calls, tokens, latency per question).
- **Everyone:** the `id_boost` decision above.

## Open items

- [ ] Run all four systems on the real corpus and CTIConnect queries.
- [ ] Tune `w` and the field boosts on a held-out slice (README assigns weight
      tuning to Module 2; the sweep is `--w` on the runner).
- [ ] Hybrid: `all-MiniLM-L6-v2` truncates at 256 word pieces, so long JSON
      entries are embedded by their opening only. Decide whether that is an
      acceptable baseline or whether entries need chunking.
- [ ] Agent: prompt `agent-v1` is a first draft, untested against a real model.
- [ ] Module 3's row in `docs/proposals/already-in-document-gate.md` is still
      *pending*.
