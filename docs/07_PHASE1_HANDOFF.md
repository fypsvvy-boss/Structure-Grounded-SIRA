# Phase 1 handoff — the enriched index, for Modules 2 and 3

> Written 2026-10-14, when Stage 1 finished and the enriched index was built and
> checked; brought up to date 2026-11-17 (corrected corpus, two Gemini
> robustness indexes). Short on purpose; every claim points at where the
> detail lives.

## In one paragraph

Every one of the 6,044 corpus entries (CVE, CWE, CAPEC, ATT&CK) has been shown
to `qwen2.5:14b`, which proposed up to 12 search terms each. Every proposal
went through the gates (does the id exist, is its name right, is the phrase too
common) and was kept with its verdict. The **accepted** terms are now in a
second Lucene field, `expansion`, of the enriched index. The base index is
unchanged and stays Module 3's plain-BM25 baseline.

## Stage 2: three enriched indexes (added 2026-11-17)

**`qwen2.5:14b` is the main index.** It is the one Modules 3 and 4 build on
and report. **Both Gemini indexes are robustness indexes**: the same corpus,
prompt, gates and settings with only the model changed, to show whether the
findings survive a much stronger model. They do not replace the 14B index.

| index | path | built from (`indexes/enrichment/`) | role |
|---|---|---|---|
| base | `indexes/base/` | `data/corpus_kb_fixed` (contents only) | plain-BM25 baseline |
| **14B** | `indexes/enriched/` | `corpus_full_v4_14b_fixed.jsonl` | **main** |
| Gemini run 1 | `indexes/enriched_gemini_run1/` | `corpus_full_v4_gemini-3.1-pro_vertexbatch1_fixed.jsonl` | robustness |
| Gemini run 2 | `indexes/enriched_gemini_run2/` | `corpus_full_v4_gemini-3.1-pro_vertexbatch2_fixed.jsonl` | robustness |

All four hold the same 6,044 documents with the same fields (`id`,
`contents`, `expansion`), so any retriever pointed at one works on the
others. Each enriched index's `manifest.json` records the enrichment file,
its SHA-256, the model, the service (`ollama` for the 14B, `vertex-batch`
for Gemini) and the run number (`enrichment_run`: 1 for the 14B, 1 or 2 for
Gemini). All three passed the same checks (document count, every stored
expansion, sampled postings): `docs/results/enriched_index_smoke_test_all.txt`.

**The corpus is the corrected one.** 117 CVEs that CTIConnect's corpus
exported as `"null"` are filled from the official CVE List
(`data/corpus_kb_fixed`, config hash `06e891b2b957`) and were redone in all
three runs; the other 5,927 records are Stage 1's, carried over unchanged
(`03_STATUS_LOG.md`, "Corpus fix"). Rebuild commands: "Where things are"
below.

**For Phase 4: the noise floor.** Gemini gave different answers on its two
runs (73.6% of accepted ids shared, 2,484 of 6,044 replies identical). So
the retrieval gap between Gemini run 1 and Gemini run 2 is the noise floor.
A 14B-vs-Gemini difference counts as real only if it is clearly larger than
the run-1-vs-run-2 difference on the same queries and metric. Report the
Gemini result as a range across the two runs, never one run alone. The
smoke test already shows the two runs differing on 1–2 of their top 5 hits
per query.

**For Module 3: the 14B's ids are valid but less closely related.** Looking
only at accepted ids the model generated (not copied from the entry), on
CWE/CAPEC/ATT&CK documents, where distance can be measured:

| generated ids | 14B | Gemini run 1 | Gemini run 2 |
|---|---|---|---|
| within 1 hop of the document in the graph | 8.5% | 33.3% | 33.4% |
| within 2 hops | 50.3% | 67.3% | 67.1% |

Every one of them passed the gates, so they are real, correctly named ids.
But half of the 14B's sit three or more links away from the document. That
means:
- **Tune `w` carefully.** A high expansion weight lets loosely related ids
  pull documents up. The October and November smoke tests already show
  short expansion fields winning on one shared word.
- **Consider two ablations.** The repair flag
  (`enrichment.index_repaired_ids`) and removing a document's own id from its
  expansion (305 entries in the 14B index carry their own id). Both can be
  tested offline without new model calls.

Details: `docs/results/stage2_three_runs.txt` (Part 3) and `03_STATUS_LOG.md`
(2026-11-17).

## Where things are

| what | path | notes |
|---|---|---|
| **enriched index (main, 14B)** | `indexes/enriched/` | Lucene (Pyserini). Fields `id`, `contents`, `expansion`. `manifest.json` says what built it |
| Gemini robustness indexes | `indexes/enriched_gemini_run1/`, `indexes/enriched_gemini_run2/` | same fields; see "Stage 2" above |
| base index | `indexes/base/` | contents only, built from `data/corpus_kb_fixed`. The DF gate reads it (Stage 1 read the uncorrected base, kept as `indexes/base_unfixed/`; replaying every saved verdict against the corrected one changed none) |
| **enrichment records (14B)** | `indexes/enrichment/corpus_full_v4_14b_fixed.jsonl` | 6,044 lines, one per document. **The only 14B file to build from** |
| its manifest | `…/corpus_full_v4_14b_fixed.jsonl.manifest.json` | model, digest, prompt, every gate, machine; under `spliced`, the Stage 1 file the 5,927 carried records came from (its SHA-256 and full manifest, both shards included) |
| raw unparseable replies | `…/corpus_full_v4_14b_fixed.jsonl.raw_failures.jsonl` | 3 records (see below) |
| Gemini enrichment records | `indexes/enrichment/corpus_full_v4_gemini-3.1-pro_vertexbatch{1,2}_fixed.jsonl` | one per Gemini index, same record format |
| superseded | `indexes/enrichment/corpus_full_v4_14b.jsonl`, `indexes/enriched_unfixed/` | Stage 1 before the corpus fix; **history only, do not build from** |
| shard files | `indexes/enrichment/kaggle_stage1_shards/` | **provenance only** — the two Kaggle shard files, their manifests and logs. No script reads them; the Stage 1 file is byte for byte the two shards one after the other (checked) |

`indexes/` is gitignored, so none of this arrives with a clone; ask the
Module 1 owner for a copy of `indexes/`. To rebuild the three enriched
indexes from the records (about 5 seconds each):

```bash
.venv/bin/python scripts/build_index.py --stage enriched \
    --enrichment-path indexes/enrichment/corpus_full_v4_14b_fixed.jsonl --run 1
for n in 1 2; do .venv/bin/python scripts/build_index.py --stage enriched \
    --enrichment-path indexes/enrichment/corpus_full_v4_gemini-3.1-pro_vertexbatch${n}_fixed.jsonl \
    --enriched-dir indexes/enriched_gemini_run$n --run $n; done
```

The first command writes to `indexes/enriched/` (the config's
`index.enriched_dir`). Do **not** edit `configs/default.yaml` to point at
the files instead: the config hash identifies the runs (`06e891b2b957` since
the corpus fix; Stage 1 was `364d30da6c75`), and the runs used command-line
flags (`--model qwen2.5:14b --name-scorer v2`) precisely so the config could
stay as it was. The config therefore still says `llm.model: qwen2.5:7b`,
`name_scorer: v1` and `enrichment_path: …/corpus.jsonl`; the manifests are
what is true for these runs.

## What built it

| | |
|---|---|
| model | `qwen2.5:14b`, digest `7cdf5a0187d5…` (the same weights on the Mac and Kaggle) |
| prompt | `corpus-v4`, truncation rules `sections-v2` (171 long entries shortened for the model; `original_text` is always the full entry) |
| gates | name scorer **v2** (`min_jaccard` 0.6, v1 fallback `min_overlap` 0.5), `df_max_ratio` 0.1, deprecated rejected, revoked rejected |
| decoding | temperature 0, seed 42, `num_ctx` 4096, JSON schema, 512-token reply cap |
| code | 5,927 records: commit `6b4eecedf1cd`; the 117 corrected CVEs: commit `b3a6259`. Clean tree both times |
| where | 5,927 records: Kaggle, 2× Tesla T4, two sessions, Ollama 0.33.2. The 117: the Mac (Apple M5), Ollama 0.40.14, same weights (digest checked) |
| schema | **1.5.0** on every record |

## What a record contains

One JSON object per document: `doc_id`, `source` (`cve | cwe | capec |
attack`), `original_text`, `proposed_terms` (every proposal, accepted or not),
`llm_calls`, `tokens`, `latency_ms`, `model`, `schema_version`, and
`truncation` when the entry was shortened. Each proposed term carries `term`,
`kind`, `structural_id`, `accepted`, `reject_reason`, `rejected_at_stage`,
`claimed_name` / `official_name`, `in_counting_run`, `graph_distance`,
`name_scorer`, `repaired_to`. Full contract with every field explained:
`02_MODULE1_STATE.md` → "The frozen enrichment-record contract". Load with
`sira_cti.common.read_jsonl(path)`, which gives `EnrichmentRecord` objects.

Totals (14B): 72,090 terms proposed, **29,865 accepted** (41%), on **5,969 of
6,044 documents** (the other 75 have an empty `expansion` field — nothing
survived the gates). Full tables for all three runs:
`docs/results/stage2_three_runs.txt`.

## What is in the `expansion` field

The accepted terms of the document, joined by spaces, analysed exactly like
`contents` (Porter stemmer, same stopwords). A structural term contributes its
**normalised id** (`T1499`), not the model's wording (`"mitre attack t1499"`)
— the same rule Module 3's query side already used (fixed 2026-10-14; it
affected 18 terms in 12 documents).

Three things to know before you use it:

1. **Three documents have an empty expansion because the model's reply never
   parsed:** `T1064`, `T1542.001`, `CVE-2022-47378`. The model kept counting ids
   past the 12-term limit and hit the 512-token cap mid-list. Each is stored as
   one rejected placeholder term with `reject_reason: llm_json_error`; its
   `term` is the start of the broken reply. It is not accepted, so none of that
   text is indexed — those three documents are searchable by `contents` only.
   If you count "terms proposed", exclude `llm_json_error` (it is not a real
   proposal). The index manifest lists the three under `parse_failures`.
2. **Some entries now carry their own id in `expansion`.** The prompt no longer
   shows the model the document's id, but it often finds it in the text: 209 of
   615 CAPEC entries, 59 of 1,342 CWE and 37 of 1,076 ATT&CK entries have their
   own id accepted (CVE: 0 — a CVE id is never a structural term). So a query
   naming `CAPEC-112` will often find the CAPEC-112 entry even with
   `retrieval.id_boost: 0.0`. This touches Module 3's open decision 4
   (`05_MODULE3_STATE.md`: should an entry be findable by its own id, given
   the baselines' index has no ids?). Not changed in the index; it is your call.
3. **Field length matters.** The expansion field is a few words long, and BM25
   scores a match in a short field much higher than the same match in a long
   description. On a five-query smoke test (not an evaluation;
   `docs/results/enriched_index_smoke_test.txt`, repeated on all four indexes
   in `enriched_index_smoke_test_all.txt`) this helped one query
   (brute-force entries rose for "repeated login failures from one IP") and
   hurt two (one word like "folder" in short expansion fields decided the
   order). The field boosts (`retrieval.fields`) are the knob; tune them on
   the dev queries.

## Reusable interfaces (Module 2: use these for the query side, so both sides judge terms the same way)

**Ontology graph** — `sira_cti.graph.OntologyGraph`

```python
from sira_cti.common import load_config
from sira_cti.graph import OntologyGraph
g = load_config("configs/default.yaml")["graph"]
graph = OntologyGraph.from_files(attack_path=g["attack_path"], cwe_path=g["cwe_path"],
                                 capec_path=g["capec_path"], domains=g.get("domains"))

graph.validate("T1110.001")        # -> ValidationResult(valid, canonical_id, node, reject_reason, replacement_id, repaired)
graph.resolve("cwe-79")            # -> OntologyNode or None (normalises the spelling)
graph.parents(id), graph.children(id), graph.siblings(id), graph.tactics_for(id), graph.mapped(id)
graph.distance(a, b, max_hops=6)   # hops between two nodes, or None
graph.context(id)                  # name, type, parents, tactics, … as a dict
graph.expansion_terms(id, include_siblings=False)   # id, name, parents' ids and names
```

`validate()` is the existence check: `reject_reason` is `not_in_graph`,
`deprecated`, `revoked` (with `replacement_id`) or `malformed_id`. Stage 1 ran
with `allow_deprecated=False`, `revoked_policy="reject"`.

**Name check** — does the name the model gave an id match MITRE's?

```python
graph.check_name("CWE-89", "SQL Injection", scorer="v2", min_jaccard=0.6, min_overlap=0.5)
# -> NameCheck(matches, claimed_name, official_name, overlap, matched_against, scorer)
```

Scorers are `sira_cti.graph.NAME_SCORERS` = `v1`, `v2`, `v3`. **Stage 1 used
v2**; pass `scorer="v2"` explicitly (the function's default and the config's
are still v1). `NameCheck.scorer` says which rule actually decided (`v2:v1-fallback`
for a node with no short names — every ATT&CK and CAPEC node, most CWEs). A
blank claim is a mismatch, never a pass. Why v2: `docs/proposals/module1-freeze.md`
→ "Which scorer".

**The whole gate chain in one call** — what Stage 1 ran after each reply:

```python
from sira_cti.enrichment.corpus_side import Proposal, adjudicate_proposals
from sira_cti.index import LuceneDFLookup
terms = adjudicate_proposals(
    [Proposal(term="T1110", kind="structural", claimed_name="Brute Force"), Proposal("password spraying", "colloquial")],
    doc, graph, LuceneDFLookup("indexes/base"),
    df_max_ratio=0.1, name_scorer="v2", name_match_min_overlap=0.5, name_match_min_jaccard=0.6,
)   # -> list[ProposedTerm], every one with its verdict; route -> graph -> name -> DF -> measurements
```

`doc` is a `sira_cti.index.CorpusDocument` (`doc_id`, `source`, `title`, `text`);
for an analyst query use `Source.QUERY`. The DF gate alone is
`sira_cti.index.too_common(term, LuceneDFLookup("indexes/base"), df_max_ratio=0.1)`.

**Retrieval scorer** (Module 3's, listed so Module 2 knows what consumes its records):

```python
from sira_cti.retrieval.weighted_bm25 import WeightedBM25Retriever
r = WeightedBM25Retriever("indexes/enriched", w=1.0)           # both halves search contents + expansion
r.retrieve("repeated login failures from one IP", enrichment=query_record, k=100)   # -> RetrievalResult
```

`query_record` is Module 2's `EnrichmentRecord` for the query; only its
accepted terms enter `q_exp`, and a structural term enters as its
`structural_id`.

## Counted for you (RQ4, full corpus)

`docs/results/stage2_three_runs.txt` (all three runs, corrected corpus) and
`04_OPEN_QUESTIONS.md` question 14. `docs/results/stage1_full_breakdown.txt`
is the same breakdown for Stage 1 before the corpus fix (history). To
recompute the 14B's: `.venv/bin/python scripts/rq4_breakdown.py
indexes/enrichment/corpus_full_v4_14b_fixed.jsonl` (read-only, about 2
seconds).
