# Phase 1 handoff — the enriched index, for Modules 2 and 3

> Written 2026-10-14, when Stage 1 finished and the enriched index was built and
> checked. Short on purpose; every claim points at where the detail lives.

## In one paragraph

Every one of the 6,044 corpus entries (CVE, CWE, CAPEC, ATT&CK) has been shown
to `qwen2.5:14b`, which proposed up to 12 search terms each. Every proposal
went through the gates (does the id exist, is its name right, is the phrase too
common) and was kept with its verdict. The **accepted** terms are now in a
second Lucene field, `expansion`, of the enriched index. The base index is
unchanged and stays Module 3's plain-BM25 baseline.

## Where things are

| what | path | notes |
|---|---|---|
| **enriched index** | `indexes/enriched/` | Lucene (Pyserini). Fields `id`, `contents`, `expansion`. `manifest.json` says what built it |
| base index | `indexes/base/` | contents only; the DF gate read it during Stage 1 |
| **enrichment records** | `indexes/enrichment/corpus_full_v4_14b.jsonl` | 6,044 lines, one per document. **The only file to build from** |
| its manifest | `…/corpus_full_v4_14b.jsonl.manifest.json` | model, digest, prompt, every gate, both shards' SHA-256, every machine |
| raw unparseable replies | `…/corpus_full_v4_14b.jsonl.raw_failures.jsonl` | 3 records (see below) |
| shard files | `indexes/enrichment/kaggle_stage1_shards/` | **provenance only** — the two Kaggle shard files, their manifests and logs. No script reads them; the merged file is byte for byte the two shards one after the other (checked) |

`indexes/` is gitignored, so none of this arrives with a clone; ask the
Module 1 owner for a copy of `indexes/`. To rebuild the enriched index from the
records (about 4 seconds):

```bash
.venv/bin/python scripts/build_index.py --stage enriched \
    --enrichment-path indexes/enrichment/corpus_full_v4_14b.jsonl
```

Do **not** edit `configs/default.yaml` to point at the new file instead: the
config hash identifies the run (`364d30da6c75`), and the run used command-line
flags (`--model qwen2.5:14b --name-scorer v2`) precisely so the config could
stay as it was. The config therefore still says `llm.model: qwen2.5:7b`,
`name_scorer: v1` and `enrichment_path: …/corpus.jsonl`; the manifests are
what is true for this run.

## What built it

| | |
|---|---|
| model | `qwen2.5:14b`, digest `7cdf5a0187d5…` (the same weights on the Mac and Kaggle) |
| prompt | `corpus-v4`, truncation rules `sections-v2` (171 long entries shortened for the model; `original_text` is always the full entry) |
| gates | name scorer **v2** (`min_jaccard` 0.6, v1 fallback `min_overlap` 0.5), `df_max_ratio` 0.1, deprecated rejected, revoked rejected |
| decoding | temperature 0, seed 42, `num_ctx` 4096, JSON schema, 512-token reply cap |
| code | commit `6b4eecedf1cd`, clean tree |
| where | Kaggle, 2× Tesla T4, two sessions, Ollama 0.33.2 |
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

Totals: 70,686 terms proposed, **28,705 accepted** (41%), on **5,852 of 6,044
documents** (the other 192 have an empty `expansion` field — nothing survived
the gates). Full RQ4 tables: `docs/results/stage1_full_breakdown.txt`.

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
   `docs/results/enriched_index_smoke_test.txt`) this helped one query
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

`docs/results/stage1_full_breakdown.txt` and `04_OPEN_QUESTIONS.md` question 14.
To recompute any of it: `.venv/bin/python scripts/rq4_breakdown.py
indexes/enrichment/corpus_full_v4_14b.jsonl` (read-only, about 2 seconds).
