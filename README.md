# Structure-Grounded SIRA (SIRA-CTI)

**A single-shot, corpus-grounded retrieval agent for Cyber Threat Intelligence.**

Testing whether SIRA's Wikipedia-category grounding mechanism generalises to the MITRE ATT&CK / CWE / CAPEC security ontology graph.

> **Status:** Phase 0 complete (baseline reproduction verified). Phase 1 in progress.
> **Type:** Final Year Project — 4-person team.

---

## Table of Contents

- [Motivation](#motivation)
- [Research Questions](#research-questions)
- [How It Works](#how-it-works)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [Phase 0 — Reproducible Smoke Test](#phase-0--reproducible-smoke-test)
- [Data Sources](#data-sources)
- [Evaluation](#evaluation)
- [Results](#results)
- [Team & Modules](#team--modules)
- [Roadmap](#roadmap)
- [Contributing Conventions](#contributing-conventions)
- [Licensing & Attribution](#licensing--attribution)
- [Citation](#citation)

---

## Motivation

Security analysts don't think in the vocabulary their knowledge bases use. They think *"weird repeated login failures from one IP"* — not `CWE-307`. Bridging that gap today means either keyword search that misses anything phrased differently, or a multi-round LLM agent that searches, reads and re-searches until it stumbles onto the right terminology, burning tokens and latency on every round.

SIRA (Yang, Ma, Chen & Shrivastava, 2026 — Meta Superintelligence Labs / Rice University) proposes the opposite: use the LLM **once, before any retrieval**, to predict the vocabulary a relevant document would contain, validate those predictions cheaply against the corpus's own statistics, then fire a **single weighted BM25 call**.

On SIRA's hardest benchmark (BrowseComp-Wikipedia, 25.5M documents), its single largest source of advantage comes from one mechanism the paper **never re-tests anywhere else**: validating LLM-proposed Wikipedia categories against the real category graph before letting them into the query.

That mechanism was demonstrated on exactly one corpus — one the LLM already knows extremely well. **This project asks whether it's a property of Wikipedia or a general principle.**

CTI is the natural second test. It is already organised around a public, machine-readable ontology graph (CVE ↔ CWE ↔ CAPEC ↔ MITRE ATT&CK) that plays the same structural role Wikipedia's categories did — but hierarchical and multi-relational rather than flat, and in a domain where the LLM's prior knowledge is narrower.

---

## Research Questions

| RQ | Question | Hypothesis |
|---|---|---|
| **RQ1** — Generalisation | Does category-graph grounding transfer from Wikipedia's flat tags to a hierarchical security ontology? | Graph-grounded query construction yields a measurably higher proportion of valid, discriminative expansion terms than ungrounded proposals, despite the different graph shape. |
| **RQ2** — Comparative performance | Does SIRA-CTI match or exceed plain BM25, hybrid dense-sparse retrieval, and multi-round agentic search on CTIConnect? | Best or joint-best Recall@10 / NDCG@10 on entity-linking and entity-attribution tasks; smaller gains on multi-document synthesis. |
| **RQ3** — Cost-efficiency | What is the retrieval-quality-per-LLM-call and per-second trade-off vs. a multi-round agent? | Substantially fewer LLM calls and lower latency for equal or better accuracy. |
| **RQ4** — Robustness *(stretch)* | How often does the LLM hallucinate an invalid ATT&CK/CWE identifier, and does grounding catch it? | A non-trivial fraction fails validation; removing the filter measurably degrades precision. |

---

## How It Works

Five zones. An offline half and an online half, meeting at exactly one retrieval call.

```
        ┌─────────────────── OFFLINE (once per corpus) ───────────────────┐
CVE ─┐  │  ┌──────────────────────────┐                                   │
CWE ─┼──┼─▶│ 1. Corpus-side enrichment│──┐                                │
CAPEC┤  │  │    (Module 1)            │  │                                │
ATT&CK┘ │  └──────────────────────────┘  │                                │
Reports │              ▲                  ▼                               │
        │              │        ┌──────────────────┐                      │
        │              │        │  Enriched BM25   │                      │
        │              │        │  index (Lucene)  │                      │
        │              │        └──────────────────┘                      │
        └──────────────┼──────────────────┼──────────────────────────────┘
                       │                  │
              ┌────────┴─────────┐        │
              │ 3. Ontology graph│        │        score(d) =
              │    tool (shared) │        │   BM25(q_orig, d)
              │    networkx over │        │ + w · BM25(q_exp, d)
              │    MITRE STIX    │        │
              └────────┬─────────┘        ▼
                       │        ┌──────────────────────┐     ┌───────────┐
        ┌──────────────┼───────▶│ 4. Weighted retrieval│────▶│ Ranked    │
        │              │        │    engine (Module 3) │     │ top-k CTI │
Analyst │  ┌───────────┴──────┐ └──────────────────────┘     │ documents │
query ──┼─▶│ 2. Query-side    │            ▲                 └───────────┘
        │  │    enrichment    │────────────┘                       │
        │  │    (Module 2)    │                                    ▼
        │  └──────────────────┘                     ┌───────────────────────┐
        └───── ONLINE (once per query) ─────┘       │ 5. Eval harness (M4)  │
                                                    │ + baselines/ablations │
                                                    └───────────────────────┘
```

**1. Corpus-side enrichment (offline, Module 1).** A frozen LLM reads each CVE/CWE/CAPEC/ATT&CK entry and proposes vocabulary an analyst might search for but that is absent from the entry's own text — plain-language symptoms, product names, misspellings, colloquial attack names. Structural proposals are validated against the graph tool. Terms that fail validation, or are too common to be discriminative, are discarded. Survivors are injected into the BM25 index as posting entries.

**2. Query-side enrichment (online, Module 2).** The same frozen LLM reads the analyst's plain-language query and predicts the CWE / ATT&CK / CAPEC vocabulary a matching document is likely to reference. It explicitly avoids guessing a specific CVE ID outright — that would bias retrieval toward a single premature candidate. Every proposal must pass the graph filter **and** exist in the enriched index.

**3. Ontology graph tool (shared).** Built over MITRE's published STIX/JSON with `networkx`. Confirms a technique or weakness class exists, returns parent tactic and sibling techniques, rejects unsupported or hallucinated identifiers. This is the component under test.

**4. Weighted retrieval engine (Module 3).** `score(d) = BM25(q_orig, d) + w · BM25(q_exp, d)`, with `w` tuned on a held-out CTIConnect slice. For multi-document synthesis queries it follows the BrowseComp-Wikipedia protocol — a small fixed budget of additional graph-grounded queries, but **evidence-blind**: intermediate results are never read back into the prompt. That property is what separates SIRA from a multi-round agent.

**5. Evaluation harness (Module 4).** CTIConnect plus a hand-written vague-query set, with cost and latency instrumented on every LLM call.

---

## Repository Structure

```
sira-cti/
├── README.md
├── requirements.txt
├── .env.example                    # LLM keys, NVD API key — never commit .env
├── configs/
│   └── default.yaml                # w, k1, b, budgets, model names
├── data/                           # gitignored — see data/README.md for fetch steps
│   ├── raw/                        # ATT&CK STIX, CWE XML, CAPEC XML, CVE feeds
│   ├── cticonnect/                 # from peng-gao-lab/CTIConnect
│   └── processed/
├── indexes/                        # gitignored — built Lucene indexes
├── src/sira_cti/
│   ├── common/                     # schemas, LLM client, cost + latency tracking
│   ├── graph/                      # Zone 3 — ontology graph tool (shared, M1+M2)
│   ├── enrichment/
│   │   ├── corpus_side.py          # Module 1
│   │   └── query_side.py           # Module 2
│   ├── index/                      # Pyserini build + posting injection (Module 1)
│   ├── retrieval/
│   │   ├── weighted_bm25.py        # Module 3
│   │   └── baselines/              # plain_bm25 | hybrid | multi_round_agent
│   └── eval/                       # Module 4 — harness, metrics, ablations
├── scripts/
│   ├── phase0_scifact_smoke_test.py
│   ├── build_index.py
│   ├── run_retrieval.py
│   └── run_eval.py
├── tests/
├── notebooks/
└── docs/
    ├── proposal/                   # FYP proposal, slide deck, references
    └── architecture/               # system diagram
```

---

## Getting Started

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | 3.12+ if you also run the upstream SIRA repo |
| JDK | 11+ (21 recommended) | Required by Pyserini (wraps Lucene/Anserini) |
| Ollama or vLLM | latest | For open-weight dev models |
| NVD API key | — | Free; unauthenticated rate limits are too low for bulk pulls |

### Setup

```bash
git clone https://github.com/fypsvvy-boss/Structure-Grounded-SIRA.git
cd sira-cti

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt

java -version                      # confirm JDK is on PATH
# if missing: conda install -c conda-forge openjdk=21 -y

cp .env.example .env               # then fill in NVD_API_KEY, LLM creds
```

### Model setup (development)

Iterative development uses an open-weight model; a frontier API model is reserved for the **final benchmark run only**. This is a deliberate cost-control decision, not a fallback.

```bash
ollama pull qwen2.5:7b             # or llama3:8b
```

---

## Phase 0 — Reproducible Smoke Test

Before touching CTI data, prove the indexing → search → evaluation loop works end to end on BEIR SciFact (~5K documents, 300 test queries — minutes, not hours).

```bash
python scripts/phase0_scifact_smoke_test.py
```

The script downloads SciFact, reformats it into Pyserini's JSON collection format, builds a Lucene index, runs BM25 over the test queries, and scores with `pytrec_eval`. Index build, for reference:

```bash
python -m pyserini.index.lucene \
  --collection JsonCollection \
  --input collections/scifact \
  --index indexes/scifact \
  --generator DefaultLuceneDocumentGenerator \
  --threads 2 --storePositions --storeDocvectors --storeRaw
```

Anything within roughly ±0.02–0.03 of the target numbers below is normal tokenizer/analyzer variation and counts as a pass.

---

## Data Sources

| Source | Location | Format | Notes |
|---|---|---|---|
| MITRE ATT&CK | [github.com/mitre/cti](https://github.com/mitre/cti) | STIX/JSON | Backing data for the graph tool |
| CWE | [cwe.mitre.org](https://cwe.mitre.org/) | XML / CSV | Weakness classes |
| CAPEC | [capec.mitre.org](https://capec.mitre.org/) | XML | Attack patterns |
| CVE | NVD API or CVE.org bulk feed | JSON | API key required for bulk |
| CTIConnect | [github.com/peng-gao-lab/CTIConnect](https://github.com/peng-gao-lab/CTIConnect) | in-repo `/data` | 1,860 expert-verified QA pairs, 9 tasks, 321 vendor reports from 35 sources |

Every corpus used is publicly available and intended for defensive security research. No proprietary or organisation-internal logs are required.

---

## Evaluation

**Primary benchmark:** CTIConnect — nine tasks across entity linking, entity attribution, and multi-document synthesis.
**Secondary check:** a hand-written set of 30–50 vague, realistic analyst-style queries, for face validity on queries plain keyword search should struggle with by construction.

### Metrics

- Recall@1 / @10 / @100
- NDCG@10
- Entity/answer coverage (multi-document synthesis)
- **LLM calls and total tokens per query** — absent from the original SIRA paper, essential for a security-operations context
- **Wall-clock latency per query**
- **Graph-validation rejection rate** (RQ4) — plus the retrieval-precision delta when the filter is disabled

### Baselines

| Baseline | What it establishes |
|---|---|
| Plain BM25 | The lexical-matching floor |
| Hybrid dense-sparse | KGAgent4CTI-style fixed scorer over unenriched text |
| Multi-round agentic | The prevailing paradigm SIRA is built to challenge |
| SIRA-CTI *without* graph-grounding | **Ablation** — isolates grounding from enrichment alone |

### Ablations

1. With vs. without graph-grounding
2. With vs. without corpus-side enrichment
3. Retrieval budget sweep (B = 1, 5, 10) for synthesis tasks
4. Expansion-weight `w` sensitivity *(stretch)*

---

## Results

### Phase 0 — Baseline reproduction ✅

| Metric | Ours | SIRA paper's BM25 row | Target |
|---|---|---|---|
| NDCG@10 (SciFact) | **0.6789** | 0.6791 | ≈0.68 |
| Recall@10 (SciFact) | **0.8038** | 0.8078 | ≈0.81 |

Toolchain verified end to end: JDK/Pyserini install → JSONL reformatting → Lucene index build → `LuceneSearcher` querying → qrels parsing → `pytrec_eval` scoring. Cleared to point the same pipeline at CTI data.

### Phase 4 — CTIConnect

*Pending. Populated after the Phase 4 evaluation run (weeks 10–13).*

---

## Team & Modules

| Module | Owner | Deliverables |
|---|---|---|
| **1** — Corpus enrichment + graph tool | `[Student 1]` | Offline enrichment pipeline; ATT&CK/CWE/CAPEC graph-lookup tool; enriched BM25 index |
| **2** — Query enrichment + filter | `[Student 2]` | Online query-enrichment module; validation filter; weight tuning |
| **3** — Retrieval engine + baselines | `[Student 3]` | Weighted BM25 scorer; plain / hybrid / multi-round baselines |
| **4** — Evaluation + cost analysis | `[Student 4]` | CTIConnect eval harness; metrics dashboard; latency/token analysis; ablations |

All four co-own the literature review, the enrichment-noise audit (RQ4), and the final report and defence.

Supervised by `[Supervisor Name]` · `[Department]` · `[University Name]`

---

## Roadmap

| Weeks | Phase | Owner | Status |
|---|---|---|---|
| 1–3 | **Phase 0** — Baseline reproduction | All | ✅ Complete |
| 3–6 | **Phase 1** — Corpus + graph tool | Student 1 | 🔨 In progress |
| 4–7 | **Phase 2** — Query enrichment | Student 2 | ⬜ |
| 6–9 | **Phase 3** — Retrieval + baselines | Student 3 | ⬜ |
| 9–10 | **Checkpoint** — Integration | All | ⬜ |
| 10–13 | **Phase 4** — Evaluation + ablations | Student 4 + All | ⬜ |
| 13–16 | **Phase 5** — Write-up + defence | All | ⬜ |

---

## Contributing Conventions

Four modules are built in parallel, so the interfaces between them are frozen before the code is.

**Branching.** `main` stays green. Work on `module-<n>/<short-description>`. PRs need one review from an owner of a downstream module.

**The enrichment record — shared contract.** Modules 1 and 2 both emit this shape; Module 3 consumes it; Module 4 audits it. Changing it requires agreement from all four owners.

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
      "reject_reason": null             // "not_in_graph" | "too_common" | "not_in_index"
    }
  ],
  "llm_calls": 1,
  "tokens": { "prompt": 812, "completion": 143 },
  "latency_ms": 1904,
  "model": "qwen2.5:7b"
}
```

Every rejected term is kept with its `reject_reason` rather than dropped — the rejection log *is* the RQ4 dataset.

**Instrumenting cost.** Every LLM call goes through the wrapper in `src/sira_cti/common/`. Never call a model directly, or Module 4's cost analysis silently loses data.

**Reproducibility.** Fix seeds, pin versions in `requirements.txt`, and record the config hash with every results file.

---

## Licensing & Attribution

- **This repository:** MIT (see [`LICENSE`](LICENSE)).
- **SIRA** ([facebookresearch/sira](https://github.com/facebookresearch/sira)) — MIT. Archived read-only by Meta on 9 May 2026; fork it rather than expecting upstream updates.
- **CTIConnect** ([peng-gao-lab/CTIConnect](https://github.com/peng-gao-lab/CTIConnect)) — CC BY 4.0.
- **MITRE ATT&CK®, CWE™, CAPEC™** — © The MITRE Corporation. Free for research use; see MITRE's terms of use. ATT&CK® is a registered trademark of The MITRE Corporation.

**Dual-use statement.** This project builds a retrieval and search tool, not an exploit generator. It helps analysts find existing, already-public defensive knowledge faster; it does not synthesise new attack techniques. If any hand-written analyst query is derived from a real incident write-up, all identifying details are paraphrased or anonymised before use.

---

## Citation

If this work is useful to you, please cite the underlying papers first:

```bibtex
@article{yang2026sira,
  title  = {Superintelligent Retrieval Agent: The Next Frontier of Agentic Retrieval},
  author = {Yang, Z. and Ma, Q. and Chen, J. and Shrivastava, A.},
  year   = {2026},
  note   = {Meta Superintelligence Labs / Rice University}
}

@inproceedings{cheng2026cticonnect,
  title = {CTIConnect: A Benchmark for Retrieval-Augmented LLMs over
           Heterogeneous Cyber Threat Intelligence},
  author = {Cheng, and Liu, and Li, and Song, and Gao, P.},
  booktitle = {KDD},
  year = {2026},
  doi = {10.1145/3770855.3817527}
}
```

---

## Acknowledgements

Built on SIRA (Yang et al., 2026, Meta Superintelligence Labs / Rice University) and evaluated on CTIConnect (Cheng et al., KDD 2026). Ontology data courtesy of The MITRE Corporation.
