# SIRA-CTI — Project Context (read this first)

> **Purpose of this file:** give an AI coding assistant (or a new team member)
> the full mental model of this project in one read, so it doesn't re-derive the
> architecture or contradict decisions already made. Read the other files in
> `docs/` for specifics; this one is the map.

---

## What this project is

A 4-person Final Year Project that extends a real research paper (**SIRA**,
Yang/Ma/Chen/Shrivastava, Meta Superintelligence Labs / Rice, 2026) into a new
domain.

**SIRA's idea:** instead of a multi-round AI search agent (search → read →
reformulate, repeated N times, each round costing an LLM call and latency), do
retrieval in **one shot**: use an LLM *once* to predict the vocabulary a
relevant document would contain, validate those predictions cheaply against the
corpus's own structure, then fire a **single weighted BM25 query**.

**SIRA's key result** on its hardest benchmark (BrowseComp-Wikipedia) depends on
one specific mechanism the paper never re-tests anywhere else: validating
LLM-proposed Wikipedia *categories* against the real Wikipedia category graph
before letting them into the query. The paper's own authors flag this as
untested outside Wikipedia.

**Our thesis:** does that graph-grounding mechanism generalize beyond Wikipedia
— specifically to the cyber threat intelligence (CTI) ontology graph
(MITRE ATT&CK / CWE / CAPEC / CVE), which is *hierarchical and multi-relational*
rather than Wikipedia's flatter category tags, and in a domain where the LLM's
prior knowledge is narrower?

---

## Research questions (the whole project is organized around these)

- **RQ1 — Generalisation:** does category-graph grounding transfer from
  Wikipedia's flat tags to the hierarchical ATT&CK/CWE/CAPEC ontology?
  *Hypothesis: grounded query construction yields a measurably higher proportion
  of valid, discriminative expansion terms than ungrounded proposals.*
- **RQ2 — Comparative performance:** does SIRA-CTI match/beat plain BM25, hybrid
  dense-sparse retrieval, and a multi-round agent on the CTIConnect benchmark?
- **RQ3 — Cost-efficiency:** fewer LLM calls and lower latency than a multi-round
  agent, for equal/better accuracy?
- **RQ4 — Robustness (stretch):** how often does the LLM hallucinate an invalid
  ATT&CK/CWE ID, and does grounding catch it? **The rejection log is the RQ4
  dataset** — every rejected term is kept, never discarded.

---

## System architecture — five zones

An **offline** half (run once over the corpus) and an **online** half (run once
per query), meeting at a **single retrieval call**.

1. **Corpus-side enrichment (offline, Module 1).** LLM reads each
   CVE/CWE/CAPEC/ATT&CK entry, proposes vocabulary an analyst would search for
   that's absent from the entry's own text. Structural proposals validated
   against the graph tool. Common/undiscriminative terms filtered out. Survivors
   injected into the BM25 index.
2. **Query-side enrichment (online, Module 2).** LLM reads the analyst's
   plain-language query, predicts CWE/ATT&CK/CAPEC vocabulary a matching doc
   likely references. Deliberately avoids guessing a specific CVE ID. Every
   proposal passes the graph filter AND must exist in the enriched index.
3. **Ontology graph tool (shared).** Built over MITRE STIX/JSON with `networkx`.
   Confirms an ID exists, returns parent/sibling, rejects hallucinated terms.
   **This is the component under test.**
4. **Weighted retrieval engine (Module 3).**
   `score(d) = BM25(q_orig, d) + w · BM25(q_exp, d)`, `w` tuned on a held-out
   CTIConnect slice. Multi-doc synthesis follows BrowseComp protocol: a small
   fixed budget of additional grounded queries, **evidence-blind** (never reads
   intermediate results back into the prompt — that's what separates SIRA from a
   multi-round agent).
5. **Evaluation harness (Module 4).** CTIConnect benchmark + a hand-written
   30–50 vague-query set. Metrics: Recall@1/10/100, NDCG@10, entity/answer
   coverage, LLM calls per query, latency per query, graph-validation rejection
   rate.

---

## Team / module ownership

| Module | Owner | Scope |
|---|---|---|
| 1 — Corpus enrichment + graph tool | Student 1 (me) | Offline enrichment pipeline; graph tool; enriched index |
| 2 — Query enrichment + filter | Student 2 | Online query-enrichment; validation filter; weight tuning |
| 3 — Retrieval engine + baselines | Student 3 | Weighted BM25; plain/hybrid/multi-round baselines |
| 4 — Evaluation + cost analysis | Student 4 | CTIConnect harness; metrics; latency/token analysis; ablations |

**I own Module 1.** When working in my territory, don't touch Module 2/3/4 code
(`enrichment/query_side.py`, `retrieval/`, `eval/`) without flagging it.

---

## Key external resources

- **SIRA repo:** github.com/facebookresearch/sira (MIT, archived read-only by
  Meta 9 May 2026 — fork, don't expect updates).
- **CTIConnect:** github.com/peng-gao-lab/CTIConnect (CC BY 4.0). Benchmark
  ships in-repo under `/data`: 1,860 expert-verified QA pairs across 9 tasks,
  spanning CVE/CWE/CAPEC/ATT&CK + 321 vendor reports.
- **MITRE ATT&CK STIX/JSON:** github.com/mitre/cti
- **CWE:** cwe.mitre.org (XML) · **CAPEC:** capec.mitre.org (XML) ·
  **CVE:** NVD API / CVE.org bulk feed.

---

## Working conventions

- Keep the **four-module split** intact when discussing implementation —
  attribute work to Module 1/2/3/4 rather than re-deriving the architecture.
- The **enrichment record schema is a frozen shared contract** — see
  `02_MODULE1_STATE.md`. Changing it needs sign-off from all four owners.
- **Every LLM call goes through the instrumented wrapper** in
  `src/sira_cti/common/llm.py`. A direct model call silently destroys Module 4's
  RQ3 cost analysis.
- **Rejected enrichment terms are kept, not dropped** — the rejection log is the
  RQ4 dataset.
- Cite properly — this is an academic FYP. Core citation set: SIRA, CTIConnect,
  RAGIntel, KGAgent4CTI, CyberLLM-FINDS, TTPrint.
- **Update `03_STATUS_LOG.md` as things progress**, so the next session picks up
  where the last left off.
