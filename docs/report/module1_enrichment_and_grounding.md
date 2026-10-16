# Module 1: Corpus-Side Enrichment and Ontology Grounding

Oct 16, 2026 · @BABYYY

## 1. Role of Module 1

Module 1 builds the enriched BM25 index and the ontology graph tool that tests SIRA's central mechanism outside Wikipedia. Its main finding is that an existence check, which suffices for Wikipedia's named categories, is weak for MITRE's dense integer identifiers, and that checking each identifier's name against its official title is the adaptation needed.

Within SIRA-CTI, Module 1 owns two of the five zones:

- **Corpus-side enrichment (zone 1).** A frozen LLM reads every CVE, CWE, CAPEC and ATT&CK entry once, offline, and proposes vocabulary an analyst might search for that the entry's own text lacks.
- **The ontology graph tool (zone 3).** Every proposed structural identifier is validated against MITRE's published data before it may enter the index. Module 2 reuses the same tool, name check and scorer for query-side enrichment.

The module answers one question from RQ1: does SIRA's propose-then-validate step, demonstrated only on Wikipedia's category graph, transfer to a hierarchical, multi-relational security ontology? It also produces the dataset for RQ4, because every rejected proposal is kept with the reason it failed.

## 2. Corpus and ontology graph

The corpus holds 6,044 documents from four public MITRE catalogues, and the same catalogues supply the graph that validates every proposed identifier.

| Catalogue | Documents | Source | Format |
| --- | --- | --- | --- |
| CVE | 3,011 | NVD API / CVE.org feed | JSON |
| CWE | 1,342 | [cwe.mitre.org](https://cwe.mitre.org/) | XML |
| ATT&CK | 1,076 | [github.com/mitre/cti](https://github.com/mitre/cti) | STIX/JSON |
| CAPEC | 615 | [capec.mitre.org](https://capec.mitre.org/) | XML |
| **Total** | **6,044** |  |  |

The graph is built with networkx from pinned releases: ATT&CK v17.1 (Enterprise, Mobile and ICS) and the CWE and CAPEC XML files. It holds 4,486 nodes and 11,514 edges. Nodes are CWE weaknesses with their categories and views, CAPEC attack patterns, and ATT&CK tactics, techniques and sub-techniques together with the groups, software, campaigns, mitigations and data sources that ATT&CK links to them.

| Catalogue | Node type | Nodes |
| --- | --- | --- |
| CWE | Weakness | 969 |
| CWE | Category | 422 |
| CWE | View | 59 |
| CAPEC | Attack pattern | 615 |
| ATT&CK | Tactic | 40 |
| ATT&CK | Technique | 588 |
| ATT&CK | Sub-technique | 518 |
| ATT&CK | Software | 887 |
| ATT&CK | Group | 185 |
| ATT&CK | Mitigation | 110 |
| ATT&CK | Campaign | 51 |
| ATT&CK | Data source | 42 |
| **Total** | | **4,486** (CWE 1,450 · CAPEC 615 · ATT&CK 2,421) |

Of the 4,486 nodes, 4,013 are active, 280 deprecated and 193 revoked.

Edges are of three kinds:

- **Hierarchy edges** within a catalogue: CWE parent and child weaknesses, CWE membership in categories and views, CAPEC parent and child patterns, ATT&CK technique to sub-technique, and technique to tactic.
- **Mapping edges** across catalogues: CWE and CAPEC cross-references, and CAPEC's taxonomy mappings to ATT&CK.
- **Revocation edges** from a revoked ATT&CK identifier to its replacement.

| Edge type | Connects | Edges |
| --- | --- | --- |
| `member_of` | CWE weakness → CWE category or view | 5,024 |
| `child_of` | CWE → CWE | 1,160 |
| `child_of` | CAPEC → CAPEC | 533 |
| `in_tactic` | ATT&CK technique → tactic | 1,396 |
| `subtechnique_of` | ATT&CK sub-technique → technique | 516 |
| `maps_to` | CWE → CAPEC | 1,212 |
| `maps_to` | CAPEC → CWE | 1,212 |
| `maps_to` | CAPEC → ATT&CK | 271 |
| `revoked_by` | revoked ATT&CK id → replacement | 190 |
| **Total** | | **11,514** |

The build reports no dangling edges, and all 8 spot checks pass, including an invented identifier (`T9999`) and an invented sub-technique of a real parent (`T1110.099`), both rejected as `not_in_graph`. The loader skipped 224 legacy ATT&CK records, all old mitigations filed under technique identifiers. The full build log and the input file hashes are in `docs/results/graph_build.txt`.

Each node keeps its official title and, where MITRE provides one, a short name. Deprecated and revoked identifiers stay in the graph, flagged, so the validator can say why an identifier is unusable rather than only that it is missing. CVE entries have no node of their own; they link to the graph only through the CWE identifiers they cite.

## 3. Enrichment design

Each document gets one LLM call that returns at most 12 proposed terms, each labelled with its kind. Structural proposals must also state what the model believes the identifier's title is.

**Term kinds.** Colloquial (analyst phrasing such as "brute force login"), symptom, product, misspelling, and structural (a CWE, CAPEC or ATT&CK identifier). The prompt (version corpus-v4) forbids proposing a specific CVE identifier, following SIRA's warning that guessing the answer outright biases retrieval toward one premature candidate.

**Decoding.**

- Temperature 0, explicit seed 42, a 512-token reply cap, and an explicit context size of 4,096 tokens.
- Output constrained by a full JSON Schema. Ollama's simpler `format: "json"` mode was tried first and rejected: on qwen2.5:14b it returned a single valid object where twelve proposals were requested, a failure that is silent because the output still parses.
- Measured cost of schema decoding: 26.4 to 17.4 tokens per second on the 7B (1.5× slower), and no slowdown on the 14B.

**The enrichment record.** Every document produces one record in a shared format (schema 1.5.0) consumed by Modules 2 to 4. Each proposed term carries its kind, the claimed name and the official name for structural terms, its document frequency, whether it was accepted, and the reason if not. Rejected terms are kept rather than dropped, because the rejection log is the RQ4 dataset. Each record also carries token counts and latency, and each run writes a manifest with the commit, model digest, config hash and machine.

## 4. Validation gates

A proposed term enters the index only if it passes every gate in order. Every gate runs after the model's reply, so all of them can be re-run offline on saved records without new model calls.

1. **Existence** (structural terms only). The identifier must be well formed and present in the graph. Rejection reasons: `malformed_id`, `not_in_graph`, `deprecated`, `revoked`.
2. **Name–ID consistency** (structural terms only). The title the model claimed must match MITRE's official title for that identifier. Rejection reason: `name_mismatch`.
3. **Document frequency.** Terms too common across the corpus to discriminate are discarded, mirroring SIRA's DF filter. Rejection reason: `too_common`.
4. **In-index.** The term must exist in the index vocabulary. Rejection reason: `not_in_index`.

&#91;embedded content: structural-identifier gates · full-corpus counts\]

On the full corpus, every structural rejection came from the two graph-based gates; non-structural terms go straight to the document-frequency and in-index gates.

**Name scorers.** Scorer v1 scores token overlap between the claimed and official titles. Scorer v2, used for the full run with a threshold of 0.6, scores symmetrically against MITRE's parenthesised short name where one exists and falls back to v1 otherwise. Each verdict records which rule decided it.

**Measurements that never gate.** Three signals are recorded for analysis but never change a decision:

- **Counting-run flag:** three or more consecutive identifiers from one catalogue in a single reply.
- **Graph distance:** shortest path in the ontology from the source document's node to the proposed identifier.
- **Repair candidate:** for a name mismatch, a real identifier within two hops whose title matches the claimed name. An off-by-default flag lets Module 3 index repaired identifiers as an ablation.

Keeping distance as a measurement rather than a gate is deliberate. Enrichment is meant to add links the entry's own data lacks, and a distance filter would penalise exactly the good novel ones.

## 5. Development findings on the 40-document sample

The method was developed on a stratified sample of 40 documents, 10 per catalogue. The findings are presented in the order they were discovered, because each one changed the design. All counts are raw; at n = 40 the percentages are for orientation only.

### 5.1 It is the model, not the prompt

With the same 40 documents, prompt and filters, only the model was changed from qwen2.5:7b to qwen2.5:14b.

| Measure | 7B | 14B |
| --- | --- | --- |
| Structural IDs proposed | 14 | 125 |
| Structural IDs accepted (existence check only) | 12 | 109 |
| ATT&CK IDs proposed on ATT&CK entries | 0 | 37 |
| Invented IDs caught | 0 | 5 |
| Out-of-date IDs caught | 0 | 3 |

Across five earlier 7B runs (125 documents), the graph check had never rejected an invented or out-of-date identifier. The 14B gave it 8 in one run. The value of grounding was invisible at 7B, so any claim about it must state the model it was measured on.

### 5.2 The counting problem

Most of the 14B's new identifiers came from counting, not reasoning. Of 83 identifiers not copied from the entry, 29 were the next number up from another identifier proposed for the same document.

- **CWE-512 (Spyware).** The model proposed CWE-73 to CWE-81. All nine exist, so all nine passed the existence check, and none concerns spyware (CWE-79 is cross-site scripting).
- **T1056.001 (Keylogging).** Sub-techniques .002 to .004 are genuine siblings. The model continued to .005 to .009, which do not exist. These were exactly the five invented identifiers the check caught: a counting run falling off the end of the namespace.

This reverses the obvious reading of the result. The share of identifiers passing the check rose with the larger model while the identifiers got worse. A check that only asks whether an identifier exists rewards a model for listing consecutive numbers, because in MITRE's dense integer namespaces almost every number is real.

### 5.3 The name–ID consistency check

The fix was to make the model state each identifier's title and compare it with MITRE's (Section 4, gate 2).

| Measure | 7B, existence only | 7B, + name check | 14B, existence only | 14B, + name check |
| --- | --- | --- | --- | --- |
| Structural proposed | 14 | 14 | 125 | 157 |
| Structural accepted | 12 (86%) | 6 (43%) | 109 (87%) | 56 (36%) |
| Rejected at existence | 2 | 4 | 16 | 32 |
| Rejected at name | – | 4 | – | 69 |
| IDs in a counting run | 0 | 0 | 38 | 51 |
| …of those, accepted | 0 | 0 | 33 (87%) | 7 (14%) |

Under existence-only checking, 33 of 38 counting-run identifiers were accepted. With the name check, 7 of 51 were. The proposal counts also changed between the two runs, because schema-constrained decoding and the name requirement altered what the model proposed.

The counting-run flag alone is not a verdict. CAPEC-24 maps to CWE-118, CWE-119 and CWE-120, three consecutive numbers that are all genuine and all one hop away, because MITRE numbered related weaknesses sequentially. Enumeration is a counting run combined with a large graph distance; either signal alone misjudges cases like this.

### 5.4 Name scorers v1 and v2

Scorer v1 catches cross-family confusions (scores 0.00 to 0.20) but misses within-family neighbours. CWE-74 claimed with CWE-89's title scored 0.67 and passed, because the real titles of CWE-78 and CWE-89 score 0.83 against each other.

Scorer v2 compares against MITRE's short names. Rescoring the saved records offline changed four verdicts, all from accepted to rejected:

- 7B, CWE-74 claimed as "SQL Injection" (CWE-89's title): correct catch.
- 7B, CWE-89 claimed as "OS Command Injection" (CWE-78's title): correct catch.
- 14B, CWE-416 (Use After Free) claimed as "Double Free": correct catch.
- 14B, CWE-415 (Double Free) claimed as "Double Free or Release of Same Resource": arguably a false rejection.

The limit of v2 is reach. Only 122 of 1,450 CWE nodes have a short name, and no ATT&CK or CAPEC node does, so most verdicts still fall back to v1.

### 5.5 Three models: validity improves, relatedness does not

A third model was added to test whether grounding behaves differently on a model that knows the ontology well. A 32B Qwen model did not fit on the development laptop (about 20 GB at 4-bit against 16 GB), so Gemini 3.1 Pro was used via its API, at low thinking, run twice. Both runs together cost ₹116.66.

| Accepted structural IDs | 7B | 14B | Gemini run 1 | Gemini run 2 |
| --- | --- | --- | --- | --- |
| Proposed | 14 | 157 | 73 | – |
| Accepted | 6 | 56 | 69 | 68 |
| Rejected at existence | 4 | 32 | 0 | 0 |
| Rejected at name | 4 | 69 | 4 | 4 |
| In a counting run | 0 | 51 | 0 | – |
| Copied from the entry | 6 (100%) | 17 (30%) | 20 (29%) | 24 (35%) |
| Generated by the model | 0 | 39 | 49 | 44 |
| Within 2 hops (of those measurable) | – | 22 of 35 | 33 of 47 | 37 of 48 |

Three findings follow:

- **The existence check had nothing left to catch on the strong model.** It rejected 0 of 73 identifiers on Gemini, against 32 on the 14B. The name check still caught 4 real identifiers with the wrong meaning in both Gemini runs.
- **Counting is the 14B's own behaviour, not a size trend.** Gemini neither invented nor counted.
- **Model strength improved validity, not relatedness.** Looking only at identifiers the model generated rather than copied, both the 14B and Gemini sit at a median of 2 to 2.5 hops from the source document. The stronger model proposes fewer wrong identifiers, but not more closely related ones.

The two Gemini runs agreed on 61 of 76 accepted identifiers (80%), and on the counts of existence and name rejections. The exact list of identifiers is not stable, so findings are stated as counts and patterns.

### 5.6 Repair: most wrong names are confusion, not near-misses

Of the 14B's name mismatches, 33 lay within two hops of the document. If these were near-misses, the claimed name should match a nearby real identifier. Only 9 repaired cleanly (for example, on CAPEC-24, CWE-119 claimed as "Integer Overflow or Wraparound" repairs to CWE-190). Two were ambiguous, and 22 matched nothing nearby. Repair therefore stays off by default and is reported as an RQ4 finding, with the flag available to Module 3 as a retrieval ablation.

### 5.7 Cross-hardware replication

The same 14B sample was re-run on a Kaggle T4 with the same model build (digest 7cdf5a0187d5), Ollama version (0.33.2) and seed. Only 5 of 40 replies were identical to the Mac's, but the patterns held: counting runs appeared on the same documents through different numbers, and the same kinds of misnaming recurred.

| Measure | Mac | Kaggle |
| --- | --- | --- |
| Rejected at existence | 32 | 23 |
| Rejected at name | 66 | 78 |
| IDs in a counting run | 51 | 47 |
| Structural accepted | 59 | 54 |

The drop in existence rejections is almost entirely deprecated identifiers (15 to 4), driven by a few documents whose counting runs happened to cross retired ranges. With 40 documents, single-document swings exceed any hardware effect, so 14B results are reported as ranges across the two runs.

## 6. Input truncation

Long documents are shortened by dropping whole low-value sections, never by cutting at a character position, so every CAPEC entry keeps the Related Weaknesses list that grounds its cross-catalogue links.

**The problem.** With a 4,096-token context, 171 documents exceed the budget of 6,000 characters (63 CVE, 44 CWE, 64 CAPEC). A plain cut at 6,000 characters looked safe for CVEs, which only lose their affected-products version table. It was not safe elsewhere: CWE entries lost about a third of their text, mostly mitigations, and 55 of 64 cut CAPEC entries lost their entire Related Weaknesses list, the field where the entry's own CWE identifiers live.

**The fix: section-aware truncation (sections-v2).** Each entry is parsed into its sections. If it exceeds the budget, whole sections are dropped in a fixed order until it fits:

1. References
2. Content history
3. CVE affected-products tables
4. Applicable-platform detail
5. Consequences
6. Prerequisites
7. Examples
8. Mitigations (trimmed before being dropped)
9. Other unprotected sections (notes, indicators, required skills and resources, modes of introduction, detection methods, execution flow), trimmed

The title, description, extended description, related weaknesses, related attack patterns and taxonomy mappings are never dropped. When a CVE's product table is removed, it is replaced by a de-duplicated list of vendor and product names without versions, so long CVEs still show the product vocabulary that short ones do.

**Result.** No document needed a plain-cut fallback. Every CAPEC entry that has a Related Weaknesses list (63 of 63) and every one with taxonomy mappings (32 of 32) keeps it. Ten entries needed step 9.

**Effect on findings.** The 14B sample was re-run under the new rule. 37 of 40 replies were byte-identical; the three that changed are the three sample documents over the budget. Accepted identifiers rose from 56 to 59, all three extra ones copies; existence rejections, counting runs and generated-identifier distances were unchanged. On CAPEC-24, the model now names CWE-119 correctly, the evidence that keeping Related Weaknesses visible helps. Stage 2 must use the same rule, so that the model is the only variable between the two indexes.

## 7. Full-corpus run

All 6,044 documents were enriched with qwen2.5:14b on Kaggle's free tier in two sessions of 2× Tesla T4, about 15 hours of compute, after the development laptop proved too slow.

**Why not the laptop.** A clean 45-minute benchmark on the development MacBook Air measured a sustained 6.5 tokens per second (43.4 seconds per document) after an initial burst at 11.5. That put the full corpus at about 75 hours on mains power and about 89 on battery. An earlier 8-document benchmark had suggested 52 hours, because it measured only the fast first minutes.

**Setup.** Two Ollama servers ran in one Kaggle session, one per GPU, each serving one shard of the corpus split by stable document-id hashing. Both shards processed CWE, CAPEC and ATT&CK before CVE.

| Shard | Documents | CWE | CAPEC | ATT&CK | CVE |
| --- | --- | --- | --- | --- | --- |
| 1 of 2 (GPU 0) | 2,999 | 667 | 298 | 557 | 1,477 |
| 2 of 2 (GPU 1) | 3,045 | 675 | 317 | 519 | 1,534 |

**Throughput.** About 190 documents per hour per T4, or 18 to 22 seconds per document, roughly twice the laptop's speed. Session 1 stopped cleanly after about 11.3 hours with 4,457 documents done, including every non-CVE entry. Session 2 finished the remaining 1,587 CVEs in about 4 hours.

**Provenance and safety.** Every manifest records the git commit (6b4eecedf1cd), model digest (7cdf5a0187d5), config hash (364d30da6c75), Ollama version (0.33.2), machine and GPU. A run refuses to start from uncommitted code and refuses to resume if any of these change. The merge checks that all manifests agree, that no document appears twice, and that every corpus document is present. The merged file is the two shards joined byte for byte.

**Failures.** Three replies could not be parsed: T1064, T1542.001 and CVE-2022-47378. In the first two, the model kept listing identifiers past its 12-term limit (T1059.001 to .020; T1070 to T1121) until the 512-token cap cut the reply off. Each is kept as a record with an `llm_json_error` placeholder and an empty expansion, so the documents remain searchable by their own text. Counting can therefore break a reply outright, not only produce wrong identifiers.

## 8. Full-corpus results (RQ1, RQ4)

On the full corpus, the name check rejected 3.6 times as many structural identifiers as the existence check: 9,852 against 2,705. An existence-only check would have let nearly half of all proposed identifiers into the index with the wrong meaning.

| Structural identifiers | Full corpus (n = 6,044) | 40-document sample, 14B |
| --- | --- | --- |
| Proposed | 20,588 | 155–157 |
| Accepted | 8,031 (39%) | 54–59 |
| Rejected: does not exist, deprecated, revoked or malformed | 2,705 (13%) | 23–32 |
| Rejected: real identifier, wrong name | 9,852 (48%) | 66–78 |
| In a counting run | 4,237 (21%) | 47–51 |

The three outcomes sum exactly to the identifiers proposed: every structural rejection on the full corpus came from the two graph-based gates, none from document frequency. The sample ranges span the Mac and Kaggle runs. The accepted and wrong-name shares match the sample (35–38% and 42–50%). Existence rejections and counting runs are lower on the full corpus (13% against 15–21%, and 21% against 30–33%). The likely reason is that the sample takes 10 documents per catalogue, while CVEs, which count least, make up half the full corpus.

**Where the errors concentrate.**

- **CWE entries.** Of 6,788 CWE identifiers proposed on CWE entries, 4,608 (68%) had the wrong name. Counting is also heaviest here.
- **Counting runs by catalogue.** CWE 2,659, ATT&CK 1,149, CVE 279, CAPEC 150.
- **CVE identifiers proposed as structural terms.** Despite the prompt forbidding it, the model proposed 813 CVE identifiers, on 804 of 3,011 CVE documents (27%). 777 were the entry's own identifier, so the habit is mostly self-reference rather than guessing other CVEs. These are caught as malformed; they raise the malformed share of structural rejections from 0.4% to 4.3%.

**Answer to RQ1.** Grounding transfers, but not as SIRA built it. Validating against the real graph does reject unsupported vocabulary (2,705 identifiers). The larger failure, though, is real identifiers with the wrong meaning, which an existence check cannot see in a namespace where nearly every number exists. Name–ID consistency is the adaptation that makes the mechanism work on MITRE's ontology.

**Answer to RQ4 (provisional on this model).** A non-trivial fraction of LLM proposals fails validation: 61% of structural proposals on the 14B. Whether removing the filter degrades retrieval precision is Module 4's ablation; the smoke test in Section 9 suggests it matters.

## 9. The enriched index and handoff

The enriched index holds all 6,044 documents with 28,705 accepted terms spread over 5,852 of them, and it is handed to Modules 2 and 3 with one clear warning: expansion terms must be weighted, not simply added.

**Checks.** The document count is 6,044. For every document, the stored expansion matches what the current code produces. 42 of 42 sampled words from accepted terms are listed under the right document (for example, "password guessing" and T1110 under T1110; "rapl" and "intel" under CVE-2020-8695). The three failed documents carry an empty expansion.

**Smoke test.** Five plain-language analyst queries were run against the base and enriched indexes. This is a sanity check, not an evaluation.

| Query | Base index, top 5 | Enriched index, top 5 |
| --- | --- | --- |
| repeated login failures from one IP | CAPEC-227, CAPEC-600, CAPEC-187, CAPEC-24, T1110.003 | T1621, T1110.003, CAPEC-227, T1110.004, T1110 |
| attacker reads memory after it's freed | CWE-415, CWE-416, CAPEC-131, CWE-825, CWE-1330 | CWE-415, CVE-2025-43587, CWE-416, CAPEC-131, CWE-825 |
| malware hides in a scheduled task | T1053.005, T1053.002, T1053, T1036.004, T1053.003 | T1053.005, T1603, CAPEC-504, T1053.001, CAPEC-557 |
| tricking users into clicking a fake login page | CAPEC-98, CAPEC-222, CAPEC-103, CAPEC-630, CVE-2024-11405 | CWE-206, CVE-2024-11405, CAPEC-98, CAPEC-222, CVE-2025-7667 |
| server lets attacker read files outside the web folder | CVE-2024-2178, T1051, CAPEC-41, CVE-2025-5961, CVE-2025-7699 | CVE-2025-7699, T1569.001, CVE-2025-49830, CVE-2025-52786, T1074.001 |

Enrichment helped the login-failure query, moving brute-force techniques to the top, and hurt the phishing and path-traversal queries. The likely cause is that the expansion field is short, and BM25 rewards a match in a short field heavily.

**Decisions handed to Module 3.**

- Score the expansion separately with a tuned weight, as the proposal specifies: score(d) = BM25(q\_orig, d) + w · BM25(q\_exp, d). Five queries prove nothing, but they show w is not a minor setting.
- Decide whether to drop a document's own identifier from its expansion. 305 entries carry it, which adds nothing for retrieval.
- Decide whether to test the repair flag as an ablation.

The handoff note (07\_PHASE1\_HANDOFF.md) gives the index location, record format, schema version and the interfaces of the graph tool, name check and scorer for Module 2's reuse.

## 10. Discussion: does SIRA's grounding transfer?

SIRA's grounding transfers to MITRE's ontology in principle, but the shape of the identifier namespace, more than the shape of the graph, decides which check does the work.

**Named versus numbered identifiers.** SIRA validates Wikipedia categories, which are names. A hallucinated category name is unlikely to exist by accident, so asking whether it exists is a strong test. CWE, CAPEC and ATT&CK use dense integer identifiers, where counting upward almost always lands on a real entry. The same existence test becomes weak: on the full corpus it caught 2,705 bad identifiers while 9,852 real-but-wrong ones would have passed it. Checking that the model knows what an identifier means, by comparing its claimed title with the official one, restores the strength the existence test had on Wikipedia.

**Grounding's value depends on the model's prior knowledge.** SIRA's authors note that a frozen LLM is most useful when the corpus lies within its pretraining knowledge, but they do not test the other case. The three-model comparison shows the consequence for grounding. On the 7B, the gates barely fired, because the model mostly copied identifiers from the page. On the 14B, they did most of the work. On Gemini, the existence check found nothing to reject. Any claim about the value of grounding therefore has to name the model it was measured on.

**Validity is not relatedness.** The current gates establish that an identifier exists and is correctly named. They do not establish that it is relevant to the document. Generated identifiers sat at a median of about 2 to 2.5 hops on both the 14B and Gemini, so a stronger model reduces errors without proposing more closely related identifiers. A gate for relatedness remains open; graph distance is a candidate measure, but used as a filter it would penalise exactly the novel links that enrichment exists to add.

## 11. Threats to validity

The full-corpus counts are robust, but the model comparisons rest on a small sample and an imperfect third model.

- **Sample size.** Development findings use 40 documents. Single documents swing the counts, as the deprecated-identifier difference between the Mac and Kaggle runs shows (15 against 4). Findings are therefore reported as counts and ranges, and the central ones were confirmed on the full corpus.
- **Model size mixed with model family.** Gemini is a different model family from Qwen, so the three-model comparison cannot separate "bigger" from "different maker". A 32B Qwen model would, but it did not fit the development laptop.
- **Gemini's configuration.** Gemini ran at low thinking to stay within the cost cap, so it was not tested at full strength. Its seed was accepted but not honoured, so its runs cannot be reproduced exactly. Its temperature was 0, against Google's recommendation of 1.0 for this model family, to match the local runs.
- **Distance as a proxy for relevance.** Hops in the ontology are a rough stand-in for relatedness, and distance cannot be measured for CVE documents, which have no node in the graph.
- **Name scorer reach.** Scorer v2's short names cover only 122 of 1,450 CWE nodes and no ATT&CK or CAPEC node, so most verdicts use v1, which misses within-family confusions.
- **Copy measurement.** "Copied from the entry" is a string match against the text the model saw; it can miss paraphrased copies and over-count coincidences.
- **Latency.** Per-record latency in the development runs includes queueing and contention, so it is not usable for RQ3. Clean latency must be measured in Phase 4.
- **Hardware.** The full run used T4 GPUs, not the laptop the method was developed on. Replies differ across hardware even with identical model, software and seed, although the measured patterns held.

## 12. Limitations and future work

The next steps follow directly from the threats above:

- **A relatedness gate.** Combine graph distance with the counting-run flag, which together separated enumeration from genuine sequential links (Section 5.3), and test it without penalising novel links.
- **A better name scorer.** The experimental v3 scorer, which matches symmetrically on every node, caught six wrong titles v2 could not reach. It also flagged two ATT&CK identifiers under their pre-rename titles, so it needs a way to accept old official names.
- **Repair as an ablation.** Index the 11 cleanly repaired identifiers and measure the effect on retrieval in Phase 4.
- **A within-family size comparison.** Run the 40-document sample on qwen2.5:32b on a larger GPU, to separate model size from model family.
- **Stage 2.** Enrich the full corpus once with Gemini 3.1 Pro under the frozen method and the same truncation rule, as the final index for the benchmark run. At low thinking this is estimated at about $67 at standard pricing, or about $34 through batch mode, which still needs testing for this model. No setting may be tuned on that index after it exists.

## Appendix: reproducibility

Every result in this chapter can be traced to a committed configuration and a saved run file.

| Item | Value |
| --- | --- |
| Code commit (full run) | 6b4eecedf1cd |
| Config hash | 364d30da6c75 |
| Model | qwen2.5:14b, digest 7cdf5a0187d5 |
| Ollama | 0.33.2 |
| Prompt | corpus-v4 |
| Record schema | 1.5.0 |
| Name scorer | v2, threshold 0.6 |
| Truncation | sections-v2, 6,000-character budget, 4,096-token context |
| Decoding | temperature 0, seed 42, 512-token cap, JSON-schema constrained, concurrency 1 |
| Full-run hardware | Kaggle, 2× Tesla T4, two sessions |
| Development hardware | MacBook Air, 16 GB |
| Enriched output | indexes/enrichment/corpus\_full\_v4\_14b.jsonl (6,044 records) |
| Shard provenance | indexes/enrichment/kaggle\_stage1\_shards/ |
| Full breakdown | docs/results/stage1\_full\_breakdown.txt |
| Smoke test | docs/results/enriched\_index\_smoke\_test.txt |
| Sample comparison | docs/results/kaggle\_sample\_vs\_mac\_14b.txt |

Start command for one shard, as run on Kaggle:

```
python scripts/enrich_corpus.py --model qwen2.5:14b --name-scorer v2 \
    --kinds cwe,capec,attack,cve --shard 1/2 \
    --output corpus_full_v4_14b.shard1of2.jsonl
```

All gates after the model's reply can be re-applied offline with scripts/rescore\_enrichment.py, so changing a gate never requires new model calls. Policy exceptions, including the Gemini runs, are logged in docs/06\_POLICY\_EXCEPTIONS.md.
