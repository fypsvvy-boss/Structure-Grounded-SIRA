# Module 1 freeze checklist — what gets locked for the full-corpus run

**Status: draft for the Module 1 owner, updated 2026-10-08 (later). Nothing is
frozen yet and the full-corpus run has not been started. Two of the five
blockers are closed in code; see "Blockers".**
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
| seed | **`42`, sent explicitly** (done 2026-10-08) | `llm.seed` | reaches Ollama as `options.seed`. Checked on the real 7B: two seeded calls are byte-identical, and they match the saved unseeded run, so the sample results still stand |
| context size | **`4096` tokens, sent explicitly** (done 2026-10-08) | `llm.num_ctx` | the value every sample run used; no longer "whatever the server loaded" |
| prompt | **`corpus-v4`** | `prompts/corpus_side.py:PROMPT_VERSION` | names required on structural ids; neutral wording (does not warn that names are checked) |
| reply schema | `REPLY_SCHEMA` (`name` optional) | `prompts/corpus_side.py` | |
| decoding mode | **`schema`** | `enrichment.json_mode` | fixed `CAPEC-587`; costs 1.5x on the 7B, nothing on the 14B (open question 11) |
| reply cap | `512` tokens | `enrichment.max_new_tokens` | no sampled reply has come near it (largest ~270) |
| terms per document | `12` | `enrichment.max_terms_per_doc` | it is in the prompt text, so it shapes the reply |
| JSON retry | `1`, with nudge | `enrichment.json_retries` | zero retries were needed in either `corpus-v4` run |
| unparseable reply | recorded as `llm_json_error` | `enrichment.record_json_failures: true` | so the run can finish |
| context handling | **section-aware truncation to `6000` characters** (rules `sections-v2`, 2026-10-09) | `enrichment.max_doc_chars`, `enrichment/truncation.py` | 171 of 6,044 documents (2.8%) are shown to the model shortened, by removing whole sections in a fixed order; description and cross-catalogue links are never removed; 0 fallbacks. Each record says what was removed. A reply to a prompt that still overflows is refused. See "The truncation rule" |
| concurrency | **`1`** | `enrichment.concurrency` (now the default) | 2 gives no speed-up on Ollama and doubles recorded latency (open question 11) |
| corpus | all four kinds, no sampling | `corpus.kinds`, no `--limit`/`--per-kind` | |
| output | a **new** file, e.g. `indexes/enrichment/corpus_full_v4_14b.jsonl` | `--output` | never the default `corpus.jsonl`, which holds `corpus-v1` records (open question 2) |

## B. Frozen for the write-up — re-derivable offline if a choice turns out wrong

| what | proposed value | where it lives | note |
|---|---|---|---|
| schema version | **`1.5.0`** | `common/schemas.py` | waiting on Modules 2, 3 and 4: `name-id-consistency.md` (1.3.0) and `thinking-tokens.md` (1.4.0 `tokens.thinking`, 1.5.0 `truncation`) |
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

## Blockers — status on 2026-10-08 (later)

| # | blocker | status |
|---|---|---|
| 1 | Context overflow (open question 12) | **Closed in code.** `llm.num_ctx: 4096` sent explicitly + section-aware truncation to 6,000 characters + a guard that refuses a reply when prompt + reply cap did not fit |
| 1c | Knowing which code produced a file | **Closed in code, 2026-10-09.** Every manifest records the git commit and whether the tree was dirty. A full-corpus run refuses to start from uncommitted code; a resume refuses a different commit unless `--allow-code-change` |
| 1b | Resuming under changed settings (open question 2) | **Closed in code, 2026-10-09.** Config hash, model, prompt, scorer, concurrency and truncation are compared with the existing file's manifest; any difference is refused |
| 2 | Explicit seed to Ollama | **Closed.** `llm.seed: 42` → `options.seed`. Verified on the real 7B (repeatable, and identical to the saved unseeded replies) |
| 3 | Schema sign-off | **Docs written, signatures missing.** 1.3.0: `name-id-consistency.md`. 1.4.0: `thinking-tokens.md`. Only the Module 1 row is filled in on either. This one cannot be closed by Module 1 alone |
| 4 | Model choice | **Proposal below** ("Two-stage plan") — needs the owner's yes |
| 5 | Sustained speed figure for the time estimate | **STILL NOT DONE.** A 45-minute benchmark was run on 2026-10-09 but the laptop came off mains 6 minutes in, so it measured battery speed (5.4 tok/s → 89 h). On mains it settled at 8.5 tok/s, in line with the ~52 h estimate, but only 4 minutes of that were captured. Needs one clean, plugged-in rerun. See "Time and cost" |

Two things to know about blocker 1:

- **Why 6,000 characters and not 12,000.** The earlier note assumed ~3.75
  characters per token. That is the *average*. The longest documents are CVE
  version tables (`"7.0.1", "7.0.2", …`), and those measured **~2.1 characters
  per token**: 8,000 characters of `CVE-2017-5753` came to 4,093 prompt tokens,
  the whole context with no room to reply. 6,000 characters fits even those
  (worst case ≈ 3,160 prompt tokens + 512 reply < 4,096).
- **The alternative, ruled out by the owner:** `num_ctx: 8192` with a
  12,000-character budget. Not tested, not planned.
- The config hash is now **`364d30da6c75`** (2026-10-09: `concurrency: 1`
  became the default). Before that `77fa240d81d1` (seed, `num_ctx`,
  `max_doc_chars`), before that `2007683a1442`.

## The truncation rule: cut by section, not by character count

**Decided by the owner, 2026-10-09. Built the same day. Same budget (6,000
characters, `enrichment.max_doc_chars`), same `num_ctx: 4096`. Current rules: `sections-v2`. It replaces the
plain cut described further down, which is kept for the record.**

**In plain words.** An entry is a title followed by a set of labelled sections
("Description", "Mitigations", "References" …). If the whole thing is too
long for the model, we no longer chop it at character 6,000 and lose whatever
happens to be at the end. We throw away whole sections, starting with the
ones least useful for finding the entry, and stop as soon as it fits.

**Order of removal** (first to go at the top):

| # | what | section names in the data |
|---|---|---|
| 1 | references | `References` |
| 2 | content history | `Content_History` (none in this corpus) |
| 3 | CVE affected-products / version tables — **replaced by a list of vendor and product names**, each once, no versions (rules `sections-v2`) | `configurations` → `affected_products` |
| 4 | applicable-platform detail | `Applicable_Platforms` |
| 5 | consequences | `Common_Consequences`, `Consequences` |
| 6 | prerequisites | `Prerequisites` |
| 7 | examples | `Example_Instances` |
| 8 | mitigations — **trimmed**: the first few are kept if they fit; dropped only if not even one fits | `Potential_Mitigations`, `Mitigations` |
| 9 | anything else that is not protected, same trimming | `Notes`, `Indicators`, `Resources_Required`, `Skills_Required`, `Modes_Of_Introduction`, `Detection_Methods`, `Execution_Flow` |

Step 9 was **not in the owner's list** — it is Module 1's addition, because
10 entries are still too long after step 8 and the alternative was a blind
cut. Say if a different order is wanted.

**Never removed:** the title, `Description`, `Extended_Description`, a CVE's
`descriptions`, and the links to other catalogues — `Related_Weaknesses`,
`Related_Attack_Patterns`, `Taxonomy_Mappings`, and a CVE's own CWE list
(`weaknesses`).

**Fallback.** If those protected sections alone are over budget, the text is
cut at 6,000 characters as before and the record says `"mode": "fallback"`.

**Where it is recorded.** Every record of a shortened entry carries a
`truncation` field (schema 1.5.0):

```json
"truncation": {"version": "sections-v2", "mode": "sections", "max_doc_chars": 6000,
               "dropped": ["References", "Consequences"], "trimmed": {"Mitigations": {"kept_items": 2}}, "summarised": {},
               "full_chars": 7503, "shown_chars": 5921}
```

The record's `original_text` is still the **full** entry, and the index is
still built from the full entry. The manifest lists every shortened document
and every fallback. The rule applies to every backend, so the Gemini run
(Stage 2) is shown exactly the same text as the local run.

### Result on the 171 over-long entries

| | CVE | CWE | CAPEC |
|---|---|---|---|
| over budget | 63 | 44 | 64 |
| handled by section removal | 63 | 44 | 64 |
| **fallback (blind cut)** | **0** | **0** | **0** |
| keeps Related Weaknesses | n/a (CWE list kept in all 63) | n/a (no such section in this corpus) | **63 of 63 that have one** (was 8 under the plain cut) |
| keeps Taxonomy Mappings | – | – | 32 of 32 (was 3) |
| keeps Related Attack Patterns | – | – | 61 of 61 |
| fits after steps 1–7 only | 63 | 8 | 46 |
| needed mitigations trimmed or dropped | 0 | 36 (30 trimmed, 6 dropped) | 18 (7 trimmed, 11 dropped) |
| reached step 9 | 0 | 1 (`CWE-732`) | 9 |

(The 64th CAPEC has no Related Weaknesses section at all.) The entries that
reached step 9: `CWE-732`, `CAPEC-7`, `CAPEC-19`, `CAPEC-33`, `CAPEC-34`,
`CAPEC-105`, `CAPEC-112`, `CAPEC-163`, `CAPEC-273`, `CAPEC-665` — in nine of
the ten what is trimmed is the step-by-step `Execution_Flow` or a detection
list; the description and links are intact in all of them.

### CVE product tables become a list of names (`sections-v2`, 2026-10-09)

Under the first version of this rule the 63 long CVEs lost their whole
affected-products table and with it every vendor and product name. Now the
table is **summarised**: the model sees
`"affected_products": ["cisco ios xe", "oracle banking platform", …]` in the
table's place — each vendor/product pair once, in the order the table lists
them, with no version numbers. The record says `summarised`, not `dropped`:

```json
"summarised": {"configurations": {"as": "affected_products", "products": 18, "kept": 18}}
```

| of the 63 long CVEs | |
|---|---|
| table replaced by a name list | **63 of 63** |
| every name fits | 51 |
| list itself cut to stay in budget | 12 (hardware advisories naming 150–1,300 processor models; the first 120–200 are kept) |
| names per CVE, typical | 45 |
| characters added, typical | **about 1,060** (smallest 39, largest 4,710) |
| still within 6,000 characters | all 63 |

The 12 with a shortened list: `CVE-2017-5715`, `CVE-2017-5753`,
`CVE-2017-5754`, `CVE-2019-11157`, `CVE-2020-0551`, `CVE-2020-12788`,
`CVE-2020-8694`, `CVE-2020-8695`, `CVE-2021-33150`, `CVE-2021-44228`,
`CVE-2022-0001`, `CVE-2022-0002`. `kept` and `products` on the record show
how many were left out. CWE and CAPEC entries are cut exactly as before.

**One side effect to know about.**

- **Whole sections go even when part would fit** (steps 1–7, other than the
  CVE table). Shortened CWE and CAPEC entries still use most of the budget
  (typically 5,600 of 6,000 characters). That is the price of a rule simple
  enough to state in one table.

### "Copied from the entry" now means copied from what the model saw

`report_enrichment.py` and `measure_redundancy.py` used to search the *full*
entry for an id. They now search the text the model was actually shown
(rebuilt from the record's `truncation` field). An id sitting in a section
that was removed is one the model had to produce itself. **No number in any
table so far changes**: every saved run was made before truncation existed,
so in all eleven saved files the model saw the whole entry (checked: copied
counts identical under both definitions in every file).

## Superseded: what the *plain* 6,000-character cut removed (why the rule above exists)

**No longer how the pipeline works.** Kept because it is the evidence for the section-aware rule.

**Decision (owner, 2026-10-08): keep `num_ctx: 4096` with the 6,000-character
cut. 8192 is not being tested.**

"Cutting long documents" sounds harmless if the long part is a list of version
numbers. It is harmless for CVEs. It is **not** harmless for CWE and CAPEC
entries. Checked on a seeded sample of 15 of the 171 cut documents (6 CVE,
4 CWE, 5 CAPEC), then counted across all 171:

| type | cut | what is after the cut |
|---|---|---|
| **CVE** | 63 | **Only the affected-products table** — rows like `cpe:2.3:o:cisco:ios_xe:16.9.3:…`, in all 63. The description and the CVSS scores come first and are untouched. Nothing a human would call content is lost |
| **CWE** | 44 | **Descriptive text.** Typically a third of the entry (median 35%). The whole "Potential Mitigations" section is gone in 13, "Applicable Platforms" in 10; most others lose the later mitigations |
| **CAPEC** | 64 | **Descriptive text and the links to other catalogues.** Median 19% of the entry. The whole **"Related Weaknesses"** list (the entry's CWE ids) is gone in **55**, "Taxonomy Mappings" in 29, "Example Instances" in 21, "Mitigations" in 12, "Consequences" in 11 |

The sampled documents that lost descriptive text (9 of the 15; all 6 sampled
CVEs lost only product tables):

| document | share cut | what the model no longer sees |
|---|---|---|
| `CWE-285` | 30% | rest of Applicable Platforms, all Potential Mitigations |
| `CWE-1423` | 52% | most of the mitigations (9 entries) |
| `CWE-1421` | 56% | most of the mitigations (12 entries) |
| `CWE-98` | 47% | most of the mitigations |
| `CAPEC-164` | 9% | end of the worked example, Related Weaknesses, References |
| `CAPEC-692` | 2% | Related Weaknesses (`CWE-494`), References |
| `CAPEC-112` | 30% | Skills/Resources Required, Indicators, Consequences, Taxonomy Mappings |
| `CAPEC-111` | 26% | end of Mitigations, Example Instances, Related Weaknesses (`CWE-345`, `346`, `352`) |
| `CAPEC-34` | 43% | Prerequisites onward: Skills, Resources, Indicators, Consequences, Notes |

All 108 CWE and CAPEC entries that lose descriptive text:

- CWE (44): `CWE-20`, `CWE-22`, `CWE-41`, `CWE-73`, `CWE-78`, `CWE-79`, `CWE-88`, `CWE-89`, `CWE-94`, `CWE-98`, `CWE-119`, `CWE-120`, `CWE-129`, `CWE-131`, `CWE-190`, `CWE-250`, `CWE-285`, `CWE-306`, `CWE-311`, `CWE-327`, `CWE-330`, `CWE-352`, `CWE-362`, `CWE-400`, `CWE-434`, `CWE-494`, `CWE-601`, `CWE-642`, `CWE-732`, `CWE-754`, `CWE-770`, `CWE-787`, `CWE-798`, `CWE-805`, `CWE-807`, `CWE-829`, `CWE-862`, `CWE-863`, `CWE-1240`, `CWE-1420`, `CWE-1421`, `CWE-1422`, `CWE-1423`, `CWE-1431`
- CAPEC (64): `CAPEC-7`, `CAPEC-13`, `CAPEC-18`, `CAPEC-19`, `CAPEC-21`, `CAPEC-24`, `CAPEC-27`, `CAPEC-32`, `CAPEC-33`, `CAPEC-34`, `CAPEC-39`, `CAPEC-42`, `CAPEC-43`, `CAPEC-47`, `CAPEC-49`, `CAPEC-52`, `CAPEC-61`, `CAPEC-62`, `CAPEC-63`, `CAPEC-66`, `CAPEC-72`, `CAPEC-77`, `CAPEC-78`, `CAPEC-79`, `CAPEC-80`, `CAPEC-86`, `CAPEC-98`, `CAPEC-103`, `CAPEC-105`, `CAPEC-107`, `CAPEC-111`, `CAPEC-112`, `CAPEC-126`, `CAPEC-127`, `CAPEC-132`, `CAPEC-139`, `CAPEC-163`, `CAPEC-164`, `CAPEC-169`, `CAPEC-174`, `CAPEC-199`, `CAPEC-215`, `CAPEC-219`, `CAPEC-244`, `CAPEC-273`, `CAPEC-275`, `CAPEC-560`, `CAPEC-565`, `CAPEC-588`, `CAPEC-591`, `CAPEC-592`, `CAPEC-597`, `CAPEC-600`, `CAPEC-644`, `CAPEC-652`, `CAPEC-653`, `CAPEC-656`, `CAPEC-662`, `CAPEC-663`, `CAPEC-664`, `CAPEC-665`, `CAPEC-676`, `CAPEC-692`, `CAPEC-696`

**Why this matters, in plain words.** A CAPEC entry ends with a list saying
"this attack exploits these weaknesses: CWE-…". That list is where a model
can *copy* a correct CWE id from. For 55 CAPEC entries (9% of all 615) the
model will not see it. Three consequences:

1. Those entries will get fewer, or less certain, CWE ids than they would uncut.
2. The "copied from the entry" measurement compares against the **full**
   text, so an id the model had to work out for itself (because its copy was
   cut off) will still be counted as copied. For cut documents that number
   overstates copying.
3. Three of the 40 seed-42 sample documents are over the limit
   (`CAPEC-126`, `CAPEC-24`, `CAPEC-656`) and were run **uncut**. The sample
   results are therefore not made under exactly the Stage 1 conditions for
   those three.

**A possible improvement that does not need a bigger context** (not built,
not decided): keep the first ~4,500 characters *and* the last ~1,500, dropping
the middle. For CAPEC that keeps the description and the Related Weaknesses
list; for CVEs it changes nothing that matters. It changes what the model
sees, so if it is wanted it has to go in **before Stage 1 starts**.

## Which model

The honest position: the three models behave so differently that the choice
is a research decision, not a tuning one. Same 40 documents, prompt
`corpus-v4`, scorer v1.

| structural ids | `qwen2.5:7b` | `qwen2.5:14b` | Gemini 3.1 Pro, run 1 | Gemini, run 2 |
|---|---|---|---|---|
| proposed | 14 | 157 | 73 | 72 |
| accepted | 6 (43%) | 56 (36%) | 69 (95%) | 68 (94%) |
| rejected at `graph` / `name` | 4 / 4 | 32 / 69 | 0 / 4 | 0 / 4 |
| in a counting run | 0 | 51 | 0 | 0 |
| **accepted and copied from the entry** | 6 (100%) | 17 (30%) | 20 (29%) | 24 (35%) |
| …of those, the entry's own id | 0 | 5 | 8 | 9 |
| **accepted and generated** (not in the entry) | 0 | 39 (70%) | 49 (71%) | 44 (65%) |
| accepted ids with a measurable graph distance | 0 | 35 | 47 | 48 |
| **median distance** (hops from the entry) | – | 2 | 1 | 1 |
| **within 2 hops** (of those measurable) | – | 22 (63%) | 33 (70%) | 37 (77%) |
| generated ids only: median distance / within 2 hops | – | 2.5 / 12 of 24 | 2.5 / 14 of 28 | 2 / 14 of 25 |

*"Copied"* means the id is written somewhere in the entry's own text, or is
the entry's own id. *"Graph distance"* is how many links apart two entries are
in MITRE's own maps (CWE-79 → its parent is 1 hop). It can only be measured
when the document is itself a CWE, CAPEC or ATT&CK entry — a CVE has no place
in the graph, which is why 20–22 accepted ids per run have no distance.

**Is Gemini's 95% mostly copying? No.** About 30% of its accepted ids are
copied — the same share as the 14B — and about 70% are ids it came up with.
Its median distance of 1 hop is flattered by the 8–9 own-id copies (0 hops);
among generated ids the median is 2–2.5 hops with about half within 2, which
is where the 14B sits too. So the difference between the 14B and Gemini is not
*where* the ids come from, it is that Gemini's generated ids are *right*
(0 non-existent, 4 mis-named) and a third of the 14B's are counting.

The 7B proposes almost no identifiers and every survivor was copied off the
page, so an index enriched by it is close to the base index.

## Time and cost for the full corpus (6,044 documents)

### Local models

| model | s/doc | full corpus | money |
|---|---|---|---|
| `qwen2.5:7b` | 12.7 | **~21 hours** | $0 |
| `qwen2.5:14b` | 31.7 | **~53 hours (2.2 days)** | $0 |

**The sustained (after-30-minutes) figure is still missing — the benchmark
that was meant to give it was spoiled.** It ran for 45 minutes on the night of
2026-10-08/09, but the laptop came off mains power **6 minutes in** (system
power log: on battery from 00:04, benchmark started 23:58). From that moment
it was measuring a laptop on battery, not a hot laptop. What it does tell us:

| phase of the benchmark | power | generation speed | seconds per document |
|---|---|---|---|
| first 1.5 minutes | mains | 13.5 tok/s | ~17–20 |
| minutes 1.5–5.5 | mains | **8.5 tok/s** | **~30** |
| minute 6 to the end (39 minutes) | **battery** | **5.4 tok/s** | **~53** |

Three things follow:

1. **The first 90 seconds are a burst** (13.5 tok/s) that no long run will
   see. Do not plan from it.
2. **On mains the machine settles at about 8.5 tok/s within two minutes.**
   That matches the older 8-document benchmark (8.9 tok/s, 31.7 s/doc), so
   the ~52-hour estimate below is the *settled* speed, not the burst. Whether
   it holds for hours or sags further has not been measured: 4 minutes is not
   30.
3. **On battery the same run would take about 89 hours (3.7 days)** — 5.4
   tok/s, rock-steady for 39 minutes. The run must never be on battery, and
   if it is found to have been, expect it to be 1.7 times slower for that
   stretch.

So the per-source estimate **stays provisional at ~52 hours on mains**, and
there is now a measured figure for the bad case.

**One more data point (2026-10-09), not a substitute for the benchmark.** The
40-document sample re-run took 24.5 minutes on mains: **36.8 seconds per
document**, against 31.7 in the short benchmark. At that rate the corpus is
about **62 hours (2.6 days)**. It is not a clean measurement — the test suite
was run a few times on the same machine while it was going, and it is 25
minutes rather than 45 — but it is the longest plugged-in stretch on record
and it points above 52, not below. Plan for 2.5–3 days until the clean
benchmark says otherwise.

| source | documents | mains, settled (provisional) | on battery (measured, sustained) |
|---|---|---|---|
| CVE | 3,011 | ~29 s/doc → ~24 h | 53.6 s/doc → 44.9 h |
| CWE | 1,342 | ~32 s/doc → ~12 h | 53.3 s/doc → 19.9 h |
| ATT&CK | 1,076 | ~33 s/doc → ~10 h | 51.4 s/doc → 15.4 h |
| CAPEC | 615 | ~33 s/doc → ~6 h | 53.5 s/doc → 9.1 h |
| **total** | 6,044 | **~52 h (2.2 days)** | **89.2 h (3.7 days)** |

The mains column is built from the 14B sample's token counts (prompt/reply
per document: CVE 965/236, CWE 581/270, ATT&CK 561/277, CAPEC 1,462/257) at
8.9 tok/s. The battery column is straight from the benchmark's last 17
documents (4–5 per source — small, but they agree to within 2 seconds). Either
way nearly all the time is the model *writing*, so every source costs about
the same per document and half the run is CVEs.

To get the real mains figure (the laptop has to stay plugged in for the whole
45 minutes — the script now checks before every document and stops if it is
unplugged, instead of quietly carrying on):

```bash
caffeinate -i .venv/bin/python scripts/bench_enrichment_speed.py --model qwen2.5:14b --minutes 45
```

Timing log of the spoiled run, kept as the battery measurement:
`indexes/enrichment/bench_speed_qwen2.5-14b.jsonl`.

### Running it, and picking it up after an interruption

```bash
caffeinate -i .venv/bin/python scripts/enrich_corpus.py \
    --model qwen2.5:14b --name-scorer v2 \
    --output indexes/enrichment/corpus_full_v4_14b.jsonl
```

**To resume: run exactly the same command again.** That is the whole
procedure. What it does:

- Each finished document is written to the output file straight away, one
  line each. A crash, a closed lid or a flat battery loses at most the one
  document that was in progress.
- On restart the script reads the file, skips every document already in it,
  and carries on with the rest. Documents that failed (listed in
  `<output>.failures.jsonl`) are *not* in the file, so they are tried again
  automatically.
- The `.manifest.json` beside the output is rewritten at the end of each
  session.

Rules while a run is unfinished:

1. **Change nothing between sessions** — not the prompt, not
   `configs/default.yaml`, not the model, not `--output`. The script now
   checks this and refuses to continue if anything differs, including the
   code's git commit.
2. Plugged in, lid open, `caffeinate -i` (stops the Mac sleeping), nothing
   else using Ollama.
3. To check progress: `wc -l indexes/enrichment/corpus_full_v4_14b.jsonl` —
   it is finished at **6044**.
4. When it says finished, look at `<output>.failures.jsonl` and the
   `truncation` block in the manifest (171 documents expected, 0 fallbacks).
5. Then build the index: set `index.enrichment_path` to the new file and run
   `.venv/bin/python scripts/build_index.py --stage enriched --config configs/default.yaml`.

## Before Stage 1 starts — checklist

**Stage 1 has not been started. Do not start it until every box in the first
group is ticked.**

Decisions and paperwork:

- [ ] **Owner says yes to the model**: `qwen2.5:14b` for the development index.
- [x] **Cut shape decided and built**: section-aware (see "The truncation rule").
- [x] **Resume guard built** (open question 2): a resume under different
      settings is refused.
- [ ] **A clean 45-minute benchmark, plugged in the whole time**, so the team
      is told a real finishing time. The 2026-10-09 attempt lost mains power
      at minute 6. `caffeinate -i .venv/bin/python scripts/bench_enrichment_speed.py --model qwen2.5:14b --minutes 45`
- [x] **The 40-document 14B sample re-run under the new truncation** — done
      2026-10-09. 37 of 40 replies byte-identical to the earlier run; the
      three shortened CAPEC entries changed slightly; no finding changes
      (`03_STATUS_LOG.md`).
- [ ] **Schema sign-off from Modules 2, 3 and 4** — one page to read and
      sign: `docs/proposals/schema-signoff.md` (1.3.0, 1.4.0, 1.5.0, all
      backward compatible). Only Module 1's row is filled in. The run *can*
      go ahead without it, but Module 3 will be reading 1.5.0 records.
- [ ] **The code is committed.** This is now enforced: a full-corpus run
      **refuses to start** if anything under `src/`, `scripts/` or `configs/`
      is uncommitted, and the manifest records the commit. Config hash must
      read **`364d30da6c75`** (unchanged by today's work).
- [ ] **All tests pass**: `.venv/bin/python -m pytest -q` (369).

The machine, on the day:

- [ ] **Plugged in, and the charger cannot get knocked out.** Measured: on
      battery the 14B drops from 8.5 to 5.4 tokens a second (1.7 times slower).
- [ ] **Lid open, on a hard surface**, somewhere it can stay for the whole run.
- [ ] **Nothing else using Ollama.** `curl -s http://localhost:11434/api/ps`
      should list nothing before you start.
- [ ] **Base index present**: `indexes/base/manifest.json` exists (it does).
- [ ] **The output file does not exist yet**:
      `indexes/enrichment/corpus_full_v4_14b.jsonl`. Never reuse `corpus.jsonl`.

Start it (`caffeinate -i` stops the Mac going to sleep):

```bash
caffeinate -i .venv/bin/python scripts/enrich_corpus.py \
    --model qwen2.5:14b --name-scorer v2 \
    --output indexes/enrichment/corpus_full_v4_14b.jsonl
```

(`--concurrency 1` is no longer needed on the command line: it is now the
config default.)

**If it stops for any reason, run exactly the same command again.** It skips
what is done and carries on. If anything has changed since the file was
started — the config file, the model, the scorer, the concurrency, the
truncation budget or rules, the prompt — the script now **refuses**, names
what differs, and appends nothing. Put the setting back, or start a new
`--output`. Progress: `wc -l indexes/enrichment/corpus_full_v4_14b.jsonl`
(finished at 6044).

The script also refuses if **the code** has changed: the manifest records the
last commit that touched `src/`, `scripts/` or `configs/`, and a resume from
a different one stops with both hashes shown. Editing or committing
**documentation** in the meantime is fine — it is not part of that check. If
a code change really cannot affect a reply (a typo in a log message), add
`--allow-code-change`; the earlier commit stays in the manifest under
`code_previous`.

**Does anything else block it?** No.

## Two-stage plan: a free local index now, one Gemini index at the end

**Status: a plan for the Module 1 owner to approve. Nothing here has been run.**

**The idea.** Build the enriched index twice. First with a free local model,
straight away, so Modules 2 and 3 have something real to develop against.
Then, once the method is frozen, once more with Gemini, and that second index
is the one the results are reported on.

### Stage 1 — development index (local, $0)

| option | time on this machine | what Modules 2/3 get |
|---|---|---|
| `qwen2.5:7b` | ~21 h best case | 14 ids proposed per 40 documents, all survivors copied — barely exercises the grounding gates. Fine for plumbing, poor for developing anything that depends on ids |
| **`qwen2.5:14b`** (recommended) | ~53 h best case; sustained figure not yet measured | every gate fires (32 graph and 69 name rejections per 40 documents), so Modules 2/3 see the hard cases while they build |

The 14B is the better *development* index precisely because it is the messier
model. Start it as soon as the sustained benchmark has been run once, so the
team is told a real finishing time.

### Stage 2 — final index (Gemini 3.1 Pro, low thinking)

Token counts are the average of the two 40-document runs, scaled to the
corpus's own mix of document types and lengths: **5.9M prompt, 1.0M reply and
3.6M thinking tokens.**

| way of running | price per 1M tokens (in / out incl. thinking) | cost | time |
|---|---|---|---|
| Standard (what we used) | $2.00 / $12.00 | **≈ $67** | ~14 h one document at a time (8.5 s each); less with several at once |
| **Batch mode** | $1.00 / $6.00 | **≈ $34** | Google's target is within 24 h, "in majority of cases, it is much quicker" |

- Prices: Google's pricing page, `gemini-3.1-pro-preview` rows, page dated
  2026-10-07 — <https://ai.google.dev/gemini-api/docs/pricing>. It lists a
  Batch row for this exact model, and says output price includes thinking.
- Batch mode: <https://ai.google.dev/gemini-api/docs/batch-api> — "Batch API
  usage is priced at 50% of the standard interactive API cost for the
  equivalent model." It supports structured output and system instructions,
  and "any request configurations you would use in a standard non-batch
  request". Jobs expire after 48 hours pending/running.
- Token and cost figures above were estimated from uncut sample documents;
  with the 6,000-character cut the prompt side is slightly lower, so they are
  a small overestimate.
- **Not confirmed:** the batch page says to check the Models page for
  per-model support and names other models in its examples. The pricing page
  listing a Batch price for `gemini-3.1-pro-preview` is our evidence it is
  available. Confirm with one tiny batch job before relying on it.
- **Batch mode is not built.** `GeminiClient` makes ordinary calls. Batch
  needs new code: write all 6,044 requests to a file, submit, poll, read the
  results back through the same adjudication. Roughly a day including tests.
  It is worth it only because it halves the largest single spend.
- Allow ~15% on top for variation between runs: budget **$80** standard or
  **$40** batch. Both are far above the $1 cap of the sample exception, so
  this needs its own entry in `06_POLICY_EXCEPTIONS.md` and a team decision.

### What must be frozen before the Gemini run

The Gemini run is the one thing in this project that **cannot be redone
cheaply and cannot be redone exactly** — it costs $34–67 each time, and the
two sample runs agreed on only 80% of accepted ids even with the same seed.
So anything that shapes the model's reply has to be final first:

1. **The prompt** (`corpus-v4`) — including whether the question-7 work
   changes it. A new prompt means a new run.
2. **The reply shape**: `REPLY_SCHEMA`, 12 terms per document, the 512-token
   reply cap.
3. **The model id and thinking level**: `gemini-3.1-pro-preview`, `low`. It
   is a *preview* model: Google can change or retire it. Run it soon after
   freezing and record the date and the `model_version` the API reports (the
   manifest does).
4. **Truncation for Gemini: the same 6,000-character cut as Stage 1.**
   **Decided by the owner, 2026-10-08; the cut itself became section-aware on
   2026-10-09 and Gemini inherits that.** Gemini could read the whole of every
   document — its context is 250 times larger — but it will be shown exactly
   what the local model was shown, **so that the model is the only thing that
   differs between the two indexes.** If Gemini saw more text, a better
   Stage 2 index could be the model or the extra text and nobody could say
   which. Stage 2 uses the identical section-aware rule (`sections-v2`). Nothing to configure: `enrichment.max_doc_chars` already
   applies to every backend.
5. **Temperature 0.0 and seed 42** as now — knowing the seed is not honoured.
6. **The resume guard** (open question 2) — built 2026-10-09. A paid run
   that crashes half-way can only be resumed under identical settings.
7. **A rule, written down before the run: nothing is tuned on the Gemini
   index after it exists.** Thresholds (`df_max_ratio`, the name-check
   threshold, the scorer) are chosen on the local index and then applied
   unchanged. Otherwise the final numbers are tuned to the test.
8. **Budget, tier and approval** recorded in `06_POLICY_EXCEPTIONS.md`.

What does **not** have to be frozen first, because it is recomputed from the
saved replies in seconds with no model call: every gate — the name scorer,
the DF threshold, the repair option, the question-7 `already_in_document`
gate.

### Three things to be honest about in the write-up

- **One run is the index.** With an 80% run-to-run overlap, a second Gemini
  run would give a slightly different index. Report the sample's agreement
  figure alongside the results.
- **Development and final models differ.** Modules 2/3 will have been built
  against 14B output (many rejections) and evaluated on Gemini output (almost
  none). The gates' *value* will look much smaller on the final index — that
  is a finding, not a bug, and RQ4 should report both.
- **The local index is still a result.** "Open-weight 14B + grounding" versus
  "frontier model + grounding" is a comparison the project can report for
  free once both indexes exist.

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

All in `src/sira_cti/`, all covered by the offline test suite (369 tests).

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

**The contract** — `common.schemas`, version 1.5.0 (`tokens.thinking`, `truncation` added): `ProposedTerm` fields
`claimed_name`, `official_name`, `rejected_at_stage`, `in_counting_run`,
`graph_distance`, `name_scorer`, `repaired_to`; reasons `name_mismatch`,
`llm_json_error`.

## Known loose ends that the freeze does *not* fix

- `expansion_query()` indexes an accepted structural term as the model
  *wrote* it (`cwe-287`), not its canonical id (`CWE-287`). Harmless here —
  the analyzer lower-cases and splits both the same way — but a model writing
  `t1110/001` would be indexed as two tokens while `T1110.001` is one. One
  occurrence of a non-canonical spelling in the 14B sample. Module 3's call.
- The config hash is now `364d30da6c75` (`concurrency: 1`; `77fa240d81d1`
  before that for seed, `num_ctx`, `max_doc_chars`;
  before that `2007683a1442` after the Module 3 merge). Earlier: it changed on 2026-10-08 (`86fee6d106b8` → `2514fd048115`)
  because the scorer and repair keys were added. They do not affect generation,
  and each manifest's `gates` block says what a run actually used — but hashes
  alone will not show that the `corpus-v4` sample runs and anything run after
  today are comparable.
- ~~Open question 2 is still unguarded.~~ Guarded since 2026-10-09.
