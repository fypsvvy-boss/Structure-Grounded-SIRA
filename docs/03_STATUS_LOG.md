# Status Log

> Rolling log — newest entry at the top. Update this at the end of every working
> session so the next session (human or AI) picks up exactly where this one left
> off. Keep entries short and factual.

---

## Current headline

**2026-10-08: scorer v2, the repair measurement, and a freeze checklist — all
offline, no model calls. The frontier-model run is approved but blocked on a
provider.** Saved runs can now be re-adjudicated for free
(`scripts/rescore_enrichment.py`), and replaying them reproduces every verdict.
Scorer **v2** (CWE short names) catches both within-family escapes v1 let
through on the 7B and one more on the 14B; its limit is reach — only 122 CWE
nodes have a short name, so 90 of 125 name verdicts on the 14B still fall back
to v1. **9 of the 33** near name-mismatches repair cleanly to the id the model
probably meant. Two corrections to earlier notes: schema decoding is **1.5x**
slower on the 7B and **not slower at all** on the 14B (not "3x"), and the
`latency_ms` in the saved sample runs is not usable for RQ3. One new blocker
for the full-corpus run: ~40 documents overflow the 4,096-token context.
`docs/proposals/module1-freeze.md` lists what would be frozen.

**2026-10-07 (later): the name-ID consistency check — the adaptation that makes
SIRA's grounding transfer to CTI.** Asking the model to state what each
identifier *is*, and checking that against MITRE's title, cut structural
acceptance on `qwen2.5:14b` from **109/125 (87%) to 56/157 (36%)** on the same
40 documents. It kills counting runs almost entirely: ids flagged as sequential
enumeration went from 33 of 38 accepted (87%) to **7 of 51 (14%)**. The finding
to write up: *an existence check is sufficient grounding for a named category
namespace like Wikipedia's and insufficient for a dense integer namespace like
MITRE's* — CWE packs ~940 active entries into 1..1425, so "does this id exist"
is nearly free, and a model that counts upwards passes it. Also: schema-
constrained decoding fixed `CAPEC-587`, so both runs completed 40/40 with zero
parse failures. Full numbers in the log entry below; sign-off request in
`docs/proposals/name-id-consistency.md`.

**2026-10-07: `qwen2.5:14b` on the same 40 documents answers "prompt or model" —
it is the model, but not in the way we wanted.** Structural proposals went from
14 to 125 and the graph gate finally rejected something it never could before
(5 `not_in_graph`, 3 `revoked`). But a third of the ids it proposes that aren't
copied are **sequential counting**, not inference: `CWE-512` (Spyware) ->
`CWE-73,74,75,76,77,78,79,80,81`, all nine accepted as valid and none about
spyware; `T1056.001` -> `.002 .003 .004` (real siblings) then `.005`-`.009`,
which don't exist and are exactly the 5 hallucinations the gate caught.
**Open question 8 (ids that are real but irrelevant) is now the most important
open issue — ahead of question 7.** Details in the log entry below.

**2026-09-15 (later): prompt `corpus-v3` — the document's own id removed from the
prompt — confirms the own-id copies came from the header (9 -> 0), and exposes
what the model does when it has nothing to copy: almost nothing, and wrong.**
ATT&CK entries produced no identifiers at all; CWE entries produced two, and
both were real CWEs that have nothing to do with the entry (Prototype Pollution
-> Format String; Infinite Loop -> Race Condition). The graph gate accepted both,
because it checks that an id *exists*, not that it *fits*. See the log entry
below and new open question 8.

**2026-09-15: first stratified run (10 documents of each type) — the model has
not made a single cross-catalogue inference.** Every structural identifier it
proposed on every document type was copied from what it was shown: 22 of 22 in
this run, 47 of 48 across all three runs to date. On CWE and ATT&CK documents it
hands back the document's *own* id, which the prompt header supplies. The
redundancy check as written in the question-7 proposal misses those copies, so
the proposal has been amended before it goes out. Full numbers in the log entry
below and in `04_OPEN_QUESTIONS.md` question 7.

**2026-09-15: the question 7 sign-off request is written and waiting on the
other three owners.** `docs/proposals/already-in-document-gate.md` — read
it before implementing anything in that area. Nothing in `schemas.py` has
changed; this is the request, not the implementation.

**Phase 1 / Module 1: two gate bugs found and fixed after the first real LLM run
(2026-08-20). Both were distorting RQ1/RQ4 rather than merely being untidy.**
`04_OPEN_QUESTIONS.md` questions 1 and 3 are now RESOLVED — read those two
sections before touching the enrichment gates, they carry the measurements.

In one line each:
1. **Every CWE identifier was being rejected as `too_common`, always**, because
   the DF gate scored `CWE-307` by its `cwe` token (49.2% of the corpus) instead
   of its number. ATT&CK ids bypassed the gate entirely. Fixed.
2. **`malformed_id` was counting form-filling slips as hallucinations**, inflating
   the RQ4 headline metric. The model had fabricated zero identifiers; the log
   said 5. Fixed.

**Data regenerated.** The old 5-record file (adjudicated under the broken gates)
is archived as `indexes/enrichment/corpus.jsonl.pre-gatefix` — keep it, it is the
only surviving record of the old behaviour and the "before" half of the evidence.
A fresh 20-document run and the enriched index now exist.

**⚠️ New and more serious: see `04_OPEN_QUESTIONS.md` question 7.** 61% of
accepted enrichment terms — and **100% of structural identifiers** — are words
already present in the document's own text, so they add no retrieval value. This
matters more than either gate bug.

Immediate priorities: (1) question 7 needs an enforced gate — prompting was
tried and failed, and the gate needs four-owner sign-off for a new
`RejectReason`, so start that conversation, (2) stratify the corpus sample (every
result so far is CVE-only), (3) investigate the zero ATT&CK/CAPEC proposals.

## Log

### Scorer v2/v3, repair ablation, RQ3 latency, freeze checklist (2026-10-08)

Schema **1.3.0** (adds `name_scorer`, `repaired_to`; folded into the pending
sign-off in `docs/proposals/name-id-consistency.md`). No model was re-run for
tasks 1 and 2.

#### 1. Name scorers, rescored offline

`propose_terms` is now `_ask_for_proposals` + `adjudicate_proposals`, and
`readjudicate_record` replays the second half on a saved record.
`scripts/rescore_enrichment.py` first replays each file under the scorer it was
written with — **identical verdicts on both `corpus-v4` files** — then
compares.

| structural ids | 7B v1 | 7B v2 | 7B v3 | 14B v1 | 14B v2 | 14B v3 |
|---|---|---|---|---|---|---|
| proposed | 14 | 14 | 14 | 157 | 157 | 157 |
| accepted | 6 | 4 | 4 | 56 | 54 | 46 |
| rejected at `name` | 4 | 6 | 6 | 69 | 71 | 79 |
| name verdicts falling back to v1 | – | 3/10 | – | – | 90/125 | – |
| counting-run ids accepted | 0 | 0 | 0 | 7/51 | 7/51 | 4/51 |

v1 -> v2 changes four verdicts in total: `CWE-74` and `CWE-89` on the 7B (the
two known escapes, both caught), `CWE-416` on the 14B ("Double Free" for Use
After Free, a real catch) and `CWE-415` on the 14B ("Double Free or Release of
Same Resource" for Double Free — arguably a false rejection). v3 adds eight
more on the 14B: six wrong titles on nodes with no short name, and `T1046`
twice under its *pre-rename* title, which is stale rather than wrong.

Loader: 122 of 1,450 CWE nodes now carry short names (quoted name in the title
+ `Alternate_Terms`) in `node.aliases` and `attrs["short_names"]`. v1 ignores
them on purpose so saved runs keep replaying. Re-adjudicated copies written to
`corpus_stratified_v4_{7b,14b}_scorer-v2.jsonl`.

#### 2. Repair (`repaired_to`), measurement only

For each name mismatch: is there exactly one *other* real id within 2 hops of
the document whose official name matches what the model said? On the 14B, of
the 33 mismatches whose proposed id was within 2 hops: **9 clean, 2 ambiguous,
22 nothing nearby**. 13 clean repairs in all; 2 are the document's own id
(recorded, never indexed). On the 7B: 2 clean, one of them own-id.
`enrichment.index_repaired_ids` (default `false`) makes the enriched index
include them — for Modules 3/4 to test; default index unchanged.

Weak spots: three repairs score 0.67–0.80 rather than 1.00, and one lands on a
tactic (`TA0006`) rather than a technique.

#### 3. Frontier model — NOT RUN

Approved by the Module 1 owner as a logged exception to the open-weight-only
development policy (cap $1, expected ~$0.25, reason: third model-size point,
open question 10). Blocked: no API key, no provider configured, Ollama is the
only backend in `common/llm.py`, and the instruction was to ask rather than
guess. **$0 spent.** The three-column table is therefore still two columns.

#### 4. RQ3 latency — two corrections

Clean benchmark (8 documents, sequential, warm, Ollama's own eval timings):
7B 26.4 tok/s unconstrained vs 17.4 under the schema (**1.5x**); 14B 8.6 vs 8.9
(**no difference**). The "~3x" in yesterday's notes was wrong and has been
corrected in every doc. Separately, `concurrency: 2` gives no speed-up on
Ollama (148.7s vs 139.1s for 12 documents) while inflating each record's
`latency_ms` with queue time, and yesterday's sample runs shared the server
with diagnostics — so **their latency fields are unusable for RQ3**. Handoff
note for Modules 3/4: `04_OPEN_QUESTIONS.md` question 11.

#### 5. Freeze checklist

`docs/proposals/module1-freeze.md`. Its organising point: only what shapes the
model's reply has to be right before the run (model, prompt, decoding, caps,
context handling); every gate after it can be re-derived offline in seconds.
Full corpus: ~21 h on the 7B, ~53 h on the 14B, $0. New blocker found while
writing it: ~40 of 6,044 documents exceed the 4,096-token context and would be
silently truncated (question 12).

#### Code

- `graph/loaders.py`: `cwe_short_names()`, CWE aliases.
- `graph/ontology.py`: `NAME_SCORERS`, `check_name(scorer=, min_jaccard=)`,
  `name_jaccard`, `split_title`, `within()`, `name_candidates()`.
- `common/schemas.py`: 1.3.0. `common/llm.py`: `OllamaClient.last_timings`.
- `enrichment/corpus_side.py`: `adjudicate_proposals`, `readjudicate_record`,
  `repair_candidates`, `annotate_repairs`; scorer in the manifest `gates`.
- `index/build_enriched.py`: `index_repaired_ids`, `repaired_ids()`.
- `scripts/rescore_enrichment.py` (new); `enrich_corpus.py --name-scorer`.
- Config: `name_scorer`, `name_match_min_jaccard`, `index_repaired_ids`. This
  changes the config hash (`86fee6d106b8` -> `2514fd048115`) without changing
  generation; the manifest `gates` block is what shows comparability.
- **256 tests pass** (was 224; +32). Offline throughout.

### Name-ID consistency, counting-run detection, ontology distance (2026-10-07, later)

Schema 1.2.0 (awaiting four-owner sign-off —
`docs/proposals/name-id-consistency.md`). Prompt `corpus-v4`. Both models
re-run on the same seed-42 40 documents, same config hash, `--model` only.

#### The table

| | 7B v3 | 7B v4 | 14B v3 | 14B v4 |
|---|---|---|---|---|
| terms proposed | 419 | 442 | 468 | 480 |
| terms accepted | 210 | 205 | 248 | 177 |
| **structural proposed** | 14 | 14 | 125 | **157** |
| **structural accepted** | 12 (86%) | 6 (43%) | 109 (87%) | **56 (36%)** |
| rejected at `parse` | 0 | 0 | 1 doc | 0 |
| rejected at `graph` | 2 | 4 | 16 | 32 |
| rejected at `name` | n/a | 4 | n/a | **69** |
| rejected at `df` | 207 | 229 | 204 | 202 |
| copied from the entry | 13 (93%) | 11 (79%) | 42 (34%) | 42 (27%) |
| generated | 1 (7%) | 3 (21%) | 83 (66%) | 115 (73%) |
| in a counting run | 0 | 0 | 38 (30%) | 51 (32%) |
| ...of those, accepted | 0 | 0 | **33 (87%)** | **7 (14%)** |

Raw counts throughout; n=40 documents, so read the percentages as orientation
only. `graph` splits for 14B v4: `deprecated` 15, `not_in_graph` 8, `revoked` 5,
`malformed_id` 4.

#### What the name check actually caught

Four on the 7B, 69 on the 14B. The cleanest one is the case open question 8 was
opened about:

```
CWE-835 "Infinite Loop" entry -> proposed CWE-362
   model claimed : "Loop with Unreachable Exit Condition ('Infinite Loop')"
   MITRE's title : "Concurrent Execution using Shared Resource ... ('Race Condition')"
```

The model wrote the **document's own title** next to a different number.
`corpus-v3` accepted that, because `CWE-362` exists. Also caught on the 7B:
`CWE-29` and `CWE-1230` both claimed CWE-119's title, `CWE-173` claimed
CWE-20's.

#### Two escapes, and what they say about the metric

On the 7B the check let two through, and both are the same failure:

```
CWE-74 claimed "...SQL Command ('SQL Injection')"
       official "...Downstream Component ('Injection')"       overlap 0.67  PASSED
CWE-89 claimed "...OS Command ('OS Command Injection')"
       official "...SQL Command ('SQL Injection')"            overlap 0.83  PASSED
```

Off by one *inside the injection family*, where CWE's titles are near-identical
sentences — CWE-78's and CWE-89's real titles score **0.83 against each
other**. The four it caught were cross-family confusions, scoring 0.00-0.20.
**So the claim is: this catches cross-family confusions and misses
within-family neighbours.** Two candidate fixes were measured offline against
the saved records (no model calls — `claimed_name`/`official_name` are stored,
which is turning out to be the most useful property of 1.2.0):

- **rarity-weighting the title words (IDF): does not work.** Zero verdicts
  change; the injection family shares its rare words too.
- **the parenthesised short name with a symmetric score: works.** 0.50 and 0.25
  for the two escapes, 1.00 for a correct answer. Needs a *loader* change —
  `node.aliases` is empty for every CWE today.

Not implemented: changing the scorer mid-experiment would make this table
incomparable. Written up as the next iteration.

#### The cost side, which needs a decision

**33 of the 69 name-mismatch rejections on the 14B are within 2 hops of the
document.** So the check does discard structurally plausible ids. Whether that
is a loss depends on what the proposal was:

```
CAPEC-24 -> CWE-119, 1 hop, claimed "Integer Overflow or Wraparound"
            (CWE-119 genuinely is relevant; the title belongs to CWE-190)
CWE-1162 -> CWE-772, 1 hop, claimed "Dangling Pointer"
            (CWE-1162 is a CERT *category*; its members are all 1 hop, and the
             model sprayed six of them with titles belonging to other entries)
```

For a retrieval index the id is what gets indexed, so a right-id-wrong-title
proposal would still have helped recall. For RQ1's claim about *grounding*, it
is not evidence of grounding — the model demonstrably did not know what the id
was, so proximity was a lucky draw from the right neighbourhood. **This is the
sharpest thing to put to the supervisor.**

#### Distance distribution (14B v4, accepted structural ids)

```
0 hops  5     (the entry's own id)
1 hop  10
2 hops  7
3 hops  4
4 hops  7
5 hops  2
none   21     (CVE documents and unreachable nodes -- NOT "unrelated")
```

#### Counting runs: distance rescues one the flag condemns

Re-running the detector over the 14B v3 output and adding distance:

```
CWE-512  Spyware                 -> CWE-73 .. CWE-81    all 4 hops   enumeration
T1003.006 DCSync                 -> T1113/4/5           all 4 hops   enumeration
CWE-1169 SEI CERT C Concurrency  -> CWE-481 .. CWE-486  3-4 hops     enumeration
T1056.001 Keylogging             -> .002/.003/.004      2 hops       real siblings
CAPEC-24 Filter Failure thru...  -> CWE-118/119/120     all 1 hop    GENUINE
T1430.001 Remote Device Mgmt     -> C0023 .. C0026      unreachable  campaign ids
```

`CAPEC-24` is why neither flag becomes a gate: three consecutive CWE numbers,
but they are the buffer-bounds weaknesses that attack pattern really maps to.
MITRE numbered related weaknesses sequentially, so "consecutive" and "actually
related" are **correlated** in CWE. Counting run **and** distance >= 3 is the
enumeration signature; either alone gives the wrong answer.

Direct answer to "how many of the earlier counting ids does the name check now
reject": of the 38 flagged in the v3 14B run, only 12 were proposed again at
all (constrained decoding plus the name requirement changed the distribution) —
the name check rejected 5, the graph rejected 5 as non-existent, 2 were
accepted. The informative version is the before/after on the flag itself: **33
of 38 accepted under existence-only, 7 of 51 under existence+name.**

#### CAPEC-587: not truncation, and `format: "json"` was the wrong fix

Re-ran that one document with the raw completion logged: 245 completion tokens,
no cap in force, Ollama's own `done_reason` = `stop`, reply ending in a
well-formed `]`. One array element was missing its opening brace. Not length.

| `format` sent | result |
|---|---|
| absent | brace missing, identical on every retry at temperature 0 |
| `"json"` | valid JSON, but a **single object** — one proposal where twelve were asked for |
| the reply schema | 12 proposals, both models, first attempt |

Plain `format: "json"` would have quietly gutted every run instead of failing
one document. Enrichment now sends `REPLY_SCHEMA`. Both v4 runs finished 40/40
with **zero** parse failures and no `.failures.jsonl` sidecar at all.

Cost: ~~grammar-constrained sampling is ~3x slower~~ **corrected 2026-10-08:
1.5x on the 7B, nothing measurable on the 14B.** The 3x figure compared runs
made under different load. See the 2026-10-08 entry.

`enrichment.max_new_tokens` also now does something — it had been read by
nothing since it was added, and every reply was generated unbounded. It reaches
Ollama as `options.num_predict`.

#### Code

- `common/llm.py`: `max_new_tokens`, `json_mode`, `json_schema` on the
  `LLMClient` base class; `GenOptions`; `last_stop_reason`/`last_truncated` on
  `OllamaClient`; `StubClient.option_calls` so a test can prove a config value
  reached the backend.
- `common/schemas.py`: 1.2.0 — `NAME_MISMATCH`, `LLM_JSON_ERROR`,
  `RejectStage`, and `claimed_name`/`official_name`/`rejected_at_stage`/
  `in_counting_run`/`graph_distance` on `ProposedTerm`.
- `graph/ontology.py`: `check_name()`, `NameCheck`, `name_tokens`,
  `name_overlap`, `distance()` with a cached undirected projection.
- `enrichment/corpus_side.py`: name stage, `Proposal` type (accepts `"id"` as a
  synonym for `"term"`), nudged JSON retry, `record_json_failures`,
  `flag_counting_runs()`, `annotate_graph_distance()`, `gates` in the manifest.
- `prompts/corpus_side.py`: `corpus-v4`, `REPLY_SCHEMA`, `JSON_RETRY_NUDGE`.
- `scripts/enrich_corpus.py`: `--no-name-check`, `--name-overlap`.
- `scripts/report_enrichment.py`: new, read-only per-run table and
  `--counting-ids-from`.
- **224 tests pass** (was 170; +54). Offline throughout.

### `qwen2.5:14b` on the same 40 documents (2026-10-07)
Command (new `--model` flag, so the config is untouched and the manifest records
what actually ran):
`.venv/bin/python scripts/enrich_corpus.py --per-kind 10 --model qwen2.5:14b --output indexes/enrichment/corpus_stratified_v3_14b.jsonl`
Same sample (seed 42), same prompt (`corpus-v3`), same gates — only the model
differs. ~30 min for 39 docs (~46s/doc, 2.7x the 7B) on 16 GB RAM; the run was
interrupted twice by this session's background time limit and resumed cleanly
from the JSONL both times, which is the resumability design working for real.

**1 of 40 failed and was not written:** `CAPEC-587`, invalid JSON — the model
emitted `"frame busting evasion", "kind": ...` with the opening `{"term":`
missing. Not truncation. Strict parsing caught it, so no fake
"proposed nothing" record exists. Note it will fail identically on every retry
at temperature 0, so a resume can never complete this document — see the new
checklist item.

```
                              7B (corpus-v3)   14B (corpus-v3)
  documents                        40               39 (+1 failed)
  terms proposed                  419              468
  accepted                        210              248
  structural proposed              14              125
  structural accepted              12              109
  rejected: too_common            207              204
            not_in_graph            0                5   <- first ever
            revoked                 0                3   <- first ever
            deprecated              0                3
            malformed_id            2                5
  already in own document       62.4%            23.4%   (33.1% under the gate rule)
```

**1. "Prompt or model" is answered: model.** The 7B proposed no ATT&CK ids for
ATT&CK entries once the header id was removed; the 14B proposed 37. Structural
proposals went 14 -> 125. Nothing else changed.

**2. The graph gate finally has work to do — and this is the RQ4 result.** Five
`not_in_graph` and three `revoked` rejections, where every earlier run had zero
of both across 125 documents. The grounding step's value is invisible at 7B and
visible at 14B; any RQ4 claim must say which model it was measured on.

**3. But most of the new identifiers are counting, not inference.** Of 83
proposed ids not copied from anywhere, **29 are adjacent (+1) to another id the
model proposed for the same document**, across 7 documents:

```
  CWE-512  Spyware        -> CWE-73,74,75,76,77,78,79,80,81   all 9 ACCEPTED, none spyware-related
  CWE-1169                -> CWE-481,482,483,484,485,486
  CWE-398                 -> CWE-481,502,693,703,732,754,770,771,787
  T1056.001 Keylogging    -> T1056, T1056.002/.003/.004 (real siblings, fine)
                             then T1056.005-.009  -> all 5 not_in_graph
  T1430.001               -> C0023,C0024,C0025,C0026 (campaign ids)
```

The existence check accepts a consecutive run whenever those numbers happen to
exist, which for CWE they usually do. So the 14B's apparent jump in
"graph-validated proposals" is substantially an artifact of enumeration, and
**a higher validity rate here means a worse result, not a better one.** This is
question 8, now upgraded to the top of the list.

**4. Cross-catalogue links are still mostly copies.** CAPEC entries did produce
CWE and ATT&CK ids (12 and 3) — but 24 of their 27 structural proposals came
from labelled mapping fields in the entry's own JSON. The clearest genuine
cross-catalogue proposal in the whole run is `CWE-1321` -> `CAPEC-448`.

**5. Redundancy fell sharply** (62.4% -> 23.4%), mostly because structural
proposals exploded and the new ones aren't copies. It does not mean the 14B
restates less prose: colloquial terms are still 33/107 already present.

**Also:** `enrichment.max_new_tokens: 512` in `configs/default.yaml` is dead —
nothing reads it, and `OllamaClient` sends only `temperature` in its options.
Either wire it to `num_predict` or delete the key; right now it reads as a
control that exists.

### Decisions on the question 7 proposal, and the `corpus-v3` prompt run
**Decisions (Module 1, 2026-09-15).** (1) Approve the `already_in_document`
gate, with its structural check limited to ids written in the text or named by
a labelled id field (`@CWE_ID`, `@CAPEC_ID`, `@Exclude_ID`, and `Entry_ID` only
inside an `ATTACK` taxonomy mapping) — the looser "any quoted number" version
would have matched WASC/OWASP codes like `"Entry_ID": "07"`. Still needs Modules
2/3/4. (2) Remove the document's own id from the prompt header; whether entries
should be searchable by their own id goes to Module 3. Both recorded in the
proposal, which now has a per-owner sign-off table.

**Changes.** Prompt `corpus-v3` (`"Catalogue entry (cwe):"`, no id; `corpus-v2`
is the reverted experiment's name so it is not reused). `enrich_corpus.py` now
records `PROMPT_VERSION` from the prompt module, and the
`enrichment.corpus_prompt_version` config key is gone — closes the latent bug
logged earlier. `measure_redundancy.py`: check tightened as above, plus a second
headline line for what the approved gate rule would reject. Four existing tests
used to pick documents by spotting "id T1110" in the prompt; they now key on the
document text instead (assertions unchanged), and one new test pins that the
prompt carries no id. 169 -> 170 tests.

**Run.** Same 40 documents as the `corpus-v1` stratified run (seed 42), output
`indexes/enrichment/corpus_stratified_v3.jsonl`. 40 docs, 0 failed, 695.5s
(slower than v1's 411.5s; nothing in the change explains that, most likely machine
load — not investigated). 419 terms: 210 accepted, 209 rejected — `too_common:
207`, `malformed_id: 2`.

```
  structural ids proposed            corpus-v1    corpus-v3
  cve     (literal copies)                10            9   (8 CWE + 1 CVE id, also in the text)
  cwe     (own id, from header)            5            0
          (not copied from anywhere)       0            2   <- both wrong, see below
  attack  (own id, from header)            4            0
  capec   (labelled-field copies)          3            2   (CWE-173; T1195.001)
```

**1. The own-id copies came from the header.** Removing it took them from 9 to
0, with no drop in overall output (437 -> 419 terms proposed). ATT&CK entries
now propose **no** identifiers at all; CWE entries propose two.

**2. The only two identifiers not copied from anywhere were both wrong.**

```
  CWE-1321 Prototype Pollution  -> CWE-134 Use of Externally-Controlled Format String
  CWE-835  Infinite Loop        -> CWE-362 Race Condition
```

Neither is a parent, child or sibling of its entry; the only ancestor each pair
shares is a CWE **Pillar** (`CWE-664`, `CWE-691`) — the top level of the
hierarchy, about as unrelated as two weaknesses in the same catalogue get. Both
passed the graph gate as valid, because validation checks that an id exists.
This is new open question 8: once the model stops copying, the error it makes is
"real but irrelevant", and existence checking cannot see it.

**3. First ATT&CK id ever proposed for a non-ATT&CK entry** — `T1195.001` for
`CAPEC-538` — but copied from that entry's own ATT&CK taxonomy mapping.

**4. Two `malformed_id`, neither a hallucinated ontology id.** `CVE-2024-34359`
for `CVE-2024-4897` is a CVE id that appears in the CVE's own text (question
6). `'Mitre mobile attack'` for `T1470` is the `"mitre-mobile-attack"`
kill-chain name copied from the entry and labelled structural; it was not
demoted to colloquial because `is_id_shaped()` treats anything *starting with*
"mitre" as an identifier attempt (`_ID_SHAPED` in `graph/normalize.py`). Same
class as question 3's known limitation — a small `malformed_id` overcount. Not
changed mid-experiment; noted under question 3.

**Redundancy** (headline rule): 55.6% -> 62.4% of accepted terms. Removing
identifiers from CWE/ATT&CK changed the denominators and n=10 per type is small;
treat as noise, not as the prompt making copying worse.

**⚠️ Live-file hazard.** `index.enrichment_path` is still `corpus.jsonl`, which
was written with `corpus-v1`. Running `enrich_corpus.py` without `--output` now
resumes into it under `corpus-v3` — two prompt versions in one file (question 2).
Always pass `--output` until question 2's guard exists. `indexes/enriched` is
still built from the v1 file.

### Stratified sample: 10 documents of each type
Command:
`.venv/bin/python scripts/enrich_corpus.py --per-kind 10 --output indexes/enrichment/corpus_stratified.jsonl`
(seed 42 from `eval.seed`, recorded in the manifest's new `sampling` field).
Result: **40 docs, 0 failed**, 411.5s (~10.3s/doc at concurrency 2). 437 terms:
225 accepted, 212 rejected — `too_common: 211`, `deprecated: 1`. Prompt
`corpus-v1`, gates unchanged since the 2026-08-20 fixes. Base index is the full
6,044 documents, so DF numbers are real.

**What was built for this** (all Module 1-internal, no contract change):
`sample_corpus()` in `index/corpus.py` (seeded random N per type; each type draws
from its own generator so dropping a type doesn't reshuffle the others);
`--per-kind` / `--seed` on `scripts/enrich_corpus.py`; a `sampling` field in the
enrichment manifest; `summarize_by_source()` printed at the end of every run; and
`scripts/measure_redundancy.py`, the question-7 measurement saved as a script. It
reproduces the logged v1 and v2 numbers exactly (80/131 with every per-kind cell
matching; 44/74). 160 -> 169 tests.

**By source document type:**

```
            docs  proposed  accepted   structural proposed    already in own text*
  cve         10       108        52   cwe 10                 48/52  (92%)
  capec       10       120        71   cwe 2, capec 1         42/71  (59%)
  attack      10       105        53   attack 4               25/53  (47%)
  cwe         10       104        49   cwe 5                  10/49  (20%)
                                                              ----------------
                                                              125/225 (55.6%)
  * headline rule from question 7 (literal id / contiguous tokens)
```

**Finding 1 — every structural proposal was a copy, on every document type.**
`measure_redundancy.py` now also classifies each structural proposal by where it
could have come from:

```
  cve     literal=10       CWE-79 etc. written in the CVE's own text
  cwe     own_id=5         CWE-1321 proposed for the CWE-1321 entry
  attack  own_id=4         T1437 proposed for the T1437 entry
  capec   bare_number=3    "@CWE_ID": "120" in the JSON -> proposed CWE-120
  not_found (i.e. a possible genuine inference): none
```

Replayed over the earlier runs: v1 19/19 literal; v2 6 literal plus **one**
not found anywhere — `CWE-125` for `CVE-2018-6484`, whose record cites no CWE at
all. That single case is the only candidate genuine inference in 48 structural
proposals, and whether it is the *right* CWE has not been checked.

The `own_id` case is invisible to the headline redundancy rule, because
`corpus_kb` text for CWE/CAPEC/ATT&CK entries holds the title but not the id —
the id reaches the model only through the prompt header
(`prompts/corpus_side.py`: `"Catalogue entry (cwe, id CWE-1321)"`). So question
7's 100%-of-structural figure was not a CVE quirk: it holds across all four
types, and the proposal's detection rule needed amending (done — see its
"Update after the stratified run" section).

**Finding 2 — the zero-ATT&CK result was not a sampling artifact.** ATT&CK ids
appear only on ATT&CK documents, and only as their own id. Nothing proposes an
ATT&CK technique for a CVE, CWE or CAPEC entry. It is also not missing
information: 3 of the 10 sampled CAPEC entries carry explicit ATT&CK taxonomy
mappings in their own text (`CAPEC-267` -> `"Entry_ID": "1027"`, `CAPEC-538` ->
`1195.001`, `CAPEC-654` -> `1056`, `1548.004`) and the model proposed none of
them, not even as copies. Whole corpus: 177 of 615 CAPEC entries carry such a
mapping. Documents with no structural proposal at all: cve 1/10, cwe 5/10,
attack 6/10, capec 7/10.

**Finding 3 — redundancy tracks how much text there is to copy.** CVE records
(median 1,390 chars, 9 of 10 cite a CWE in their text) are 92% redundant; CWE
entries (median 502 chars — `corpus_kb`'s CWE rows have no Description field)
are 20%. Do not read the overall 61% -> 56% change as the model improving: CVEs
alone went from 61% (the first 20 in file order, 2012–2018 records) to 92% (this
random 10, mostly 2024–2025). At 10–20 documents per cell these rates are not
yet stable — enough to see the pattern, not to quote a figure.

**Also:** one `deprecated` rejection is `T1470` proposing its own id — the
`corpus_kb` snapshot contains an entry ATT&CK v17.1 marks deprecated.
`too_common` is 211 of 212 rejections here; the `df_max_ratio` decision is still
open. `build_index.py --stage enriched` was **not** re-run: `indexes/enriched`
still reflects `corpus.jsonl` (v1, CVE-only), which is the live set.

### Question 7 sign-off request drafted
Wrote up the recommendation from the failed `corpus-v2` experiment (below) as
a formal decision request for all four module owners:
`docs/proposals/already-in-document-gate.md`. Covers: the exact
`RejectReason` value being proposed (`already_in_document`), where the new
gate would run in `corpus_side.py`'s pipeline (before the DF filter, flagged
as itself part of the decision), the detection rule (same contiguous-token
match used for the 61.1%/100% measurement, not a looser set check), and a
"what this changes for you" section per module — Module 2 almost certainly
doesn't need the gate logic itself (no source document to compare against on
the query side) but does need to know the enum value exists; Module 3 sees
fewer/more-genuinely-new expansion terms with no code change required; Module
4 gets a seventh `RejectReason` bucket, automatically counted by
`rejection_rate()` but worth checking against anything that special-cases the
current six by name.

No code changed. `schemas.py` is untouched pending the actual sign-off.

### Prompt iteration against question 7 — NEGATIVE RESULT, reverted
Tried `corpus-v2`, a much more forceful version of the "do not restate the
entry's own words" instruction, run against the same 20 documents as the v1
baseline. **It did not work and was reverted.**

```
                                   v1        v2
  terms proposed                  223       148
  accepted                        131        74
  redundant share of accepted   61.1%     59.5%   <- target metric: unmoved
  GENUINELY NEW terms indexed      51        30   <- 41% worse
  structural accepted               17         3
  malformed_id                       1         3
  completion tokens               3935      2586
```

The copying rate barely moved while total useful output fell by nearly half. The
model read the added "fewer is better than restated" line as "propose less"
rather than "propose better" — it complied with the letter and not the intent.
Since v1 already carried the instruction and v2 made it about as forceful as a
prompt can be, that is two rounds of evidence that **prompting is not the lever
for question 7**. Its recommendation flips to option 1, an enforced
`already_in_document` gate, which needs four-owner sign-off for a new
`RejectReason`.

Full experiment record, including the exact v2 prompt text so nobody rewrites
it from scratch: `docs/experiments/prompt-corpus-v2.md`.

**Side finding worth keeping.** v2's extra `malformed_id` cases were all shaped
`'CWE-331: Use of Inadequate Randomness'` — identifier plus its title. Unlike the
original five mislabels, these **are** normalizer-recoverable: `parse_structural_id`
returns `None` but the existing `extract_structural_ids` recovers `CWE-331`
correctly. If a future prompt ever encourages descriptive identifier forms, the
adjudicator should fall back to `extract_structural_ids` when
`parse_structural_id` fails on an ID-shaped term.

**Kept from this work even though the prompt was reverted:** the two tests that
hardcoded `"corpus-v1"` now compare against the `PROMPT_VERSION` constant
instead. They exist to check the manifest *records* the version, not what the
version is, and would have broken on every future prompt change.

**Latent bug spotted, not yet fixed:** `scripts/enrich_corpus.py` writes the
manifest's `prompt_version` from the *config* key `enrichment.corpus_prompt_version`,
not from `prompts/corpus_side.py:PROMPT_VERSION`. Change the prompt without
editing the config and the manifest silently records the wrong version — the same
provenance-contamination class as question 2. A comment now ties them together in
`configs/default.yaml`, but the real fix is to read the constant.

**Data:** v2's output is kept at `indexes/enrichment/corpus_v2.jsonl` as the
experiment's evidence. `indexes/enrichment/corpus.jsonl` (v1) remains the live
enrichment set and `indexes/enriched` is still built from it — unchanged and
still correct.


### Regenerated the corpus under the fixed gates — and found a bigger problem
Command: `.venv/bin/python scripts/enrich_corpus.py --limit 20` (fresh, not a
resume; old file archived as `corpus.jsonl.pre-gatefix`).
Result: **20 docs, 0 failed**, 251.6s (~12.6s/doc at concurrency 2; 24.6s/doc of
model time). 223 terms: **131 accepted (58.7%)**, 92 rejected —
`too_common: 90`, `deprecated: 1`, `malformed_id: 1`.
Enriched index then built: `indexes/enriched`, 6,044 docs.

**The gate fixes hold at scale.** 10 distinct CWE identifiers accepted at their
real document frequencies (4 to 108), where every one of them would have been
rejected before. `malformed_id` fell from 5-in-5-docs to 1-in-20-docs, and the
one remaining is `CVE-2018-6542` — a CVE identifier, i.e. exactly the case
question 6 was opened for, not a hallucination. **Qwen2.5-7B has still fabricated
zero ontology identifiers across 25 documents.**

**Verified the enriched index really works:** `CWE-331` searched against the
`expansion` field returns CVE-2012-4687 and four other enriched CVEs, a different
and better result set than the base index's contents-only match. Note
`LuceneSearcher.search()` queries `contents` only by default — to see expansion
terms you must pass `fields={EXPANSION_FIELD: 1.0}`. Forgetting that makes a
working enriched index look empty.

**The serious finding — question 7.** 80 of 131 accepted terms (61.1%) already
appear verbatim in their document's own text, including **17 of 17 structural
identifiers (100%)**. Those terms are already indexed and already retrievable;
injecting them adds nothing. CTIConnect CVE records embed their CWE mapping, so
the model is reading the identifier off the page and handing it back, and the
graph then validates a transcription rather than an inference. The prompt already
forbids this and is being ignored, with nothing enforcing it. Full analysis,
measurement method and options in `04_OPEN_QUESTIONS.md` question 7.

**Two more from the same run:**
- **Zero ATT&CK and zero CAPEC proposals** across 20 documents — all 19
  structural proposals were CWE (18) plus one CVE, and structural terms were only
  8.5% of all proposals. The mechanism under test is barely exercised.
- **The sample was 100% CVE documents.** `--limit N` takes the first N in load
  order and those are all CVEs. No conclusion about CWE/CAPEC/ATT&CK source
  documents can be drawn from this run. Cross-catalogue RQ1 work needs a
  stratified sample.

**`df_max_ratio` sensitivity** (now measurable, since the CWE artifact is gone —
90 `too_common` rejections against the 6,044-doc base index):

```
  0.10 (current) -> 131/223 accepted (58.7%)
  0.15           -> 153/223 (68.6%)
  0.25           -> 163/223 (73.1%)
  0.30           -> 179/223 (80.3%)
```

The far end looks correctly rejected: `remote attacker` / `network attack` /
`man-in-the-middle attack` all sit at 0.660. The borderline is arguable —
`denial of service` (0.141) is a real CTI search term that 0.10 cuts and 0.15
keeps. Not yet a decision; it should be tuned against retrieval metrics by
Module 3/4, not eyeballed here.

**Known gap in the kind-routing fix:** a demoted term is written to the JSONL as
`colloquial` with no trace that the model originally said `structural`, and
`CallRecord` (`common/llm.py`) stores no prompt or reply text. **The kind-mislabel
rate is therefore not measurable after the fact.** If prompt-iterating against it
matters, it needs a runtime counter on `EnrichmentRunSummary` (Module 1's own
dataclass, not the frozen contract) or a sidecar log next to the JSONL.


### Gate fixes: structural kind routing + structural DF (open questions 1 and 3)
Both found by inspecting the first real run's output. Neither was visible from
the code alone — the run's numbers are what exposed them.

**Question 3 — the 5 `malformed_id` rejections.** They were neither genuine
hallucinations nor normalizer-fixable format variants (the two options the
question posed). They were `heap-based` (x2), `zzip_get32`, `local` and `medium`
— ordinary vocabulary the model tagged `kind="structural"`. The normalizer was
right to refuse them; the model just filled in the wrong field. Because the
rejection log is the RQ4 dataset, this was booking a schema slip as an identifier
hallucination: **true hallucination count for that run was 0, the log said 5.**
Fix: new `is_id_shaped()` in `graph/normalize.py` + `_route_kind()` in
`corpus_side.py` demote a mislabelled `structural` to `colloquial`, while a term
that genuinely reached for an identifier and missed (`CWE-abc`, `T99`) still
records `MALFORMED_ID`. Routing only ever demotes, never promotes.

**Question 1 — DF for multi-token structural ids.** Measured on the real base
index (6,044 docs, `df_max_ratio` 0.10): the gate took the *most common* token of
a multi-token term, so every `CWE-*` scored DF(`cwe`) = 2974/6044 = **0.492** —
the same number for all of them, ~5x the threshold. **Every CWE identifier was
rejected unconditionally regardless of which CWE it was**, including ones whose
number appears in 6 documents; one-token `T1110.001` scored 0 and passed
unconditionally. Not tunable — 0.492 is a constant. Fix: `doc_freq` takes an
explicit `combine` argument; structural ids use `"min"` (the number carries the
identity, the prefix is a catalogue-wide constant), everything else keeps
`"max"`. The gate still rejects a genuinely common identifier — this is a
correction, not an exemption.

**Measured effect.** Replaying the recorded proposals through the new gates with
no new LLM calls, so only gate logic differs:

```
                  BEFORE -> AFTER
      ACCEPTED:      28  ->  35
    deprecated:       1  ->   1
  malformed_id:       5  ->   0
    too_common:      24  ->  22
```

11 terms changed verdict. All 5 CWE ids flipped `too_common` -> accepted at their
true DFs (7, 6, 6, 41, 108, 92). `zzip_get32` flipped `malformed_id` -> accepted
at DF 0 — a real zziplib symbol, maximally discriminative. `heap-based`, `local`
and `medium` flipped `malformed_id` -> `too_common`: still rejected, but now for
the true reason.

**Tests:** 145 -> 160, all still offline/StubClient. Includes a regression test
pinning the analyzer's actual tokenization (`CWE-307` -> two tokens, `T1110.001`
-> one), so a Lucene upgrade that changes it fails loudly instead of silently
skewing RQ1.

**Opened as a side effect:** question 6 — whether a CVE identifier should count
as structural. Left at the conservative default, not decided.

**Not changed:** the frozen `EnrichmentRecord` contract. Both fixes were designed
to avoid a schema sign-off round.


### First real Ollama run — `--limit 5`
Command: `.venv/bin/python scripts/enrich_corpus.py --limit 5`
Result: 5 docs, 0 already done, 5 processed, **0 failed**, 88.2s (~17.6s/doc).
Accept/reject (cumulative): accepted 28, rejected 30 — of which
`too_common: 24`, `malformed_id: 5`, `deprecated: 1`; repaired 0;
staleness_rate 0.000.

Reading of this run:
- **0 failed** is the important success — no `MalformedReplyError`, real replies
  parse at the record level. First time the OllamaClient path has actually
  executed (all prior testing was StubClient).
- **`malformed_id: 5`** — needs eyeballing. Determine whether these are genuine
  garbage IDs or valid-but-slightly-misformatted IDs the normalizer should have
  caught pre-validation. If the latter → normalizer bug, not a model problem.
- **`too_common: 24`** — NOT meaningful yet. DF pool is only ~5 docs, so almost
  everything reads as common. Re-derive `df_max_ratio` against a real-sized index.
- Numbers here supersede the earlier stubbed 4-accept/5-reject demo figure, which
  was never meaningful.

### Environment brought up
- venv confirmed clean (python.org 3.13, not conda). conda PATH trap documented
  in `01_ENVIRONMENT.md`; workaround = always call `.venv/bin/python` explicitly.
- Base index built successfully: `indexes/base`.
- Enriched-index step correctly errors until enrichment JSONL exists (ordering
  guard working as designed).

### Prior state (from Module 1 build handoff)
- Branch `module-1/corpus-enrichment`, 145 tests passing, all offline.
- Full detail in `02_MODULE1_STATE.md`.

---

## Next actions (living checklist)

- [x] Inspect the 5 `malformed_id` rejections. — Neither genuine nor
      normalizer-fixable: kind-mislabelling. Fixed.
- [x] Resolve the multi-token DF question. — Structural ids judged on their
      rarest token. `04_OPEN_QUESTIONS.md` q1.
- [x] Regenerate the enrichment JSONL under the fixed gates. — Done, 20 docs,
      old run archived as `corpus.jsonl.pre-gatefix`.
- [x] Build the enriched index. — Done, `indexes/enriched`, expansion-field
      retrieval verified.
- [x] Question 7, attempt 1: prompt iteration. — **Failed.** Redundancy 61.1% ->
      59.5% while genuinely-new terms fell 51 -> 30. Reverted to `corpus-v1`.
      See `docs/experiments/prompt-corpus-v2.md`.
- [ ] **Question 7 — get four-owner sign-off for an `already_in_document`
      `RejectReason`, then build the gate.** Highest priority; it undercuts RQ1
      more than either gate bug did, and prompting has been ruled out.
      **Sign-off request drafted 2026-09-15:**
      `docs/proposals/already-in-document-gate.md` — **Module 1 approved
      2026-09-15** (check 2 limited to labelled id fields); waiting on Module
      2/3/4 owners before Module 1 implements the gate.
- [x] Fix `scripts/enrich_corpus.py` to read `PROMPT_VERSION` from the prompt
      module rather than from config. — Done 2026-09-15, alongside `corpus-v3`
      (changing the version is exactly when the old way would have recorded the
      wrong one). The `enrichment.corpus_prompt_version` config key is removed.
- [x] **Stratify the corpus sample.** — Done 2026-09-15: `--per-kind`, 10 of
      each type, `corpus_stratified.jsonl`. See that log entry.
- [ ] Investigate why the model proposes **no ATT&CK or CAPEC identifiers**. —
      **Narrowed 2026-09-15:** not the sample (it holds across all four types)
      and not missing information (3/10 CAPEC entries carry ATT&CK mappings it
      ignores). What remains open is prompt vs. model. Evidence so far leans
      model: the reverted v2 prompt asked explicitly for the related ATT&CK
      technique / CAPEC pattern and got 7 ids back, all CWE. But v2 also
      suppressed output overall, so it is not a clean test. Next step that
      stays inside the model policy: re-run the same stratified sample with a
      larger open-weight model (e.g. `qwen2.5:14b`) to see whether the links
      appear with scale. A frontier model would answer it faster but is reserved
      for the final run (`01_ENVIRONMENT.md`), so using one here is a team call.
- [x] Decide whether the prompt header should keep giving the model the
      document's own id. — **Decided 2026-09-15 (Module 1): no.** Removed in
      prompt `corpus-v3`; whether entries are searchable by their own id is
      handed to Module 3 (next item). Reasoning in the proposal. Confirmed by
      re-running the 40-document sample: own-id copies 9 -> 0.
- [x] **Question 8, first half — the name-ID consistency check.** Done
      2026-10-07. The model must state what each id *is*; the graph checks that
      against MITRE's title. 14B structural acceptance 109/125 (87%) ->
      56/157 (36%); accepted counting-run ids 33/38 -> 7/51. `graph_distance`
      and `in_counting_run` recorded per proposal, neither gated —
      `docs/proposals/name-id-consistency.md`.
- [ ] **Question 8, second half — relevance, not just identity.** Still open
      and now the top research item. The name check cannot catch `CWE-79` with
      its *correct* title proposed for a spyware entry. The number to take to
      the supervisor: **33 of 69 name-mismatch rejections are within 2 hops of
      the document**, so the check discards structurally plausible ids — a loss
      for recall, not a loss for a grounding claim, and which framing the
      project uses is a supervisor call. A distance gate is **not** the answer:
      `CAPEC-24 -> CWE-118/119/120` is three consecutive numbers (counting-run
      flag) at one hop (genuine mapping), and MITRE numbered related weaknesses
      sequentially, so the two signals are correlated. Counting run **and**
      distance >= 3 is the enumeration signature.
- [x] **Name scorer v2 + CWE short-name loader.** Done 2026-10-08, rescored
      offline. Catches all three within-family escapes it can reach; falls back
      to v1 for 90 of 125 verdicts on the 14B because most nodes have no short
      name. v3 (symmetric everywhere) exists as experimental.
- [x] **Repair measurement.** Done 2026-10-08: 9 of 33 near mismatches repair
      cleanly. `enrichment.index_repaired_ids` off by default.
- [ ] **Frontier model on the 40-document sample — approved, blocked on a
      provider and API key.** Then: backend subclass, cost estimate, $1 cap.
- [ ] **Freeze blockers** (`docs/proposals/module1-freeze.md`): context
      overflow (question 12), explicit seed to Ollama, schema 1.3.0 sign-off,
      model choice. Then the full-corpus run with `--concurrency 1`.
- [ ] Tell Modules 3/4 about question 11 (same decoding setup for the
      multi-round baseline; sample-run latencies are unusable).
- [x] ~~**Name check, next iteration (measured, not yet built).**~~ Built — see above. Original note: It catches
      cross-family confusions and misses within-family neighbours: `CWE-74`
      claimed with CWE-89's title scores 0.67 and passes, because CWE-78's and
      CWE-89's real titles score 0.83 against *each other*. Two fixes tested
      offline against the saved records, no model calls needed: IDF-weighting
      the title words changes **zero** verdicts; the **parenthesised short name
      with a symmetric score** gives 0.50/0.25 for the two escapes and 1.00 for
      a correct answer. That needs a *loader* change — `node.aliases` is empty
      for every CWE, so the short names and `Alternate_Terms` are never loaded.
      Do the loader change, re-score the saved runs offline to confirm, then
      decide about re-running.
- [ ] **Get four-owner sign-off for schema 1.3.0** (was 1.2.0; amended) —
      `docs/proposals/name-id-consistency.md`. Two new `RejectReason` values,
      `RejectStage`, five optional `ProposedTerm` fields. All additive and a
      1.1.0 record still loads, but new enum values reach Module 4's switch.
      Bundle with the question-7 proposal, which is also still waiting.
- [x] **Run the same 40 documents with `qwen2.5:14b`.** — Done 2026-10-07,
      `corpus_stratified_v3_14b.jsonl`. "Prompt or model" = model. See that log
      entry; it reframed question 8.
- [x] **A deterministically malformed reply can never be resumed past.** Fixed
      2026-10-07 three ways: schema-constrained decoding (which was the actual
      cure — `CAPEC-587` now completes on both models), a nudged retry, and
      `reject_reason=llm_json_error` as the backstop so a resume can reach "all
      done". Diagnosed first: it was **not** truncation. `04_OPEN_QUESTIONS.md`
      q9. Note plain `format: "json"` is the wrong fix and looks like the right
      one — it makes qwen2.5:14b answer with a single object.
- [x] `enrichment.max_new_tokens: 512` was dead config. Fixed 2026-10-07 — it
      reaches Ollama as `options.num_predict` through the wrapper, and
      `StubClient.option_calls` lets a test prove it got there.
- [x] ~~Decide whether schema decoding is worth 3x the run time.~~ **Moot,
      2026-10-08:** it is not 3x. Measured cleanly: 1.5x on the 7B, no difference
      on the 14B. Keep it on.
- [ ] **Third model (`04_OPEN_QUESTIONS.md` q10).** A 32B will not fit in 16 GiB
      (~20 GB of weights at 4-bit). Needs the frontier API: ~$0.25 for the
      40-document sample, ~$9-35 for the full corpus, from measured token
      counts. Module 1 recommends spending it on the sample; it breaks the
      open-weight-only development policy, so it is a team call.
- [ ] **Before the next default-path run:** `index.enrichment_path` still points
      at the `corpus-v1` file `corpus.jsonl`. Either implement question 2's
      version guard, or always pass `--output`.
- [ ] **Flag to Module 3:** a CWE/CAPEC/ATT&CK entry's own id is not in its
      indexed `contents` (title + JSON body only, the same as CTIConnect's own
      baselines). Measured on `indexes/base`: `CWE-1321` and `CWE-378` do not
      return their own entry in the top 1,000; `T1437` returns zero hits;
      `CAPEC-14` finds itself at rank 306. Included in the proposal's Module 3
      section so it reaches Student 3 either way.
- [ ] Decide `df_max_ratio` against retrieval metrics, not by eye. Sensitivity
      table is in the log entry above.
- [ ] Make the kind-mislabel rate observable (runtime counter or sidecar log).
- [ ] Fix prompt-versioning-vs-resume composition (`04_OPEN_QUESTIONS.md` q2).
- [ ] Decide `04_OPEN_QUESTIONS.md` q6 (CVE identifiers as structural) — still
      live: `CVE-2024-34359` was proposed as structural in the 7B v4 run.
- [ ] **New RQ4 surface worth mining: a `malformed_id` with a *correct* name.**
      Two of the three 7B `malformed_id` rejections carry a real title —
      `"Supply Chain Compromise: Software Dependencies and Development Tools"`
      is a genuine ATT&CK technique name attached to the garbage id
      `"att&ck supply chain"`. The model knew the concept and botched the
      identifier. `OntologyGraph`'s name index could repair these rather than
      reject them; `graph.resolve(name)` already does exact-name lookup. That
      is a different failure from a hallucination and is currently booked as
      the same thing.
- [x] ~~(Low priority) `build_base.py` subprocess should use `sys.executable`.~~
      — **Not a bug, corrected 2026-09-15:** `build_base.py` has invoked the
      indexer as `sys.executable -m pyserini.index.lucene` since its first commit
      (`988709b`). The conda Python seen earlier must have come from launching the
      script itself with a bare `python`, which the `.venv/bin/python` rule in
      `01_ENVIRONMENT.md` already covers.
