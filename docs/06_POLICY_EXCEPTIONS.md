# Policy Exception Log

> The project rule (README, "model policy"): **day-to-day development uses
> free, local, open-weight models. A paid frontier model is reserved for the
> final benchmark run.** That rule exists to control cost and to keep results
> reproducible on our own machines.
>
> Sometimes there is a good reason to break it once. When that happens it is
> written down here **before the run**, with who approved it, why, the spending
> limit, and what was actually spent. Newest entry at the top.

---

## Not an exception: Stage 1 on Kaggle's free GPUs (noted 2026-10-13)

Running the Stage 1 enrichment on Kaggle is **inside** the policy, so it has
no entry below. It is the same free, open-weight model as on the Mac
(`qwen2.5:14b`; the weights are checked by their fingerprint, digest
`7cdf5a0187d5…`, and the run refuses to continue on any other), with the same
prompt, seed and settings. Only the computer is borrowed. Cost: $0. No paid
API is called. What is uploaded to Kaggle (as a private dataset) is public
MITRE / NVD content and CTIConnect's CC-BY-4.0 `corpus_kb`. How to run it:
`kaggle-run.md`. Whether a borrowed GPU gives the same replies as the Mac is
measured, not assumed — the 40-document comparison described there.

---

## Decision: what the frontier model is for (2026-11-14)

**`qwen2.5:14b` stays the project's main model.** The index built with it
(Stage 1, `indexes/enriched/`) is the one Modules 2–4 build on and report.

**Gemini is used for a *robustness* index**, not a replacement: the same
pipeline, gates and settings, with only the model changed, so the write-up
can show whether the findings hold when a much stronger model writes the
proposals. "Robustness" here means: do the conclusions survive a change of
model? It is a check on the main result, not the main result.

This replaces the wording in `proposals/module1-freeze.md` (written
2026-10-08) that called the Gemini index the "final index … the one the
results are reported on". Decided by the Module 1 owner.

**How the robustness index is reported — confirmed by the Module 1 owner,
2026-11-14** (evidence: two Vertex samples, `04_OPEN_QUESTIONS.md` q15):

1. **Agreement figure: about 60%.** Gemini's run-to-run agreement on
   accepted ids is quoted as **~60% (Vertex, two same-day runs)**, not the
   80% measured on AI Studio in October. The 80% may be mentioned only as
   the AI Studio figure, labelled as such.
2. **Robustness is reported as aggregate behaviour.** The robustness index
   is compared with the main (`qwen2.5:14b`) index on validity (share of ids
   accepted), wrong names, non-existent/retired ids, counting runs and graph
   distance — where all four Gemini runs agree. The write-up does not claim
   that any particular id would reappear in another Gemini run.
3. **Vertex only.** The full Gemini index is compared only with the Vertex
   samples (`…_vertex.jsonl`, `…_vertex2.jsonl`). The October AI Studio runs
   stay on record as history, not as a reference point for the robustness
   index.

The money now comes from a **Google Cloud trial-credit account through
Vertex AI** (shown in the Cloud Console as "Agent Platform API"), not the
AI Studio key. Same model id, same request; the route is recorded in every
manifest (`llm.api`, `llm.vertex.project_id`, `llm.vertex.location`). Sign-in
is by application-default credentials (`gcloud auth application-default
login`); no key or service account is used. **The AI Studio key's prepaid
credits are used up** (402 "prepayment credits are depleted", seen
2026-11-14), so that route cannot run without a top-up.

---

## Exception 6 — Vertex batch mode: 5-document test and 40-document sample (2026-11-14, evening)

| | |
|---|---|
| **What** | (a) 5 documents (CVE-2024-4897, CVE-2024-56180, CWE-1321, CAPEC-587, T1048.003) and (b) the 40-document stratified sample, as Vertex AI **batch** jobs with the frozen settings (`corpus-v4`, `sections-v2`, schema 1.5.0, temperature 0, seed 42, low thinking) |
| **Requested by** | Module 1 owner, 2026-11-14 |
| **Why** | Batch is half price; before relying on it for the robustness run, show the schema and thinking settings are honoured and the output looks like the online Vertex runs |
| **Provider / model** | Google Cloud Vertex AI batch prediction, `global`, `gemini-3.1-pro-preview`; input and output in a new private bucket `gs://<project>-sira-batch` (us-central1, public access prevented) |
| **Spending caps** | US$0.25 (5 docs), US$0.50 (40 docs); checked before each submission |
| **Spent** | **≈ US$0.27** at batch list price ($1 / $6): 5 docs $0.029 (4,652 prompt, 1,071 reply, 3,024 thinking tokens); 40 docs $0.240 (40,182 prompt, 7,921 reply, 25,400 thinking). Plus Cloud Storage for a few hundred KB (negligible). **To check on the bill:** result lines say `trafficType: "ON_DEMAND"`; ≈ $0.54 would mean the online rate was charged |
| **Output** | `indexes/enrichment/corpus_ids5_v4_gemini-3.1-pro_vertexbatch.jsonl` and `corpus_stratified_v4_gemini-3.1-pro_vertexbatch.jsonl`, each with manifest and `.batch/` folder (git-ignored); comparison: `results/vertex_batch_vs_online_gemini.txt` |
| **Result** | Every reply a full array, `LOW` thinking echoed, $0.0060 per document (online $0.0117–0.0122); shares 68% / 55% of accepted ids with the two online Vertex runs — another Vertex run. `03_STATUS_LOG.md`, 2026-11-14 evening |
| **Data sent** | Public MITRE / NVD content only |

---

## Exception 5 — second Vertex sample, for open question 15 (2026-11-14, later)

| | |
|---|---|
| **What** | The 40-document sample through Vertex again, identical command and settings to exception 3's sample |
| **Approved by** | Module 1 owner, 2026-11-14 |
| **Why** | The first Vertex sample shared only half its ids with the October AI Studio runs; a repeat on the same route shows how much of that is Vertex's own run-to-run variation |
| **Spending cap** | US$1.00 |
| **Spent** | **≈ US$0.51** — $0.487 for 40 documents (40,182 prompt, 8,919 reply, 25,006 thinking tokens) + $0.026 preflight |
| **Output** | `indexes/enrichment/corpus_stratified_v4_gemini-3.1-pro_vertex2.jsonl` + manifest (git-ignored); added to `results/vertex_sample_vs_aistudio_gemini.txt` |
| **Result** | Vertex shares 60% of accepted ids with itself (AI Studio: 80%); aggregate behaviour unchanged. `04_OPEN_QUESTIONS.md` q15 |
| **Data sent** | Public MITRE / NVD content only |

---

## Exception 7 — the 117 fixed CVE documents on Vertex, batch mode, twice (APPROVED 2026-11-16; not started)

| | |
|---|---|
| **What** | The 117 CVE documents filled by the corpus fix (open question 16), `gemini-3.1-pro-preview`, low thinking, same frozen settings and flags as exception 4 (`--batch`, `--name-scorer v2`), once for each of the two robustness runs, selected with `--doc-ids`. Then spliced into the two full runs with `scripts/splice_enrichment.py` |
| **Approved by** | Module 1 owner, 2026-11-16 (chose "Splice: redo only 117", which includes this spend). Team approval: the team decided the corpus fix on 2026-11-15 |
| **Purpose** | Keep the robustness index complete on the fixed corpus without re-running all 6,044 documents (≈ $70 more) |
| **Estimated cost** | ≈ $0.70 per run, ≈ **$1.40** both: the fixed documents are longer than average (median 929 characters of description), so ≈ $0.0060 per document as measured is a floor; the pre-submit estimate will be higher |
| **Cap set** | `--cost-cap-usd 2` per run (the cautious pre-submit estimate must fit under it) |
| **Spent** | not yet |
| **Data sent** | Public CVE List / NVD content only |

---

## Exception 4 — the whole corpus on Vertex, batch mode, twice (APPROVED 2026-11-15; DONE 2026-11-15)

| | |
|---|---|
| **What** | All 6,044 documents, `gemini-3.1-pro-preview`, low thinking, same frozen settings as the Vertex sample, as **two independent Vertex batch runs** (`--batch`, `--name-scorer v2`, kinds cwe,capec,attack,cve). Start command and checklist: `proposals/module1-freeze.md`, "Stage 2 (Gemini, Vertex)" |
| **Approved by** | Module 1 owner, 2026-11-15 ("Do the two batch runs"). Team approval: not recorded here |
| **Started** | 2026-11-15, from commit `46e9f27` (clean, pushed). Model probe passed the same day; 527 tests pass; trial credit ₹28,452 of ₹28,569 left |
| **Outputs** | `indexes/enrichment/corpus_full_v4_gemini-3.1-pro_vertexbatch.jsonl` and `…_vertexbatch2.jsonl` (+ manifests, `.batch/` folders; git-ignored). Jobs `batchPredictionJobs/4267156661203894272` and `…/8875464979910754304` (which job belongs to which file: each `.batch/state.json`) |
| **Requests** | 6,039 per run, not 6,044: five pairs of ATT&CK entries have identical text in the corpus (T1583.005/T1584.005, T1583.007/T1584.007, T1585.002/T1586.002, T1585.003/T1586.003, T1618/T1628.002), so they make identical prompts and share one request and one reply. Stage 1 gave each pair identical proposals too. Both documents' records carry the tokens, so summing records over-counts the bill by 5 calls (~$0.03); the billed total is `llm.batch.billed_usd` in the manifest |
| **Purpose** | The robustness index (above) |
| **Estimated cost** | ≈ **$68** standard (≈ $79 with 15% margin); ≈ **$35** with batch, built and tested 2026-11-14 (≈ $40 with margin; ≈ $70 / $81 for two runs). From the Vertex samples' measured tokens, thinking included |
| **Estimated time** | online ≈ 19 hours one document at a time (11.3 s each, measured); batch: one job, Google says most finish within 24 h of starting (plus up to 72 h queue); the 40-doc job took under 5 minutes |
| **Cap set** | `--cost-cap-usd 55` per run (pre-submit estimate $50.55 each, checked before submitting). Expected ≈ $35 each, ≈ $70 both |
| **Finished** | Both jobs SUCCEEDED, 6,039 of 6,039 requests each, 0 failed. Running time 20 h 07 min (`…/8875464979910754304`, `…_vertexbatch.jsonl`) and 19 h 59 min (`…/4267156661203894272`, `…_vertexbatch2.jsonl`), queue ≈ 1.5 min each. Results processed 2026-11-15 21:53 UTC from commit `7534173` (the poll-retry fix; the waiting commands had crashed on a timeout, the jobs had not) |
| **Spent** | **≈ US$69.70** at the batch list price, from the billed result lines: run 1 **$34.912** (5,951,937 prompt, 1,142,219 reply, 3,684,522 thinking tokens), run 2 **$34.791** (5,951,937 / 1,145,801 / 3,660,732). $0.0058 per document. **Actual charge confirmed at the batch rate:** the console read **₹6,781 used of ₹28,569** on 2026-11-16 (Module 1 owner), up ₹6,664 from ₹117. Expected at the batch rate: ≈ ₹6,636 for these two runs + ≈ ₹26 for exception 6 = ≈ ₹6,662. The online rate would have been ≈ ₹13,300 |
| **Data sent** | Public MITRE / NVD content and CTIConnect's CC-BY-4.0 corpus only |

---

## Exception 3 — Gemini through Vertex AI: model check and 40-document sample (2026-11-14)

| | |
|---|---|
| **What** | (a) List the models the Cloud project can use and check `gemini-3.1-pro-preview` gives JSON-schema replies on Vertex; (b) the 40-document stratified sample through Vertex with the frozen settings (`corpus-v4`, `sections-v2` truncation, schema 1.5.0, temperature 0, seed 42, low thinking); (c) a real interrupt-and-resume test on 4 documents |
| **Approved by** | Module 1 owner, 2026-11-14 |
| **Why** | Moving the Gemini run onto Google Cloud trial credits. Before trusting the new route for a $70 run, show it behaves like the two AI Studio runs on the same 40 documents |
| **Provider / model** | Google Cloud Vertex AI, `global` location, model id `gemini-3.1-pro-preview` (still listed, same id; Public preview, released 2026-02-19); `google-genai` 2.29.0; application-default credentials |
| **Spending cap** | **US$2.00** for the sample |
| **Spent** | **≈ US$0.72** at list price, all on the Cloud project: sample $0.493 ($0.468 for 40 documents — 40,182 prompt, 8,345 reply, 23,993 thinking tokens — plus $0.025 preflight); two resume tests $0.20; model and schema-token probes ≈ $0.025. Token counting is free. The actual charge appears in the Cloud billing console about a day later |
| **Output** | `indexes/enrichment/corpus_stratified_v4_gemini-3.1-pro_vertex.jsonl` + manifest (git-ignored); comparison: `results/vertex_sample_vs_aistudio_gemini.txt` |
| **Result** | Same *kind* of output as October (near-perfect validity, no counting runs) but a **different set of ids**: only 50–51% of accepted ids shared with either AI Studio run, against 80% between the two AI Studio runs. `03_STATUS_LOG.md`, 2026-11-14 |
| **Data sent** | Public MITRE / NVD content only |

---

## Running total

| exception | spent (our calculation from list prices) |
|---|---|
| 1 — first 40-document run and its checks | ≈ $0.57 |
| 2 — repeat run | ≈ $0.46 |
| 3 — Vertex model check, sample and resume tests (Cloud trial credits) | ≈ $0.72 |
| 5 — second Vertex sample (Cloud trial credits) | ≈ $0.51 |
| 6 — Vertex batch tests, 5 + 40 documents (Cloud trial credits) | ≈ $0.27 |
| 4 — whole corpus, Vertex batch, twice (Cloud trial credits) | ≈ $69.70 |
| **total, calculated** | **≈ $72.23** |
| **total, actually charged (exceptions 1–2, AI Studio key)** | **₹116.66** |
| **actually charged (exceptions 3–6, Cloud project)** | **₹6,781 used of ₹28,569 trial credit** (read 2026-11-16; ₹21,788 left). Matches the calculation at the batch rate: ≈ $71.2 × ₹95.2 ≈ ₹6,780. Earlier reading: **₹117 used of ₹28,569 trial credit** (read 2026-11-15 by the Module 1 owner; ₹28,452 left). At the credit's implied ₹95.2 per $ (if the trial is $300) that is ≈ $1.23 — exactly exceptions 3 + 5, so exception 6's batch tests (≈ $0.27 ≈ ₹26 at batch rate, ≈ ₹51 at online rate) had probably not posted yet. Re-read in a day: ≈ ₹143 total means batch was billed at the batch rate |

**Confirmed by the key owner on 2026-10-08: the key is on the paid tier, and
the actual charge for both exceptions together was ₹116.66.** The bill is in
rupees and our calculation is in US dollars at list price before any tax or
currency conversion, so the two are not expected to match to the paisa; the
rupee figure is the one that counts. Each exception stayed under its own
US$1.00 cap by our calculation.

**Paid tier means Google does not use what we sent to improve its products**
(Google's pricing page: paid-tier content is "not used to improve our
products"). What was sent was public MITRE / NVD content in any case.

---

## Exception 2 — repeat of the Gemini run, for repeatability (2026-10-08)

| | |
|---|---|
| **What** | The same 40 documents again, identical settings (`gemini-3.1-pro-preview`, low thinking, temperature 0, seed 42, prompt `corpus-v4`) |
| **Approved by** | Module 1 owner, 2026-10-08 |
| **Why** | The seed is not honoured, so one run could not say how much of the result is luck |
| **Spending cap** | US$1.00 for this run |
| **Spent** | **≈ US$0.46** — $0.432 for the 40 documents (35,915 prompt, 6,752 reply, 23,259 thinking tokens) + $0.025 for the two-call check |
| **Output** | `indexes/enrichment/corpus_stratified_v4_gemini-3.1-pro_run2.jsonl` + manifest |
| **Result** | 80% of accepted ids the same across the two runs; rejection counts identical. `03_STATUS_LOG.md` |
| **Data sent** | Public MITRE / NVD content only, as in exception 1. Paid tier |

---

## Exception 1 — Gemini 3.1 Pro on the 40-document sample (2026-10-08)

| | |
|---|---|
| **What** | Corpus-side enrichment of the 40-document stratified sample (10 each of CVE, CWE, CAPEC, ATT&CK; sampling seed 42), prompt `corpus-v4` — the same documents and prompt as the two local runs |
| **Approved by** | Module 1 owner, 2026-10-08 |
| **Why** | Open question 10: we had two model sizes (7B, 14B) that disagreed. A third, stronger model was needed to tell a trend from a quirk, and a 32B model does not fit on the 16 GiB development machine |
| **Provider / model** | Google Gemini API, model id **`gemini-3.1-pro-preview`** (the newest Pro model the key could list on the day; a pinned id, not the `gemini-pro-latest` alias) |
| **SDK** | `google-genai` 2.29.0, JSON-schema-constrained output (`response_json_schema`) |
| **Spending cap** | **US$1.00**, hard |
| **Spent** | **≈ US$0.57** by our calculation (actual charge for exceptions 1 and 2 together: ₹116.66) at list price (US$2.00 per million prompt tokens, US$12.00 per million output tokens, thinking billed as output). See the breakdown below |
| **Output** | `indexes/enrichment/corpus_stratified_v4_gemini-3.1-pro.jsonl` + its `.manifest.json` |
| **Result** | `03_STATUS_LOG.md`, entry "Frontier model on the 40-document sample" |

### Where the money went

| step | calls | prompt tokens | reply tokens | thinking tokens | cost |
|---|---|---|---|---|---|
| one-document check, default (`high`) thinking | 2 | 1,728 | 487 | 3,484 | $0.051 |
| one-document check, `low` thinking | 2 | 1,728 | 446 | 1,336 | $0.025 |
| check before the first run attempt (stopped itself — see below) | 2 | 1,728 | 431 | 1,347 | $0.025 |
| check before the real run | 2 | 1,728 | 301 | 1,490 | $0.025 |
| **the 40-document run** | 40 | 35,915 | 6,464 | 24,832 | $0.447 |
| **total** | 48 | | | | **≈ $0.57** |

The original estimate was ~$0.25. It was low because it was built from the
local model's token counts, and local models do not "think". **About two
thirds of the bill was thinking tokens** — reasoning the model does privately
and charges for at the output price.

### Data sent to Google, and whether Google may use it

Everything sent was **public MITRE / NVD content** (CVE, CWE, CAPEC and ATT&CK
catalogue entries) plus our own prompt. No private, personal or unpublished
data left the machine.

The key is on the **paid tier** (confirmed by the key owner, 2026-10-08).
Google's pricing page says paid-tier content is "not used to improve our
products".

### The API key

Stored in `.env` as `GEMINI_API_KEY`. `.env` is git-ignored. The key was never
printed or logged; the code returns only variable *names* when it loads `.env`
and removes the key from any error message before recording it.

### Settings that differ from the local runs (all recorded in the manifest)

- **Thinking: `low`.** A Pro model cannot have thinking switched off. At the
  model's default (`high`) the one-document check projected about $1.0–1.6
  for the sample — over the cap. `low` fit. So this run is "Gemini 3.1 Pro at
  low reasoning effort", not Gemini at its strongest.
- **Seed: sent (42), not honoured.** The API accepted the seed, but identical
  requests gave different replies in 3 of the 4 check pairs — even the *number*
  of proposals changed (12, 11, 7 for the same document). This run cannot be
  reproduced exactly by re-running it.
- **Reply cap: 512 + 8,192.** Gemini counts thinking against the same limit as
  the reply, so the usual 512 was sent with extra room for reasoning.
- **Temperature 0.0**, same as the local runs. (Google recommends leaving
  Gemini 3 models at their default of 1.0. We kept 0.0 so that only the model
  differs from the local runs; no looping or broken replies were seen.)
- **Config hash `2007683a1442`**, not the `2514fd048115` of the 14B run. The
  only difference is the Module 3 retrieval/baseline settings that arrived
  with the `sarthak` merge; the `enrichment` and `llm` sections are identical.
  The manifest's `gates` block is what shows the runs are comparable.

### One thing that went differently from plan

The instruction was "check one document first; stop if the reply collapses".
The first version of that check demanded exactly 12 proposals and stopped the
run when one reply had 11. Eleven is not a collapse — the prompt says "at
most 12" — so the check now only stops on a real collapse (fewer than half,
or not a list at all). That false stop cost one extra pair of calls ($0.025).
