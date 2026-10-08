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

## Running total

| exception | spent (our calculation from list prices) |
|---|---|
| 1 — first 40-document run and its checks | ≈ $0.57 |
| 2 — repeat run | ≈ $0.46 |
| **total, calculated** | **≈ $1.03** |
| **total, actually charged** | **₹116.66** |

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
