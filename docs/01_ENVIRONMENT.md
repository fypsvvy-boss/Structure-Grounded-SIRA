# Environment & Setup Notes

> Machine-specific gotchas discovered the hard way. Read before running anything.

---

## The machine

- macOS (Apple Silicon), user `Purab`.
- Repo lives at: `/Users/Purab/Desktop/Final Year Project/Structure-Grounded-SIRA`
  (note the spaces in the path — quote it in shell commands).
- Python venv: `.venv/` in the repo root, built on the **python.org** Python 3.13
  framework build (`/Library/Frameworks/Python.framework/Versions/3.13`), NOT
  conda. The venv is clean and correct.

---

## ⚠️ The conda-vs-venv PATH trap (important)

Miniconda is installed and **auto-activates its `base` environment on every new
shell** (there's a conda init block in the shell rc file). This means even after
`source .venv/bin/activate`, a bare `python` / `pip` can still resolve to
`/Users/Purab/miniconda3/bin/python` because conda's PATH entries sit ahead of
the venv's. Symptom: prompt shows `(.venv) (base)` and `which python` points at
miniconda. Pyserini is installed in the venv, not in conda's base, so this
produces `ModuleNotFoundError: No module named 'pyserini'`.

**Reliable workaround — always invoke the venv's interpreter by explicit path:**

```bash
.venv/bin/python scripts/whatever.py ...
.venv/bin/pip install ...
```

This sidesteps PATH entirely and always hits the right interpreter. **Prefer this
form in all instructions and scripts.** `conda deactivate` alone does NOT reliably
fix it because conda re-inserts itself.

**Permanent fix (optional, not yet done):** remove/disable the conda auto-activate
block in `~/.zshrc` (or set `conda config --set auto_activate_base false`) so new
shells start clean.

**Related real bug flagged for fixing:** `src/sira_cti/index/build_base.py`
invokes the pyserini indexer as a subprocess using `python` by name rather than
`sys.executable`. On this machine that let conda's Python get picked. It should
use `sys.executable` so the subprocess always matches the running interpreter.
(Low priority — the explicit-path workaround masks it — but it's a genuine
portability bug worth fixing.)

---

## Java (required by Pyserini)

Pyserini wraps Lucene/Anserini and needs a JDK (11+, 21 recommended). If
`java -version` fails: `brew install openjdk@21` and follow the symlink
instructions Homebrew prints. On this machine Java was already present and the
base index built fine.

---

## Ollama (local LLM for development)

- Installed and running. `qwen2.5:7b` pulled.
- Server runs on `http://localhost:11434`. It auto-starts (desktop app or
  `brew services`), so `ollama serve` will error with "address already in use" —
  that's fine, it means it's already up. Verify with:
  `curl http://localhost:11434/api/tags`
- First call after (re)start is slow — the model loads into memory. Don't mistake
  that for a hang.
- **Determinism:** Ollama takes `temperature`/`seed` under an `options` object in
  the request body, not at top level. If reproducibility matters, confirm the
  wrapper in `common/llm.py` actually nests them there — easy to set and have
  silently ignored. Same trap for the reply-length cap: it is
  `options.num_predict`, and `max_new_tokens` set beside `"model"` is accepted
  and ignored. `common/llm.py` nests both (added 2026-10-07; before that
  `enrichment.max_new_tokens` was read by nothing at all).
- **Seed and context size are now sent explicitly** (2026-10-08): `llm.seed: 42`
  and `llm.num_ctx: 4096` go out as `options.seed` / `options.num_ctx`. Checked
  on the real 7B — seeded replies repeat exactly and match the earlier
  unseeded ones.
- **Ollama does not fail a prompt that is too long — it silently drops part
  of it and answers anyway.** Long documents are therefore shortened on
  purpose — whole sections removed in a fixed order, never the description or
  the links to other catalogues (`enrichment.max_doc_chars: 6000`,
  `enrichment/truncation.py`) — and listed in the run manifest, and the
  client refuses any reply where prompt + reply cap did not fit. Do not size
  that budget from "~3.75 characters per token": CVE version tables are ~2.1.
- **Never benchmark — or run — on battery.** Measured 2026-10-09 on the 14B:
  8.5 tokens a second on mains, 5.4 on battery (1.7 times slower), and the
  first 90 seconds after loading are a 13.5 tok/s burst that means nothing.
  `scripts/bench_enrichment_speed.py` refuses to start on battery and stops
  if the charger comes out part-way.

### ⚠️ `format: "json"` is not the JSON mode you want (2026-10-07)

Ollama's `format` field takes either the string `"json"` or a whole JSON
Schema. They behave very differently, measured on `CAPEC-587` with
`qwen2.5:14b`:

| `format` | result |
|---|---|
| absent | one array element's opening brace missing — identical on every retry at temperature 0 |
| `"json"` | valid JSON, but a single **object**: one proposal where twelve were asked for |
| the reply schema | 12 proposals, both models, first attempt |

Plain `"json"` only promises *valid* JSON, and one object is valid JSON. It
biases the model towards `{...}` and quietly guts a run rather than failing it.
Send the schema (`prompts/corpus_side.py:REPLY_SCHEMA`, selected by
`enrichment.json_mode: schema`). Structured outputs need Ollama 0.5 or later;
this machine runs **0.33.2**, which is a later release than 0.5 (0.5 → 0.6 →
… → 0.33), so it is supported. Read those version numbers as semver, not
decimals.

**What it costs (measured 2026-10-08, corrected).** Same 8 documents, one
request at a time, model already loaded, generation speed from Ollama's own
`eval_count / eval_duration`:

| model | unconstrained | schema-constrained | slowdown |
|---|---|---|---|
| `qwen2.5:7b` | 26.4 tok/s, 9.1 s/doc | 17.4 tok/s, 12.7 s/doc | **1.5x** |
| `qwen2.5:14b` | 8.6 tok/s, 34.5 s/doc | 8.9 tok/s, 31.7 s/doc | **none** |

An earlier version of this note said "~3x slower (17s vs 50s)". **That was
wrong.** It compared a wall-clock figure from one run with per-call latencies
from another run during which other Ollama jobs (including the 14B) were being
fired at the same server. The grammar has a roughly fixed per-token cost, which
is a third of the 7B's token time and lost in the noise of the 14B's.

### ⚠️ Three things that make a run's `latency_ms` untrustworthy

1. **`enrichment.concurrency: 2` buys nothing and corrupts latency.** Ollama
   runs one request at a time per loaded model, so the second worker's request
   just queues. Measured on 12 documents (7B, schema): 148.7s at concurrency 1,
   139.1s at concurrency 2. But each record's `latency_ms` is timed from when
   the request was *sent*, so at concurrency 2 it includes the time spent
   queued behind the other worker — roughly double the real figure. **Any run
   whose latency will be reported (RQ3) must use `--concurrency 1`.**
2. **Don't use Ollama for anything else while a run is going.** A second model
   forces a load/unload cycle on 16 GB; even the same model queues. The
   `corpus-v4` 40-document runs recorded 43.9 s/doc (7B) and 122.3 s/doc (14B)
   against a clean 12.7 and 31.7, purely because diagnostics were being run
   against the same server at the same time. **Their `latency_ms` values are
   not usable for RQ3.** Their verdicts are unaffected.
3. **The context window is 4,096 tokens** (`ollama ps` shows it). Prompt +
   512 reply tokens has to fit. Measured: ~3.75 characters per token on
   `corpus_kb` text, ~330 tokens of system prompt — so a document over roughly
   **12,000 characters does not fit**, and Ollama truncates the prompt silently
   rather than failing. None of the 40 sampled documents is close (largest:
   1,999 prompt tokens). In the full corpus about **40 of 6,044** are over, the
   largest being `CVE-2017-5753` at 162k characters. Decide before the
   full-corpus run (`docs/proposals/module1-freeze.md`).

`qwen2.5:14b` is also pulled (9.0 GB) for the model-scale comparison. On this
16 GB machine it runs at roughly **32-35 s/document** against the 7B's 9-13 s
(table above), so a clean 40-document run is ~22 minutes on the 14B and ~8 on
the 7B.

**Don't run two models at once.** 7B (5 GB) plus 14B (9 GB) exceeds 16 GB, and
Ollama will swap instead of answering. Run them in sequence; both runs are
resumable, so a sequence that gets interrupted picks up where it stopped.
A third, larger model is not an option on this machine: `qwen2.5:32b` at
4-bit is ~20 GB of weights, so it cannot be held in 16 GB at all
(`docs/04_OPEN_QUESTIONS.md`, model-scale note). Select it per run with
`--model qwen2.5:14b` rather than editing the config, so the config hash stays
comparable across runs; the manifest records the model that actually ran.

---

## Gemini (frontier model — policy exceptions only)

Development stays on local Ollama models. A Gemini run is a **logged
exception**: write it up in `06_POLICY_EXCEPTIONS.md` before you start.

- **Key:** `GEMINI_API_KEY` in `.env` at the repo root (`.env` is git-ignored).
  Get one from Google AI Studio. **Never print, log or commit it.**
  `load_env_file()` in `common/repro.py` loads it and only ever returns the
  variable *names*; `GeminiClient` scrubs it out of error messages.
- **SDK:** `google-genai` (in `requirements.txt`). Install with
  `.venv/bin/python -m pip install google-genai` — note `python -m pip`, not
  `.venv/bin/pip`: the venv was moved and `pip`'s own launcher still points at
  the old folder.
- **Model id:** pass a pinned id (`gemini-3.1-pro-preview` on 2026-10-08), not
  an alias like `gemini-pro-latest` — an alias silently changes which model
  you are measuring.

```bash
.venv/bin/python scripts/enrich_corpus.py --per-kind 10 --backend gemini \
    --model gemini-3.1-pro-preview --thinking-level low --concurrency 1 \
    --price-in 2.00 --price-out 12.00 --cost-cap-usd 0.88 \
    --output indexes/enrichment/corpus_stratified_v4_gemini-3.1-pro.jsonl
```

`--backend` and `--model` are flags on purpose: editing `configs/default.yaml`
would change the config hash and make the run look like a different experiment.

### ⚠️ Four ways Gemini is not Ollama (measured 2026-10-08)

1. **It thinks, and you pay for it.** Before answering, the model writes
   private reasoning you never see. It is billed at the output price. On our
   documents it was *several times larger than the reply itself*. It is
   recorded as `tokens.thinking`, separate from `tokens.completion`
   (`proposals/thinking-tokens.md`). Thinking cannot be switched off on a Pro
   model; `--thinking-level low|medium|high` only turns it down. Leaving the
   flag off uses the model's default, which is `high`.
2. **The reply cap covers the thinking too.** Gemini's `max_output_tokens`
   is one budget shared by reasoning and reply. Sending our 512 as-is would
   let the reasoning use all of it and return nothing. `GeminiClient` sends
   `512 + 8192` instead, so the reply still gets its 512.
3. **The seed is accepted but not honoured.** We send `seed=42` at
   temperature 0. The API takes it without complaint, and two identical
   requests still came back different in 3 of 4 tries. Do not describe a
   Gemini run as reproducible. The manifest records this per run
   (`llm.seed_honoured`).
4. **"At most 12" is taken literally.** The schema-constrained reply is
   always a proper array (no single-object collapse), but the model often
   stops short: 6 to 12 terms per document on the sample, 12 on only 8 of 40.
   The local models nearly always fill all 12. That is allowed by the prompt;
   the preflight only aborts on a real collapse (fewer than half).
5. **Some replies report no thinking tokens at all** (5 of 40). The API simply
   returned none for them; those records have no `thinking` key.

The script runs a **preflight** before every Gemini run: one document, asked
twice. It checks the array did not collapse, compares the two replies (the
seed test), and turns their cost into an estimate for the whole run. It
refuses to start if the estimate is over `--cost-cap-usd`, and stops mid-run
if actual spend passes it (which is why a capped run must use
`--concurrency 1`).

---

## Canonical run sequence (Module 1)

Order matters — the pipeline enforces it with hard errors, by design:

```bash
# 1. Base index first (DF stats are read from it; also = Module 3's plain-BM25 baseline)
.venv/bin/python scripts/build_index.py --stage base --config configs/default.yaml

# 2. Corpus-side enrichment (needs base index; calls Ollama)
.venv/bin/python scripts/enrich_corpus.py --limit 20        # smoke test only: first 20 = all CVEs
.venv/bin/python scripts/enrich_corpus.py --per-kind 10 \
    --output indexes/enrichment/corpus_stratified.jsonl     # 10 random of each type (seed = eval.seed)

# 2b. (optional, no LLM) how many accepted terms just repeat their own document
.venv/bin/python scripts/measure_redundancy.py indexes/enrichment/corpus_stratified.jsonl

# 2c. (optional, no LLM) per-run summary table; pass several files to compare models
.venv/bin/python scripts/report_enrichment.py indexes/enrichment/corpus_stratified_v4_7b.jsonl \
                                              indexes/enrichment/corpus_stratified_v4_14b.jsonl

# 3. Enriched index (needs the enrichment JSONL from step 2)
.venv/bin/python scripts/build_index.py --stage enriched --config configs/default.yaml
```

`build_index.py` requires `--stage {base|enriched}` explicitly — there is no
`both` option, deliberately, to keep the ordering visible rather than hidden.

Use `--limit` only to check the pipeline runs. For any result about behaviour,
use `--per-kind`: `corpus_kb` files are concatenated CVE-first and sorted by id,
so a `--limit` prefix is CVE-only and not random. Give every sampled run its own
`--output` — resuming a different sample into an existing file mixes the two.
A 40-document `--per-kind 10` run took ~7 minutes at concurrency 2.

`build_index.py --stage enriched` always reads `index.enrichment_path` from the
config (`corpus.jsonl`), not whatever `--output` you last enriched into.

**⚠️ Always pass `--output` for now.** `corpus.jsonl` (the config default) was
written with prompt `corpus-v1`; the live prompt is `corpus-v3`. A run without
`--output` resumes into that file, skipping the 20 CVEs it already holds and
appending new records under a different prompt, with one manifest overwritten to
claim a single version (`04_OPEN_QUESTIONS.md` question 2). Nothing currently
stops this.
