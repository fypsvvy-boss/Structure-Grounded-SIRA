# Running Stage 1 enrichment on Kaggle

> **Status, 2026-10-14: the sample (Session 0) has been run on Kaggle and
> accepted; the full run has not been started.** Result: 5 of 40 replies
> identical to the Mac's (expected across hardware, not the test), the same
> patterns in the table, about 20 s per document. Write-up:
> `03_STATUS_LOG.md` (2026-10-14); full printout:
> `docs/results/kaggle_sample_vs_mac_14b.txt`. Full mode (two GPUs, chained
> sessions) has only been rehearsed on the Mac — what is still untried is
> listed at the bottom.

**The idea.** The full run is ~75 hours on the Mac. Kaggle lends two GPUs for
free. We split the documents in half, give each GPU one half, and stop each
process shortly before Kaggle switches the session off. The next session picks
up where the last one stopped. At the end the two files are joined into one.

**Policy: this is not an exception.** It is still the project's open-weight
model, `qwen2.5:14b` — same weights (checked by fingerprint), same prompt,
seed and settings as on the Mac. Only the computer is borrowed. Nothing goes
to a paid API and it costs nothing, so `06_POLICY_EXCEPTIONS.md` gets a note,
not an entry. What is uploaded is public MITRE / NVD content plus CTIConnect's
`corpus_kb` (CC-BY-4.0).

Files: `notebooks/kaggle_stage1.ipynb` (the notebook),
`scripts/kaggle_stage1.py` (its logic, tested), `scripts/merge_enrichment.py`,
`scripts/compare_enrichment.py`.

## The split

Both GPUs run `--kinds cwe,capec,attack,cve`; one takes `--shard 1/2`, the
other `--shard 2/2`. A document's shard is worked out from its id alone
(a SHA-256 hash), so the two never share a document and miss none.

| | documents | CWE | CAPEC | ATT&CK | CVE | Mac-hours | non-CVE done after |
|---|---|---|---|---|---|---|---|
| GPU 0, shard 1/2 | 2,999 | 667 | 298 | 557 | 1,477 | **37.0** | 18.5 |
| GPU 1, shard 2/2 | 3,045 | 675 | 317 | 519 | 1,534 | **37.6** | 18.4 |

"Mac-hours" = documents × the Mac's measured seconds per document for that
source (`module1-freeze.md`, "Time and cost"). They show the two shares are
equal; they are **not** Kaggle's clock time. **Measured on the sample
(2026-10-14): 18.0–21.7 s per document on a T4, so about 16.3 h for shard 1/2
and 16.5 h for shard 2/2 — about 2 sessions.** That rests on 10 documents of
each kind; session 1's progress lines will show the real pace.

Why not "CVEs on one GPU, the rest on the other"? That is also balanced on
paper (37.7 vs 37.0 Mac-hours), but it leans on per-source figures that are
only good to ±15%, and the catalogue entries Modules 2/3 want would not be
complete until the very end. Splitting every kind in half is balanced however
wrong those figures are, and every non-CVE entry is done at the half-way
point. To use the other split, change `PLAN` in the notebook; it checks that
every document is covered exactly once.

## What you do by hand, once

1. **Commit and push the code.** A full run refuses to start from uncommitted
   code. Note the full hash: `git rev-parse HEAD`.
2. **Make the dataset folder** (from the repo root; about 76 MB):

   ```bash
   D=~/Desktop/sira-kaggle-inputs
   mkdir -p "$D/data/CTIConnect/corpus_kb" "$D/data/raw" "$D/indexes/enrichment"
   cp data/CTIConnect/corpus_kb/{cve,cwe,capec,mitre}.jsonl "$D/data/CTIConnect/corpus_kb/"
   cp -R data/raw/attack data/raw/cwe data/raw/capec "$D/data/raw/"
   cp -R indexes/base "$D/indexes/"
   cp indexes/enrichment/corpus_stratified_v4_14b_sections-v2.jsonl{,.manifest.json} "$D/indexes/enrichment/"
   ```

   The base index goes too: the `too_common` gate reads word counts from it,
   and it must be the Mac's own index, not one rebuilt on Kaggle. The last
   line is the Mac's 40-document sample, for the cross-hardware check.
3. **Upload it**: kaggle.com → Datasets → New Dataset → drag the folder in →
   keep it **Private**. Any name.
4. **Import the notebook**: Code → New Notebook → File → Import Notebook →
   `notebooks/kaggle_stage1.ipynb`.
5. **In the notebook's right-hand panel:**
   - Add Input → your dataset.
   - Accelerator → **GPU T4 x2**.
   - Internet → **On** (needs a phone-verified Kaggle account).
6. **Only if the GitHub repo is private:** GitHub → Settings → Developer
   settings → Fine-grained token → this repository only, *Contents:
   Read-only*. Then in the notebook: Add-ons → Secrets → add it under the
   name `GITHUB_TOKEN` and tick it for this notebook. The token is never
   typed into the notebook.
7. **In the first code cell** set `COMMIT` to the hash from step 1.

## Session 0 — the sample (about 20 minutes, do this first)

`MODE = "sample"`, then **Run All** in the editor. It installs everything,
checks the model's fingerprint against the Mac's, checks the model is on the
GPU, enriches the same 40 documents as the Mac's sample, and prints:

- **`REPLIES IDENTICAL: n of 40`** and which documents differ;
- **`TABLE NUMBERS`**: which of the report's counts move, old → new;
- seconds per document here, and how many sessions the full run will need.

A Mac and an NVIDIA card do arithmetic slightly differently, so fewer than 40
identical replies would not be a bug. **Write the two numbers in
`03_STATUS_LOG.md` either way** — it is the evidence that the borrowed GPU
gives the same kind of output. If many replies differ or the table moves a
lot, stop and decide as a team before spending the quota.

To compare on the Mac instead, download
`corpus_stratified_v4_14b_sections-v2_kaggle.jsonl` and its `.manifest.json`
into `indexes/enrichment/` and run:

```bash
.venv/bin/python scripts/compare_enrichment.py \
    indexes/enrichment/corpus_stratified_v4_14b_sections-v2.jsonl \
    indexes/enrichment/corpus_stratified_v4_14b_sections-v2_kaggle.jsonl
```

## Session 1 — the first full session

1. Set `MODE = "full"`. Change nothing else.
2. **Save Version → Save & Run All (Commit)** → Advanced: GPU on. Do **not**
   run it in the editor: an editor session is closed when idle, and
   `/kaggle/working` is only kept when a committed run *finishes*.
3. It runs for about 11¼ hours and stops itself. Progress is in the version's
   log every 10 minutes (`GPU 0 shard 1/2: 812/2999 … about 21 h left`).
4. When it shows **Complete**, open the version → Output. There should be
   `corpus_full_v4_14b.shard1of2.jsonl`, `…shard2of2.jsonl`, a
   `.manifest.json` for each, and `logs/`.

## Chaining sessions

1. Add Input → Notebooks → Your Work → this notebook → **the version that
   just finished**. Remove any older version of it from the inputs.
2. Save Version → Save & Run All again. Same settings, same `COMMIT`.
3. The notebook copies the earlier files into `/kaggle/working` and carries
   on. Check the log says `resuming from … (N records)`.
4. Repeat until the last cell prints **ALL DONE** — it then merges the two
   files itself into `corpus_full_v4_14b.jsonl` (6,044 documents). Download
   that and its `.manifest.json` into `indexes/enrichment/`.

Each session is about 11¼ quota hours. Check your weekly GPU quota before
starting one: a session that runs out of quota part-way can be stopped by Kaggle,
and a stopped session saves nothing.

**Change nothing between sessions** — not the commit, the model, or the
flags. The run refuses to continue if the config, prompt, scorer, truncation,
shard, code commit **or the model's fingerprint** differ from the file's.

Partial index for Modules 2/3: every non-CVE entry is done once shard 1 holds
at least **1,522** records and shard 2 at least **1,511**. Download both,
merge without `--expect`, and build as in `module1-freeze.md`.

To merge on the Mac instead:

```bash
.venv/bin/python scripts/merge_enrichment.py \
    indexes/enrichment/corpus_full_v4_14b.shard1of2.jsonl \
    indexes/enrichment/corpus_full_v4_14b.shard2of2.jsonl \
    --output indexes/enrichment/corpus_full_v4_14b.jsonl --expect 6044
```

It refuses if the two files were made under different settings or weights, or
if a document appears twice with different content.

## If something goes wrong

| what you see | what it means |
|---|---|
| `DIGEST MISMATCH` | Kaggle downloaded different weights under the name `qwen2.5:14b`. Do not run. (On 2026-10-13 the registry's digest was the Mac's, `7cdf5a0187d5…`.) Re-pulling on the Mac to match would change the Mac's model too — a team decision, and the sample would need re-running |
| `… partly or wholly on the CPU` | the model did not fit on the card; read `logs/ollama_gpu*.log` |
| `The base index does not match the Mac's` | wrong index uploaded, or a different Pyserini — it must be `2.3.0` to read this index |
| `Refusing to resume …` | something changed since the file was started; the message names it |
| the version shows **Failed** or **Timeout** | that session's output is lost. Re-run with the same input attached; only that session's work is redone |

## Still not tested on Kaggle

The sample session (2026-10-14) ran from start to finish, so the install
cell, the clone, finding the uploaded files, the digest check and the
model-on-GPU check all worked there. Sample mode uses **one** GPU and one
session, so these remain untried:

- `CUDA_VISIBLE_DEVICES` really pinning each of the two servers to its own T4
  (cell 6 prints `nvidia-smi`: both cards should show about 10 GB in use).
- Two enrichment processes side by side — the speed estimate assumes each
  runs as fast as one did alone.
- Chaining: attaching a finished version and resuming from it.
- A committed "Save & Run All" run, as opposed to the editor.
