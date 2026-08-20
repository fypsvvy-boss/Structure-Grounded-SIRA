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
  silently ignored.
- Config model string must be exactly `qwen2.5:7b` (not `qwen2.5`, which resolves
  to a different default tag).

Model policy: open-weight (Qwen2.5-7B) for all development; a frontier/paid API
model is reserved for the **final benchmark run only** (deliberate cost control).

---

## Canonical run sequence (Module 1)

Order matters — the pipeline enforces it with hard errors, by design:

```bash
# 1. Base index first (DF stats are read from it; also = Module 3's plain-BM25 baseline)
.venv/bin/python scripts/build_index.py --stage base --config configs/default.yaml

# 2. Corpus-side enrichment (needs base index; calls Ollama)
.venv/bin/python scripts/enrich_corpus.py --limit 20        # --dry-run / --limit N for cheap iteration

# 3. Enriched index (needs the enrichment JSONL from step 2)
.venv/bin/python scripts/build_index.py --stage enriched --config configs/default.yaml
```

`build_index.py` requires `--stage {base|enriched}` explicitly — there is no
`both` option, deliberately, to keep the ordering visible rather than hidden.
