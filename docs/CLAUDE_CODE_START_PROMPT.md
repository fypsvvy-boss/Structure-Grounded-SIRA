# Start prompt — paste this into Claude Code at the repo root

---

You're joining an in-progress 4-person Final Year Project called **SIRA-CTI**. I
own **Module 1**. Before doing anything, read the handoff docs in `docs/` — they
contain context that isn't obvious from the code alone:

1. `docs/00_PROJECT_CONTEXT.md` — the thesis, research questions, 5-zone
   architecture, module ownership, and conventions. Start here.
2. `docs/01_ENVIRONMENT.md` — machine setup and one critical gotcha: conda
   shadows the venv on PATH, so **always invoke `.venv/bin/python` by explicit
   path**, never bare `python`.
3. `docs/02_MODULE1_STATE.md` — what Module 1 has already built (don't
   recreate it), plus the **frozen enrichment-record schema** (changing it needs
   sign-off from all four owners).
4. `docs/03_STATUS_LOG.md` — where we are right now and the live next-actions
   checklist.
5. `docs/04_OPEN_QUESTIONS.md` — decisions that still need a human call.

Also skim these before writing code, per the docs:
- `src/sira_cti/common/schemas.py` (frozen contract), `common/llm.py` (the LLM
  wrapper every call must go through), `common/repro.py`.
- `src/sira_cti/graph/` (the ontology tool — already built and tested).
- `src/sira_cti/enrichment/corpus_side.py`, `src/sira_cti/index/`.
- `tests/` — match the existing offline, fixture-based, StubClient style.

**Hard rules (from the docs, repeated because they matter):**
- I own Module 1 only. Don't touch `enrichment/query_side.py`, `retrieval/`, or
  `eval/` without flagging it first.
- Every LLM call goes through `common/llm.py`. Never call a model directly.
- Rejected enrichment terms are **kept** with their `reject_reason` — that
  rejection log is the RQ4 dataset. Never silently drop them.
- Don't reimplement `parse_json_loose` — reuse the one in `llm.py`.
- Prefer `.venv/bin/python` in every command you suggest or run.

**Current state (see the status log for detail):** the pipeline just ran against
the real local LLM (Ollama + Qwen2.5-7B) for the first time — `--limit 5`, 0
failures, but 5 `malformed_id` rejections and a `too_common` rate that isn't
meaningful yet at that scale.

**Where I want to start this session:**

> _[EDIT THIS LINE before sending — pick one so Claude Code has a concrete
> starting task. Examples:]_
>
> - "Start with Open Question #3: inspect the 5 `malformed_id` rejections in
>   `indexes/enrichment/corpus.jsonl` and tell me whether they're genuine
>   hallucinations or normalizer-fixable format variants."
> - "Start with Open Question #1: trace how the DF gate handles multi-token
>   structural IDs like `CWE-307`, and propose a deliberate rule."
> - "Implement the resume/prompt-version guard from Open Question #2."

Before you make changes, give me a short plan and wait for my go-ahead. When we
finish, update `docs/03_STATUS_LOG.md` with what changed.
