# Proposal: count "thinking" tokens separately (schema 1.4.0) — and record truncation (1.5.0, see the amendment)

> **Status: implemented by Module 1 on 2026-10-08, awaiting four-owner
> sign-off.** It touches `common/schemas.py`, the frozen contract, so it needs
> all four of us even though nothing existing changes.

## In one paragraph

Some models (Gemini Pro is the one we used) "think" before they answer: they
write a private scratchpad of reasoning, throw it away, and only then write
the reply we see. The provider **charges** for the scratchpad at the same
price as the reply, but never shows it to us. Our token counter only had two
boxes — `prompt` (what we sent) and `completion` (what came back) — so there
was nowhere honest to put it. This adds a third box, `thinking`.

## The change

`TokenUsage` (in `common/schemas.py`) gains one field:

```python
prompt: int = 0
completion: int = 0
thinking: int = 0      # new
```

- `total` is now `prompt + completion + thinking`.
- Adding two `TokenUsage` values adds the `thinking` parts too.
- `SCHEMA_VERSION` goes `1.3.0` → `1.4.0`.

In a saved record it looks like this:

```json
"tokens": {"prompt": 864, "completion": 240, "thinking": 668}
```

## Why not just add it to `completion`?

Because they answer different questions, and mixing them breaks both:

- `completion` is **the size of the reply the pipeline parses**. The reply cap
  (`enrichment.max_new_tokens: 512`) is about this number. If thinking were
  folded in, a Gemini reply would look five times longer than a Qwen reply
  when the visible text is the same length.
- `thinking` is **extra work we pay for but never see**. On the Gemini run it
  was the biggest part of the bill. RQ3 (cost) needs it; hiding it inside
  `completion` would make it impossible to say how much of the cost was
  reasoning.

## Does it break anything that already exists?

No, and there are tests for each of these:

- **Old files load unchanged.** A record with no `thinking` key reads as
  `thinking = 0`.
- **Old files re-save byte-for-byte the same.** When `thinking` is 0 the key
  is left out of the JSON entirely. Every Ollama record — which is every
  record before today — is 0.
- **Ollama runs are unaffected.** Local models report no thinking tokens.

## What each module should know

| module | what changes for you |
|---|---|
| 2 (query enrichment) | Nothing unless you use a thinking model. If you write your own backend, fill `thinking` rather than adding it to `completion`. |
| 3 (retrieval, baselines) | Same. The multi-round baseline's cost is `tokens.total` summed over calls, which now includes thinking automatically. |
| 4 (evaluation) | **Cost in dollars = `prompt` × input price + (`completion` + `thinking`) × output price.** If you compute cost from `prompt` and `completion` only, a thinking model will look much cheaper than it was. `tokens.total` is safe to use as-is. |

## Amendment, 2026-10-09: `truncation` on the record (schema 1.5.0)

**One more optional field, same sign-off.**

When an entry is too long for the model, the model is shown a shortened copy
(whole sections removed in a fixed order — `docs/proposals/module1-freeze.md`,
"The truncation rule"). `EnrichmentRecord` gains a field saying what was
removed:

```json
"truncation": {"version": "sections-v1", "mode": "sections", "max_doc_chars": 6000,
               "dropped": ["References", "Consequences"], "trimmed": {"Mitigations": {"kept_items": 2}},
               "full_chars": 7503, "shown_chars": 5921}
```

- `mode` is `"sections"` (the normal case) or `"fallback"` (a blind cut,
  because even the protected sections did not fit — 0 cases in this corpus).
- **`original_text` does not change meaning: it is still the full entry.**
  Module 3 keeps indexing the full entry.
- The field is **absent** when nothing was removed, so every older record
  loads and re-saves exactly as before. `SCHEMA_VERSION` goes to `1.5.0`.

| module | what changes for you |
|---|---|
| 2 (query enrichment) | Nothing: queries are short. If you ever shorten an input, use `enrichment/truncation.py` and fill the field |
| 3 (retrieval) | Nothing. Index `original_text` as now |
| 4 (evaluation) | If you ask "was this term already in the document?", ask it of what the model **saw**: `record_shown_text(record)` in `enrichment/truncation.py`, not `original_text`. For the 171 shortened entries the two differ |

## Sign-off

**Sign in `schema-signoff.md` instead** — one page covering 1.3.0, 1.4.0 and 1.5.0 together. The table below is kept only as history.

| module | decision | date | notes |
|---|---|---|---|
| Module 1 | **Approve** (implemented) | 2026-10-08; amended 2026-10-09 | needed for the frontier run, `docs/06_POLICY_EXCEPTIONS.md`; 1.5.0 for truncation |
| Module 2 | | | |
| Module 3 | | | |
| Module 4 | | | |
