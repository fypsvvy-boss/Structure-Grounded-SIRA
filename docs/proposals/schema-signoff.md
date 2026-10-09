# Schema sign-off: 1.1.0 → 1.5.0 (one page, for Modules 2, 3 and 4)

**What we need from you:** read this page, then put Approve / Object in the
table at the bottom. It replaces the separate requests in
`name-id-consistency.md` and `thinking-tokens.md` (those keep the detail).

The "schema" is the shape of the record Module 1 writes for every document
(`common/schemas.py`). All four of us agreed not to change it without asking.
Module 1 has added to it three times. **Nothing was removed, renamed or given
a new meaning. Every record written under an older version still loads** —
there is a test for each old version (1.0.0, 1.1.0, 1.2.0) — and the 1.4.0
and 1.5.0 fields are simply left out of the file when they are not used, so a
local-model record of a short document looks exactly as it did before.

## What changed, and why

| version | what was added | why |
|---|---|---|
| **1.3.0** (includes 1.2.0) | On each proposed term: `claimed_name`, `official_name`, `rejected_at_stage`, `in_counting_run`, `graph_distance`, `name_scorer`, `repaired_to`. Two new reject reasons: `name_mismatch`, `llm_json_error` | Checking that an id *exists* was not enough: a model can count upwards (CWE-73, 74, 75…) and every one exists. Now the model must say what the id *is*, and that is checked against MITRE's title. `llm_json_error` lets a run finish when one reply is unreadable |
| **1.4.0** | `tokens.thinking` — a third token count beside `prompt` and `completion` | Gemini "thinks" before answering and bills for it. Folding that into `completion` would hide two thirds of the cost. Absent when 0, i.e. on every local-model record |
| **1.5.0** | On the record: `truncation` — which sections were removed from the copy of a long entry shown to the model | 171 entries are too long for the local model. The record says exactly what the model did not see. Absent when nothing was removed. **`original_text` is still the full entry** |

## What you have to do differently

| module | action |
|---|---|
| **2** (query side) | Nothing breaks. If you reuse the name check, a term can now be `graph_validated = true` **and rejected** (reason `name_mismatch`) — do not read `graph_validated` as "accepted" |
| **3** (retrieval) | Nothing breaks. Keep indexing `original_text` and accepted terms only. A document whose reply was unreadable has one rejected term with reason `llm_json_error`; it never reaches the index |
| **4** (evaluation) | Three things. (a) Your switch over reject reasons needs the two new values. (b) Cost = `prompt` × input price + (`completion` + `thinking`) × output price. (c) "Was this term already in the document?" must be asked of what the model **saw** — `record_shown_text(record)` in `enrichment/truncation.py` — not of `original_text` |

## Sign-off

| module | 1.3.0 | 1.4.0 | 1.5.0 | date | notes |
|---|---|---|---|---|---|
| Module 1 | Approve | Approve | Approve | 2026-10-09 | implemented; 369 tests pass |
| Module 2 | | | | | |
| Module 3 | | | | | |
| Module 4 | | | | | |
