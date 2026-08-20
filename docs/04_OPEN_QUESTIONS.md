# Open Questions & Known Issues

> Decisions that are NOT yet made, or made but not yet documented as deliberate.
> These need a human call, not a silent default. Each affects the research
> validity, not just code cleanliness.

---

## 1. How is document frequency computed for multi-token structural IDs? (affects RQ1)

**The situation:** Anserini's default analyzer keeps `T1110.001` as a single
token, but splits `CWE-307` into `["cwe", "307"]` (and CAPEC IDs similarly). The
DF `too_common` filter reads frequencies from the real base index.

**The question:** for a multi-token term like `CWE-307`, what DF does the filter
use — the max across its tokens, the min, the mean, the DF of the whole phrase as
a bigram, something else?

**Why it matters:** `cwe` on its own is near-ubiquitous in a CWE corpus. If the
filter keys off that token, nearly every CWE identifier gets rejected as
`too_common`, while one-token ATT&CK IDs like `T1110.001` sail through. That's an
apples-to-oranges filtering standard across the three catalogues — and RQ1 is
literally "the proportion of valid, discriminative expansion terms that survive."
An artifact here would masquerade as a finding.

**What's needed:** find how the DF gate currently handles multi-token terms
(inspect `df_stats.py` and the gate in `corpus_side.py`), make it a *deliberate,
documented* choice, and note the ATT&CK-vs-CWE/CAPEC tokenization asymmetry in the
write-up regardless of which rule is chosen. Consider whether structural IDs
should be filtered on a whole-ID basis rather than per-analyzer-token.

---

## 2. Prompt versioning doesn't compose with resumability (affects RQ4 data integrity)

**The situation:** `PROMPT_VERSION` is recorded once per output file in a sidecar
`<output>.manifest.json` (chosen to avoid a schema sign-off round). But
`run_corpus_enrichment()` is resumable — a resume skips already-done docs.

**The problem:** if the prompt changes between an initial run and a resume, one
JSONL ends up holding records produced under two different prompt versions, under
a single manifest claiming one version. Since the rejection log is the RQ4
dataset, that's silent provenance contamination that can't be untangled later.

**Proposed fix (no schema change needed):** on resume, compare the current prompt
hash against the manifest's; if they differ, refuse to append and require a new
output path (or an explicit `--force`). Cheap to add now while the corpus is
small and nothing's lost.

---

## 3. `malformed_id` rejections from the first real run — genuine or normalizer-fixable?

**The situation:** the first real Ollama run (`--limit 5`) produced 5
`malformed_id` rejections.

**The question:** are these genuinely malformed IDs the model invented, or are
they valid IDs in a slightly-off format (`T1110.1` for `T1110.001`, `CWE 307`
with a space, lowercase, etc.) that the normalizer should have canonicalized
*before* they reached graph validation?

**What's needed:** inspect the 5 records. If they're format variants of real IDs,
that's a normalizer gap to fix in `normalize.py` — not a model problem, and fixing
it will change the accept/reject balance. If they're genuinely fabricated IDs,
that's exactly the RQ4 hallucination signal we want to capture (leave as-is).

---

## 4. (Handoff to Module 3) expansion-field length normalization

Not a Module 1 action, but flag it in the Module 1→3 handoff so Student 3 decides
knowingly: BM25 length-normalization is per-field in Lucene, and the `expansion`
field is short. So `BM25(q_exp, d)` against the expansion field isn't scaled like
the contents field. Module 3 must decide explicitly whether `q_orig` searches
contents-only or contents+expansion, and how the two-field scoring maps onto
SIRA's `score(d) = BM25(q_orig,d) + w·BM25(q_exp,d)`. This is a fidelity question
against the paper's formula and should be a deliberate call, not inherited by
default.

---

## 5. (Low priority) subprocess interpreter bug

`src/sira_cti/index/build_base.py` calls the pyserini indexer subprocess as
`python` by name. On this machine conda's Python got picked instead of the venv's.
Should use `sys.executable`. Masked by the `.venv/bin/python` explicit-path
workaround, so low urgency, but it's a real portability bug.
