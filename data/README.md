# Data

Everything under `data/` is gitignored. Fetch it with the commands below.

## MITRE ATT&CK (STIX 2.1)

```bash
mkdir -p data/raw/attack
for domain in enterprise-attack mobile-attack ics-attack; do
  curl -L -o data/raw/attack/$domain.json \
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v17.1/$domain/$domain.json
done
```

Source is `mitre-attack/attack-stix-data` (STIX 2.1, one versioned release per
tag), **not** the `mitre/cti` mirror — that repo tracks `master`, i.e.
whatever the current live release is on the day you happen to `curl` it, which
makes every result silently unreproducible six months later.

**Pinned to `v17.1`.** CTIConnect's corpus snapshot (`snapshot_date` in
`data/cticonnect/corpus_kb/MANIFEST.json`) is dated 2025-09-01. `v17.1` was
tagged 2025-05-06 and `v18.0` not until 2025-10-28, so `v17.1` is the release
CTIConnect's snapshot actually reflects — pin anything later and gold labels
that were valid when the benchmark was built (e.g. the `T1562` family,
`T1656`) come out revoked for reasons that have nothing to do with the model
under test.

**Load all three domains.** `configs/default.yaml`'s `graph.attack_path`
takes a list; give it enterprise, mobile, and ICS. CTIConnect's QA rows span
all three matrices, and loading enterprise alone leaves every mobile- and
ICS-only technique unresolvable (`not_in_graph`) even though it is real.

Record the pinned tag (`v17.1`) alongside every results file — the next ATT&CK
release will revoke more IDs, and a re-run against a different pin will
produce a different rejection rate for reasons that have nothing to do with
the model.

## CWE

```bash
mkdir -p data/raw/cwe
curl -L -o data/raw/cwe/cwec_latest.xml.zip https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
```

The loader reads `.zip` directly, so unzipping is optional — but if you leave it
zipped, point `cwe_path` at the `.zip`.

## CAPEC

```bash
mkdir -p data/raw/capec
curl -L -o data/raw/capec/capec_latest.xml https://capec.mitre.org/data/xml/capec_latest.xml
```

## CVE / NVD

CVE records are per-document rather than part of the static ontology, so they
are **not** loaded into the graph tool. A CVE's `CWE` mapping is read at
enrichment time and used to look up the corresponding CWE node.

Get a free API key first — the unauthenticated NVD rate limit (5 requests per
30 seconds) is too low for a bulk pull.

```bash
# key request: https://nvd.nist.gov/developers/request-an-api-key
echo "NVD_API_KEY=..." >> .env
```

## CTIConnect

```bash
git clone https://github.com/peng-gao-lab/CTIConnect data/cticonnect
```

Verify the `/data` layout, task splits and qrels format **now**, in parallel
with the rest of Phase 1. It is the project's highest-impact unknown, and it is
cheap to check today and expensive to discover in week 10.

## The fixed corpus (`data/corpus_kb_fixed`) — what the config uses

CTIConnect's `corpus_kb/cve.jsonl` has **117 rows exported with
`"contents": "null"`**, so those documents are just `"CVE-2025-38250 null"`.
All 117 were on NVD before the snapshot date (2025-09-01), so this was a bug
in the export. The team decided on 2026-11-15 to fix it (`docs/04_OPEN_QUESTIONS.md`
q16). `configs/default.yaml`'s `corpus.kb_dir` points at the fixed copy. Build
it after cloning CTIConnect:

```bash
.venv/bin/python scripts/build_fixed_corpus.py
```

No network needed. It checks CTIConnect's files against their own
`MANIFEST.json`, fills only the 117 `"null"` rows from the committed patch
`configs/corpus_patches/cve_null_fill_v1.jsonl`, copies everything else byte
for byte, and writes a `MANIFEST.json` saying what changed. Each filled row is
the NVD record **as it stood on 2025-09-01**: the English description then in
force, plus any CWE ids attached by then. NVD analysis added later (most of
these are Linux kernel CVEs analysed months afterwards) and CVSS scores are
left out; each patch row lists what was left out and why.

The patch itself was made once with `scripts/fetch_cve_fill.py`, which asks
NVD's public CVE and CVE Change History APIs (CVE ids only, no key; replies
cached in `data/raw/nvd_fill/`). Rerun it only to rebuild the patch.

## After fetching

```bash
python scripts/build_graph.py --config configs/default.yaml
```

Node counts, status breakdowns and spot checks. Everything downstream assumes
this passes.
