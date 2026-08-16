# Data

Everything under `data/` is gitignored. Fetch it with the commands below.

## MITRE ATT&CK (STIX 2.1)

```bash
mkdir -p data/raw/attack
curl -L -o data/raw/attack/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

The full `mitre/cti` repo is large; only the enterprise bundle is needed unless
the project later extends to the mobile or ICS matrices, in which case fetch the
corresponding bundle and drop the `domains` filter in `configs/default.yaml`.

**Pin the version.** ATT&CK ships a new release roughly twice a year, and
technique IDs are deprecated and revoked between them. Record the bundle's
`x_mitre_version` alongside every results file, or a re-run six months from now
will produce a different rejection rate for reasons that have nothing to do
with the model.

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

## After fetching

```bash
python scripts/build_graph.py --config configs/default.yaml
```

Node counts, status breakdowns and spot checks. Everything downstream assumes
this passes.
