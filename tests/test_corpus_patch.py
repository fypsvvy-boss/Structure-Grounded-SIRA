"""Filling the CVE rows corpus_kb exported as ``"null"`` (``sira_cti.index.corpus_patch``)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fetch_cve_fill  # noqa: E402
from sira_cti.index import load_kb  # noqa: E402
from sira_cti.index import corpus_patch as cp  # noqa: E402

CUTOFF = "2025-09-01"


def _record(cve_id="CVE-2025-38250", published="2025-07-09T10:42:30.294Z", updated="2025-07-28T04:16:12.006Z",
            desc="Use-after-free in vhci_flush().", state="PUBLISHED", cna_cwe=None, adp=()):
    cna = {"providerMetadata": {"shortName": "Linux"},
           "descriptions": [{"lang": "es", "value": "en español"}, {"lang": "en", "value": desc}],
           "problemTypes": [{"descriptions": [{"cweId": cna_cwe, "description": "x"}] if cna_cwe else
                                             [{"description": "n/a"}]}]}
    return {"cveMetadata": {"cveId": cve_id, "state": state, "datePublished": published, "dateUpdated": updated},
            "containers": {"cna": cna, "adp": list(adp)}}


def test_the_description_as_of_the_cutoff_goes_in_and_nothing_else():
    out = cp.contents_from_cve_list(_record(), CUTOFF)
    assert out["contents"] == {"id": "CVE-2025-38250", "descriptions": [{"value": "Use-after-free in vhci_flush()."}]}
    assert out["provenance"]["cna"] == "Linux" and out["provenance"]["cwe_from"] == []
    assert out["provenance"]["cvss_existed_not_included"] is False


def test_cwes_from_the_cna_and_adps_are_kept_as_secondary_and_cvss_is_noted_not_copied():
    adp = {"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [{"cvssV3_1": {}}],
           "problemTypes": [{"descriptions": [{"cweId": "CWE-120"}, {"cweId": "CWE-787"}]}]}
    out = cp.contents_from_cve_list(_record("CVE-2025-51630", cna_cwe="CWE-787", adp=[adp]), CUTOFF)
    assert out["contents"]["weaknesses"] == [
        {"type": "Secondary", "description": [{"value": "CWE-787"}]},
        {"type": "Secondary", "description": [{"value": "CWE-120"}]},
    ]
    assert out["provenance"]["cwe_from"] == ["CISA-ADP", "Linux"]
    assert out["provenance"]["cvss_existed_not_included"] is True
    assert "metrics" not in out["contents"]


@pytest.mark.parametrize("kwargs, match", [
    ({"published": "2025-09-02T00:00:01Z"}, "after the 2025-09-01 cutoff"),
    ({"updated": "2025-11-19T21:01:21Z"}, "not the cutoff-day record"),
    ({"state": "REJECTED"}, "not PUBLISHED"),
    ({"desc": ""}, "no English description"),
])
def test_records_that_cannot_be_the_cutoff_day_record_are_refused(kwargs, match):
    with pytest.raises(cp.PatchError, match=match):
        cp.contents_from_cve_list(_record(**kwargs), CUTOFF)


def test_cve_list_paths_follow_the_repositorys_layout():
    assert cp.cve_list_path("CVE-2025-38250") == "cves/2025/38xxx/CVE-2025-38250.json"
    assert cp.cve_list_path("CVE-2025-9802") == "cves/2025/9xxx/CVE-2025-9802.json"
    assert cp.cve_list_path("CVE-2024-1000123") == "cves/2024/1000xxx/CVE-2024-1000123.json"


# --- applying the patch -----------------------------------------------------------------

def _kb(tmp_path, rows):
    src = tmp_path / "corpus_kb"
    src.mkdir()
    (src / "cve.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    (src / "cwe.jsonl").write_text('{"id": "1", "cwe_id": "79", "title": "XSS", "contents": "é"}\n', encoding="utf-8")
    files = {n: {"sha256": cp.sha256_file(src / n)} for n in ("cve.jsonl", "cwe.jsonl")}
    (src / "MANIFEST.json").write_text(json.dumps({"snapshot_date": CUTOFF, "files": files}), encoding="utf-8")
    return src


GOOD = {"id": "0", "cve_id": "CVE-2024-1", "title": "CVE-2024-1", "contents": "{\"descriptions\": [{\"value\": \"ünïcode\"}]}", "metadata": {"source": "cve"}}
EMPTY = {"id": "1", "cve_id": "CVE-2025-38250", "title": "CVE-2025-38250", "contents": "null", "metadata": {"source": "cve"}}


def _patch(tmp_path, ids=("CVE-2025-38250",)):
    path = tmp_path / "patch.jsonl"
    rebuilt = {"contents": {"id": "x", "descriptions": [{"value": "Use-after-free."}]}, "provenance": {}}
    path.write_text("".join(json.dumps(cp.patch_row(i, rebuilt, cutoff=CUTOFF, commit="abc")) + "\n" for i in ids))
    return path


def test_only_the_null_rows_change_and_everything_else_is_byte_identical(tmp_path):
    src = _kb(tmp_path, [GOOD, EMPTY])
    out = tmp_path / "fixed"

    manifest = cp.apply_patch(src, _patch(tmp_path), out)

    old = (src / "cve.jsonl").read_text(encoding="utf-8").split("\n")
    new = (out / "cve.jsonl").read_text(encoding="utf-8").split("\n")
    assert new[0] == old[0] and new[2] == old[2] == ""          # untouched line, trailing newline kept
    assert json.loads(new[1])["contents"] == '{"id": "x", "descriptions": [{"value": "Use-after-free."}]}'
    assert (out / "cwe.jsonl").read_bytes() == (src / "cwe.jsonl").read_bytes()
    assert manifest["fixed_by"]["rows_filled"] == 1
    assert manifest["files"]["cve.jsonl"]["sha256"] == cp.sha256_file(out / "cve.jsonl")
    docs = {d.doc_id: d for d in load_kb(out, "cve")}
    assert list(docs) == ["CVE-2024-1", "CVE-2025-38250"]          # same ids, same order
    assert docs["CVE-2025-38250"].text == 'CVE-2025-38250 {"id": "x", "descriptions": [{"value": "Use-after-free."}]}'
    assert not cp.null_cve_ids(out)


def test_a_null_row_without_a_patch_row_is_refused(tmp_path):
    src = _kb(tmp_path, [GOOD, EMPTY])
    with pytest.raises(cp.PatchError, match="no row in"):
        cp.apply_patch(src, _patch(tmp_path, ids=()), tmp_path / "fixed")
    assert not (tmp_path / "fixed").exists()


def test_a_patch_for_a_row_that_has_text_is_refused(tmp_path):
    src = _kb(tmp_path, [GOOD, EMPTY])
    with pytest.raises(cp.PatchError, match="is not 'null'"):
        cp.apply_patch(src, _patch(tmp_path, ids=("CVE-2025-38250", "CVE-2024-1")), tmp_path / "fixed")


def test_a_patch_for_a_cve_not_in_the_corpus_is_refused(tmp_path):
    src = _kb(tmp_path, [GOOD, EMPTY])
    with pytest.raises(cp.PatchError, match="not in the corpus"):
        cp.apply_patch(src, _patch(tmp_path, ids=("CVE-2025-38250", "CVE-1999-0001")), tmp_path / "fixed")


def test_a_source_that_differs_from_its_manifest_is_refused(tmp_path):
    src = _kb(tmp_path, [GOOD, EMPTY])
    (src / "cwe.jsonl").write_text("changed\n")
    with pytest.raises(cp.PatchError, match="does not match its MANIFEST"):
        cp.apply_patch(src, _patch(tmp_path), tmp_path / "fixed")


def test_the_same_cve_twice_in_a_patch_is_refused(tmp_path):
    src = _kb(tmp_path, [GOOD, EMPTY])
    with pytest.raises(cp.PatchError, match="appears twice"):
        cp.apply_patch(src, _patch(tmp_path, ids=("CVE-2025-38250", "CVE-2025-38250")), tmp_path / "fixed")


# --- fetching -----------------------------------------------------------------------------

class FakeResp:
    def __init__(self, status, body):
        self.status_code, self._body, self.text = status, body, json.dumps(body)

    def json(self):
        return self._body


class FakeGitHub:
    def __init__(self, fail_first=0, timeouts=0):
        self.calls, self.fail_first, self.timeouts = [], fail_first, timeouts

    def get(self, url, headers, timeout):
        self.calls.append((url, headers))
        if self.timeouts:
            self.timeouts -= 1
            raise fetch_cve_fill.requests.ReadTimeout("Read timed out. (read timeout=60)")
        if self.fail_first:
            self.fail_first -= 1
            return FakeResp(503, {})
        return FakeResp(200, _record(url.rsplit("/", 1)[1][:-5]))


def test_records_are_read_at_the_pinned_commit_with_a_generic_client_name_and_cached(tmp_path):
    gh = FakeGitHub(fail_first=1, timeouts=1)           # one timeout, then one 503, then answers
    fetcher = fetch_cve_fill.Fetcher(tmp_path / "cache", "c0ffee" * 6, session=gh, sleep=lambda _s: None)

    rows, problems = fetch_cve_fill.build(["CVE-2025-38250"], fetcher, CUTOFF)

    assert not problems and len(rows) == 1
    assert rows[0]["cve_list_commit"] == "c0ffee" * 6
    assert json.loads(rows[0]["contents"])["descriptions"] == [{"value": "Use-after-free in vhci_flush()."}]
    assert gh.calls[-1] == (f"{fetch_cve_fill.RAW}/{'c0ffee' * 6}/cves/2025/38xxx/CVE-2025-38250.json",
                            {"User-Agent": "sira-research-client"})
    calls = len(gh.calls)
    again = fetch_cve_fill.Fetcher(tmp_path / "cache", "c0ffee" * 6, session=gh, sleep=lambda _s: None)
    assert fetch_cve_fill.build(["CVE-2025-38250"], again, CUTOFF)[0] == rows   # same rows from the cache
    assert len(gh.calls) == calls                                              # and no new requests


def test_the_pinned_commit_is_the_last_one_of_the_snapshot_day():
    assert fetch_cve_fill.SNAPSHOT_COMMIT == "98fa1ad30aab38c0795065b63e249ed0a1d93b7d"
