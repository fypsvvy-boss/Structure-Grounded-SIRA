"""Vertex batch mode: same request as online, replies through the same gates, guards that keep it apart."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from helpers import FakeDFLookup, build_fixture_graph

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import enrich_corpus  # noqa: E402
from merge_enrichment import MergeError, merge  # noqa: E402

from sira_cti.common import GeminiClient, LLMError, Source, StubClient, TokenUsage, read_jsonl  # noqa: E402
from sira_cti.common import vertex_batch as vb  # noqa: E402
from sira_cti.enrichment.corpus_side import (  # noqa: E402
    ResumeMismatchError, run_corpus_enrichment, truncate_document,
)
from sira_cti.enrichment.prompts.corpus_side import REPLY_SCHEMA, SYSTEM_PROMPT, build_prompt  # noqa: E402
from sira_cti.index.corpus import CorpusDocument  # noqa: E402

DOCS = [
    CorpusDocument(doc_id="T1110", source=Source.ATTACK, title="Brute Force", text="Brute Force against accounts."),
    CorpusDocument(doc_id="CVE-2024-1", source=Source.CVE, title="t", text="A buffer overflow in a parser."),
]
GOOD = json.dumps([{"term": "t1110/001", "kind": "structural"}, {"term": "password guessing", "kind": "colloquial"}])


def _gemini(**kwargs) -> GeminiClient:
    settings = dict(api="vertex", project="proj", location="global", temperature=0.0, seed=42,
                    thinking_level="low", max_new_tokens=512, json_schema=REPLY_SCHEMA, sdk_client=object())
    settings.update(kwargs)
    return GeminiClient("gemini-3.1-pro-preview", **settings)


def _result_line(request_line, text, *, prompt=1000, completion=200, thinking=600, finish="STOP", thought=None):
    parts = ([{"text": thought, "thought": True}] if thought else []) + [{"text": text}]
    return {
        "status": "",
        "processed_time": "2026-11-14T12:00:00Z",
        "request": request_line["request"],
        "response": {
            "candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": finish}],
            "usageMetadata": {"promptTokenCount": prompt, "candidatesTokenCount": completion,
                              "thoughtsTokenCount": thinking},
            "modelVersion": "gemini-3.1-pro-preview",
        },
    }


def _first_prompt(doc, max_terms=12, max_doc_chars=6000):
    return build_prompt(truncate_document(doc, max_doc_chars)[0], max_terms=max_terms)


def _write_results(batch_dir: Path, n: int, lines) -> None:
    batch_dir.mkdir(parents=True, exist_ok=True)
    with (batch_dir / f"round-{n}.results.jsonl").open("w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(json.dumps(line) + "\n")


# -- the request ---------------------------------------------------------------------------


def test_a_batch_request_carries_the_online_settings():
    line = vb.build_request(_gemini(), "the prompt", "the system")

    req = line["request"]
    assert req["contents"] == [{"role": "user", "parts": [{"text": "the prompt"}]}]
    assert req["systemInstruction"] == {"role": "user", "parts": [{"text": "the system"}]}
    assert req["generationConfig"] == {
        "temperature": 0.0, "seed": 42, "maxOutputTokens": 512 + 8192,
        "thinkingConfig": {"thinkingLevel": "LOW"},
        "responseMimeType": "application/json", "responseJsonSchema": REPLY_SCHEMA,
    }


def test_the_batch_request_matches_what_the_sdk_sends_online():
    """Our hand-built body against google-genai's own Vertex converter, for the same config."""
    models = pytest.importorskip("google.genai.models")
    types = pytest.importorskip("google.genai.types")
    client = _gemini()
    config = client._config("SYS", client._resolved_options({}))
    params = types._GenerateContentParameters(
        model="gemini-3.1-pro-preview",
        contents=[types.Content(role="user", parts=[types.Part(text="PROMPT")])],
        config=types.GenerateContentConfig(**config),
    )
    sdk_body = models._GenerateContentParameters_to_vertex(
        SimpleNamespace(vertexai=True, project="proj", location="global"), params.model_dump(exclude_none=True),
    )
    sdk_body.pop("_url", None)
    gen = sdk_body["generationConfig"]
    level = gen["thinkingConfig"].pop("thinking_level")
    gen["thinkingConfig"]["thinkingLevel"] = getattr(level, "value", level)
    ours = vb.build_request(client, "PROMPT", "SYS")["request"]

    assert json.loads(json.dumps(sdk_body, default=str)) == json.loads(json.dumps(ours))


def test_an_online_setting_with_no_batch_translation_is_refused(monkeypatch):
    client = _gemini()
    real = client._config
    monkeypatch.setattr(client, "_config", lambda s, o: {**real(s, o), "top_k": 3})

    with pytest.raises(LLMError, match="top_k"):
        vb.build_request(client, "p", "s")


def test_without_thinking_level_or_schema_neither_is_sent():
    req = vb.build_request(_gemini(thinking_level=None, json_schema=None), "p", None)["request"]

    assert "thinkingConfig" not in req["generationConfig"]
    assert "responseJsonSchema" not in req["generationConfig"]
    assert "systemInstruction" not in req


# -- results -------------------------------------------------------------------------------


def test_a_result_line_is_filed_under_the_key_of_its_echoed_request():
    request = vb.build_request(_gemini(), "the prompt", "the system")
    reply = vb.parse_result_line(_result_line(request, GOOD, thought="hidden reasoning"))

    assert reply.key == vb.prompt_key("the system", "the prompt")
    assert reply.text == GOOD                    # the thought part is not part of the reply
    assert reply.usage == TokenUsage(prompt=1000, completion=200, thinking=600)
    assert reply.finish_reason == "STOP"
    assert reply.model_version == "gemini-3.1-pro-preview"
    assert reply.thinking_level_echoed == "LOW"
    assert not reply.error


def test_a_failed_result_line_is_an_error_not_a_reply():
    request = vb.build_request(_gemini(), "p", "s")
    reply = vb.parse_result_line({"status": "429 Resource exhausted", "request": request["request"]})

    assert reply.error.startswith("429")
    assert reply.key == vb.prompt_key("s", "p")


def test_the_store_bills_every_line_and_a_later_success_replaces_an_error(tmp_path):
    request = vb.build_request(_gemini(), "p", "s")
    _write_results(tmp_path, 1, [{"status": "boom", "request": request["request"]}])
    store = vb.ReplyStore(tmp_path)
    assert vb.prompt_key("s", "p") not in store and store.errors

    _write_results(tmp_path, 2, [_result_line(request, GOOD)])
    store.reload()

    assert store.get(vb.prompt_key("s", "p")).text == GOOD
    assert not store.errors
    assert store.lines == 2
    assert store.billed == TokenUsage(prompt=1000, completion=200, thinking=600)


def test_the_replay_client_answers_from_the_store_and_logs_the_billed_tokens(tmp_path):
    request = vb.build_request(_gemini(), "p", "s")
    _write_results(tmp_path, 1, [_result_line(request, GOOD, finish="MAX_TOKENS")])
    missing: dict = {}
    client = vb.BatchReplayClient("gemini-3.1-pro-preview", vb.ReplyStore(tmp_path), missing=missing)

    assert client.generate("p", system="s") == GOOD
    assert client.log.tokens == TokenUsage(prompt=1000, completion=200, thinking=600)
    assert client.last_truncated is True
    assert not missing


def test_a_prompt_with_no_reply_fails_once_and_is_queued_for_the_next_round(tmp_path):
    missing: dict = {}
    client = vb.BatchReplayClient("m", vb.ReplyStore(tmp_path), missing=missing)

    with pytest.raises(LLMError):
        client.generate("p", system="s")

    assert missing == {vb.prompt_key("s", "p"): ("s", "p")}
    assert client.log.calls == 1                 # no pointless retries of a stored answer


def test_cost_and_estimate():
    assert vb.cost_usd(TokenUsage(prompt=1_000_000, completion=500_000, thinking=500_000), 1.0, 6.0) == 7.0
    # 300 chars -> 100 tokens + 150 for the schema; 1000 output tokens.
    estimate = vb.estimate_request_cost([("", "x" * 300)], price_in=1.0, price_out=6.0, output_tokens=1000)
    assert abs(estimate - (250 * 1.0 + 1000 * 6.0) / 1e6) < 1e-12


# -- Cloud Storage and jobs (fakes, no network) ---------------------------------------------


class FakeResponse:
    def __init__(self, status=200, body=None, content=b""):
        self.status_code, self._body, self.content = status, body or {}, content
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


class FakeSession:
    """Cloud Storage as a dict of object name -> bytes."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.buckets: set[str] = set()
        self.calls: list[tuple] = []

    def get(self, url, params=None):
        self.calls.append(("get", url, params))
        if url.endswith("/o") and params and "prefix" in params:
            names = [n for n in self.objects if n.startswith(params["prefix"])]
            return FakeResponse(body={"items": [{"name": n} for n in names]})
        if params and params.get("alt") == "media":
            from urllib.parse import unquote
            name = unquote(url.rsplit("/o/", 1)[1])
            return FakeResponse(content=self.objects[name])
        bucket = url.rsplit("/b/", 1)[1]
        return FakeResponse(200 if bucket in self.buckets else 404)

    def post(self, url, params=None, json=None, data=None, headers=None):
        self.calls.append(("post", url, params))
        if url.endswith("/b"):
            self.buckets.add(json["name"])
            return FakeResponse(body=json)
        self.objects[params["name"]] = data
        return FakeResponse()


class FakeBatches:
    """A batch service whose job runs the moment it is polled ``finish_after`` times."""

    def __init__(self, session, reply=GOOD, finish_after=2):
        self.session, self.reply, self.finish_after = session, reply, finish_after
        self.created: list[dict] = []
        self.polls = 0

    def create(self, *, model, src, config):
        self.created.append({"model": model, "src": src, "config": config})
        return SimpleNamespace(name=f"projects/p/locations/global/batchPredictionJobs/{len(self.created)}",
                               state=SimpleNamespace(name="JOB_STATE_PENDING"))

    def get(self, *, name):
        self.polls += 1
        job = self.created[int(name.rsplit("/", 1)[1]) - 1]
        if self.polls < self.finish_after:
            return SimpleNamespace(name=name, state=SimpleNamespace(name="JOB_STATE_RUNNING"),
                                   create_time="t0", start_time="t1", end_time=None, error=None)
        src = vb.parse_gs_uri(job["src"])[1]
        out = vb.parse_gs_uri(job["config"]["dest"])[1] + "/prediction-model-x/predictions.jsonl"
        lines = [json.loads(line) for line in self.session.objects[src].decode().splitlines()]
        self.session.objects[out] = "".join(
            json.dumps(_result_line(line, self.reply)) + "\n" for line in lines
        ).encode()
        return SimpleNamespace(name=name, state=SimpleNamespace(name="JOB_STATE_SUCCEEDED"),
                               create_time="t0", start_time="t1", end_time="t2", error=None)


def _runner(tmp_path, session, batches, **kwargs):
    return vb.VertexBatchRunner(
        sdk=SimpleNamespace(batches=batches), gcs=vb.GcsClient(session=session), model="gemini-3.1-pro-preview",
        bucket="bkt", prefix="sira-batch/run", batch_dir=tmp_path / "b", poll_s=0, sleep=lambda _s: None,
        log=lambda _m: None, **kwargs,
    )


def test_a_round_is_uploaded_submitted_polled_and_its_results_downloaded(tmp_path):
    session = FakeSession()
    batches = FakeBatches(session)
    runner = _runner(tmp_path, session, batches)

    entry = runner.submit([vb.build_request(_gemini(), "p", "s")])
    runner.wait(entry)

    assert batches.created[0]["src"] == "gs://bkt/sira-batch/run/round-1/requests.jsonl"
    assert batches.created[0]["config"]["dest"] == "gs://bkt/sira-batch/run/round-1/output"
    assert entry["state"] == "JOB_STATE_SUCCEEDED" and entry["collected"] and entry["result_lines"] == 1
    assert (tmp_path / "b" / "round-1.results.jsonl").exists()
    assert vb.ReplyStore(tmp_path / "b").get(vb.prompt_key("s", "p")).text == GOOD
    saved = json.loads((tmp_path / "b" / "state.json").read_text())
    assert saved["rounds"][0]["job_name"].endswith("/1")


def test_a_job_still_running_when_the_wait_ends_is_resumed_not_resubmitted(tmp_path):
    session = FakeSession()
    batches = FakeBatches(session, finish_after=5)
    clock = iter(range(0, 10_000, 100))
    runner = _runner(tmp_path, session, batches, max_wait_s=150, clock=lambda: next(clock))
    entry = runner.submit([vb.build_request(_gemini(), "p", "s")])

    with pytest.raises(vb.BatchJobTimeout):
        runner.wait(entry)

    again = _runner(tmp_path, session, batches)          # a new session reads state.json
    assert [r["round"] for r in again.open_rounds()] == [1]
    again.wait(again.open_rounds()[0])
    assert len(batches.created) == 1                      # the same job, paid once
    assert not again.open_rounds()


def test_bucket_checks_and_creation_are_private(tmp_path):
    session = FakeSession()
    gcs = vb.GcsClient(session=session)
    assert not gcs.bucket_exists("bkt")

    gcs.create_bucket("bkt", project="proj", location="US-CENTRAL1")

    assert gcs.bucket_exists("bkt")
    post = next(c for c in session.calls if c[0] == "post")
    assert post[2] == {"project": "proj"}


def test_a_cloud_storage_error_is_raised_with_the_token_scrubbed():
    class Denied(FakeSession):
        def get(self, url, params=None):
            return FakeResponse(403, {"error": "Bearer ya29.secret-token denied"})

    with pytest.raises(LLMError) as excinfo:
        vb.GcsClient(session=Denied()).bucket_exists("bkt")
    assert "ya29" not in str(excinfo.value)


# -- through the real pipeline ------------------------------------------------------------


def _llm_settings(service):
    return {"backend": "gemini", "api": "vertex", "service": service, "provider": "x", "temperature": 0.0,
            "seed_sent": 42, "thinking": {"thinking_level": "low"}, "max_output_tokens_sent": 8704,
            "structured_output": "response_json_schema"}


def _run(out, client_factory, *, service="vertex-batch", before_first_call=None):
    return run_corpus_enrichment(
        DOCS, client_factory=client_factory, graph=build_fixture_graph(),
        df_lookup=FakeDFLookup({}, total_docs=100), output_path=out, max_terms=12, df_max_ratio=0.9,
        name_match_min_overlap=0.5, json_retries=1, record_json_failures=True, max_doc_chars=6000,
        config_hash="364d30da6c75", corpus_kinds=["mitre", "cve"], sampling={"method": "prefix", "limit": None},
        llm_settings=_llm_settings(service), before_first_call=before_first_call,
    )


def test_batch_replies_make_the_same_records_as_the_same_replies_online(tmp_path):
    gem = _gemini()
    lines = [_result_line(vb.build_request(gem, _first_prompt(d), SYSTEM_PROMPT), GOOD,
                          prompt=1000, completion=200, thinking=600) for d in DOCS]
    _write_results(tmp_path / "b", 1, lines)
    store = vb.ReplyStore(tmp_path / "b")

    _run(tmp_path / "batch.jsonl", lambda: vb.BatchReplayClient("gemini-3.1-pro-preview", store, missing={}))
    _run(tmp_path / "online.jsonl", lambda: StubClient(
        model="gemini-3.1-pro-preview", responder=lambda _p: GOOD,
        fixed_usage=TokenUsage(prompt=1000, completion=200, thinking=600)), service="vertex-online")

    def strip(rec):
        d = rec.to_dict()
        d.pop("latency_ms", None)
        return d

    batch = [strip(r) for r in read_jsonl(tmp_path / "batch.jsonl")]
    online = [strip(r) for r in read_jsonl(tmp_path / "online.jsonl")]
    assert batch == online
    assert batch[0]["proposed_terms"][0]["structural_id"] == "T1110.001"


def test_an_unparseable_reply_gets_its_nudge_in_the_next_round(tmp_path):
    """Round 1 answers T1110 with broken JSON; the nudge prompt goes out; pass 2 finishes it."""
    gem = _gemini()
    first = {d.doc_id: _first_prompt(d) for d in DOCS}
    _write_results(tmp_path / "b", 1, [
        _result_line(vb.build_request(gem, first["T1110"], SYSTEM_PROMPT), "[{broken"),
        _result_line(vb.build_request(gem, first["CVE-2024-1"], SYSTEM_PROMPT), GOOD),
    ])
    store = vb.ReplyStore(tmp_path / "b")
    missing: dict = {}
    out = tmp_path / "run.jsonl"

    first_pass = _run(out, lambda: vb.BatchReplayClient("gemini-3.1-pro-preview", store, missing=missing))

    assert first_pass.remaining == 1 and [r.doc_id for r in read_jsonl(out)] == ["CVE-2024-1"]
    [(system, nudge_prompt)] = missing.values()
    assert nudge_prompt != first["T1110"] and nudge_prompt.startswith(first["T1110"])

    _write_results(tmp_path / "b", 2, [_result_line(vb.build_request(gem, nudge_prompt, system), GOOD)])
    store.reload()
    second_pass = _run(out, lambda: vb.BatchReplayClient("gemini-3.1-pro-preview", store, missing=missing))

    assert second_pass.remaining == 0
    t1110 = next(r for r in read_jsonl(out) if r.doc_id == "T1110")
    assert t1110.llm_calls == 2                           # both attempts billed, as online
    assert t1110.tokens.prompt == 2000


def test_a_batch_file_cannot_be_resumed_as_an_online_run(tmp_path):
    out = tmp_path / "run.jsonl"
    _run(out, lambda: StubClient(model="m", responder=lambda _p: GOOD), service="vertex-batch")
    # Remove one record so there is something left to do, then resume online.
    records = list(read_jsonl(out))
    out.write_text(json.dumps(records[0].to_dict()) + "\n", encoding="utf-8")

    with pytest.raises(ResumeMismatchError, match="llm.service"):
        _run(out, lambda: StubClient(model="m", responder=lambda _p: GOOD), service="vertex-online")


def test_a_batch_file_and_an_online_file_cannot_be_merged(tmp_path):
    def stub():
        return StubClient(model="m", responder=lambda _p: GOOD)

    one = tmp_path / "batch.jsonl"
    two = tmp_path / "online.jsonl"
    _run(one, stub, service="vertex-batch")
    _run(two, stub, service="vertex-online")
    # Give both a digest so the only disagreement left is the service.
    for path in (one, two):
        side = path.with_suffix(".jsonl.manifest.json")
        manifest = json.loads(side.read_text())
        manifest["model_digest"] = "d" * 64
        side.write_text(json.dumps(manifest))

    with pytest.raises(MergeError) as excinfo:
        merge([one, two], tmp_path / "merged.jsonl")
    assert "  llm.service:" in str(excinfo.value)


def test_the_online_client_records_its_service():
    assert _gemini().describe()["service"] == "vertex-online"
    assert _gemini(api="ai_studio", api_key="k").describe()["service"] == "ai-studio-online"


# -- the CLI's collapse report ------------------------------------------------------------


def test_the_collapse_line_flags_short_replies_and_unparseable_ones(tmp_path):
    out = tmp_path / "run.jsonl"
    one_term = json.dumps([{"term": "password guessing", "kind": "colloquial"}])
    replies = {"T1110": one_term, "CVE-2024-1": "not json"}
    run_corpus_enrichment(
        DOCS, client_factory=lambda: StubClient(responder=lambda p: replies["T1110" if "Brute" in p else "CVE-2024-1"]),
        graph=build_fixture_graph(), df_lookup=FakeDFLookup({}, total_docs=100), output_path=out,
        max_terms=12, df_max_ratio=0.9, json_retries=0, record_json_failures=True,
    )

    line = enrich_corpus.collapse_line(out, 12)

    assert "T1110 (1)" in line and "unparseable: ['CVE-2024-1']" in line


def test_doc_ids_selects_exactly_those_documents_and_refuses_unknown_ones():
    docs, sampling = enrich_corpus.select_doc_ids(DOCS, "CVE-2024-1, T1110")
    assert [d.doc_id for d in docs] == ["T1110", "CVE-2024-1"]          # corpus order
    assert sampling == {"method": "ids", "ids": ["CVE-2024-1", "T1110"]}

    with pytest.raises(ValueError, match="CWE-9"):
        enrich_corpus.select_doc_ids(DOCS, "T1110,CWE-9")
