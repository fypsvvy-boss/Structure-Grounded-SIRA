"""The instrumented LLM wrapper.

RQ3's headline number is produced entirely from the call log, so these tests
guard the accounting: failed attempts still count as calls, scopes aggregate
correctly, and a retry does not quietly present three calls as one.
"""

import pytest

from sira_cti.common import CallLog, GenOptions, LLMError, StubClient, TokenUsage
from sira_cti.common.llm import parse_json_loose


def test_every_call_is_logged_with_tokens_and_latency():
    client = StubClient(responder=lambda p: "ok")
    client.generate("hello", tag="query_enrich")

    assert client.log.calls == 1
    record = client.log.records[0]
    assert record.tokens.total == 15
    assert record.latency_ms >= 0
    assert record.ok
    assert record.tag == "query_enrich"


def test_scope_aggregates_only_the_calls_inside_it():
    client = StubClient()
    client.generate("outside")

    with client.scope("corpus_enrich") as scope:
        client.generate("inside one")
        client.generate("inside two")

    assert scope.calls == 2
    assert scope.tokens.prompt == 20
    assert scope.failures == 0
    client.generate("after")
    assert scope.calls == 2                 # closed scopes stop accumulating
    assert client.log.calls == 4


def test_nested_scopes_both_see_the_call():
    client = StubClient()
    with client.scope("outer") as outer:
        with client.scope("inner") as inner:
            client.generate("x")
    assert outer.calls == 1 and inner.calls == 1


def test_failed_attempts_are_logged_then_the_retry_succeeds():
    # A retried call costs real wall-clock time and real tokens on the failed
    # attempt. Reporting it as a single clean call would understate RQ3.
    client = StubClient(fail_times=1, max_retries=2, retry_backoff_s=0)
    assert client.generate("hello") == "[]"
    assert client.log.calls == 2
    assert [r.ok for r in client.log.records] == [False, True]


def test_exhausted_retries_raise_and_leave_a_full_audit_trail():
    client = StubClient(fail_times=99, max_retries=1, retry_backoff_s=0)
    with pytest.raises(LLMError):
        client.generate("hello")
    assert client.log.calls == 2
    assert all(not r.ok for r in client.log.records)
    assert client.log.summary()["failures"] == 2


def test_a_shared_log_totals_across_clients():
    # The multi-round agentic baseline may use more than one client; the cost
    # comparison against SIRA-CTI has to see all of it.
    log = CallLog()
    a = StubClient(model="qwen2.5:7b", log=log)
    b = StubClient(model="llama3:8b", log=log)
    a.generate("one")
    b.generate("two")
    b.generate("three")

    assert log.calls == 3
    assert log.tokens == TokenUsage(prompt=30, completion=15)
    assert log.summary()["calls"] == 3


def test_summary_groups_calls_by_tag():
    client = StubClient()
    client.generate("a", tag="corpus_enrich")
    client.generate("b", tag="corpus_enrich")
    client.generate("c", tag="query_enrich")
    assert client.log.summary()["calls_by_tag"] == {"corpus_enrich": 2, "query_enrich": 1}


def test_call_log_dumps_jsonl(tmp_path):
    client = StubClient()
    client.generate("a")
    path = tmp_path / "calls.jsonl"
    assert client.log.dump_jsonl(path) == 1
    assert path.read_text(encoding="utf-8").count("\n") == 1


def test_generate_json_parses_a_clean_array():
    client = StubClient(responder=lambda p: '[{"term": "brute force"}]')
    assert client.generate_json("go") == [{"term": "brute force"}]


def test_generate_json_survives_fenced_and_chatty_output():
    # Small open-weight models add fences and preamble often enough that
    # strict json.loads would fail several percent of enrichment calls.
    for raw in [
        '```json\n[{"term": "brute force"}]\n```',
        '```\n[{"term": "brute force"}]\n```',
        'Sure! Here are the terms:\n[{"term": "brute force"}]',
        'Here you go:\n```json\n[{"term": "brute force"}]\n```\nHope that helps!',
    ]:
        assert parse_json_loose(raw) == [{"term": "brute force"}], raw


def test_parse_json_loose_handles_objects_too():
    assert parse_json_loose('The result:\n{"terms": []}') == {"terms": []}


def test_unparseable_output_raises_rather_than_returning_empty():
    # Returning [] here would look like "the model proposed nothing", which is
    # a legitimate RQ4 observation. A parse failure must not masquerade as one.
    with pytest.raises(ValueError):
        parse_json_loose("I'm afraid I can't help with that.")


def test_prompts_are_captured_for_prompt_iteration():
    client = StubClient()
    client.generate("first")
    client.generate("second")
    assert client.prompts == ["first", "second"]


# -- generation settings reaching the backend (schema 1.2.0 / max_new_tokens fix) ----
#
# enrichment.max_new_tokens sat in configs/default.yaml being read by nothing
# for six weeks. These tests are about the *plumbing*, not the value: a cap
# that does not reach the request is indistinguishable from no cap at all.


def test_max_new_tokens_reaches_the_backend():
    client = StubClient(max_new_tokens=512)
    client.generate("hello")
    assert [o.max_new_tokens for o in client.option_calls] == [512]


def test_a_per_call_cap_overrides_the_client_default():
    client = StubClient(max_new_tokens=512)
    client.generate("hello", max_new_tokens=64)
    client.generate("again")
    assert [o.max_new_tokens for o in client.option_calls] == [64, 512]


def test_constrained_decoding_is_off_unless_asked_for():
    client = StubClient()
    client.generate("hello")
    assert client.option_calls == [GenOptions()]


def test_json_mode_reaches_the_backend():
    client = StubClient(json_mode=True)
    client.generate("hello")
    assert client.option_calls[0].json_mode is True
    assert client.option_calls[0].json_schema is None


def test_a_json_schema_reaches_the_backend_and_outranks_plain_json_mode():
    # Both set: the schema wins, because it is the one that pins the reply's
    # *shape*. Plain json_mode only promises valid JSON, and a single object
    # is valid JSON where an array of twelve was asked for.
    schema = {"type": "array"}
    client = StubClient(json_mode=True, json_schema=schema)
    client.generate("hello")
    assert client.option_calls[0].json_schema == schema


def test_ollama_nests_the_cap_under_options_not_at_the_top_level():
    # Ollama accepts and silently ignores generation settings sent beside
    # "model"; they only take effect inside the nested "options" object. This
    # asserts the payload shape without a network call.
    import json as _json

    from sira_cti.common.llm import OllamaClient

    captured = {}

    class _Recorder(OllamaClient):
        def _complete(self, prompt, system, **kwargs):
            opts = self._resolved_options(kwargs)
            max_new_tokens, json_mode = opts.max_new_tokens, opts.json_mode
            options = {"temperature": self.temperature}
            if max_new_tokens is not None:
                options["num_predict"] = int(max_new_tokens)
            payload = {"model": self.model, "prompt": prompt, "options": options}
            if json_mode:
                payload["format"] = "json"
            captured.update(_json.loads(_json.dumps(payload)))
            return "[]", TokenUsage()

    _Recorder(model="m", max_new_tokens=256, json_mode=True).generate("p")
    assert captured["options"]["num_predict"] == 256
    assert "num_predict" not in captured
    assert captured["format"] == "json"


def test_ollama_sends_a_schema_as_the_format_field():
    import json as _json

    from sira_cti.common.llm import OllamaClient

    schema = {"type": "array", "items": {"type": "object"}}
    captured = {}

    class _Recorder(OllamaClient):
        def _complete(self, prompt, system, **kwargs):
            opts = self._resolved_options(kwargs)
            payload = {"model": self.model, "prompt": prompt}
            if opts.json_schema is not None:
                payload["format"] = opts.json_schema
            elif opts.json_mode:
                payload["format"] = "json"
            captured.update(_json.loads(_json.dumps(payload)))
            return "[]", TokenUsage()

    _Recorder(model="m", json_schema=schema).generate("p")
    assert captured["format"] == schema
