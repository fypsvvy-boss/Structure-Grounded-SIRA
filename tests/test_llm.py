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


# -- Gemini (frontier backend) --------------------------------------------------------
#
# No network and no key: a fake SDK object stands in for google-genai, so
# these check what is *sent* and how the reply's usage is *booked*.


class _FakeGeminiSDK:
    def __init__(self, *, text="[]", prompt=100, candidates=40, thoughts=300, finish="STOP", error=None):
        from types import SimpleNamespace as NS

        self.calls = []
        self._error = error
        self._response = NS(
            text=text,
            model_version="gemini-test-001",
            usage_metadata=NS(
                prompt_token_count=prompt, candidates_token_count=candidates, thoughts_token_count=thoughts
            ),
            candidates=[NS(finish_reason=NS(name=finish))],
        )
        self.models = self

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        return self._response


def test_gemini_books_thinking_tokens_apart_from_the_reply():
    from sira_cti.common import GeminiClient

    client = GeminiClient("gemini-test", sdk_client=_FakeGeminiSDK())
    client.generate("p")

    tokens = client.log.records[0].tokens
    assert (tokens.prompt, tokens.completion, tokens.thinking) == (100, 40, 300)
    assert tokens.total == 440
    assert tokens.to_dict() == {"prompt": 100, "completion": 40, "thinking": 300}


def test_gemini_sends_seed_schema_and_a_cap_that_leaves_room_to_think():
    from sira_cti.common import GeminiClient

    schema = {"type": "array", "items": {"type": "object"}}
    sdk = _FakeGeminiSDK()
    client = GeminiClient(
        "gemini-test", sdk_client=sdk, seed=42, thinking_level="low",
        thinking_headroom_tokens=1000, max_new_tokens=512, json_schema=schema,
    )
    client.generate("p", system="sys")

    config = sdk.calls[0]["config"]
    assert config["seed"] == 42
    assert config["temperature"] == 0.0
    # The provider's cap covers reasoning and reply together; sending 512
    # as-is would let the reasoning starve the reply.
    assert config["max_output_tokens"] == 1512
    assert config["thinking_config"] == {"thinking_level": "low"}
    assert config["response_mime_type"] == "application/json"
    assert config["response_json_schema"] == schema
    assert config["system_instruction"] == "sys"


def test_gemini_does_not_send_a_thinking_config_it_was_not_given():
    from sira_cti.common import GeminiClient

    sdk = _FakeGeminiSDK()
    client = GeminiClient("gemini-test", sdk_client=sdk)
    client.generate("p")

    assert "thinking_config" not in sdk.calls[0]["config"]
    assert "seed" not in sdk.calls[0]["config"]
    assert client.describe()["thinking"]["thinking_level"] == "model default (not sent)"


def test_gemini_flags_a_reply_cut_off_at_the_token_cap():
    from sira_cti.common import GeminiClient

    client = GeminiClient("gemini-test", sdk_client=_FakeGeminiSDK(finish="MAX_TOKENS"))
    client.generate("p")

    assert client.last_truncated
    assert client.last_model_version == "gemini-test-001"


def test_gemini_never_lets_the_api_key_reach_the_call_log():
    from sira_cti.common import GeminiClient

    sdk = _FakeGeminiSDK(error=RuntimeError("403 for key=SECRET-KEY-123"))
    client = GeminiClient("gemini-test", sdk_client=sdk, api_key="SECRET-KEY-123", max_retries=0)

    with pytest.raises(LLMError):
        client.generate("p")
    assert "SECRET-KEY-123" not in client.log.records[0].error
    assert "SECRET-KEY-123" not in str(client.describe())


def test_gemini_refuses_to_start_without_a_key(monkeypatch):
    from sira_cti.common import GeminiClient

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(LLMError, match="GEMINI_API_KEY"):
        GeminiClient("gemini-test")


def test_load_env_file_returns_names_not_values(tmp_path, monkeypatch):
    from sira_cti.common import load_env_file

    env = tmp_path / ".env"
    env.write_text('# comment\nSIRA_TEST_KEY="abc123"\nSIRA_TEST_KEPT=from-file\n')
    monkeypatch.delenv("SIRA_TEST_KEY", raising=False)
    monkeypatch.setenv("SIRA_TEST_KEPT", "from-shell")

    assert load_env_file(env) == ["SIRA_TEST_KEY"]
    import os

    assert os.environ["SIRA_TEST_KEY"] == "abc123"
    assert os.environ["SIRA_TEST_KEPT"] == "from-shell"   # the real environment wins
    monkeypatch.delenv("SIRA_TEST_KEY")
    assert load_env_file(tmp_path / "missing.env") == []


# -- Ollama: explicit seed, explicit context, and the silent-truncation guard ----------


def _fake_ollama(monkeypatch, *, prompt_eval_count=100):
    """Replace the HTTP call; return the list that collects request payloads."""
    import io
    import json as _json
    import urllib.request

    sent = []

    def _urlopen(req, timeout=None):
        sent.append(_json.loads(req.data.decode("utf-8")))
        body = {"response": "[]", "prompt_eval_count": prompt_eval_count, "eval_count": 5, "done_reason": "stop"}
        return io.BytesIO(_json.dumps(body).encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    return sent


def test_ollama_sends_seed_and_num_ctx_inside_options(monkeypatch):
    from sira_cti.common.llm import OllamaClient

    sent = _fake_ollama(monkeypatch)
    OllamaClient(model="m", seed=42, num_ctx=4096, max_new_tokens=512).generate("p")

    assert sent[0]["options"] == {"temperature": 0.0, "num_predict": 512, "seed": 42, "num_ctx": 4096}
    assert "seed" not in sent[0] and "num_ctx" not in sent[0]   # top level is silently ignored


def test_ollama_leaves_seed_and_num_ctx_out_when_not_configured(monkeypatch):
    from sira_cti.common.llm import OllamaClient

    sent = _fake_ollama(monkeypatch)
    OllamaClient(model="m").generate("p")

    assert sent[0]["options"] == {"temperature": 0.0}


def test_ollama_flags_a_prompt_that_does_not_fit_the_context(monkeypatch):
    from sira_cti.common.llm import OllamaClient

    _fake_ollama(monkeypatch, prompt_eval_count=3700)
    client = OllamaClient(model="m", num_ctx=4096, max_new_tokens=512)
    client.generate("p")
    assert client.last_context_overflow            # 3700 + 512 > 4096

    _fake_ollama(monkeypatch, prompt_eval_count=3000)
    client.generate("p")
    assert not client.last_context_overflow
