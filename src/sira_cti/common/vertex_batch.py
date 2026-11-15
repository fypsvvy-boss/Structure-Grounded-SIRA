"""Vertex AI batch prediction for Gemini: the same requests at half price.

How a batch run differs from an online one, and how it is kept the same:

* **Same request.** :func:`build_request` turns ``GeminiClient._config()`` --
  the very dict an online call sends -- into the REST body Vertex batch
  reads. A setting the online path gains later and this function does not
  know is refused, not dropped (:class:`LLMError`).
* **Same gates.** Replies are not parsed here. :class:`BatchReplayClient` is
  an ordinary :class:`LLMClient` that answers ``generate()`` from the batch
  results instead of the network, so ``run_corpus_enrichment`` runs exactly
  as it does online: same prompt building, same truncation, same JSON retry
  with the nudge, same adjudication, same record, same manifest and resume
  check. A prompt it has no reply for (the nudge after an unparseable reply)
  is noted in ``missing`` and goes out in the next batch round.
* **Different transport.** Requests go to a JSONL file in Cloud Storage, a
  batch job reads it, and writes results to Cloud Storage
  (``docs.cloud.google.com/vertex-ai/generative-ai/docs/multimodal/
  batch-prediction-from-cloud-storage``). Vertex does not take inline
  requests; ``google-genai`` says "inlined_requests parameter is only
  supported in Gemini Developer API".

Replies are matched to requests by a hash of the system and user text
(:func:`prompt_key`), read back from the request Vertex echoes on every result
line. No custom id field is sent: the Cloud Storage input format documents
only ``request``.

Everything a job did is kept in a local folder (``state.json``, each round's
request and result files), so a run that is stopped while a job is queued
picks the same job up again instead of paying for a second one.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .llm import GeminiClient, LLMClient, LLMError, scrub_secrets
from .schemas import TokenUsage

SERVICE = "vertex-batch"
PROVIDER = "Google Cloud Vertex AI batch prediction (application-default credentials)"

FINISHED_STATES = frozenset({
    "JOB_STATE_SUCCEEDED", "JOB_STATE_PARTIALLY_SUCCEEDED", "JOB_STATE_FAILED",
    "JOB_STATE_CANCELLED", "JOB_STATE_EXPIRED", "JOB_STATE_PAUSED",
})
"""States after which a job writes nothing more. Google's sample code stops
polling on SUCCEEDED, FAILED, CANCELLED and PAUSED; a cancelled job still
returns "any already completed work", so results are read in every case."""

_CONFIG_TO_REST = {
    "temperature": "temperature",
    "seed": "seed",
    "max_output_tokens": "maxOutputTokens",
    "response_mime_type": "responseMimeType",
    "response_json_schema": "responseJsonSchema",
}


def prompt_key(system: Optional[str], prompt: str) -> str:
    """The id a reply is filed under: SHA-256 of the system and user text."""
    blob = json.dumps([system or "", prompt], ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build_request(client: GeminiClient, prompt: str, system: Optional[str]) -> dict[str, Any]:
    """One batch input line for ``prompt``, with the client's online settings.

    Built from ``client._config()`` so that temperature, seed, reply cap,
    thinking level and JSON schema cannot drift from the online route. The
    shape matches what ``google-genai`` itself sends to Vertex for an online
    call (``contents`` as one user turn, ``systemInstruction`` with role
    user, ``thinkingLevel`` upper-case) -- ``tests/test_vertex_batch.py``
    checks it against the SDK's own converter.
    """
    config = client._config(system, client._resolved_options({}))
    generation: dict[str, Any] = {}
    unknown: list[str] = []
    for key, value in config.items():
        if key in _CONFIG_TO_REST:
            generation[_CONFIG_TO_REST[key]] = value
        elif key == "thinking_config":
            generation["thinkingConfig"] = {"thinkingLevel": str(value["thinking_level"]).upper()}
        elif key != "system_instruction":
            unknown.append(key)
    if unknown:
        raise LLMError(
            f"online setting(s) {sorted(unknown)} have no batch translation; "
            "add them to vertex_batch.build_request before running a batch"
        )
    request: dict[str, Any] = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": generation,
    }
    if system:
        request["systemInstruction"] = {"role": "user", "parts": [{"text": system}]}
    return {"request": request}


# -- reading results --------------------------------------------------------------------


@dataclass
class BatchReply:
    """One result line, reduced to what the pipeline and the bill need."""

    key: str
    text: str = ""
    usage: TokenUsage = field(default_factory=TokenUsage)
    finish_reason: str = ""
    model_version: str = ""
    error: str = ""
    thinking_level_echoed: Optional[str] = None
    """``thinkingConfig.thinkingLevel`` as it appears in the request Vertex
    echoed back -- evidence the setting arrived, not that it took effect."""


def _texts(contents: Iterable[Any]) -> str:
    out: list[str] = []
    for content in contents:
        if not isinstance(content, dict):
            continue
        for part in content.get("parts") or []:
            if isinstance(part, dict) and "text" in part and not part.get("thought"):
                out.append(str(part["text"]))
    return "".join(out)


def parse_result_line(obj: dict[str, Any]) -> BatchReply:
    """A Vertex batch output line -> :class:`BatchReply`.

    Successful lines carry the reply in ``response``; failed ones put the
    error in ``status`` ("model responses are stored in the response field.
    Otherwise, error details are stored in the status field").
    """
    request = obj.get("request") or {}
    system_obj = request.get("systemInstruction") or request.get("system_instruction")
    system = _texts([system_obj]) if system_obj else ""
    prompt = _texts(request.get("contents") or [])
    key = prompt_key(system, prompt)
    thinking = (request.get("generationConfig") or {}).get("thinkingConfig") or {}
    echoed = thinking.get("thinkingLevel")

    status = obj.get("status")
    response = obj.get("response") or {}
    if status and not response:
        message = status if isinstance(status, str) else json.dumps(status)
        return BatchReply(key=key, error=scrub_secrets(message)[:600], thinking_level_echoed=echoed)

    meta = response.get("usageMetadata") or {}
    usage = TokenUsage(
        prompt=int(meta.get("promptTokenCount") or 0),
        completion=int(meta.get("candidatesTokenCount") or 0),
        thinking=int(meta.get("thoughtsTokenCount") or 0),
    )
    candidates = response.get("candidates") or []
    first = candidates[0] if candidates else {}
    return BatchReply(
        key=key,
        text=_texts([first.get("content") or {}]),
        usage=usage,
        finish_reason=str(first.get("finishReason") or ""),
        model_version=str(response.get("modelVersion") or ""),
        error="" if candidates else "response has no candidates",
        thinking_level_echoed=echoed,
    )


class ReplyStore:
    """Every result line of every round, filed by :func:`prompt_key`.

    A failed line is kept apart (``errors``) and is not a reply: the
    request is sent again in the next round rather than turned into a
    failed document. If the same request was answered twice, the first
    answer is the one used and both are billed.
    """

    def __init__(self, batch_dir: Path) -> None:
        self.batch_dir = Path(batch_dir)
        self.replies: dict[str, BatchReply] = {}
        self.errors: dict[str, BatchReply] = {}
        self.billed = TokenUsage()
        self.lines = 0
        self.reload()

    def reload(self) -> None:
        """Re-read every ``round-*.results.jsonl`` (in place: clients hold this object)."""
        self.replies.clear()
        self.errors.clear()
        self.billed = TokenUsage()
        self.lines = 0
        for path in sorted(self.batch_dir.glob("round-*.results.jsonl")):
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        self.add(parse_result_line(json.loads(line)))

    def add(self, reply: BatchReply) -> None:
        self.lines += 1
        self.billed = self.billed + reply.usage
        if reply.error:
            if reply.key not in self.replies:
                self.errors[reply.key] = reply
            return
        self.errors.pop(reply.key, None)
        self.replies.setdefault(reply.key, reply)

    def __contains__(self, key: str) -> bool:
        return key in self.replies

    def get(self, key: str) -> Optional[BatchReply]:
        return self.replies.get(key)

    def model_versions(self) -> list[str]:
        return sorted({r.model_version for r in self.replies.values() if r.model_version})

    def thinking_levels_echoed(self) -> list[str]:
        return sorted({str(r.thinking_level_echoed) for r in self.replies.values()})


class BatchReplayClient(LLMClient):
    """An :class:`LLMClient` that answers from batch results, never the network.

    Goes through ``LLMClient.generate()`` like every backend, so each reply
    is a logged call with its billed tokens and the enrichment driver cannot
    tell it from an online client. ``max_retries`` is 0: asking again cannot
    change a stored answer. A prompt with no reply raises :class:`LLMError`
    (the document is left unwritten, as for any failed call) and is recorded
    in ``missing`` for the next round.
    """

    last_stop_reason: str = ""
    last_truncated: bool = False
    last_model_version: str = ""

    def __init__(
        self, model: str, store: ReplyStore, *, missing: dict[str, tuple[Optional[str], str]], **kwargs: Any,
    ) -> None:
        kwargs["max_retries"] = 0
        super().__init__(model, **kwargs)
        self.store = store
        self.missing = missing

    def _complete(self, prompt: str, system: Optional[str], **kwargs: Any) -> tuple[str, TokenUsage]:
        self._resolved_options(kwargs)
        key = prompt_key(system, prompt)
        reply = self.store.get(key)
        if reply is None:
            self.missing[key] = (system, prompt)
            failed = self.store.errors.get(key)
            raise LLMError(
                "batch request failed, will be sent again: " + failed.error if failed
                else "no batch reply yet for this prompt; it goes in the next batch round"
            )
        self.last_stop_reason = reply.finish_reason
        self.last_truncated = reply.finish_reason == "MAX_TOKENS"
        self.last_model_version = reply.model_version
        return reply.text, reply.usage


# -- cost ---------------------------------------------------------------------------------


def cost_usd(tokens: TokenUsage, price_in: float, price_out: float) -> float:
    """Dollars at per-million prices; thinking is billed as output."""
    return (tokens.prompt * price_in + (tokens.completion + tokens.thinking) * price_out) / 1e6


SCHEMA_PROMPT_TOKENS = 150
"""Vertex counts the JSON schema as prompt tokens: ~134 measured on the
online Vertex sample (2026-11-14), rounded up."""


def estimate_request_cost(
    requests: Iterable[tuple[Optional[str], str]], *, price_in: float, price_out: float,
    output_tokens: int, chars_per_token: float = 3.0,
) -> float:
    """A cautious dollar estimate for sending ``requests`` as one batch.

    Prompt tokens from character counts (3 characters a token; the 40-doc
    sample averaged about 3.5) plus the schema; reply + thinking tokens
    fixed at ``output_tokens`` per request.
    """
    total = 0.0
    for system, prompt in requests:
        prompt_tokens = (len(system or "") + len(prompt)) / chars_per_token + SCHEMA_PROMPT_TOKENS
        total += (prompt_tokens * price_in + output_tokens * price_out) / 1e6
    return total


# -- Cloud Storage ------------------------------------------------------------------------


def parse_gs_uri(uri: str) -> tuple[str, str]:
    """``gs://bucket/a/b`` -> ``("bucket", "a/b")``."""
    if not uri.startswith("gs://"):
        raise ValueError(f"not a gs:// URI: {uri!r}")
    bucket, _, name = uri[5:].partition("/")
    return bucket, name


class GcsClient:
    """The five Cloud Storage calls a batch needs, over the JSON API.

    Signs in with application-default credentials, like the Vertex client.
    ``session`` is anything with ``requests``-style ``get``/``post``; tests
    pass a fake.
    """

    API = "https://storage.googleapis.com/storage/v1"
    UPLOAD = "https://storage.googleapis.com/upload/storage/v1"

    def __init__(self, session: Any = None) -> None:
        if session is None:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession

            credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            session = AuthorizedSession(credentials)
        self.session = session

    @staticmethod
    def _check(resp: Any, what: str) -> Any:
        if resp.status_code >= 400:
            raise LLMError(scrub_secrets(f"Cloud Storage {what}: HTTP {resp.status_code} {resp.text[:300]}"))
        return resp

    def bucket_exists(self, bucket: str) -> bool:
        resp = self.session.get(f"{self.API}/b/{bucket}")
        if resp.status_code == 404:
            return False
        self._check(resp, f"read bucket {bucket}")
        return True

    def create_bucket(self, bucket: str, *, project: str, location: str) -> None:
        """A private bucket: uniform access, public access prevented."""
        body = {
            "name": bucket,
            "location": location,
            "iamConfiguration": {
                "uniformBucketLevelAccess": {"enabled": True},
                "publicAccessPrevention": "enforced",
            },
        }
        self._check(
            self.session.post(f"{self.API}/b", params={"project": project}, json=body),
            f"create bucket {bucket}",
        )

    def upload(self, bucket: str, name: str, path: Path) -> None:
        self._check(
            self.session.post(
                f"{self.UPLOAD}/b/{bucket}/o", params={"uploadType": "media", "name": name},
                data=Path(path).read_bytes(), headers={"Content-Type": "application/jsonl"},
            ),
            f"upload gs://{bucket}/{name}",
        )

    def list(self, bucket: str, prefix: str) -> list[str]:
        names: list[str] = []
        params: dict[str, str] = {"prefix": prefix}
        while True:
            body = self._check(self.session.get(f"{self.API}/b/{bucket}/o", params=params), "list").json()
            names.extend(item["name"] for item in body.get("items") or [])
            if not body.get("nextPageToken"):
                return sorted(names)
            params["pageToken"] = body["nextPageToken"]

    def download(self, bucket: str, name: str) -> bytes:
        quoted = urllib.parse.quote(name, safe="")
        resp = self.session.get(f"{self.API}/b/{bucket}/o/{quoted}", params={"alt": "media"})
        return self._check(resp, f"download gs://{bucket}/{name}").content


# -- jobs ---------------------------------------------------------------------------------


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _state_name(job: Any) -> str:
    state = getattr(job, "state", None)
    return str(getattr(state, "name", state) or "")


class BatchJobTimeout(RuntimeError):
    """A job was still running when this session's wait ran out. Nothing is lost."""


class VertexBatchRunner:
    """Submits one round of requests as a batch job, waits, and fetches the results.

    State lives in ``batch_dir/state.json``; a round is written there as soon
    as its job exists, so an interrupted session resumes polling that job
    rather than submitting (and paying for) the same requests again.
    """

    def __init__(
        self,
        *,
        sdk: Any,
        gcs: GcsClient,
        model: str,
        bucket: str,
        prefix: str,
        batch_dir: Path,
        poll_s: float = 30.0,
        max_wait_s: Optional[float] = None,
        max_poll_failures: int = 20,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        log: Callable[[str], None] = print,
    ) -> None:
        self.sdk = sdk
        self.gcs = gcs
        self.model = model
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.batch_dir = Path(batch_dir)
        self.poll_s = poll_s
        self.max_wait_s = max_wait_s
        self.max_poll_failures = max(1, max_poll_failures)
        self.clock = clock
        self.sleep = sleep
        self.log = log
        self.state_path = self.batch_dir / "state.json"
        self.state: dict[str, Any] = (
            json.loads(self.state_path.read_text(encoding="utf-8")) if self.state_path.exists()
            else {"rounds": []}
        )

    def _save(self) -> None:
        self.batch_dir.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self.state, indent=2), encoding="utf-8")

    @property
    def rounds(self) -> list[dict[str, Any]]:
        return self.state["rounds"]

    def open_rounds(self) -> list[dict[str, Any]]:
        return [r for r in self.rounds if not r.get("collected")]

    def submit(self, requests: list[dict[str, Any]]) -> dict[str, Any]:
        n = len(self.rounds) + 1
        self.batch_dir.mkdir(parents=True, exist_ok=True)
        local = self.batch_dir / f"round-{n}.requests.jsonl"
        with local.open("w", encoding="utf-8") as fh:
            for line in requests:
                fh.write(json.dumps(line, ensure_ascii=False) + "\n")
        src = f"gs://{self.bucket}/{self.prefix}/round-{n}/requests.jsonl"
        dest = f"gs://{self.bucket}/{self.prefix}/round-{n}/output"
        self.gcs.upload(self.bucket, parse_gs_uri(src)[1], local)
        try:
            job = self.sdk.batches.create(
                model=self.model, src=src,
                config={"dest": dest, "display_name": f"sira-{self.prefix.rsplit('/', 1)[-1]}-r{n}"[:120]},
            )
        except Exception as exc:  # noqa: BLE001 - re-raised scrubbed
            raise LLMError(scrub_secrets(f"batch create failed: {type(exc).__name__}: {exc}")[:600]) from None
        entry = {
            "round": n, "requests": len(requests), "src": src, "dest": dest,
            "job_name": job.name, "state": _state_name(job),
            "submitted_at": self.clock(), "collected": False,
        }
        self.rounds.append(entry)
        self._save()
        self.log(f"  batch round {n}: {len(requests)} requests submitted as {job.name}")
        return entry

    def wait(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Poll until the job finishes, then download its results. Raises :class:`BatchJobTimeout`."""
        started = self.clock()
        last_state = None
        failures = 0
        while True:
            # A failed status check is not a failed job. On 2026-11-15 both
            # full-corpus pollers died on one httpx.ReadTimeout after ~16 h,
            # while their jobs kept running; so a check that fails is logged
            # and tried again, and only a long unbroken run of failures stops.
            try:
                job = self.sdk.batches.get(name=entry["job_name"])
            except Exception as exc:  # noqa: BLE001 -- network/SDK errors vary by transport
                failures += 1
                self.log(
                    f"  batch round {entry['round']}: status check failed ({failures}/"
                    f"{self.max_poll_failures}): {scrub_secrets(f'{type(exc).__name__}: {exc}')[:200]}"
                )
                if failures >= self.max_poll_failures:
                    self._save()
                    raise
                self.sleep(self.poll_s)
                continue
            failures = 0
            state = _state_name(job)
            entry.update({
                "state": state,
                "create_time": _iso(getattr(job, "create_time", None)),
                "start_time": _iso(getattr(job, "start_time", None)),
                "end_time": _iso(getattr(job, "end_time", None)),
            })
            if state != last_state:
                self.log(f"  batch round {entry['round']}: {state}")
                last_state = state
                self._save()
            if state in FINISHED_STATES:
                break
            if self.max_wait_s is not None and self.clock() - started >= self.max_wait_s:
                self._save()
                raise BatchJobTimeout(
                    f"batch job {entry['job_name']} is still {state}; run the same command again to "
                    "keep waiting for it (it will not be submitted twice)"
                )
            self.sleep(self.poll_s)
        error = getattr(job, "error", None)
        if error:
            entry["error"] = scrub_secrets(str(error))[:600]
        self._collect(entry)
        return entry

    def _collect(self, entry: dict[str, Any]) -> None:
        bucket, prefix = parse_gs_uri(entry["dest"])
        names = [n for n in self.gcs.list(bucket, prefix + "/") if n.endswith(".jsonl")]
        results = self.batch_dir / f"round-{entry['round']}.results.jsonl"
        lines = 0
        with results.open("wb") as fh:
            for name in names:
                data = self.gcs.download(bucket, name)
                if data and not data.endswith(b"\n"):
                    data += b"\n"
                fh.write(data)
                lines += sum(1 for line in data.splitlines() if line.strip())
        entry.update({
            "collected": True, "collected_at": self.clock(), "result_files": names, "result_lines": lines,
        })
        self._save()
        self.log(f"  batch round {entry['round']}: {lines} result lines from {len(names)} file(s)")

    def summary(self) -> dict[str, Any]:
        """For the manifest: where the files went and each round's job and timings."""
        return {
            "bucket": self.bucket,
            "gcs_prefix": self.prefix,
            "rounds": [
                {k: r.get(k) for k in (
                    "round", "requests", "job_name", "state", "submitted_at", "create_time",
                    "start_time", "end_time", "collected_at", "result_lines", "error",
                ) if r.get(k) is not None}
                for r in self.rounds
            ],
        }
