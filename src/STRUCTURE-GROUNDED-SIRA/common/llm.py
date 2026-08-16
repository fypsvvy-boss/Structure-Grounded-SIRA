"""The single choke point for every LLM call in SIRA-CTI.

**Never call a model directly.** RQ3 (cost-efficiency) is measured entirely
from the :class:`CallLog` this module maintains. A call that bypasses the
wrapper is invisible to Module 4 and silently biases the headline
cost-per-query number downward — the exact figure the project claims as its
contribution over the original SIRA paper.

Typical use::

    client = OllamaClient(model="qwen2.5:7b")

    with client.scope() as scope:
        reply = client.generate("Propose analyst vocabulary for ...")

    record = EnrichmentRecord(
        doc_id="CVE-2024-1234", source=Source.CVE, original_text=text,
        proposed_terms=terms,
        llm_calls=scope.calls, tokens=scope.tokens,
        latency_ms=scope.latency_ms, model=client.model,
    )
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from .schemas import TokenUsage


class LLMError(RuntimeError):
    """Raised when a backend call fails after exhausting retries."""


@dataclass
class CallRecord:
    """One LLM call, as seen by Module 4."""

    model: str
    tokens: TokenUsage
    latency_ms: int
    ok: bool = True
    tag: str = ""          # e.g. "corpus_enrich" | "query_enrich" | "agent_round_3"
    error: str = ""
    started_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "tokens": self.tokens.to_dict(),
            "latency_ms": self.latency_ms,
            "ok": self.ok,
            "tag": self.tag,
            "error": self.error,
            "started_at": self.started_at,
        }


@dataclass
class Scope:
    """Aggregate over the calls made inside one ``client.scope()`` block."""

    tag: str = ""
    records: list[CallRecord] = field(default_factory=list)

    @property
    def calls(self) -> int:
        return len(self.records)

    @property
    def tokens(self) -> TokenUsage:
        total = TokenUsage()
        for r in self.records:
            total = total + r.tokens
        return total

    @property
    def latency_ms(self) -> int:
        return sum(r.latency_ms for r in self.records)

    @property
    def failures(self) -> int:
        return sum(1 for r in self.records if not r.ok)


class CallLog:
    """Every call the process has made. Owned by the client, read by Module 4."""

    def __init__(self) -> None:
        self.records: list[CallRecord] = []
        self._scopes: list[Scope] = []

    def add(self, record: CallRecord) -> None:
        self.records.append(record)
        for scope in self._scopes:
            scope.records.append(record)

    @contextmanager
    def scope(self, tag: str = "") -> Iterator[Scope]:
        scope = Scope(tag=tag)
        self._scopes.append(scope)
        try:
            yield scope
        finally:
            self._scopes.remove(scope)

    # -- aggregates ---------------------------------------------------------------

    @property
    def calls(self) -> int:
        return len(self.records)

    @property
    def tokens(self) -> TokenUsage:
        total = TokenUsage()
        for r in self.records:
            total = total + r.tokens
        return total

    @property
    def latency_ms(self) -> int:
        return sum(r.latency_ms for r in self.records)

    def summary(self) -> dict[str, Any]:
        by_tag: dict[str, int] = {}
        for r in self.records:
            by_tag[r.tag] = by_tag.get(r.tag, 0) + 1
        return {
            "calls": self.calls,
            "tokens": self.tokens.to_dict(),
            "latency_ms": self.latency_ms,
            "failures": sum(1 for r in self.records if not r.ok),
            "calls_by_tag": by_tag,
        }

    def dump_jsonl(self, path: str | Path) -> int:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for r in self.records:
                fh.write(json.dumps(r.to_dict()) + "\n")
        return len(self.records)


class LLMClient(ABC):
    """Base class. Subclasses implement :meth:`_complete` only.

    Timing, token accounting, retries and logging all happen here so that no
    backend can forget to do them.
    """

    def __init__(
        self,
        model: str,
        *,
        log: Optional[CallLog] = None,
        max_retries: int = 2,
        retry_backoff_s: float = 1.5,
    ) -> None:
        self.model = model
        self.log = log if log is not None else CallLog()
        self.max_retries = max_retries
        self.retry_backoff_s = retry_backoff_s

    @abstractmethod
    def _complete(self, prompt: str, system: Optional[str], **kwargs: Any) -> tuple[str, TokenUsage]:
        """Backend-specific completion. Return (text, usage)."""

    def generate(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        tag: str = "",
        **kwargs: Any,
    ) -> str:
        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            started = time.perf_counter()
            try:
                text, usage = self._complete(prompt, system, **kwargs)
            except Exception as exc:  # noqa: BLE001 - recorded, then re-raised below
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                self.log.add(
                    CallRecord(
                        model=self.model,
                        tokens=TokenUsage(),
                        latency_ms=elapsed_ms,
                        ok=False,
                        tag=tag,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                last_error = exc
                if attempt < self.max_retries:
                    time.sleep(self.retry_backoff_s * (2**attempt))
                continue

            elapsed_ms = int((time.perf_counter() - started) * 1000)
            self.log.add(
                CallRecord(model=self.model, tokens=usage, latency_ms=elapsed_ms, ok=True, tag=tag)
            )
            return text

        raise LLMError(f"{self.model}: failed after {self.max_retries + 1} attempts") from last_error

    def generate_json(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        tag: str = "",
        **kwargs: Any,
    ) -> Any:
        """Generate and parse JSON, tolerating ```json fences and stray prose.

        Enrichment prompts ask for a JSON array of proposed terms. Small
        open-weight models wrap it in a fence or prepend a sentence roughly
        one time in ten, so parsing is defensive by default.
        """
        raw = self.generate(prompt, system=system, tag=tag, **kwargs)
        return parse_json_loose(raw)

    @contextmanager
    def scope(self, tag: str = "") -> Iterator[Scope]:
        with self.log.scope(tag) as s:
            yield s


def parse_json_loose(raw: str) -> Any:
    """Best-effort JSON extraction from a model reply."""
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("```")[1] if "```" in text[3:] else text[3:]
        if text.lstrip().lower().startswith("json"):
            text = text.lstrip()[4:]
        text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Fall back to the outermost bracketed span. Candidates are tried in order
    # of where they *start*: searching "[" first would match the inner array of
    # `{"terms": []}` and return an empty list — a parse failure disguised as a
    # model that proposed nothing, which is a real RQ4 observation and must not
    # be counterfeited.
    candidates: list[tuple[int, int]] = []
    for opener, closer in (("[", "]"), ("{", "}")):
        start, end = text.find(opener), text.rfind(closer)
        if start != -1 and end > start:
            candidates.append((start, end))

    for start, end in sorted(candidates):
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            continue
    raise ValueError(f"could not parse JSON from model output: {raw[:200]!r}")


class OllamaClient(LLMClient):
    """Local open-weight models for iterative development (README, cost control).

    Uses ``urllib`` rather than ``requests`` to keep the dependency surface at
    stdlib + networkx.
    """

    def __init__(
        self,
        model: str = "qwen2.5:7b",
        *,
        host: Optional[str] = None,
        temperature: float = 0.0,
        timeout_s: float = 120.0,
        **kwargs: Any,
    ) -> None:
        super().__init__(model, **kwargs)
        self.host = (host or os.environ.get("OLLAMA_HOST") or "http://localhost:11434").rstrip("/")
        self.temperature = temperature
        self.timeout_s = timeout_s

    def _complete(self, prompt: str, system: Optional[str], **kwargs: Any) -> tuple[str, TokenUsage]:
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": kwargs.pop("temperature", self.temperature)},
        }
        if system:
            payload["system"] = system
        payload.update(kwargs)

        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise LLMError(f"Ollama unreachable at {self.host}: {exc}") from exc

        usage = TokenUsage(
            prompt=int(body.get("prompt_eval_count", 0)),
            completion=int(body.get("eval_count", 0)),
        )
        return body.get("response", ""), usage


class StubClient(LLMClient):
    """Deterministic backend for tests and CI — no network, no GPU.

    ``responder`` maps a prompt to a reply; the default echoes an empty JSON
    array, which is the shape enrichment prompts expect.
    """

    def __init__(
        self,
        model: str = "stub",
        *,
        responder: Optional[Callable[[str], str]] = None,
        fixed_usage: TokenUsage | None = None,
        fail_times: int = 0,
        **kwargs: Any,
    ) -> None:
        super().__init__(model, **kwargs)
        self.responder = responder or (lambda _prompt: "[]")
        self.fixed_usage = fixed_usage or TokenUsage(prompt=10, completion=5)
        self.fail_times = fail_times
        self.prompts: list[str] = []

    def _complete(self, prompt: str, system: Optional[str], **kwargs: Any) -> tuple[str, TokenUsage]:
        self.prompts.append(prompt)
        if self.fail_times > 0:
            self.fail_times -= 1
            raise LLMError("stub failure")
        return self.responder(prompt), self.fixed_usage
