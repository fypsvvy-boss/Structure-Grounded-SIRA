"""Baseline: a multi-round agentic searcher -- the paradigm SIRA argues against.

Search, read the top results, let the LLM rewrite the query, search again.
Each round after the first costs one LLM call and one more retrieval, and
each rewrite is written *after reading evidence* -- exactly what the
evidence-blind protocol in :mod:`sira_cti.retrieval.weighted_bm25` forbids
itself. RQ2 compares the rankings; RQ3 compares what they cost.

Loop, for at most ``max_rounds`` searches::

    search(query) -> show the model the top ``read_k`` unseen snippets
                  -> model replies {"query": "..."} or {"done": true}
                  -> repeat with the new query

The rounds' rankings are merged by reciprocal rank fusion, so a document
found early is not lost when a later rewrite drifts.

Every model call goes through the instrumented client (``common/llm.py``),
tagged ``agent_round_<n>``, inside one scope per question -- that scope is
where this baseline's per-query cost comes from. A reply that cannot be
parsed ends the loop with the results gathered so far; the call is still
counted, because it was still paid for. A backend failure
(:class:`~sira_cti.common.llm.LLMError`) is not caught: an unreachable model
would otherwise turn this baseline into plain BM25 without anyone noticing,
and that run would then be reported as the agent's result.

Retrieval is plain BM25 over the base index: the agent's advantage is
supposed to come from iterating, not from the enriched index.
"""

from __future__ import annotations

from typing import Optional

from ...common.llm import LLMClient, parse_json_loose
from ...common.schemas import EnrichmentRecord
from ..types import Hit, RetrievalResult, rrf_fuse

PROMPT_VERSION = "agent-v1"

SYSTEM_PROMPT = (
    "You are a search agent over a cyber threat intelligence knowledge base "
    "(CVE, CWE, CAPEC and MITRE ATT&CK entries). The search engine is keyword "
    "based (BM25): it matches the words in your query against the words in "
    "each entry. Reply with JSON only."
)


def build_prompt(question: str, queries: list[str], snippets: list[tuple[str, str]]) -> str:
    tried = "\n".join(f"  {i}. {q}" for i, q in enumerate(queries, start=1))
    shown = "\n".join(f"[{doc_id}] {text}" for doc_id, text in snippets) or "(no new results)"
    return (
        f"Question:\n{question}\n\n"
        f"Queries tried so far:\n{tried}\n\n"
        f"New results from the last query:\n{shown}\n\n"
        "If these results already answer the question, reply {\"done\": true}.\n"
        "Otherwise write one better keyword query, using vocabulary the right "
        "entry is likely to contain, and reply {\"query\": \"<your query>\"}."
    )


class MultiRoundAgent:
    name = "multi_round_agent"

    def __init__(
        self,
        searcher,
        client: LLMClient,
        *,
        max_rounds: int = 3,
        read_k: int = 5,
        snippet_chars: int = 400,
        rrf_k: int = 60,
    ) -> None:
        """``searcher`` is a plain-BM25 retriever exposing ``doc_text(doc_id)``."""
        if max_rounds < 1:
            raise ValueError(f"max_rounds must be >= 1, got {max_rounds}")
        self.searcher = searcher
        self.client = client
        self.max_rounds = max_rounds
        self.read_k = read_k
        self.snippet_chars = snippet_chars
        self.rrf_k = rrf_k

    def _next_query(self, question: str, queries: list[str], snippets: list[tuple[str, str]], round_no: int) -> Optional[str]:
        """Ask the model for the next query. ``None`` means stop."""
        raw = self.client.generate(
            build_prompt(question, queries, snippets), system=SYSTEM_PROMPT, tag=f"agent_round_{round_no}"
        )
        try:
            reply = parse_json_loose(raw)
        except ValueError:
            return None
        if not isinstance(reply, dict) or reply.get("done") is True:
            return None
        nxt = reply.get("query")
        if not isinstance(nxt, str) or not nxt.strip():
            return None
        nxt = nxt.strip()
        # Repeating a query would return the same list again for another LLM call.
        return None if nxt.lower() in {q.lower() for q in queries} else nxt

    def retrieve(
        self,
        query: str,
        *,
        query_id: str = "",
        enrichment: Optional[EnrichmentRecord] = None,
        k: int = 100,
    ) -> RetrievalResult:
        queries: list[str] = []
        rankings: list[list[Hit]] = []
        seen: set[str] = set()
        retrieval_ms = 0
        current: Optional[str] = query

        with self.client.scope(self.name) as scope:
            for round_no in range(1, self.max_rounds + 1):
                result = self.searcher.retrieve(current, k=k)
                queries.append(current)
                rankings.append(result.hits)
                retrieval_ms += result.retrieval_ms

                if round_no == self.max_rounds:
                    break

                fresh = [h.doc_id for h in result.hits if h.doc_id not in seen][: self.read_k]
                seen.update(fresh)
                snippets = [(d, self.searcher.doc_text(d)[: self.snippet_chars]) for d in fresh]

                current = self._next_query(query, queries, snippets, round_no)
                if current is None:
                    break

        return RetrievalResult(
            query_id=query_id,
            system=self.name,
            hits=rrf_fuse(rankings, k=k, rrf_k=self.rrf_k),
            retrieval_calls=len(rankings),
            retrieval_ms=retrieval_ms,
            llm_calls=scope.calls,
            tokens=scope.tokens,
            llm_latency_ms=scope.latency_ms,
            expansion_terms=queries[1:],
        )
