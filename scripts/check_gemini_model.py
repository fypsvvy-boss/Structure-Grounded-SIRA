#!/usr/bin/env python3
"""Check that a Gemini model is still offered, and still gives JSON-schema replies.

Run it before any paid Gemini run, and again on the day of the full run:
``gemini-3.1-pro-preview`` is a *preview* model, and Google can rename,
replace or retire a preview without much notice.

    .venv/bin/python scripts/check_gemini_model.py --gemini-api vertex
    .venv/bin/python scripts/check_gemini_model.py --gemini-api vertex --probe

What it does:

1. Lists the Gemini models this project/location (Vertex) or key (AI Studio)
   can see, and says whether ``--model`` is among them.
2. With ``--probe``: one tiny request (about 500 tokens, well under a US cent)
   with the same settings the enrichment run uses -- temperature 0, seed 42,
   low thinking, a JSON schema -- and checks that a JSON array comes back.

Credentials are never printed: the Vertex route uses application-default
credentials (``gcloud auth application-default login``), the AI Studio route
``GEMINI_API_KEY``; only the project id and location are shown.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import GEMINI_APIS, GeminiClient, LLMError, gemini_api_from_env, load_env_file

PROBE_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {"term": {"type": "string"}, "kind": {"type": "string", "enum": ["phrase", "id"]}},
        "required": ["term", "kind"],
    },
}
PROBE_PROMPT = "List exactly three CWE ids for injection weaknesses as JSON."


def gemini_model_ids(names) -> list[str]:
    """Bare model ids, e.g. ``gemini-3.1-pro-preview``, from the SDK's listing.

    Vertex names models ``publishers/google/models/<id>``; AI Studio,
    ``models/<id>``. Only Gemini models are kept, sorted.
    """
    ids = {str(n).rsplit("/", 1)[-1] for n in names}
    return sorted(i for i in ids if i.startswith("gemini"))


def probe_verdict(text: str) -> tuple[bool, str]:
    """Did the probe reply parse as a non-empty JSON array of objects?"""
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return False, f"not JSON: {str(text)[:120]!r}"
    if not isinstance(parsed, list) or not parsed or not all(isinstance(x, dict) for x in parsed):
        return False, f"JSON, but not a non-empty array of objects: {str(text)[:120]!r}"
    return True, f"a JSON array of {len(parsed)} objects"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default="gemini-3.1-pro-preview")
    parser.add_argument("--gemini-api", choices=[a.replace("_", "-") for a in GEMINI_APIS], default=None)
    parser.add_argument("--probe", action="store_true", help="also make one tiny JSON-schema request")
    args = parser.parse_args()

    load_env_file()
    try:
        client = GeminiClient(
            args.model, api=gemini_api_from_env(args.gemini_api), temperature=0.0, seed=42,
            thinking_level="low", max_new_tokens=512, json_schema=PROBE_SCHEMA, max_retries=0,
        )
    except LLMError as exc:
        print(f"Cannot set up the client: {exc}")
        return 1
    where = f"project={client.project} location={client.location}" if client.api == "vertex" else "AI Studio key"
    print(f"Route: {client.describe()['provider']}  ({where})")

    listing = {"query_base": True} if client.api == "vertex" else None
    ids = gemini_model_ids(m.name for m in client._sdk.models.list(config=listing))
    print(f"{len(ids)} Gemini models visible:")
    for model_id in ids:
        print(("  * " if model_id == args.model else "    ") + model_id)
    if args.model not in ids:
        print(f"NOT FOUND: {args.model!r} is not offered here. Pick its replacement from the list above.")
        return 2
    print(f"FOUND: {args.model}")

    if args.probe:
        try:
            text = client.generate(PROBE_PROMPT, tag="model_check")
        except LLMError as exc:
            print(f"PROBE FAILED: {exc}")
            return 2
        ok, verdict = probe_verdict(text)
        t = client.log.tokens
        print(
            f"Probe: {verdict}; stop reason {client.last_stop_reason or '?'}; "
            f"model_version={client.last_model_version or '?'}; "
            f"tokens prompt {t.prompt}, reply {t.completion}, thinking {t.thinking}"
        )
        if not ok:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
