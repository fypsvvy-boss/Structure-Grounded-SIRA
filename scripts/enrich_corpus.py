#!/usr/bin/env python3
"""Module 1, part A — run corpus-side enrichment over the CTI corpus.

Requires the base index to already exist (``scripts/build_index.py --stage
base``): the too_common filter reads document frequency from it, which is
exactly the two-pass ordering this project's design docs call for --
base index -> DF stats -> enrichment -> enriched index -- made explicit here
rather than silently assumed.

    python scripts/enrich_corpus.py --config configs/default.yaml
    python scripts/enrich_corpus.py --limit 5 --dry-run   # cheap iteration
    python scripts/enrich_corpus.py --per-kind 10 --output indexes/enrichment/corpus_stratified.jsonl

``--limit N`` takes the first N documents in load order, which for corpus_kb
means CVEs only until N passes 3,011 -- fine for smoke-testing, useless for any
claim about CWE/CAPEC/ATT&CK. ``--per-kind N`` takes a seeded random N from
each document type instead (seed: ``--seed``, default ``eval.seed``).

Frontier run (a logged policy exception -- ``docs/06_POLICY_EXCEPTIONS.md``).
``--backend gemini`` reads ``GEMINI_API_KEY`` from ``.env`` and, before the
run, asks for one document twice: the reply must be the full array (not the
single-object collapse plain JSON mode produces) and the two replies are
compared to see whether the seed is honoured. A cost estimate from those two
calls is checked against ``--cost-cap-usd`` and the run stops if spend passes it.

    python scripts/enrich_corpus.py --per-kind 10 --backend gemini \
        --model gemini-3.1-pro-preview --concurrency 1 \
        --price-in 2.00 --price-out 12.00 --cost-cap-usd 1.00 \
        --output indexes/enrichment/corpus_stratified_v4_gemini.jsonl

Resumable: re-running with the same ``--output`` skips documents already in
that file and only retries ones that previously failed to parse. Give a
sampled run its own ``--output`` -- resuming a different sample into the same
file mixes two populations.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import (
    GeminiClient, OllamaClient, TokenUsage, code_version, config_hash, full_run_blocker,
    load_config, load_env_file,
)
from sira_cti.common.llm import parse_json_loose
from sira_cti.enrichment.corpus_side import (
    ResumeMismatchError, run_corpus_enrichment, summarize, summarize_by_source,
)
from sira_cti.enrichment.prompts.corpus_side import PROMPT_VERSION, REPLY_SCHEMA, SYSTEM_PROMPT, build_prompt
from sira_cti.graph import OntologyGraph
from sira_cti.index import LuceneDFLookup, load_corpus, order_kinds, sample_corpus


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--output", default=None, help="defaults to config's index.enrichment_path")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--limit", type=int, default=None, help="first N documents in load order (CVE-only below 3,011)")
    selection.add_argument("--per-kind", type=int, default=None, help="seeded random N documents from each type")
    parser.add_argument("--seed", type=int, default=None, help="sampling seed for --per-kind (default: eval.seed)")
    parser.add_argument(
        "--kinds", default=None,
        help="document types to process, in this order, e.g. cwe,capec,attack,cve "
             "(default: config's corpus.kinds, in its order). Safe to change when resuming",
    )
    parser.add_argument("--concurrency", type=int, default=None, help="override config's enrichment.concurrency")
    parser.add_argument("--model", default=None, help="override config's llm.model (recorded in the manifest)")
    parser.add_argument(
        "--no-name-check",
        action="store_true",
        help="disable the name-ID consistency stage (reproduces corpus-v3 adjudication)",
    )
    parser.add_argument(
        "--name-overlap",
        type=float,
        default=None,
        help="override enrichment.name_match_min_overlap (0.0-1.0)",
    )
    parser.add_argument(
        "--name-scorer", choices=["v1", "v2", "v3"], default=None,
        help="override enrichment.name_scorer",
    )
    parser.add_argument("--backend", choices=["ollama", "gemini"], default=None, help="override config's llm.backend")
    parser.add_argument(
        "--thinking-level", choices=["low", "medium", "high"], default=None,
        help="gemini only: reasoning effort; omitted = the model's own default",
    )
    parser.add_argument("--llm-seed", type=int, default=None, help="gemini only: generation seed (default: eval.seed)")
    parser.add_argument("--price-in", type=float, default=None, help="USD per 1M prompt tokens (list price on the run date)")
    parser.add_argument(
        "--price-out", type=float, default=None,
        help="USD per 1M output tokens; thinking tokens are billed at this rate too",
    )
    parser.add_argument("--cost-cap-usd", type=float, default=None, help="abort when estimated or actual spend passes this")
    parser.add_argument(
        "--allow-code-change", action="store_true",
        help="resume even though the code (src/, scripts/, configs/) is at a different commit than the "
             "one that started the output file; the earlier commit stays in the manifest",
    )
    parser.add_argument("--dry-run", action="store_true", help="run the pipeline but write nothing to disk")
    args = parser.parse_args()

    cfg = load_config(args.config)

    # Which commit is about to run. A full-corpus run takes days and cannot be
    # cheaply redone, so it may only start from committed code; a sample run
    # may start dirty, and its manifest says so.
    version = code_version(Path(__file__).resolve().parents[1])
    # (A --kinds subset is still treated as a full run: it is the first leg of one.)
    is_full_run = args.limit is None and args.per_kind is None and not args.dry_run
    if is_full_run:
        blocker = full_run_blocker(version)
        if blocker:
            print(blocker)
            return 2
    output_path = Path(args.output) if args.output else Path(cfg["index"]["enrichment_path"])

    base_dir = Path(cfg["index"]["base_dir"])
    if not (base_dir / "manifest.json").exists():
        print(f"Base index not found at {base_dir} -- build it first:")
        print("  python scripts/build_index.py --stage base --config " + args.config)
        return 1

    graph_cfg = cfg["graph"]
    missing = [
        p for p in (*_as_list(graph_cfg["attack_path"]), graph_cfg["cwe_path"], graph_cfg["capec_path"])
        if not Path(p).exists()
    ]
    if missing:
        print("Missing ontology source files -- see data/README.md for fetch steps:")
        for p in missing:
            print(f"  {p}")
        return 1

    graph = OntologyGraph.from_files(
        attack_path=graph_cfg["attack_path"],
        cwe_path=graph_cfg["cwe_path"],
        capec_path=graph_cfg["capec_path"],
        domains=graph_cfg.get("domains"),
    )
    df_lookup = LuceneDFLookup(base_dir)

    llm_cfg = cfg["llm"]
    backend = args.backend or llm_cfg["backend"]
    if backend not in {"ollama", "gemini"}:
        print(f"llm.backend={backend!r} is not supported (only 'ollama' and 'gemini').")
        return 1
    if backend == "gemini":
        if not args.model:
            print("--backend gemini needs an explicit --model (a pinned id, not a '-latest' alias).")
            return 1
        if args.cost_cap_usd is not None and (args.price_in is None or args.price_out is None):
            print("--cost-cap-usd needs --price-in and --price-out to turn tokens into dollars.")
            return 1
        load_env_file()     # GEMINI_API_KEY; names only are ever returned, values never printed

    model = args.model or llm_cfg["model"]

    corpus_cfg = cfg["corpus"]
    enrich_cfg = cfg["enrichment"]
    try:
        kinds = order_kinds(args.kinds, corpus_cfg["kinds"])
    except ValueError as exc:
        print(f"--kinds: {exc}")
        return 1

    # enrichment.max_new_tokens used to be read by nothing at all: the cap sat
    # in the config file while every reply was generated unbounded. It now
    # reaches Ollama as options.num_predict via the wrapper.
    max_new_tokens = enrich_cfg.get("max_new_tokens")

    # enrichment.json_mode: "schema" | "json" | "off". Only "schema" pins the
    # reply *shape*; plain "json" is valid-JSON-only and made qwen2.5:14b
    # answer with one object instead of an array (see REPLY_SCHEMA).
    json_mode_cfg = str(enrich_cfg.get("json_mode", "off")).lower()
    if json_mode_cfg not in {"schema", "json", "off", "true", "false"}:
        print(f"enrichment.json_mode={json_mode_cfg!r} must be one of: schema, json, off")
        return 1
    json_schema = REPLY_SCHEMA if json_mode_cfg == "schema" else None
    json_mode = json_mode_cfg in {"json", "true"}

    llm_seed = args.llm_seed if args.llm_seed is not None else cfg["eval"]["seed"]

    def client_factory():
        if backend == "gemini":
            return GeminiClient(
                model=model, temperature=llm_cfg.get("temperature", 0.0), seed=llm_seed,
                thinking_level=args.thinking_level, max_retries=llm_cfg.get("max_retries", 2),
                max_new_tokens=max_new_tokens, json_mode=json_mode, json_schema=json_schema,
            )
        return OllamaClient(
            model=model, host=llm_cfg.get("host"),
            temperature=llm_cfg.get("temperature", 0.0), max_retries=llm_cfg.get("max_retries", 2),
            seed=llm_cfg.get("seed"), num_ctx=llm_cfg.get("num_ctx"),
            max_new_tokens=max_new_tokens, json_mode=json_mode, json_schema=json_schema,
        )

    if args.no_name_check:
        name_overlap = None
    elif args.name_overlap is not None:
        name_overlap = args.name_overlap
    else:
        name_overlap = enrich_cfg.get("name_match_min_overlap")
    if args.per_kind is not None:
        seed = args.seed if args.seed is not None else cfg["eval"]["seed"]
        docs = sample_corpus(corpus_cfg["kb_dir"], kinds, per_kind=args.per_kind, seed=seed)
        sampling = {"method": "per_kind", "per_kind": args.per_kind, "seed": seed}
    else:
        docs = load_corpus(corpus_cfg["kb_dir"], kinds, limit=args.limit)
        sampling = {"method": "prefix", "limit": args.limit}

    print(
        f"Enriching -> {output_path}  (model={model}, dry_run={args.dry_run})\n"
        f"  prompt={PROMPT_VERSION}  name_check="
        + ("off" if name_overlap is None else f"overlap>={name_overlap}")
        + f"  max_new_tokens={max_new_tokens}  decoding={json_mode_cfg}"
    )
    concurrency = args.concurrency if args.concurrency is not None else enrich_cfg.get("concurrency", 1)
    # Sent on every Ollama request, so the manifest states them rather than
    # leaving the reader to assume the server's defaults.
    llm_settings = {
        "backend": "ollama", "temperature": llm_cfg.get("temperature", 0.0),
        "seed_sent": llm_cfg.get("seed"), "num_ctx": llm_cfg.get("num_ctx"),
    }
    on_record = None
    if backend == "gemini":
        if args.cost_cap_usd is not None and concurrency > 1:
            # Worker threads already in flight cannot be recalled, so the cap
            # is only a hard stop when documents go one at a time.
            print("--cost-cap-usd is only enforceable with --concurrency 1.")
            return 1

        def cost_usd(tokens: TokenUsage):
            if args.price_in is None or args.price_out is None:
                return None
            return (tokens.prompt * args.price_in + (tokens.completion + tokens.thinking) * args.price_out) / 1e6

        done_ids = set()
        if output_path.exists():
            from sira_cti.common import read_jsonl
            done_ids = {r.doc_id for r in read_jsonl(output_path)}
        n_pending = sum(1 for d in docs if d.doc_id not in done_ids)
        preflight = _gemini_preflight(
            client_factory(), docs[0], max_terms=enrich_cfg["max_terms_per_doc"], cost_usd=cost_usd,
        )
        if not preflight["ok"]:
            print("ABORTING before the run: " + preflight["verdict"])
            return 2
        spent = {"usd": preflight.get("cost_usd") or 0.0}
        if args.cost_cap_usd is not None:
            # Worst of the two preflight calls, per pending document, plus half
            # again for documents that think longer or need the JSON retry.
            estimate = spent["usd"] + 1.5 * n_pending * preflight["max_call_cost_usd"]
            print(f"  cost estimate: ${estimate:.3f} for {n_pending} documents (cap ${args.cost_cap_usd:.2f})")
            if estimate > args.cost_cap_usd:
                print("ABORTING before the run: the estimate is over the cap.")
                return 2

            def on_record(record):
                spent["usd"] += cost_usd(record.tokens) or 0.0
                if spent["usd"] > args.cost_cap_usd:
                    raise SystemExit(
                        f"ABORTED mid-run: spend ${spent['usd']:.3f} passed the cap "
                        f"${args.cost_cap_usd:.2f}. Records so far are kept in {output_path}."
                    )

        probe = client_factory()
        probe.last_model_version = preflight["model_version_reported"] or ""
        llm_settings = probe.describe()
        llm_settings["seed_honoured"] = preflight["seed_honoured"]
        llm_settings["seed_evidence"] = preflight["seed_evidence"]
        llm_settings["pricing_usd_per_1m"] = {"prompt": args.price_in, "output_incl_thinking": args.price_out}
        llm_settings["cost_cap_usd"] = args.cost_cap_usd
        llm_settings["preflight"] = {k: v for k, v in preflight.items() if k not in {"ok", "seed_honoured", "seed_evidence"}}

    try:
        summary = run_corpus_enrichment(
            docs,
            client_factory=client_factory,
            graph=graph,
            df_lookup=df_lookup,
            output_path=output_path,
            max_terms=enrich_cfg["max_terms_per_doc"],
            df_max_ratio=enrich_cfg["df_max_ratio"],
            allow_deprecated=graph_cfg.get("allow_deprecated", False),
            revoked_policy=graph_cfg.get("revoked_policy", "reject"),
            name_match_min_overlap=name_overlap,
            name_scorer=args.name_scorer or enrich_cfg.get("name_scorer", "v1"),
            name_match_min_jaccard=float(enrich_cfg.get("name_match_min_jaccard", 0.6)),
            json_retries=int(enrich_cfg.get("json_retries", 0)),
            record_json_failures=bool(enrich_cfg.get("record_json_failures", False)),
            max_new_tokens=max_new_tokens,
            json_mode=json_mode_cfg,
            max_doc_chars=enrich_cfg.get("max_doc_chars"),
            concurrency=concurrency,
            prompt_version=PROMPT_VERSION,
            config_hash=config_hash(args.config),
            corpus_kinds=kinds,
            sampling=sampling,
            llm_settings=llm_settings,
            code_version=version,
            allow_code_change=args.allow_code_change,
            dry_run=args.dry_run,
            on_record=on_record,
        )
    except ResumeMismatchError as exc:
        print(f"\n{exc}")
        return 2

    print(
        f"\n{summary.total_docs} docs total, {summary.already_done} already done, "
        f"{summary.processed} processed, {summary.failed} failed, "
        f"{summary.json_failures} unparseable, {summary.elapsed_s:.1f}s"
    )
    if backend == "gemini":
        t = summary.tokens
        line = f"  tokens this run: prompt {t.prompt}, completion {t.completion}, thinking {t.thinking}"
        run_cost = cost_usd(t)
        if run_cost is not None:
            line += f"  (~${run_cost:.3f}, plus ${preflight.get('cost_usd') or 0.0:.3f} preflight)"
        print(line)
    if summary.json_failures:
        print(
            "  (unparseable replies are written as reject_reason=llm_json_error; "
            f"the raw text is in {output_path.name}.raw_failures.jsonl)"
        )
    if summary.failures:
        print("Failures:")
        for doc_id, error in summary.failures[:10]:
            print(f"  {doc_id}: {error}")

    if not args.dry_run and output_path.exists():
        stats = summarize(output_path)
        print("\nAccept/reject summary (cumulative, whole file):")
        print(f"  accepted: {stats['accepted']}")
        print(f"  rejected: {stats['rejected']}")
        for reason, n in sorted(stats["rejected_by_reason"].items()):
            print(f"    {reason}: {n}")
        print(f"  repaired: {stats['repaired']}")
        rate = stats["staleness_rate"]
        print(f"  staleness_rate: {rate:.3f}" if rate is not None else "  staleness_rate: n/a")

        print("\nBy source document type:")
        for source, s in sorted(summarize_by_source(output_path).items()):
            print(f"  {source}: {s['docs']} docs, {s['proposed']} proposed, {s['accepted']} accepted")
            print(f"    rejected: {s['rejected_by_reason'] or '{}'}")
            print(f"    structural proposed by catalogue: {s['structural_proposed_by_namespace'] or '{}'}")
            print(f"    structural accepted by catalogue: {s['structural_accepted_by_namespace'] or '{}'}")

    return 0


def _gemini_preflight(client, doc, *, max_terms, cost_usd):
    """Ask for one document twice before spending on the whole sample.

    Two questions, one pair of calls. Did the full array come back, or did
    structured output collapse to a single object/short list the way plain
    JSON mode does? And are the two replies identical, i.e. is the seed
    actually honoured rather than merely accepted?
    """
    prompt = build_prompt(doc, max_terms=max_terms)
    replies, counts, call_costs = [], [], []
    for _ in range(2):
        before = len(client.log.records)
        raw = client.generate(prompt, system=SYSTEM_PROMPT, tag="preflight")
        replies.append(raw)
        try:
            parsed = parse_json_loose(raw)
            counts.append(len(parsed) if isinstance(parsed, list) else -1)
        except ValueError:
            counts.append(-2)
        call_costs.append(cost_usd(client.log.records[before].tokens) or 0.0)

    tokens = client.log.tokens
    # The prompt says "at most" max_terms, so 11 of 12 is a model choosing to
    # stop, not a collapse. A collapse is the plain-JSON-mode failure: one
    # object, or an array holding a term or two. Half the cap separates them.
    floor = max(2, max_terms // 2)
    ok = all(c >= floor for c in counts)
    identical = replies[0] == replies[1]
    shape = {-1: "not an array", -2: "unparseable"}
    seen = ", ".join(shape.get(c, f"{c} proposals") for c in counts)
    verdict = (
        f"a full array on both calls ({seen}; cap {max_terms}, collapse floor {floor})" if ok
        else f"the reply collapsed: asked for up to {max_terms}, got: {seen} (stop reason {client.last_stop_reason!r})"
    )
    print(
        f"Preflight on {doc.doc_id}: {seen}; replies identical: {identical}\n"
        f"  tokens: prompt {tokens.prompt}, completion {tokens.completion}, thinking {tokens.thinking}"
        f"  model_version={client.last_model_version or '?'}"
    )
    return {
        "ok": ok,
        "verdict": verdict,
        "doc_id": doc.doc_id,
        "calls": client.log.calls,
        "proposals_per_reply": counts,
        "tokens": tokens.to_dict(),
        "cost_usd": cost_usd(tokens),
        "max_call_cost_usd": max(call_costs),
        "model_version_reported": client.last_model_version or None,
        "seed_honoured": identical,
        "seed_evidence": (
            f"seed {client.seed} at temperature {client.temperature}: two identical requests for "
            f"{doc.doc_id} returned {'byte-identical' if identical else 'different'} replies"
        ),
    }


def _as_list(value):
    return [value] if isinstance(value, str) else list(value)


if __name__ == "__main__":
    raise SystemExit(main())
