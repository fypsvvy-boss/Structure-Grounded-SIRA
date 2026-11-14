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

``--gemini-api vertex`` sends the same requests through Google Cloud's Vertex
AI instead, billed to ``GOOGLE_CLOUD_PROJECT`` and signed in with
application-default credentials (``gcloud auth application-default login``);
no key is used. Without the flag, ``GOOGLE_GENAI_USE_VERTEXAI=True`` in
``.env`` picks Vertex too. The manifest records which route ran, plus the
project id and location.

Batch mode (``--batch``, Vertex only): the same requests sent as a Vertex AI
batch job at half the online price. The requests file goes to a private Cloud
Storage bucket (``--batch-bucket``; created once with ``--batch-create-bucket``),
the job is polled until it finishes, and its replies are then run through the
normal pipeline -- same prompts, truncation, JSON retry, gates, records and
manifest -- by a client that answers from the results instead of the network.
A reply that needs the JSON retry gets its follow-up prompt in a second, small
round. The manifest says ``"service": "vertex-batch"``, so a batch file can
never be resumed or merged together with an online one. State is kept beside
the output in ``<output>.batch/``; stopping while a job is queued is safe --
the same command picks the same job up again and never submits it twice.
No preflight (it would be billed at the online price): every reply is checked
for the collapse afterwards instead, and the seed is not tested.

    python scripts/enrich_corpus.py --per-kind 10 --backend gemini --gemini-api vertex --batch \
        --model gemini-3.1-pro-preview --thinking-level low \
        --price-in 1.00 --price-out 6.00 --cost-cap-usd 0.50 \
        --output indexes/enrichment/corpus_stratified_v4_gemini-3.1-pro_vertexbatch.jsonl

The cost cap covers the whole output file, not one session: on a resume, the
cost of the records already in the file is counted first.

Resumable: re-running with the same ``--output`` skips documents already in
that file and only retries ones that previously failed to parse. Give a
sampled run its own ``--output`` -- resuming a different sample into the same
file mixes two populations.

Split across two GPUs (``docs/kaggle-run.md``). ``--shard I/N`` keeps only the
documents whose id hashes into slice I of N, so processes given different I
never overlap; each needs its own ``--output`` and its own Ollama server
(``--host``). ``--stop-after-minutes`` ends a session cleanly before a
time-limited machine is switched off. ``scripts/merge_enrichment.py`` joins
the files afterwards.

    python scripts/enrich_corpus.py --model qwen2.5:14b --name-scorer v2 \
        --kinds cwe,capec,attack,cve --shard 1/2 --host http://127.0.0.1:11434 \
        --stop-after-minutes 660 --output out/corpus_full_v4_14b.shard1of2.jsonl
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sira_cti.common import (
    GEMINI_APIS, GeminiClient, LLMError, OllamaClient, RejectReason, TokenUsage, code_version, config_hash,
    full_run_blocker, gemini_api_from_env, load_config, load_env_file, machine_info, read_jsonl,
)
from sira_cti.common import vertex_batch as vb
from sira_cti.common.llm import parse_json_loose
from sira_cti.enrichment.corpus_side import (
    ResumeMismatchError, run_corpus_enrichment, summarize, summarize_by_source, truncate_document,
)
from sira_cti.enrichment.prompts.corpus_side import PROMPT_VERSION, REPLY_SCHEMA, SYSTEM_PROMPT, build_prompt
from sira_cti.graph import OntologyGraph
from sira_cti.index import (
    LuceneDFLookup, load_corpus, order_kinds, parse_shard, sample_corpus, shard_corpus, source_of_kind,
)


def main() -> int:
    launched = time.monotonic()     # --stop-after-minutes counts from here, set-up included
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--output", default=None, help="defaults to config's index.enrichment_path")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--limit", type=int, default=None, help="first N documents in load order (CVE-only below 3,011)")
    selection.add_argument("--per-kind", type=int, default=None, help="seeded random N documents from each type")
    selection.add_argument("--doc-ids", default=None,
                           help="exactly these documents, comma-separated (e.g. a slice of an earlier sample)")
    parser.add_argument("--seed", type=int, default=None, help="sampling seed for --per-kind (default: eval.seed)")
    parser.add_argument(
        "--kinds", default=None,
        help="document types to process, in this order, e.g. cwe,capec,attack,cve "
             "(default: config's corpus.kinds, in its order). Safe to change when resuming",
    )
    parser.add_argument(
        "--shard", default=None, metavar="I/N",
        help="process only slice I of N of the selected documents, e.g. 1/2. Slices are chosen by a "
             "hash of the document id, so they never overlap. Use a separate --output per slice",
    )
    parser.add_argument(
        "--host", default=None,
        help="override config's llm.host (ollama only), e.g. http://127.0.0.1:11435 for a second server",
    )
    parser.add_argument(
        "--stop-after-minutes", type=float, default=None, metavar="N",
        help="start no new document once N minutes have passed since launch; the one in progress is "
             "finished and written. Resume with the same command. Default: no limit",
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
    parser.add_argument(
        "--gemini-api", choices=[a.replace("_", "-") for a in GEMINI_APIS], default=None,
        help="gemini only: 'vertex' (Google Cloud, application-default credentials) or 'ai-studio' "
             "(GEMINI_API_KEY); default: vertex if GOOGLE_GENAI_USE_VERTEXAI is true in .env",
    )
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
    batch = parser.add_argument_group("batch mode (gemini on vertex only)")
    batch.add_argument("--batch", action="store_true",
                       help="send the requests as a Vertex AI batch job (half price, not immediate)")
    batch.add_argument("--batch-bucket", default=None,
                       help="Cloud Storage bucket for request and result files (default: <project>-sira-batch)")
    batch.add_argument("--batch-create-bucket", action="store_true",
                       help="create the bucket (private) if it does not exist")
    batch.add_argument("--batch-bucket-location", default="US-CENTRAL1", help="location for a new bucket")
    batch.add_argument("--batch-dir", default=None, help="local state folder (default: <output>.batch)")
    batch.add_argument("--batch-poll-seconds", type=float, default=30.0)
    batch.add_argument("--batch-max-wait-hours", type=float, default=30.0,
                       help="stop waiting after this long; the same command resumes waiting for the same job")
    batch.add_argument("--batch-est-output-tokens", type=int, default=1200,
                       help="reply + thinking tokens per request assumed by the pre-submit cost check "
                            "(online Vertex sample mean: 808)")
    batch.add_argument("--batch-rounds", type=int, default=3,
                       help="most batch rounds per invocation (round 2+ carries JSON-retry prompts)")
    args = parser.parse_args()

    cfg = load_config(args.config)

    # Which commit is about to run. A full-corpus run takes days and cannot be
    # cheaply redone, so it may only start from committed code; a sample run
    # may start dirty, and its manifest says so.
    version = code_version(Path(__file__).resolve().parents[1])
    # (A --kinds subset is still treated as a full run: it is the first leg of one.)
    is_full_run = args.limit is None and args.per_kind is None and args.doc_ids is None and not args.dry_run
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
        load_env_file()     # key or Cloud project; names only are ever returned, values never printed
    gemini_api = gemini_api_from_env(args.gemini_api) if backend == "gemini" else None
    if args.batch:
        problem = (
            "--batch needs --backend gemini" if backend != "gemini"
            else "--batch runs on Vertex AI only (--gemini-api vertex)" if gemini_api != "vertex"
            else "--batch cannot be a --dry-run (a batch job is billed)" if args.dry_run
            else "--batch needs --price-in, --price-out and --cost-cap-usd (the cap is checked before submitting)"
            if None in (args.price_in, args.price_out, args.cost_cap_usd)
            else "--batch ignores --stop-after-minutes; use --batch-max-wait-hours" if args.stop_after_minutes
            else None
        )
        if problem:
            print(problem)
            return 1

    model = args.model or llm_cfg["model"]

    corpus_cfg = cfg["corpus"]
    enrich_cfg = cfg["enrichment"]
    try:
        kinds = order_kinds(args.kinds, corpus_cfg["kinds"])
    except ValueError as exc:
        print(f"--kinds: {exc}")
        return 1
    try:
        shard = parse_shard(args.shard)
    except ValueError as exc:
        print(f"--shard: {exc}")
        return 1
    if args.stop_after_minutes is not None and args.stop_after_minutes <= 0:
        print("--stop-after-minutes must be greater than 0.")
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
                model=model, api=gemini_api, temperature=llm_cfg.get("temperature", 0.0), seed=llm_seed,
                thinking_level=args.thinking_level, max_retries=llm_cfg.get("max_retries", 2),
                max_new_tokens=max_new_tokens, json_mode=json_mode, json_schema=json_schema,
            )
        return OllamaClient(
            model=model, host=args.host or llm_cfg.get("host"),
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
    elif args.doc_ids is not None:
        try:
            docs, sampling = select_doc_ids(load_corpus(corpus_cfg["kb_dir"], kinds), args.doc_ids)
        except ValueError as exc:
            print(f"--doc-ids: {exc}")
            return 1
    else:
        docs = load_corpus(corpus_cfg["kb_dir"], kinds, limit=args.limit)
        sampling = {"method": "prefix", "limit": args.limit}
    # The slice is taken last, from whatever was selected above, so the
    # slices of one selection always add up to exactly that selection.
    docs = list(shard_corpus(docs, shard))

    # Which machine, and which exact weights. The model name is only a label;
    # the digest is what shows a second machine pulled the same file.
    machine = machine_info()
    model_digest = None
    if backend == "ollama":
        probe = client_factory()
        try:
            model_digest = probe.model_digest()
            machine["ollama_version"] = probe.server_version()
        except LLMError as exc:
            print(f"Cannot read the model digest: {exc}")
            return 1
        if model_digest is None:
            print(f"The Ollama server at {probe.host} has no model named {model!r} -- pull it first.")
            return 1
        machine["ollama_host"] = probe.host

    print(
        f"Enriching -> {output_path}  (model={model}, dry_run={args.dry_run})\n"
        f"  prompt={PROMPT_VERSION}  name_check="
        + ("off" if name_overlap is None else f"overlap>={name_overlap}")
        + f"  max_new_tokens={max_new_tokens}  decoding={json_mode_cfg}\n"
        f"  documents={len(docs)}" + (f"  shard={shard[0]}/{shard[1]}" if shard else "")
        + (f"  model_digest={model_digest[:12]}" if model_digest else "")
        + (f"  stop_after={args.stop_after_minutes:g}min" if args.stop_after_minutes is not None else "")
    )
    concurrency = args.concurrency if args.concurrency is not None else enrich_cfg.get("concurrency", 1)
    # Sent on every Ollama request, so the manifest states them rather than
    # leaving the reader to assume the server's defaults.
    llm_settings = {
        "backend": "ollama", "temperature": llm_cfg.get("temperature", 0.0),
        "seed_sent": llm_cfg.get("seed"), "num_ctx": llm_cfg.get("num_ctx"),
    }
    on_record = None
    before_first_call = None
    batch_state = None
    if args.batch:
        concurrency = 1     # replies come from a file; threads would only reorder the output
        try:
            template = client_factory()
        except LLMError as exc:
            print(f"Cannot set up the Gemini client: {exc}")
            return 1
        try:
            batch_state = _setup_batch(args, template=template, model=model, docs=docs,
                                       output_path=output_path, enrich_cfg=enrich_cfg)
        except LLMError as exc:
            print(f"Cannot set up batch mode: {exc}")
            return 1
        if batch_state is None:
            return 1
        client_factory = batch_state["client_factory"]
        before_first_call = batch_state["before_first_call"]
        llm_settings = batch_state["llm_settings"]
    elif backend == "gemini":
        if args.cost_cap_usd is not None and concurrency > 1:
            # Worker threads already in flight cannot be recalled, so the cap
            # is only a hard stop when documents go one at a time.
            print("--cost-cap-usd is only enforceable with --concurrency 1.")
            return 1

        def cost_usd(tokens: TokenUsage):
            if args.price_in is None or args.price_out is None:
                return None
            return (tokens.prompt * args.price_in + (tokens.completion + tokens.thinking) * args.price_out) / 1e6

        try:
            first = client_factory()
        except LLMError as exc:
            print(f"Cannot set up the Gemini client: {exc}")
            return 1
        route = first.describe()
        print(f"  gemini route: {route['provider']}"
              + (f"  project={first.project} location={first.location}" if first.api == "vertex" else ""))
        done_ids, already_usd = spend_in_file(output_path, cost_usd)
        n_pending = sum(1 for d in docs if d.doc_id not in done_ids)
        if done_ids:
            print(f"  resuming: {len(done_ids)} documents already in the file"
                  + (f", ~${already_usd:.3f} spent on them (counted against the cap)" if already_usd else ""))
        # The cap is for the whole output file: what earlier sessions spent on
        # it counts, so a restart cannot quietly hand out a fresh budget.
        spent = {"usd": already_usd}
        preflight: dict = {}

        # What the manifest records about the backend. Filled in further by
        # the preflight, which runs inside the enrichment call below -- after
        # the resume check, so a refused resume or a finished file costs nothing.
        llm_settings = route
        llm_settings["pricing_usd_per_1m"] = {"prompt": args.price_in, "output_incl_thinking": args.price_out}
        llm_settings["cost_cap_usd"] = args.cost_cap_usd
        llm_settings["cost_cap_scope"] = "whole output file (earlier sessions' records counted)"

        def before_first_call():
            preflight.update(_gemini_preflight(
                first, docs[0], max_terms=enrich_cfg["max_terms_per_doc"], cost_usd=cost_usd,
            ))
            if not preflight["ok"]:
                print("ABORTING before the run: " + preflight["verdict"])
                raise SystemExit(2)
            spent["usd"] += preflight.get("cost_usd") or 0.0
            if args.cost_cap_usd is not None:
                # Worst of the two preflight calls, per pending document, plus
                # half again for documents that think longer or need the JSON retry.
                estimate = spent["usd"] + 1.5 * n_pending * preflight["max_call_cost_usd"]
                print(f"  cost estimate: ${estimate:.3f} for the file, {n_pending} documents still to do "
                      f"(cap ${args.cost_cap_usd:.2f})")
                if estimate > args.cost_cap_usd:
                    print("ABORTING before the run: the estimate is over the cap.")
                    raise SystemExit(2)
            llm_settings["model_version_reported"] = preflight["model_version_reported"]
            llm_settings["seed_honoured"] = preflight["seed_honoured"]
            llm_settings["seed_evidence"] = preflight["seed_evidence"]
            llm_settings["preflight"] = {
                k: v for k, v in preflight.items() if k not in {"ok", "seed_honoured", "seed_evidence"}
            }

        if args.cost_cap_usd is not None:
            def on_record(record):
                spent["usd"] += cost_usd(record.tokens) or 0.0
                if spent["usd"] > args.cost_cap_usd:
                    raise SystemExit(
                        f"ABORTED mid-run: spend ${spent['usd']:.3f} passed the cap "
                        f"${args.cost_cap_usd:.2f}. Records so far are kept in {output_path}."
                    )

    passes = args.batch_rounds if batch_state else 1
    for pass_no in range(1, passes + 1):
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
                model_digest=model_digest,
                shard=shard,
                machine=machine,
                stop_after_s=(
                    None if args.stop_after_minutes is None
                    else max(0.0, args.stop_after_minutes * 60 - (time.monotonic() - launched))
                ),
                dry_run=args.dry_run,
                on_record=on_record,
                before_first_call=before_first_call,
            )
        except ResumeMismatchError as exc:
            print(f"\n{exc}")
            return 2
        if not batch_state or not summary.remaining:
            break
        store, missing = batch_state["store"], batch_state["missing"]
        if not any(key not in store for key in missing):
            break
        if pass_no < passes:
            print(f"\n{summary.remaining} documents need a reply to a follow-up prompt: next batch round.")

    print(
        f"\n{summary.total_docs} docs total, {summary.already_done} already done, "
        f"{summary.processed} processed, {summary.failed} failed, "
        f"{summary.json_failures} unparseable, {summary.elapsed_s:.1f}s"
    )
    if summary.stopped_early:
        print(
            f"STOPPED AT THE TIME LIMIT ({args.stop_after_minutes:g} min): {summary.remaining} documents "
            "still to do. Nothing is lost -- run the same command again to carry on."
        )
    elif not summary.remaining:
        print("COMPLETE: every selected document has a record.")
    if batch_state:
        store = batch_state["store"]
        b = store.billed
        print(f"  billed, all batch rounds: prompt {b.prompt}, completion {b.completion}, thinking {b.thinking}"
              f"  (~${vb.cost_usd(b, args.price_in, args.price_out):.3f} over {store.lines} result lines, "
              f"{len(store.errors)} failed)")
        for r in batch_state["runner"].rounds:
            print(f"  round {r['round']}: {r['requests']} requests, {r.get('state')}, "
                  f"created {r.get('create_time')}, started {r.get('start_time')}, ended {r.get('end_time')}")
        print(f"  thinking level as echoed in the results: {store.thinking_levels_echoed()}")
        if output_path.exists():
            print("  " + collapse_line(output_path, enrich_cfg["max_terms_per_doc"]))
    elif backend == "gemini":
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
        for line in by_source_lines(output_path, kinds):
            print(line)

    return 0


def _setup_batch(args, *, template, model, docs, output_path, enrich_cfg):
    """Everything batch mode swaps in: a replaying client, a submit-and-wait hook, the manifest block.

    Returns ``None`` (after printing why) when the bucket is missing and may
    not be created.
    """
    bucket = args.batch_bucket or f"{template.project}-sira-batch"
    batch_dir = Path(args.batch_dir) if args.batch_dir else output_path.with_suffix(output_path.suffix + ".batch")
    gcs = vb.GcsClient()
    if not gcs.bucket_exists(bucket):
        if not args.batch_create_bucket:
            print(f"Cloud Storage bucket {bucket!r} does not exist. Add --batch-create-bucket to create it "
                  "(private), or name an existing one with --batch-bucket.")
            return None
        gcs.create_bucket(bucket, project=template.project, location=args.batch_bucket_location)
        print(f"  created private bucket gs://{bucket} ({args.batch_bucket_location})")
    runner = vb.VertexBatchRunner(
        sdk=template._sdk, gcs=gcs, model=model, bucket=bucket,
        prefix=f"sira-batch/{output_path.stem}", batch_dir=batch_dir,
        poll_s=args.batch_poll_seconds, max_wait_s=args.batch_max_wait_hours * 3600,
    )
    store = vb.ReplyStore(batch_dir)
    missing: dict = {}
    cap = args.cost_cap_usd
    max_terms = enrich_cfg["max_terms_per_doc"]
    max_doc_chars = enrich_cfg.get("max_doc_chars")

    def billed_usd() -> float:
        return vb.cost_usd(store.billed, args.price_in, args.price_out)

    llm_settings = template.describe()
    llm_settings.update({
        "service": vb.SERVICE,
        "provider": vb.PROVIDER,
        "seed_honoured": None,
        "seed_evidence": "not measured: a batch run makes no duplicate calls",
        "pricing_usd_per_1m": {"prompt": args.price_in, "output_incl_thinking": args.price_out},
        "cost_cap_usd": cap,
        "cost_cap_scope": "every batch round for this output file (billed tokens of all result lines), "
                          "checked before each submission",
    })
    print(f"  gemini route: {vb.PROVIDER}  project={template.project} location={template.location}\n"
          f"  batch: bucket gs://{bucket}, state in {batch_dir}")

    def client_factory():
        return vb.BatchReplayClient(model, store, missing=missing)

    def needed() -> dict:
        """First-attempt prompts of documents not yet in the file, plus follow-ups asked for, minus answered."""
        done = {r.doc_id for r in read_jsonl(output_path)} if output_path.exists() else set()
        need: dict = {}
        for doc in docs:
            if doc.doc_id in done:
                continue
            prompt = build_prompt(truncate_document(doc, max_doc_chars)[0], max_terms=max_terms)
            key = vb.prompt_key(SYSTEM_PROMPT, prompt)
            if key not in store:
                need[key] = (SYSTEM_PROMPT, prompt)
        for key, value in missing.items():
            if key not in store:
                need[key] = value
        return need

    def before_first_call():
        try:
            for entry in runner.open_rounds():
                print(f"  batch round {entry['round']} was submitted earlier: waiting for it, not resubmitting")
                runner.wait(entry)
            store.reload()
            need = needed()
            if need:
                estimate = vb.estimate_request_cost(
                    need.values(), price_in=args.price_in, price_out=args.price_out,
                    output_tokens=args.batch_est_output_tokens,
                )
                print(f"  next batch round: {len(need)} requests, estimate ${estimate:.3f}; "
                      f"billed so far ${billed_usd():.3f} (cap ${cap:.2f})")
                if billed_usd() + estimate > cap:
                    print("ABORTING before submitting: the estimate is over the cap.")
                    raise SystemExit(2)
                entry = runner.submit([vb.build_request(template, p, s) for s, p in need.values()])
                runner.wait(entry)
                store.reload()
        except vb.BatchJobTimeout as exc:
            print(f"\nSTOPPED WAITING: {exc}")
            raise SystemExit(3)
        except LLMError as exc:
            print(f"\nBatch failed: {exc}")
            raise SystemExit(1)
        llm_settings["model_version_reported"] = ", ".join(store.model_versions()) or None
        llm_settings["batch"] = {
            **runner.summary(),
            "thinking_level_echoed": store.thinking_levels_echoed(),
            "result_lines": store.lines,
            "failed_lines": len(store.errors),
            "billed_tokens": store.billed.to_dict(),
            "billed_usd": round(billed_usd(), 6),
        }
        if billed_usd() > cap:
            print(f"WARNING: billed ${billed_usd():.3f} is over the cap ${cap:.2f}. That is already spent; "
                  "no further round will be submitted.")

    return {
        "client_factory": client_factory, "before_first_call": before_first_call,
        "llm_settings": llm_settings, "store": store, "missing": missing, "runner": runner,
    }


def select_doc_ids(docs, spec: str):
    """The documents named in ``spec`` (comma-separated), in corpus order, and the sampling record.

    Raises ``ValueError`` naming any id the corpus does not have, so a typo
    cannot quietly shrink a paid run.
    """
    wanted = [i.strip() for i in spec.split(",") if i.strip()]
    if not wanted:
        raise ValueError("no ids given")
    chosen = [d for d in docs if d.doc_id in set(wanted)]
    unknown = sorted(set(wanted) - {d.doc_id for d in chosen})
    if unknown:
        raise ValueError(f"not in the corpus (or not in --kinds): {', '.join(unknown)}")
    return chosen, {"method": "ids", "ids": sorted(wanted)}


def collapse_line(output_path: Path, max_terms: int) -> str:
    """How many proposals each reply held, flagging the single-object collapse.

    Same floor as the online preflight: fewer than half the cap (at least 2)
    is a collapse, not a model choosing to stop early.
    """
    floor = max(2, max_terms // 2)
    counts: list[int] = []
    unparseable: list[str] = []
    low: list[str] = []
    for record in read_jsonl(output_path):
        if any(t.reject_reason is RejectReason.LLM_JSON_ERROR for t in record.proposed_terms):
            unparseable.append(record.doc_id)
            continue
        n = len(record.proposed_terms)
        counts.append(n)
        if n < floor:
            low.append(f"{record.doc_id} ({n})")
    if not counts:
        return f"proposals per reply: none parsed; unparseable {unparseable}"
    counts.sort()
    return (
        f"proposals per reply: min {counts[0]}, median {counts[len(counts) // 2]}, max {counts[-1]} "
        f"over {len(counts)} replies; below the collapse floor ({floor}): {low or 'none'}; "
        f"unparseable: {unparseable or 'none'}"
    )


def spend_in_file(output_path: Path, cost_usd) -> tuple[set[str], float]:
    """The documents already in ``output_path`` and what they cost, in dollars.

    Read from each record's own token counts, so it is exact for the
    documents and leaves out only the two-call preflight of earlier sessions
    (about $0.025 each at list price). 0.0 when no prices were given.
    """
    if not output_path.exists():
        return set(), 0.0
    done: set[str] = set()
    total = 0.0
    for record in read_jsonl(output_path):
        done.add(record.doc_id)
        total += cost_usd(record.tokens) or 0.0
    return done, total


def by_source_lines(output_path: Path, kinds) -> list[str]:
    """The per-type block of the end-of-run summary, one entry for every kind.

    Ordered as ``kinds`` (corpus_kb file names, ``mitre`` for ATT&CK), each
    shown under its record ``source`` name. A kind with no records yet is
    printed as 0 rather than left out, so a missing kind is visible; a source
    in the file that ``kinds`` does not name is appended at the end.
    """
    stats = summarize_by_source(output_path)
    order = [source_of_kind(k).value for k in kinds]
    order += sorted(set(stats) - set(order))
    lines: list[str] = []
    for source in order:
        s = stats.get(source)
        if s is None:
            lines.append(f"  {source}: 0 docs")
            continue
        lines.append(f"  {source}: {s['docs']} docs, {s['proposed']} proposed, {s['accepted']} accepted")
        lines.append(f"    rejected: {s['rejected_by_reason'] or '{}'}")
        lines.append(f"    structural proposed by catalogue: {s['structural_proposed_by_namespace'] or '{}'}")
        lines.append(f"    structural accepted by catalogue: {s['structural_accepted_by_namespace'] or '{}'}")
    return lines


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
