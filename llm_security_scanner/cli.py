"""Command-line interface for the LLM Security Scanner."""

from __future__ import annotations

import argparse
import sys

from .attacks import CATEGORIES, load_all
from .classifier import classify_all
from .analyzer import analyze_all
from .config import Config
from .report import to_json, to_markdown
from .runner import run_tests
from .target import OpenAITarget


def _progress_callback(result):
    case = result.case
    status = "ERROR" if result.response.error else "done"
    print(f"  [{status}] {case.id} ({case.category_label})", file=sys.stderr)


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        config = Config.from_env(model=args.model)
    except EnvironmentError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    config.concurrency = args.concurrency
    categories = args.categories or list(CATEGORIES)
    cases = load_all(categories)

    if args.limit:
        cases = cases[: args.limit]

    print(
        f"Scanning model '{config.model}' with {len(cases)} attack case(s) "
        f"across {len(categories)} categor{'y' if len(categories) == 1 else 'ies'}...",
        file=sys.stderr,
    )

    target = OpenAITarget(config, system_prompt=args.system_prompt)
    results = run_tests(
        target, cases, concurrency=config.concurrency, on_result=_progress_callback
    )
    findings = analyze_all(results)
    classified = classify_all(findings)

    if args.format == "json":
        output = to_json(classified, config.model)
    else:
        output = to_markdown(classified, config.model)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"\nReport written to {args.output}", file=sys.stderr)
    else:
        print(output)

    flagged_count = sum(1 for c in classified if c.finding.flagged)
    print(
        f"\nDone. {flagged_count} potential vulnerabilit{'y' if flagged_count == 1 else 'ies'} flagged "
        f"out of {len(classified)} tests.",
        file=sys.stderr,
    )
    return 0


def cmd_list_categories(_args: argparse.Namespace) -> int:
    for key, label in CATEGORIES.items():
        cases = load_all([key])
        print(f"{key:24s} {label:35s} ({len(cases)} test cases)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-scan",
        description="Automated security scanner for OpenAI-compatible chat models.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a security scan against a target model.")
    scan_parser.add_argument(
        "--model", default="gpt-4o-mini", help="Target model name (default: gpt-4o-mini)."
    )
    scan_parser.add_argument(
        "--categories",
        nargs="+",
        choices=list(CATEGORIES),
        help="Attack categories to run (default: all).",
    )
    scan_parser.add_argument(
        "--system-prompt",
        default=None,
        help="Optional system prompt to give the target, to test leakage/override resistance.",
    )
    scan_parser.add_argument(
        "--limit", type=int, default=None, help="Limit number of attack cases (useful for a quick smoke test)."
    )
    scan_parser.add_argument(
        "--concurrency", type=int, default=5, help="Number of concurrent requests (default: 5)."
    )
    scan_parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Report format (default: markdown)."
    )
    scan_parser.add_argument(
        "--output", "-o", default=None, help="Write report to this file instead of stdout."
    )
    scan_parser.set_defaults(func=cmd_scan)

    list_parser = subparsers.add_parser("list-categories", help="List available attack categories.")
    list_parser.set_defaults(func=cmd_list_categories)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
