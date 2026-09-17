#!/usr/bin/env python3
"""Command-line entry point for the SSH log triage tool.

Usage:
    python cli.py samples/demo_auth.log
    python cli.py /var/log/auth.log --threshold 15 --window 120 --html out/report.html
"""

from __future__ import annotations

import argparse
import datetime
import sys
import time

from src.detections import Analyzer, Config
from src.parser import ParseStats, parse_file
from src.report import render_console, write_csv, write_html


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-log-triage",
        description="Find SSH credential attacks in a Linux auth.log file.",
    )
    parser.add_argument("logfile", help="path to auth.log (plain text or .gz)")
    parser.add_argument(
        "--year", type=int, default=datetime.date.today().year,
        help="year to assume, since syslog timestamps omit it (default: current year)",
    )
    parser.add_argument("--threshold", type=int, default=10,
                        help="failed logins inside the window before an IP is flagged (default: 10)")
    parser.add_argument("--window", type=int, default=60,
                        help="sliding window in seconds (default: 60)")
    parser.add_argument("--spray-users", type=int, default=8,
                        help="distinct accounts that make a source look like a sprayer (default: 8)")
    parser.add_argument("--spray-attempts", type=int, default=4,
                        help="max attempts per account for spray classification (default: 4)")
    parser.add_argument("--compromise-window", type=int, default=300,
                        help="seconds before a success to look back for failures (default: 300)")
    parser.add_argument("--csv", metavar="PATH", help="also write findings to this CSV file")
    parser.add_argument("--html", metavar="PATH", help="also write an HTML report to this path")
    parser.add_argument("--quiet", action="store_true", help="suppress the console report")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    config = Config(
        burst_threshold=args.threshold,
        window_seconds=args.window,
        spray_min_users=args.spray_users,
        spray_max_per_user=args.spray_attempts,
        compromise_window=args.compromise_window,
    )

    stats = ParseStats()
    analyzer = Analyzer(config)

    started = time.perf_counter()
    try:
        for event in parse_file(args.logfile, args.year, stats):
            analyzer.feed(event)
    except FileNotFoundError:
        print(f"error: no such file: {args.logfile}", file=sys.stderr)
        return 2
    elapsed = time.perf_counter() - started

    findings = analyzer.findings()

    if not args.quiet:
        print(render_console(findings, stats))
        print(f"Parsed in {elapsed:.2f}s.")

    if args.csv:
        write_csv(findings, args.csv)
        print(f"CSV written to {args.csv}")
    if args.html:
        write_html(findings, stats, args.html, source=args.logfile)
        print(f"HTML report written to {args.html}")

    # Exit 1 when something high severity turned up, so the tool can be used in
    # a pipeline or a cron wrapper that cares about the result.
    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
