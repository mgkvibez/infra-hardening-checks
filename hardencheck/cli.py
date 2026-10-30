"""hardencheck command line.

Exit codes are a contract: 0 nothing at or above the threshold, 3 findings,
2 a problem with the invocation itself.
"""

from __future__ import annotations

import argparse
import sys

from . import RULESET, __version__
from .model import SEVERITIES
from .report import render_json, render_sarif, render_text, summary_line
from .rules import BY_ID, RULES
from .scanner import scan_paths

EXIT_CLEAN, EXIT_USAGE, EXIT_FINDINGS = 0, 2, 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hardencheck",
                                description="Static hardening checks for Dockerfiles, compose files, manifests and sshd config.")
    p.add_argument("--version", action="version", version="hardencheck {} (ruleset {})".format(__version__, RULESET))
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="check files or directories")
    s.add_argument("paths", nargs="+")
    s.add_argument("--min-severity", choices=SEVERITIES, default="low")
    s.add_argument("--ignore", action="append", default=[], metavar="RULE_ID")
    s.add_argument("--json", action="store_true")
    s.add_argument("--sarif", action="store_true")
    s.add_argument("--no-colour", "--no-color", dest="no_colour", action="store_true")

    sub.add_parser("rules", help="list the ruleset")
    e = sub.add_parser("explain", help="why one rule exists and how to fix it")
    e.add_argument("rule_id")
    return p


def _cmd_rules() -> int:
    print("hardencheck ruleset {} ({} rules)".format(RULESET, len(RULES)))
    for r in RULES:
        print("  {} {:6} {:9} {}".format(r.id, r.severity, r.kind, r.title))
    return EXIT_CLEAN


def _cmd_explain(rule_id: str) -> int:
    rule = BY_ID.get(rule_id.upper())
    if rule is None:
        print("unknown rule {!r}; run 'hardencheck rules' for the list".format(rule_id), file=sys.stderr)
        return EXIT_USAGE
    print("{}  {}  [{}]".format(rule.id, rule.title, rule.severity))
    print("  applies to: {}".format(rule.kind))
    print("  fix: {}".format(rule.remediation))
    return EXIT_CLEAN


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None:
        parser.print_help()
        return EXIT_USAGE
    if args.cmd == "rules":
        return _cmd_rules()
    if args.cmd == "explain":
        return _cmd_explain(args.rule_id)

    findings, skipped = scan_paths(args.paths, args.min_severity, tuple(args.ignore))
    if args.sarif:
        print(render_sarif(findings))
    elif args.json:
        print(render_json(findings, skipped))
    else:
        print(render_text(findings, skipped, colour=not args.no_colour))
    return EXIT_FINDINGS if findings else EXIT_CLEAN


if __name__ == "__main__":      # so `python -m hardencheck.cli` works too
    raise SystemExit(main())
