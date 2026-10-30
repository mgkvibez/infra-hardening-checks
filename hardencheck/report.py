"""Three ways to read a result: for a human, for a script, for code scanning."""

from __future__ import annotations

import json
from typing import Dict, List

from . import RULESET, __version__
from .model import Finding

SEV_COLOUR = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"


def summary_line(findings: List[Finding]) -> str:
    counts: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.rule.severity] += 1
    if not findings:
        # Deliberate wording: absence of findings is a fact about the ruleset, not a verdict.
        return "No issues found by ruleset {}".format(RULESET)
    return "{} finding(s): {} high, {} medium, {} low (ruleset {})".format(
        len(findings), counts["high"], counts["medium"], counts["low"], RULESET)


def render_text(findings: List[Finding], skipped: List[str] = (), colour: bool = True) -> str:
    def paint(text: str, code: str) -> str:
        return "{}{}{}".format(code, text, RESET) if colour else text

    out = [paint("hardencheck {}  {}".format(__version__, RULESET), DIM), ""]
    current = None
    if not findings:
        out.append(summary_line(findings))
    grouped = {}
    for f in findings:
        grouped.setdefault(f.path, []).append(f)
    for f in [x for path in sorted(grouped) for x in sorted(grouped[path], key=lambda y: (-y.rank, y.line_no, y.rule.id))]:
        if f.path != current:
            out.extend(["", paint(f.path, BOLD)])
            current = f.path
        where = "line {}".format(f.line_no) if f.line_no else "file"
        out.append("  {} {}  {} {}".format(
            paint(f.rule.severity.upper().ljust(6), SEV_COLOUR[f.rule.severity]),
            f.rule.id, f.rule.title, paint("({})".format(where), DIM)))
        if f.evidence:
            out.append("      {}".format(paint(f.evidence[:120], DIM)))
        out.append("      fix: {}".format(f.rule.remediation))
    if findings:
        out.extend(["", summary_line(findings)])
    if skipped:
        out.extend(["", paint("skipped:", DIM)] + ["  " + s for s in skipped])
    out.append(paint('Findings are bounded by ruleset {}: "none found" is not "safe".'.format(RULESET), DIM))
    return "\n".join(out)


def render_json(findings: List[Finding], skipped: List[str] = ()) -> str:
    return json.dumps({"tool": "hardencheck", "version": __version__, "ruleset": RULESET,
                       "summary": summary_line(findings),
                       "findings": [f.as_dict() for f in findings],
                       "skipped": list(skipped)}, indent=2)


def render_sarif(findings: List[Finding]) -> str:
    """Minimal SARIF 2.1.0 so GitHub code scanning can ingest the results."""
    levels = {"high": "error", "medium": "warning", "low": "note"}
    rules, seen = [], set()
    for f in findings:
        if f.rule.id in seen:
            continue
        seen.add(f.rule.id)
        rules.append({"id": f.rule.id, "name": f.rule.title,
                      "shortDescription": {"text": f.rule.title},
                      "help": {"text": f.rule.remediation},
                      "properties": {"severity": f.rule.severity}})
    results = []
    for f in findings:
        region = {"startLine": f.line_no} if f.line_no else {"startLine": 1}
        results.append({
            "ruleId": f.rule.id,
            "level": levels[f.rule.severity],
            "message": {"text": "{} {}".format(f.rule.title, "- " + f.evidence if f.evidence else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path},
                "region": region}}],
        })
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
           "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "hardencheck", "version": __version__,
                                         "rules": rules}},
                     "results": results}]}
    return json.dumps(doc, indent=2)
