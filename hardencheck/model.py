"""Findings, severity and the rule shape every check shares."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

SEVERITIES = ("high", "medium", "low")
_RANK = {"high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class Rule:
    """One static check. `check` returns (line_no, evidence) pairs or nothing."""

    id: str
    title: str
    severity: str
    remediation: str
    kind: str                      # dockerfile | compose | k8s | sshd
    check: Callable = field(compare=False, default=None)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError("unknown severity {!r}".format(self.severity))


@dataclass
class Finding:
    rule: Rule
    path: str
    line_no: int
    evidence: str = ""

    @property
    def rank(self) -> int:
        return _RANK[self.rule.severity]

    def as_dict(self) -> Dict[str, object]:
        return {"rule": self.rule.id, "title": self.rule.title,
                "severity": self.rule.severity, "path": self.path,
                "line": self.line_no, "evidence": self.evidence,
                "remediation": self.rule.remediation}


def at_least(severity: str) -> int:
    return _RANK[severity]


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Worst first, then by file and line so output is stable between runs."""
    return sorted(findings, key=lambda f: (-f.rank, f.path, f.line_no, f.rule.id))
