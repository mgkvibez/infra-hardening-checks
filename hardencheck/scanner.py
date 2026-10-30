"""Decide what a file is, then run only the rules for that kind."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .model import Finding, Rule, sort_findings
from .rules import for_kind

MAX_BYTES = 2_000_000


def detect_kind(path: Path, text: str) -> Optional[str]:
    name = path.name.lower()
    suffix = path.suffix.lower()
    stem = name.split(".", 1)[0]
    # A stem match catches the real-world spellings: Dockerfile.bad, sshd_config.ci
    if stem in ("dockerfile", "containerfile") or name.endswith(".dockerfile"):
        return "dockerfile"
    if stem.startswith(("docker-compose", "compose")) and suffix in (".yml", ".yaml"):
        return "compose"
    if suffix in (".yml", ".yaml"):
        head = "\n".join(text.splitlines()[:40])
        if "apiVersion:" in head and "kind:" in head:
            return "k8s"
        if "services:" in head:
            return "compose"
        return None
    if stem.startswith(("sshd_config", "sshd-config")) or name.endswith(".sshd"):
        return "sshd"
    return None


def scan_text(path: str, kind: str, text: str, rules: Optional[List[Rule]] = None) -> List[Finding]:
    lines = text.splitlines()
    out: List[Finding] = []
    for rule in (rules if rules is not None else for_kind(kind)):
        for line_no, evidence in rule.check(lines):
            out.append(Finding(rule=rule, path=path, line_no=line_no, evidence=evidence))
    return out


def iter_files(paths: Iterable[str]) -> List[Path]:
    found: List[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for root, _dirs, files in os.walk(p):
                for name in files:
                    found.append(Path(root) / name)
        elif p.is_file():
            found.append(p)
    return sorted(found)


def scan_paths(paths: Iterable[str], min_severity: str = "low",
               ignore: Tuple[str, ...] = ()) -> Tuple[List[Finding], List[str]]:
    """Return findings plus a note for every file that was skipped and why."""
    findings: List[Finding] = []
    skipped: List[str] = []
    threshold = {"low": 1, "medium": 2, "high": 3}[min_severity]
    for path in iter_files(paths):
        try:
            if path.stat().st_size > MAX_BYTES:
                skipped.append("{}: larger than {} bytes".format(path, MAX_BYTES))
                continue
            text = path.read_text(errors="replace")
        except OSError as exc:
            skipped.append("{}: {}".format(path, exc))
            continue
        kind = detect_kind(path, text)
        if kind is None:
            skipped.append("{}: not a Dockerfile, compose, manifest or sshd config".format(path))
            continue
        for finding in scan_text(str(path), kind, text):
            if finding.rule.id in ignore or finding.rank < threshold:
                continue
            findings.append(finding)
    return sort_findings(findings), skipped
