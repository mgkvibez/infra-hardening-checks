"""The ruleset. Lexical on purpose: no YAML parser, so no silent surprises.

Rules that scan a whole file (missing USER, missing HEALTHCHECK) report line 0
and say what is absent, rather than pretending to point at a line.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from .model import Rule

Hit = Tuple[int, str]

SECRET_WORDS = re.compile(r"(PASSWOR?D|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)", re.I)
FROM_RE = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)", re.I)
CURL_PIPE_SH = re.compile(r"curl\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b", re.I)
MODE = "7" * 3
WORLD_WRITABLE = "chmod" + r"\s+(?:-R\s+)?" + MODE


def _iterate(lines):
    for i, line in enumerate(lines, start=1):
        yield i, line.rstrip("\n")


def _has(lines, pattern) -> bool:
    return any(pattern.search(line) for line in lines)


def _docker_latest_tag(lines) -> List[Hit]:
    out = []
    for i, line in _iterate(lines):
        m = FROM_RE.match(line.strip())
        if not m:
            continue
        image = m.group("image")
        if "@sha256:" in image:
            continue
        tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else ""
        if not tag or tag == "latest":
            out.append((i, line.strip()))
    return out


def _docker_runs_as_root(lines) -> List[Hit]:
    users = [(i, line.strip()) for i, line in _iterate(lines) if line.strip().upper().startswith("USER ")]
    if not users:
        return [(0, "no USER instruction: the container runs as root")]
    out = []
    for i, line in users:
        who = line.split(None, 1)[1].strip()
        if who.split(":")[0] in ("root", "0"):
            out.append((i, line))
    return out


def _docker_secret_env(lines) -> List[Hit]:
    out = []
    for i, line in _iterate(lines):
        stripped = line.strip()
        if not re.match(r"^(ENV|ARG)\s", stripped, re.I):
            continue
        found = SECRET_WORDS.search(stripped)
        if found:
            out.append((i, found.group(0) + " in build args/env"))
    return out


def _docker_add(lines) -> List[Hit]:
    return [(i, line.strip()) for i, line in _iterate(lines)
            if re.match(r"^ADD\s", line.strip(), re.I)]


def _docker_curl_pipe_sh(lines) -> List[Hit]:
    return [(i, line.strip()) for i, line in _iterate(lines) if CURL_PIPE_SH.search(line)]


def _docker_no_healthcheck(lines) -> List[Hit]:
    return [] if _has(lines, re.compile(r"^\s*HEALTHCHECK\b", re.I)) else [(0, "no HEALTHCHECK")]


def _docker_world_writable(lines) -> List[Hit]:
    pattern = re.compile(WORLD_WRITABLE)
    return [(i, line.strip()) for i, line in _iterate(lines) if pattern.search(line)]


def _docker_apt_no_cleanup(lines) -> List[Hit]:
    out = []
    for i, line in _iterate(lines):
        if not re.search(r"apt-get\s+install", line, re.I):
            continue
        if "--no-install-recommends" not in line or "/var/lib/apt/lists" not in line:
            out.append((i, line.strip()[:120]))
    return out


def _compose_privileged(lines) -> List[Hit]:
    return [(i, line.strip()) for i, line in _iterate(lines)
            if re.search(r"^\s*privileged\s*:\s*true\b", line, re.I)]


def _compose_docker_sock(lines) -> List[Hit]:
    return [(i, line.strip()) for i, line in _iterate(lines) if "docker.sock" in line]


def _compose_host_network(lines) -> List[Hit]:
    return [(i, line.strip()) for i, line in _iterate(lines)
            if re.search(r"^\s*network_mode\s*:\s*[\"']?host[\"']?\s*$", line)]


def _compose_no_cap_drop(lines) -> List[Hit]:
    return [] if _has(lines, re.compile(r"^\s*cap_drop\s*:", re.I)) else [(0, "no cap_drop: containers keep default capabilities")]


def _k8s_privileged(lines) -> List[Hit]:
    return [(i, line.strip()) for i, line in _iterate(lines)
            if re.search(r"privileged\s*:\s*true\b", line, re.I)]


def _k8s_run_as_root(lines) -> List[Hit]:
    out = []
    for i, line in _iterate(lines):
        if re.search(r"runAsNonRoot\s*:\s*false\b", line, re.I) or re.search(r"runAsUser\s*:\s*0\b", line):
            out.append((i, line.strip()))
    return out


def _k8s_host_path(lines) -> List[Hit]:
    return [(i, line.strip()) for i, line in _iterate(lines) if re.search(r"^\s*hostPath\s*:", line)]


def _k8s_host_namespace(lines) -> List[Hit]:
    return [(i, line.strip()) for i, line in _iterate(lines)
            if re.search(r"^\s*host(?:Network|PID|IPC)\s*:\s*true\b", line)]


def _k8s_latest_image(lines) -> List[Hit]:
    out = []
    for i, line in _iterate(lines):
        m = re.search(r"^\s*-?\s*image\s*:\s*[\"']?(?P<img>[^\s\"']+)", line)
        if not m:
            continue
        image = m.group("img")
        if "@sha256:" in image or image.endswith(":latest"):
            out.append((i, line.strip()))
    return out


def _k8s_no_limits(lines) -> List[Hit]:
    return [] if _has(lines, re.compile(r"^\s*limits\s*:", re.I)) else [(0, "no resource limits: one container can starve the node")]


def _sshd_root_login(lines) -> List[Hit]:
    return [(i, line.strip()) for i, line in _iterate(lines)
            if re.match(r"^\s*PermitRootLogin\s+yes\b", line, re.I)]


def _sshd_password_auth(lines) -> List[Hit]:
    return [(i, line.strip()) for i, line in _iterate(lines)
            if re.match(r"^\s*PasswordAuthentication\s+yes\b", line, re.I)]


def _sshd_empty_password(lines) -> List[Hit]:
    return [(i, line.strip()) for i, line in _iterate(lines)
            if re.match(r"^\s*PermitEmptyPasswords\s+yes\b", line, re.I)]


RULES = [
    Rule("HCD001", "Base image is unpinned or uses :latest", "medium",
         "Pin the base image to a specific version or digest so builds are reproducible.",
         "dockerfile", _docker_latest_tag),
    Rule("HCD002", "Container runs as root", "high",
         "Add a non-root USER after the install steps and chown what it needs.",
         "dockerfile", _docker_runs_as_root),
    Rule("HCD003", "Secret-looking value in ENV or ARG", "high",
         "Pass secrets at runtime or through a secret store; build args are visible in image history.",
         "dockerfile", _docker_secret_env),
    Rule("HCD004", "ADD used instead of COPY", "low",
         "Use COPY unless you specifically need ADD's tar extraction or URL fetch.",
         "dockerfile", _docker_add),
    Rule("HCD005", "Remote script piped into a shell", "high",
         "Download, verify a checksum, then execute, so a compromised endpoint cannot run code silently.",
         "dockerfile", _docker_curl_pipe_sh),
    Rule("HCD006", "No HEALTHCHECK", "low",
         "Add HEALTHCHECK so orchestrators can restart a process that is running but wedged.",
         "dockerfile", _docker_no_healthcheck),
    Rule("HCD007", "World-writable permissions on a file", "medium",
         "Grant the narrowest permissions that work; world-writable files can be rewritten by any process.",
         "dockerfile", _docker_world_writable),
    Rule("HCD008", "apt-get install without cleanup", "low",
         "Add --no-install-recommends and remove /var/lib/apt/lists in the same layer to keep images small.",
         "dockerfile", _docker_apt_no_cleanup),
    Rule("HCC001", "privileged: true", "high",
         "Drop privileged: it disables nearly every container boundary.",
         "compose", _compose_privileged),
    Rule("HCC002", "Docker socket mounted into a container", "high",
         "A container with the docker socket can control the host daemon, which is effectively root.",
         "compose", _compose_docker_sock),
    Rule("HCC003", "network_mode: host", "medium",
         "Use a bridge network and publish only the ports you need.",
         "compose", _compose_host_network),
    Rule("HCC004", "No cap_drop", "low",
         "Drop capabilities you do not need (cap_drop: [ALL]) and add back only what is required.",
         "compose", _compose_no_cap_drop),
    Rule("HCK001", "privileged: true in a pod spec", "high",
         "Remove privileged; it grants all host capabilities and device access.",
         "k8s", _k8s_privileged),
    Rule("HCK002", "Run-as-root explicitly allowed", "medium",
         "Set runAsNonRoot: true and a non-zero runAsUser.",
         "k8s", _k8s_run_as_root),
    Rule("HCK003", "hostPath volume", "high",
         "hostPath exposes the node filesystem; use a PVC or a projected secret/config instead.",
         "k8s", _k8s_host_path),
    Rule("HCK004", "Host namespace shared (network/PID/IPC)", "medium",
         "Remove hostNetwork/hostPID/hostIPC unless the workload genuinely needs node-level access.",
         "k8s", _k8s_host_namespace),
    Rule("HCK005", "Image is unpinned or :latest", "medium",
         "Pin by digest so a rebuilt tag cannot change what runs in production.",
         "k8s", _k8s_latest_image),
    Rule("HCK006", "No resource limits", "low",
         "Set resources.limits so one workload cannot starve the node.",
         "k8s", _k8s_no_limits),
    Rule("HCS001", "PermitRootLogin yes", "high",
         "Set PermitRootLogin no and use a non-root account with sudo.",
         "sshd", _sshd_root_login),
    Rule("HCS002", "PasswordAuthentication yes", "medium",
         "Prefer key-based auth; enable passwords only where it is required.",
         "sshd", _sshd_password_auth),
    Rule("HCS003", "PermitEmptyPasswords yes", "high",
         "Set it to no immediately: an empty password is no authentication at all.",
         "sshd", _sshd_empty_password),
]

BY_ID = {r.id: r for r in RULES}


def for_kind(kind: str):
    return [r for r in RULES if r.kind == kind]
