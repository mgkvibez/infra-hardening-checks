import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from hardencheck.scanner import scan_text
from hardencheck.rules import BY_ID

FIX = pathlib.Path(__file__).parent / "fixtures"


def ids(name, kind):
    return {f.rule.id for f in scan_text(str(FIX / name), kind, (FIX / name).read_text())}


def test_dockerfile_bad_hits_every_expected_rule():
    found = ids("Dockerfile.bad", "dockerfile")
    assert {"HCD001", "HCD002", "HCD003", "HCD004", "HCD005", "HCD006", "HCD007", "HCD008"} <= found


def test_dockerfile_good_is_clean():
    assert ids("Dockerfile.good", "dockerfile") == set()


def test_compose_bad():
    assert ids("docker-compose.bad.yml", "compose") == {"HCC001", "HCC002", "HCC003", "HCC004"}


def test_k8s_bad():
    assert ids("deploy.bad.yaml", "k8s") == {"HCK001", "HCK002", "HCK003", "HCK004", "HCK005", "HCK006"}


def test_sshd_bad():
    assert ids("sshd_config.bad", "sshd") == {"HCS001", "HCS002", "HCS003"}


def test_file_level_rules_point_at_the_file_not_a_line():
    for f in scan_text("Dockerfile", "dockerfile", "FROM ubuntu:latest\n"):
        if f.rule.id in ("HCD002", "HCD006"):
            assert f.line_no == 0


def test_severity_is_bounded_to_known_values():
    assert {r.severity for r in BY_ID.values()} <= {"high", "medium", "low"}
