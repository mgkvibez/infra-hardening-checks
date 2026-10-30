import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from hardencheck import RULESET, report
from hardencheck.model import Finding
from hardencheck.rules import BY_ID
from hardencheck.scanner import detect_kind, scan_paths

FIX = pathlib.Path(__file__).parent / "fixtures"


def test_detect_kind_handles_real_world_names():
    p = pathlib.Path
    assert detect_kind(p("Dockerfile"), "FROM x") == "dockerfile"
    assert detect_kind(p("Dockerfile.bad"), "FROM x") == "dockerfile"
    assert detect_kind(p("sshd_config.bad"), "") == "sshd"
    assert detect_kind(p("docker-compose.bad.yml"), "services:") == "compose"
    assert detect_kind(p("deploy.bad.yaml"), "apiVersion: v1\nkind: Pod\n") == "k8s"
    assert detect_kind(p("notes.txt"), "hello") is None


def test_severity_threshold_filters_but_keeps_high():
    findings, _ = scan_paths([str(FIX)], min_severity="high")
    assert findings and all(f.rule.severity == "high" for f in findings)


def test_ignore_silences_one_rule():
    findings, _ = scan_paths([str(FIX)], ignore=("HCD002",))
    assert "HCD002" not in {f.rule.id for f in findings}
    assert findings


def test_unknown_files_are_reported_as_skipped_not_failed():
    _, skipped = scan_paths([str(FIX)])
    assert any("notes.txt" in s and "not a Dockerfile" in s for s in skipped)


def test_clean_result_wording_is_bounded_by_ruleset():
    text = report.render_text([], colour=False)
    assert "No issues found by ruleset {}".format(RULESET) in text
    assert "safe" not in text.lower().split("findings are bounded")[0].replace("no issues found", "")


def test_json_shape():
    f = [Finding(BY_ID["HCD002"], "Dockerfile", 0, "no USER")]
    doc = json.loads(report.render_json(f))
    assert doc["ruleset"] == RULESET and doc["findings"][0]["rule"] == "HCD002"


def test_sarif_maps_severity_to_level():
    f = [Finding(BY_ID["HCD002"], "Dockerfile", 1, "x"),
         Finding(BY_ID["HCD006"], "Dockerfile", 2, "y")]
    doc = json.loads(report.render_sarif(f))
    levels = [r["level"] for r in doc["runs"][0]["results"]]
    assert levels == ["error", "note"]
    assert doc["version"] == "2.1.0"


def test_summary_counts_by_severity():
    f = [Finding(BY_ID["HCD002"], "D", 1, ""), Finding(BY_ID["HCD006"], "D", 2, "")]
    assert "1 high" in report.summary_line(f) and "1 low" in report.summary_line(f)
