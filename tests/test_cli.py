import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from hardencheck.cli import EXIT_CLEAN, EXIT_FINDINGS, EXIT_USAGE, main

FIX = pathlib.Path(__file__).parent / "fixtures"


def test_scan_reports_findings_with_documented_exit(capsys):
    assert main(["scan", str(FIX), "--no-colour"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "finding(s)" in out and "HCD002" in out


def test_min_severity_high_changes_the_count(capsys):
    main(["scan", str(FIX), "--no-colour", "--json"])
    all_doc = json.loads(capsys.readouterr().out)
    main(["scan", str(FIX), "--no-colour", "--json", "--min-severity", "high"])
    high_doc = json.loads(capsys.readouterr().out)
    assert len(high_doc["findings"]) < len(all_doc["findings"])
    assert all(f["severity"] == "high" for f in high_doc["findings"])


def test_clean_target_exits_zero(tmp_path, capsys):
    clean = tmp_path / "Dockerfile"
    clean.write_text("FROM python:3.12-slim@sha256:" + "b" * 64 + "\nUSER app\nHEALTHCHECK CMD true\n")
    assert main(["scan", str(clean), "--no-colour"]) == EXIT_CLEAN
    assert "No issues found by ruleset" in capsys.readouterr().out


def test_sarif_flag_is_valid_json(capsys):
    main(["scan", str(FIX), "--sarif"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"


def test_rules_and_explain(capsys):
    assert main(["rules"]) == EXIT_CLEAN
    assert "HCD002" in capsys.readouterr().out
    assert main(["explain", "hcd002"]) == EXIT_CLEAN
    assert "non-root" in capsys.readouterr().out
    assert main(["explain", "NOPE999"]) == EXIT_USAGE


def test_no_subcommand_is_a_usage_error():
    assert main([]) == EXIT_USAGE
