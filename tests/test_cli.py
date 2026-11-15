import json
from pathlib import Path

import pytest

from spillway.cli import main
from tests.helpers import allow, bucket, bucket_policy, plan, policy

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "public-share"


def test_example_plan_fails_the_gate_with_the_expected_findings(capsys):
    assert main([str(EXAMPLE / "plan.json"), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    got = {(f["rule"], f["address"], f["severity"]) for f in report["findings"]}
    assert got == {
        ("SPW103", "aws_iam_role.deploy", "critical"),
        ("SPW203", "aws_iam_role_policy.deploy", "high"),
        ("SPW202", "aws_iam_role_policy.deploy", "medium"),
        ("SPW001", "aws_s3_bucket_policy.shares", "high"),
        ("SPW006", "aws_s3_bucket.shares", "medium"),
    }
    # The VPC-endpoint-only upload grant is correctly NOT reported as public write.
    assert not any(f["details"].get("level") == "write" for f in report["findings"])
    assert all(f["status"] == "new" for f in report["findings"])
    assert report["gate_failed"] is True


def test_example_passes_when_threshold_is_above_every_finding(capsys):
    assert main([str(EXAMPLE / "plan.json"), "--fail-on", "none"]) == 0
    assert "Gate: pass" in capsys.readouterr().out


def test_sarif_output_with_source_locations(tmp_path, capsys):
    out = tmp_path / "spillway.sarif"
    code = main([str(EXAMPLE / "plan.json"), "--format", "sarif", "-o", str(out), "--tf-dir", str(EXAMPLE)])
    assert code == 1
    assert "Gate: FAIL" in capsys.readouterr().out  # a human summary still goes to the log
    sarif = json.loads(out.read_text())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]
        assert float(result["properties"]["security-severity"]) > 0
        assert result["partialFingerprints"]["spillway/v1"]
    by_rule = {r["ruleId"]: r for r in run["results"]}
    loc = by_rule["SPW103"]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "main.tf"
    text = (EXAMPLE / "main.tf").read_text().splitlines()
    assert text[loc["region"]["startLine"] - 1].startswith('resource "aws_iam_role" "deploy"')


def test_sarif_marks_accepted_findings_as_suppressed(tmp_path, capsys):
    tagged = bucket(tags={"spillway:accept-public-read": "public docs site, ticket SEC-7"})
    path = tmp_path / "p.json"
    path.write_text(json.dumps(plan(tagged, bucket_policy(policy(allow())))))
    assert main([str(path), "--format", "sarif"]) == 0
    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert results and all(r["suppressions"][0]["kind"] == "inSource" for r in results)
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == str(path)


def test_hostile_sid_cannot_inject_terminal_or_workflow_commands(tmp_path, capsys):
    evil = "x\n::error::pwned\x1b[2J"
    path = tmp_path / "p.json"
    path.write_text(json.dumps(plan(bucket(), bucket_policy(policy(allow(sid=evil))))))
    main([str(path)])
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert not any(line.startswith("::") for line in out.splitlines())


def test_clean_plan_passes(tmp_path, capsys):
    path = tmp_path / "p.json"
    path.write_text(json.dumps(plan(bucket())))
    assert main([str(path)]) == 0
    assert "No findings." in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [["/nonexistent.json"], ["{plan}", "--account-id", "12345"], ["{plan}", "--account-id", "abcdefghijkl"]],
)
def test_input_and_argument_errors_exit_2(tmp_path, capsys, argv):
    path = tmp_path / "p.json"
    path.write_text(json.dumps(plan()))
    assert main([a.replace("{plan}", str(path)) for a in argv]) == 2
    assert capsys.readouterr().err.startswith("spillway:")


def test_module_entry_point(tmp_path):
    import subprocess
    import sys

    path = tmp_path / "p.json"
    path.write_text(json.dumps(plan()))
    proc = subprocess.run([sys.executable, "-m", "spillway", str(path)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
