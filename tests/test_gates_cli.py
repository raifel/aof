from __future__ import annotations

import json

from aof.cli import main
from aof.enums import Stage
from aof.gates import run_gate, status
from aof.loader import load_project

from .conftest import codes


def test_example_passes_up_to_promotion(example, platform):
    results = {r.stage: r.passed for r in status(load_project(example), platform)}
    assert all(results[s] for s in Stage if s is not Stage.PROMOTE)
    assert not results[Stage.PROMOTE]


def test_promotion_needs_review_board_for_t3(example, platform, edit_yaml):
    lp = load_project(example)
    assert "AOF-G061" in codes(run_gate(Stage.PROMOTE, lp, platform).findings)
    edit_yaml(example / "aof.yaml", lambda d: d["approvals"].update(
        review_board={"by": "ai-review-board", "date": "2026-11-24", "ref": "AIRB-9"}))
    assert run_gate(Stage.PROMOTE, load_project(example), platform).passed


def test_autonomy_rises_one_level_at_a_time(example, platform, edit_yaml):
    edit_yaml(example / "aof.yaml", lambda d: d["autonomy"].update(current="L0", target="L2"))
    assert "AOF-G060" in codes(run_gate(Stage.PROMOTE, load_project(example), platform).findings)


def test_not_ready_dimension_blocks(example, platform, edit_yaml):
    edit_yaml(example / "aof/readiness.yaml",
              lambda d: d["dimensions"]["data"].update(status="not_ready", remediation="publish contract"))
    assert "AOF-G011" in codes(run_gate(Stage.READINESS, load_project(example), platform).findings)


def test_agentic_pattern_needs_justification(example, platform, edit_yaml):
    edit_yaml(example / "aof.yaml", lambda d: d.pop("pattern_justification"))
    assert "AOF-G021" in codes(run_gate(Stage.PATTERN, load_project(example), platform).findings)


def test_eval_threshold_by_tier(example, platform):
    p = example / "evals/results.json"
    data = json.loads(p.read_text())
    data["safety_pass_rate"] = 0.99  # T3 requires 1.00
    p.write_text(json.dumps(data))
    assert "AOF-G041" in codes(run_gate(Stage.EVALUATE, load_project(example), platform).findings)


def test_pilot_incident_cap(example, platform):
    p = example / "evals/pilot.json"
    data = json.loads(p.read_text())
    data["incidents"] = 1  # T3 allows 0
    p.write_text(json.dumps(data))
    assert "AOF-G054" in codes(run_gate(Stage.PILOT, load_project(example), platform).findings)


def test_init_scaffold_passes_build_gate(tmp_path, capsys):
    dest = tmp_path / "app"
    assert main(["init", str(dest), "--name", "sales-insights", "--owner", "sales-analytics"]) == 0
    assert main(["validate", str(dest)]) == 0
    assert "{{" not in (dest / "aof.yaml").read_text()
    assert (dest / ".github/workflows/aof.yml").exists()
    # a fresh scaffold is blocked at intake until the platform team triages it
    assert main(["gate", "intake", str(dest)]) == 1


def test_cli_compile_and_schema(example, tmp_path):
    out = tmp_path / "policy.json"
    assert main(["compile-policy", str(example), "-o", str(out)]) == 0
    assert json.loads(out.read_text())["agent"]["id"] == "agent:refunds-assistant"
    assert main(["schema", "-o", str(tmp_path / "schemas")]) == 0
    assert (tmp_path / "schemas" / "tools-manifest.schema.json").exists()


def test_cli_validate_fails_on_errors(example):
    (example / "AGENTS.md").unlink()
    assert main(["validate", str(example)]) == 1
