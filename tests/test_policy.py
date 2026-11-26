from __future__ import annotations

import pytest

from aof.enums import AutonomyLevel
from aof.loader import load_project
from aof.policy import PolicyError, check_policy, compile_policy, decide

from .conftest import codes


def _manifest_edit(example, edit_yaml, fn):
    edit_yaml(example / "aof/tools.manifest.yaml", fn)
    return load_project(example)


def _tool(data, name):
    return next(t for t in data["tools"] if t["name"] == name)


def test_example_policy_is_clean(example, platform):
    lp = load_project(example)
    assert codes(check_policy(lp.project, lp.manifest, platform)) == set()


def test_write_tool_without_approval_fails_build(example, platform, edit_yaml):
    lp = _manifest_edit(example, edit_yaml, lambda d: _tool(d, "update_ticket_status").pop("approval"))
    assert "AOF-P001" in codes(check_policy(lp.project, lp.manifest, platform))


def test_t3_needs_per_action_and_dry_run(example, platform, edit_yaml):
    def fn(d):
        t = _tool(d, "create_refund_request")
        t["approval"]["mode"] = "within_limits"
        t["supports_dry_run"] = False

    lp = _manifest_edit(example, edit_yaml, fn)
    got = codes(check_policy(lp.project, lp.manifest, platform))
    assert {"AOF-P003", "AOF-P004"} <= got


def test_irreversible_write_below_t3_fails(example, platform, edit_yaml):
    lp = _manifest_edit(example, edit_yaml,
                        lambda d: _tool(d, "update_ticket_status").update(reversibility="irreversible"))
    assert "AOF-P007" in codes(check_policy(lp.project, lp.manifest, platform))


def test_code_tools_not_allowed_at_low_tiers(example, platform, edit_yaml):
    lp = _manifest_edit(example, edit_yaml,
                        lambda d: _tool(d, "lookup_order").update(executes_code=True))
    assert "AOF-P011" in codes(check_policy(lp.project, lp.manifest, platform))


def test_read_only_target_rejects_write_tools(example, platform, edit_yaml):
    edit_yaml(example / "aof.yaml", lambda d: d["autonomy"].update(target="L1"))
    lp = load_project(example)
    assert "AOF-P021" in codes(check_policy(lp.project, lp.manifest, platform))


def test_l2_requires_per_action_on_every_write(example, platform, edit_yaml):
    lp = _manifest_edit(example, edit_yaml,
                        lambda d: _tool(d, "update_ticket_status")["approval"].update(mode="within_limits"))
    assert "AOF-P022" in codes(check_policy(lp.project, lp.manifest, platform))


def test_app_budget_cannot_exceed_platform(example, platform, edit_yaml):
    edit_yaml(example / "aof.yaml", lambda d: d["budgets"].update(max_steps_per_run=999))
    lp = load_project(example)
    assert "AOF-P025" in codes(check_policy(lp.project, lp.manifest, platform))


def test_compile_enforces_the_approved_level_not_the_target(example, platform):
    lp = load_project(example)
    policy = compile_policy(lp.project, lp.manifest, platform)
    decisions = {t["name"]: t["decision"] for t in policy["tools"]}
    assert policy["default"] == "deny"
    assert decisions == {
        "lookup_order": "allow",
        "summarize_refund_history": "allow",
        "create_refund_request": "deny",  # approved level L1 is read-only
        "update_ticket_status": "deny",
        "delete_customer_account": "deny",  # T4
    }
    assert policy["budgets"]["max_steps_per_run"] == 15  # app tightened the platform's 25
    assert policy["identity"]["mode"] == "on_behalf_of"


def test_decisions_by_level(example):
    lp = load_project(example)
    refund = lp.manifest.tool("create_refund_request")
    ticket = lp.manifest.tool("update_ticket_status")
    assert decide(refund, AutonomyLevel.L2)[0] == "require_approval"
    assert decide(refund, AutonomyLevel.L3)[0] == "require_approval"  # T3 always needs a human
    assert decide(ticket, AutonomyLevel.L2)[0] == "require_approval"


def test_compile_refuses_invalid_manifest(example, platform, edit_yaml):
    lp = _manifest_edit(example, edit_yaml, lambda d: _tool(d, "update_ticket_status").pop("approval"))
    with pytest.raises(PolicyError):
        compile_policy(lp.project, lp.manifest, platform)
