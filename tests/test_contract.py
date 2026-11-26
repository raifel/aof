from __future__ import annotations

import json

from aof.checks import validate
from aof.conformance import compare
from aof.lint import lint_manifest
from aof.loader import load_project

from .conftest import codes


def test_example_validates(example, platform):
    report = validate(load_project(example), platform)
    assert report.errors == []


def test_missing_artefact_is_reported(example, platform):
    (example / "RUNBOOK.md").unlink()
    assert "AOF-C041" in codes(validate(load_project(example), platform).findings)


def test_schema_typos_fail(example, platform, edit_yaml):
    edit_yaml(example / "aof.yaml", lambda d: d.update(risk_teir="T1"))
    assert "AOF-S003" in codes(validate(load_project(example), platform).findings)


def test_tool_must_read_through_a_data_contract(example, platform, edit_yaml):
    edit_yaml(example / "aof/tools.manifest.yaml",
              lambda d: d["tools"][0].update(reads=["raw_orders_table"]))
    assert "AOF-C024" in codes(validate(load_project(example), platform).findings)


def test_pii_contract_must_be_confidential(example, platform, edit_yaml):
    def fn(d):
        d["classification"] = "internal"
        for f in d["fields"]:
            f["classification"] = "internal"

    edit_yaml(example / "aof/data-contracts/order_facts.yaml", fn)
    assert "AOF-C022" in codes(validate(load_project(example), platform).findings)


def test_registry_metadata_must_match_project(example, platform):
    p = example / "server.json"
    data = json.loads(p.read_text())
    data["_meta"]["io.modelcontextprotocol.registry/publisher-provided"]["aof"]["autonomy_level"] = "L2"
    p.write_text(json.dumps(data))
    assert "AOF-C014" in codes(validate(load_project(example), platform).findings)


def test_runbook_needs_kill_switch(example, platform):
    (example / "RUNBOOK.md").write_text("# Runbook\non call: payments-support-oncall\n")
    assert "AOF-C042" in codes(validate(load_project(example), platform).findings)


def test_golden_case_cannot_expect_unknown_tool(example, platform):
    p = example / "evals/golden.jsonl"
    p.write_text(p.read_text() + json.dumps(
        {"id": "gx", "input": "x", "expected": "y", "expected_tools": ["send_email"]}) + "\n")
    assert "AOF-E005" in codes(validate(load_project(example), platform).findings)


def test_lint_flags_crud_and_unenumerated_params(example, platform, edit_yaml):
    def fn(d):
        d["tools"][0]["name"] = "get_data"
        d["tools"][0]["params"]["status"] = {"type": "string", "description": "status"}

    edit_yaml(example / "aof/tools.manifest.yaml", fn)
    found = {f.code for f in lint_manifest(load_project(example).manifest, platform)}
    assert {"AOF-L002", "AOF-L007"} <= found


class _ServedTool:
    def __init__(self, name, description, props, read_only):
        self.name = name
        self.description = description
        self.input_schema = {"properties": {p: {} for p in props}}
        self.annotations = {"read_only_hint": read_only}


def test_conformance_detects_drift(example):
    m = load_project(example).manifest
    lookup = m.tool("lookup_order")
    served = [
        _ServedTool("lookup_order", lookup.description, ["order_id"], True),
        _ServedTool("export_all_orders", "x", [], True),  # not in manifest
    ]
    found = {f.code for f in compare(m, served)}
    assert "AOF-C061" in found  # served but undeclared
    assert "AOF-C060" in found  # declared but not served (non-T4 tools)


def test_conformance_skips_t4_tools(example):
    m = load_project(example).manifest
    served = [_ServedTool(t.name, t.description, list(t.params), t.access.value == "read")
              for t in m.tools if t.risk_tier.value != "T4"]
    assert compare(m, served) == []


def test_example_server_conforms(example):
    import sys

    import pytest

    pytest.importorskip("mcp")
    from aof.conformance import check_server

    lp = load_project(example)
    assert check_server(lp.manifest, [sys.executable, "src/server.py"], lp.root) == []
