"""Data-safety contract rules (D1, docs/data-safety.md): field exposure, row filters,
semantic model, query tools, provider terms, and the compiled policy section."""

from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from aof.checks import validate
from aof.datasafety import ViewSchema, views_from_contracts
from aof.enums import Exposure
from aof.loader import load_project
from aof.platform import PlatformConfig
from aof.policy import compile_policy, data_safety_mode

from .conftest import codes

GL = {
    "name": "gl_journal_lines",
    "owner": "finance-data",
    "source": "snowflake:FINANCE.GL.JOURNAL_LINES",
    "semantic_view": "gl_journal_lines",
    "freshness_sla": "1h",
    "classification": "confidential",
    "fields": [
        {"name": "company_code", "type": "string", "classification": "public", "llm_exposure": "allowed"},
        {"name": "account_code", "type": "string"},
        {"name": "posting_date", "type": "date"},
        {"name": "amount_eur", "type": "number(18,2)", "classification": "confidential"},
        {"name": "vendor_id", "type": "string", "pii": True, "llm_exposure": "token"},
        {"name": "description", "type": "string", "classification": "confidential", "free_text": True},
    ],
    "quality": ["balances to the trial balance daily"],
    "row_filter": [{"column": "company_code", "claim": "tenant"}],
    "measures": [
        {"name": "opex", "field": "amount_eur", "agg": "sum",
         "filter": [{"column": "account_code", "op": "between", "value": ["6000", "7999"]}]},
        {"name": "lines", "agg": "count"},
    ],
    "dimensions": [
        {"name": "company", "field": "company_code", "required": True},
        {"name": "posting_date", "field": "posting_date", "time": True},
    ],
    "fiscal_calendar": {"year_start_month": 4},
    "glossary": {"opex": "operating expenses, accounts 6000-7999"},
}

QUERY_TOOL = {
    "name": "query_ledger",
    "description": "Answer a question about the general ledger with a semantic query over journal lines; "
                   "returns a result handle and its columns, never the rows.",
    "example": 'query_ledger(query={"view": "gl_journal_lines", "metrics": ["opex"]})',
    "not_for": "Order or refund lookups: use lookup_order.",
    "access": "read",
    "risk_tier": "T1",
    "idempotent": True,
    "scopes": ["ledger:read"],
    "rate_limit": {"calls": 30, "per": "minute"},
    "approval": {"mode": "sampled", "sample_rate": 0.05},
    "reads": ["gl_journal_lines"],
    "query": {"form": "ir", "dialect": "snowflake", "max_rows": 1000, "timeout_seconds": 30,
              "max_bytes_scanned": 1000000000},
    "params": {"query": {"type": "object", "description": "Semantic query: view, metrics, dimensions, filters, period"}},
}


@pytest.fixture
def ledger(example):
    """The example app plus a GL data contract and a query tool."""
    (example / "aof/data-contracts/gl_journal_lines.yaml").write_text(yaml.safe_dump(GL, sort_keys=False))
    path = example / "aof/tools.manifest.yaml"
    data = yaml.safe_load(path.read_text())
    data["tools"].append(dict(QUERY_TOOL))
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return example


def _errors(app, platform) -> set[str]:
    return codes(validate(load_project(app), platform).findings)


def _edit_gl(app, edit_yaml, fn):
    edit_yaml(app / "aof/data-contracts/gl_journal_lines.yaml", fn)


def _edit_tool(app, edit_yaml, fn):
    edit_yaml(app / "aof/tools.manifest.yaml", lambda d: fn(next(t for t in d["tools"] if t["name"] == "query_ledger")))


def _field(d, name):
    return next(f for f in d["fields"] if f["name"] == name)


def test_ledger_app_is_clean(ledger, platform):
    findings = validate(load_project(ledger), platform)
    assert findings.errors == []


def test_exposure_above_ceiling_fails(ledger, platform, edit_yaml):
    _edit_gl(ledger, edit_yaml, lambda d: _field(d, "amount_eur").update(llm_exposure="aggregate"))
    assert "AOF-C070" in _errors(ledger, platform)


def test_pii_above_token_fails(ledger, platform, edit_yaml):
    _edit_gl(ledger, edit_yaml, lambda d: _field(d, "vendor_id").update(llm_exposure="masked"))
    found = _errors(ledger, platform)
    assert "AOF-C071" in found and "AOF-C070" not in found


def test_free_text_must_be_hidden(ledger, platform, edit_yaml):
    def fn(d):
        f = _field(d, "description")
        f.update(classification="internal")  # default exposure for internal is aggregate
    _edit_gl(ledger, edit_yaml, fn)
    assert "AOF-C072" in _errors(ledger, platform)


def test_row_filter_column_and_claim_must_exist(ledger, platform, edit_yaml):
    _edit_gl(ledger, edit_yaml, lambda d: d.update(row_filter=[{"column": "entity", "claim": "cost_centres"}]))
    report = validate(load_project(ledger), platform)
    msgs = [f.message for f in report.errors if f.code == "AOF-C073"]
    assert len(msgs) == 2


def test_row_filter_claim_can_come_from_the_platform(ledger, platform, edit_yaml):
    _edit_gl(ledger, edit_yaml, lambda d: d.update(row_filter=[{"column": "company_code", "claim": "entities"}]))
    assert "AOF-C073" in _errors(ledger, platform)
    platform.data_safety.row_filter_claims["entities"] = "ext.company_codes"
    assert "AOF-C073" not in _errors(ledger, platform)


@pytest.mark.parametrize("fn", [
    lambda d: d["measures"][0].update(field="amount_usd"),
    lambda d: d["measures"][0].update(field="account_code"),  # sum over a string
    lambda d: d["measures"][0]["filter"][0].update(column="gl_account"),
    lambda d: d["dimensions"][1].update(field="booking_date"),
    lambda d: d["dimensions"].append({"name": "opex", "field": "account_code"}),
    lambda d: d["dimensions"][0].update(time=True),
])
def test_semantic_model_must_match_fields(ledger, platform, edit_yaml, fn):
    _edit_gl(ledger, edit_yaml, fn)
    assert "AOF-C074" in _errors(ledger, platform)


def test_user_facing_query_tool_needs_row_filters(ledger, platform, edit_yaml):
    _edit_gl(ledger, edit_yaml, lambda d: d.update(row_filter=[]))
    assert "AOF-C075" in _errors(ledger, platform)
    edit_yaml(ledger / "aof.yaml", lambda d: d["app"].update(user_facing=False))
    assert "AOF-C075" not in _errors(ledger, platform)


def test_query_param_must_exist(ledger, platform, edit_yaml):
    _edit_tool(ledger, edit_yaml, lambda t: t["query"].update(param="sql"))
    assert "AOF-C076" in _errors(ledger, platform)


def test_query_tool_needs_limits(ledger, platform, edit_yaml):
    _edit_tool(ledger, edit_yaml, lambda t: t["query"].pop("max_rows"))
    assert "AOF-P070" in _errors(ledger, platform)


def test_query_limits_within_platform_ceilings(ledger, platform, edit_yaml):
    _edit_tool(ledger, edit_yaml, lambda t: t["query"].update(timeout_seconds=600))
    assert "AOF-P075" in _errors(ledger, platform)


def test_raw_sql_in_t3_app_needs_per_action_approval(ledger, platform, edit_yaml):
    _edit_tool(ledger, edit_yaml, lambda t: t["query"].update(form="sql"))
    assert "AOF-P071" in _errors(ledger, platform)
    _edit_tool(ledger, edit_yaml, lambda t: t.update(approval={"mode": "per_action"}))
    assert "AOF-P071" not in _errors(ledger, platform)


def test_query_tool_must_be_read(ledger, platform, edit_yaml):
    _edit_tool(ledger, edit_yaml, lambda t: t.update(access="write"))
    assert "AOF-P072" in _errors(ledger, platform)


def test_zero_data_retention_must_be_confirmed(example, platform, edit_yaml):
    edit_yaml(example / "aof.yaml", lambda d: d["llm"].pop("zero_data_retention"))
    assert "AOF-P073" in _errors(example, platform)
    platform.data_safety.provider.zero_data_retention = "recommended"
    assert "AOF-P073" not in _errors(example, platform)


def test_t3_app_cannot_use_contract_mode(example, platform, edit_yaml):
    edit_yaml(example / "aof.yaml", lambda d: d.update(data_safety={"mode": "contract"}))
    assert "AOF-P074" in _errors(example, platform)


def test_compiled_policy_carries_views_and_query_settings(ledger, platform):
    lp = load_project(ledger)
    policy = compile_policy(lp.project, lp.manifest, platform, lp.data_contracts)
    ds = policy["data_safety"]
    assert ds["mode"] == "metadata_only"
    view = ViewSchema.model_validate(ds["views"]["gl_journal_lines"])
    # metadata_only: everything hidden except token columns, whatever the contract allows
    assert view.column("company_code").exposure is Exposure.NONE
    assert view.column("vendor_id").exposure is Exposure.TOKEN
    assert view.row_filter[0].claim == "tenant"
    tool = next(t for t in policy["tools"] if t["name"] == "query_ledger")
    assert tool["query"]["max_rows"] == 1000


def test_contract_mode_uses_declared_and_default_exposure(ledger, platform, edit_yaml):
    edit_yaml(ledger / "aof.yaml", lambda d: d.update(data_safety={"mode": "contract"}))
    lp = load_project(ledger)
    views = views_from_contracts(lp.data_contracts, platform.data_safety.default_exposure,
                                 data_safety_mode(lp.project, platform))
    view = views["gl_journal_lines"]
    assert view.column("company_code").exposure is Exposure.ALLOWED    # declared
    assert view.column("account_code").exposure is Exposure.AGGREGATE  # internal default
    assert view.column("amount_eur").exposure is Exposure.NONE         # confidential default
    assert view.column("vendor_id").exposure is Exposure.TOKEN


def test_platform_default_exposure_must_be_within_ceiling(platform):
    data = platform.model_dump(mode="json")
    data["data_safety"]["default_exposure"]["confidential"] = "allowed"
    with pytest.raises(ValidationError):
        PlatformConfig.model_validate(data)
