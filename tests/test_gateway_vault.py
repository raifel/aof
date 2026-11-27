"""Result vault and data shield (D2, docs/data-safety.md).

End to end: the app's query tool runs the gateway-guarded SQL against an in-memory
DuckDB ledger, so what the agent gets back is checked against real rows."""

from __future__ import annotations

import asyncio
import base64
import json
import re

import httpx2
import pytest
import yaml
from starlette.applications import Starlette

from aof.enums import AutonomyLevel, DataSafetyMode, RiskTier
from aof.gateway import Gateway, Principal, ToolResult, UpstreamTool
from aof.gateway.compiled import CompiledPolicy
from aof.gateway.identity import StaticTokenVerifier
from aof.gateway.results_api import results_routes
from aof.gateway.shield import bucket, mask
from aof.gateway.vault import ResultVault, VaultError, load_key, new_key
from aof.loader import load_project
from aof.models.project import Autonomy
from aof.platform import load_platform
from aof.policy import compile_policy

from .test_datasafety import GL, QUERY_TOOL

duckdb = pytest.importorskip("duckdb")

ALICE = Principal.of("alice", ["orders:read", "refunds:read", "refunds:create", "tickets:write", "ledger:read"],
                     tenant="DE01")
MALLORY = Principal.of("mallory", ["orders:read", "ledger:read"], tenant="DE01")
ROWS = [
    ("DE01", "6100", "2025-10-15", 100.00, "V1"),
    ("DE01", "6200", "2025-11-03", 50.00, "V2"),
    ("DE01", "6100", "2025-12-20", 30.00, "V1"),
    ("DE02", "6100", "2025-10-15", 7000.00, "V9"),
]


def run(coro):
    return asyncio.run(coro)


def has_number(value, number: str) -> bool:
    """`number` as a whole number in the JSON, not inside a hash, handle or timestamp."""
    return re.search(rf"(?<![\w.]){re.escape(number)}(?:\.0+)?(?![\w])(?!\.\d)", json.dumps(value)) is not None


@pytest.fixture
def app(example):
    """The example app plus a GL contract and a semantic query tool; raw SQL for a second tool."""
    (example / "aof/data-contracts/gl_journal_lines.yaml").write_text(yaml.safe_dump(GL, sort_keys=False))
    path = example / "aof/tools.manifest.yaml"
    data = yaml.safe_load(path.read_text())
    sql_tool = json.loads(json.dumps(QUERY_TOOL))  # switched to form: sql after compiling (see make_policy)
    sql_tool.update(name="query_ledger_sql", approval={"mode": "sampled", "sample_rate": 0.0})
    sql_tool["query"]["dialect"] = "duckdb"
    data["tools"] += [dict(QUERY_TOOL, query={**QUERY_TOOL["query"], "dialect": "duckdb"}), sql_tool]
    lookup = next(t for t in data["tools"] if t["name"] == "lookup_order")
    # order_id is a contract field (its contract exposure wins); ticket_ref is not
    lookup["result_keys"] = {"status": "allowed", "ticket_ref": "token", "order_id": "allowed"}
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return example


def make_policy(app, *, results="enforce", mode=None, level="L1", **ds) -> CompiledPolicy:
    lp = load_project(app)
    lp.project.autonomy = Autonomy(current=AutonomyLevel(level), target=max(AutonomyLevel(level), AutonomyLevel.L2))
    platform = load_platform()
    platform.data_safety.metadata_only_from_tier = RiskTier.T4  # let tests use contract mode on a T3 app
    platform.data_safety.query.allowed_functions.append("TIMESTAMP_TRUNC")
    if mode:
        lp.project.data_safety.mode = DataSafetyMode(mode)
    data = compile_policy(lp.project, lp.manifest, platform, lp.data_contracts)
    # Raw SQL in a T3 app needs per_action approval (AOF-P071); these tests exercise the
    # guard, so the second tool is compiled as `ir` and switched to `sql` here.
    next(t for t in data["tools"] if t["name"] == "query_ledger_sql")["query"]["form"] = "sql"
    data["data_safety"].update(results=results, **ds)
    return CompiledPolicy.model_validate(data)


class LedgerUpstream:
    """The app's MCP server: query tools run the SQL they are given against DuckDB."""

    def __init__(self, fail_queries: bool = False):
        self.db = duckdb.connect()
        self.db.execute("CREATE TABLE gl_journal_lines (company_code VARCHAR, account_code VARCHAR, "
                        "posting_date DATE, amount_eur DECIMAL(18,2), vendor_id VARCHAR, description VARCHAR)")
        self.db.executemany("INSERT INTO gl_journal_lines VALUES (?, ?, ?, ?, ?, 'x')", ROWS)
        self.calls: list[tuple[str, dict]] = []
        self.fail_queries = fail_queries

    async def list_tools(self, token=None):
        return [UpstreamTool(n, n, {"type": "object"}) for n in ("lookup_order", "query_ledger")]

    async def call_tool(self, name, args, token=None):
        self.calls.append((name, dict(args)))
        if name.startswith("query_ledger"):
            if self.fail_queries:
                return ToolResult("Binder Error: amount_eur = 4711.00 is not comparable", is_error=True)
            cur = self.db.execute(args["query"])
            cols = [d[0].lower() for d in cur.description]
            return ToolResult({"columns": cols, "rows": [[str(v) if v is not None else None for v in r]
                                                         for r in cur.fetchall()]})
        if name == "lookup_order":
            return ToolResult({"order_id": args["order_id"], "ticket_ref": f"TCK-{args['order_id']}",
                               "status": "delivered", "customer_id": "CUS-88123",
                               "amount": 49.9, "items": [{"sku": "A-1", "amount": 49.9}]})
        if name == "create_refund_request" and args.get("dry_run"):
            return ToolResult({"would_refund": args["amount"], "order_id": args["order_id"], "status": "preview"})
        return ToolResult({"ok": True})


def gateway(app, upstream=None, **kw) -> tuple[Gateway, LedgerUpstream]:
    up = upstream or LedgerUpstream()
    return Gateway(make_policy(app, **kw), up), up


def call(gw, tool, args, who=ALICE, run_id="run-1"):
    return run(gw.call_tool(who, tool, args, run_id=run_id))


OPEX_Q3 = {"view": "gl_journal_lines", "metrics": ["opex"], "dimensions": ["company"],
           "period": {"fiscal_year": 2026, "quarter": 3}}


# --------------------------------------------------------------------------- vault


def test_vault_is_owner_bound_encrypted_and_expires():
    now = [1000.0]
    v = ResultVault(ttl_seconds=60, clock=lambda: now[0])
    h = v.put(ALICE, agent_id="a", run_id="r", tool="t", content={"amount": 4711.5})
    assert v.get(h, ALICE).content == {"amount": 4711.5}
    assert not has_number(v.store.all("vault_results"), "4711")  # ciphertext at rest
    for who in (MALLORY, Principal.of("alice", tenant="DE02")):
        with pytest.raises(VaultError):
            v.get(h, who)
    now[0] += 61
    with pytest.raises(VaultError):
        v.get(h, ALICE)


def test_vault_key_from_env(monkeypatch):
    key = new_key()
    monkeypatch.setenv("AOF_VAULT_KEY", key)
    assert load_key() == base64.b64decode(key)
    for bad in ("not base64!", base64.b64encode(b"short").decode()):
        with pytest.raises(VaultError):
            load_key(bad)


def test_tokens_are_stable_per_run_and_resolve_only_for_their_owner():
    v = ResultVault()
    t1 = v.tokenize(ALICE, "r1", "vendor_id", "V1")
    assert t1 == v.tokenize(ALICE, "r1", "vendor_id", "V1") != v.tokenize(ALICE, "r2", "vendor_id", "V1")
    assert v.resolve(t1, ALICE, "r1") == (True, "V1")
    assert v.resolve(t1, ALICE, "r2")[0] is False
    assert v.resolve(t1, MALLORY, "r1")[0] is False
    assert v.detokenize({"a": [t1, "plain"], "b": 3}, ALICE, "r1") == {"a": ["V1", "plain"], "b": 3}


def test_result_size_limit():
    v = ResultVault(max_bytes=100)
    with pytest.raises(VaultError) as e:
        v.put(ALICE, agent_id="a", run_id="r", tool="t", content={"x": "y" * 200})
    assert e.value.code == "RESULT_TOO_LARGE"


@pytest.mark.parametrize("n,label", [(0, "0"), (1, "1-9"), (9, "1-9"), (10, "10-99"), (12000, "10000+")])
def test_row_count_buckets(n, label):
    assert bucket(n, [0, 1, 10, 100, 1000, 10000]) == label


def test_mask():
    assert (mask("DE89370400440532013000"), mask("2025-10-15"), mask(12.5)) == ("****3000", "2025", "****")


# --------------------------------------------------------------------------- query tools


def test_semantic_query_returns_a_handle_not_values(app):
    gw, up = gateway(app)
    res = call(gw, "query_ledger", {"query": OPEX_Q3})
    assert not res.is_error
    body = res.content
    assert body["result_handle"].startswith("res_") and body["row_count"] == "1-9"
    assert not has_number(body, "180")  # 100 + 50 + 30: only in the vault
    sql = up.calls[-1][1]["query"]
    assert "company_code IN ('DE01')" in sql and "LIMIT 1000" in sql
    stored = gw.vault.get(body["result_handle"], ALICE).content
    assert stored["rows"][0][:2] == ["DE01", "180.00"]  # the user's UI gets the real numbers


def test_audit_records_handles_never_values(app):
    gw, _ = gateway(app)
    call(gw, "query_ledger", {"query": OPEX_Q3})
    events = {r["event"]: r for r in gw.audit.read()}
    assert events["query_guarded"]["views"] == ["gl_journal_lines"]
    assert events["tool_executed"]["result_handle"].startswith("res_")
    assert events["tool_executed"]["row_count"] == "1-9"
    assert not has_number(gw.audit.read(), "180")


def test_contract_mode_shows_allowed_columns_and_hides_measures(app):
    gw, _ = gateway(app, mode="contract")
    body = call(gw, "query_ledger", {"query": OPEX_Q3}).content
    assert body["rows"] == [{"company": "DE01"}]  # opex is none: not in the rows
    assert {c["name"]: c["exposure"] for c in body["columns"]} == {"company": "allowed", "opex": "none"}


def test_small_groups_hide_aggregate_values(app):
    gw, _ = gateway(app, mode="contract", min_group_size=2)
    sql = ("SELECT account_code, count(*) AS n FROM gl_journal_lines "
           "WHERE company_code = 'DE01' GROUP BY account_code ORDER BY account_code")
    body = call(gw, "query_ledger_sql", {"query": sql}).content
    assert body["rows"] == [{"account_code": "6100", "n": "2"}, {}]  # 6200 has one line: suppressed
    assert body["suppressed_small_groups"] is True


def test_tokens_flow_from_one_query_into_the_next(app):
    gw, up = gateway(app, mode="contract")
    sql = "SELECT vendor_id, count(*) AS n FROM gl_journal_lines GROUP BY vendor_id ORDER BY vendor_id"
    rows = call(gw, "query_ledger_sql", {"query": sql}).content["rows"]
    token = rows[0]["vendor_id"]
    assert token.startswith("tok_") and "V1" not in json.dumps(rows)
    res = call(gw, "query_ledger_sql",
               {"query": f"SELECT count(*) AS n FROM gl_journal_lines WHERE vendor_id = '{token}'"})
    assert not res.is_error
    assert "vendor_id = 'V1'" in up.calls[-1][1]["query"]  # resolved on the syntax tree
    other_run = call(gw, "query_ledger_sql",
                     {"query": f"SELECT count(*) AS n FROM gl_journal_lines WHERE vendor_id = '{token}'"},
                     run_id="run-2")
    assert f"'{token}'" in up.calls[-1][1]["query"] and not other_run.is_error  # unknown there: stays a token


def test_rejected_query_never_reaches_the_app(app):
    gw, up = gateway(app)
    res = call(gw, "query_ledger_sql", {"query": "SELECT count(*) FROM gl_journal_lines WHERE amount_eur > 1000"})
    assert res.is_error and res.content["error"] == "SQL_FILTER_NOT_ALLOWED"
    assert up.calls == []
    rec = gw.audit.read()[-1]
    assert rec["event"] == "query_rejected" and "reason" not in rec


def test_missing_tenant_claim_fails_closed(app):
    gw, up = gateway(app)
    res = call(gw, "query_ledger", {"query": OPEX_Q3}, who=Principal.of("bob", ["ledger:read"]))
    assert res.content["error"] == "ROW_FILTER_UNBOUND" and up.calls == []


def test_query_budget(app):
    gw, _ = gateway(app, max_queries_per_run=1)
    assert not call(gw, "query_ledger", {"query": OPEX_Q3}).is_error
    assert call(gw, "query_ledger", {"query": OPEX_Q3}).content["error"] == "QUERY_BUDGET"


def test_failed_query_error_is_generic(app):
    gw, _ = gateway(app, upstream=LedgerUpstream(fail_queries=True))
    res = call(gw, "query_ledger", {"query": OPEX_Q3})
    assert res.is_error and res.content["error"] == "QUERY_FAILED" and not has_number(res.content, "4711")


def test_shadow_returns_the_result_but_vaults_it(app):
    gw, _ = gateway(app, results="shadow")
    res = call(gw, "query_ledger", {"query": OPEX_Q3})
    assert res.content["rows"][0][1] == "180.00"
    assert gw.audit.read()[-1]["result_handle"].startswith("res_")


# --------------------------------------------------------------------------- other governed tools


def test_json_results_show_declared_keys_only(app):
    gw, _ = gateway(app, mode="contract")
    body = call(gw, "lookup_order", {"order_id": "ORD-1"}).content
    assert body["result"]["status"] == "delivered"
    assert body["result"]["ticket_ref"].startswith("tok_")
    assert "CUS-88123" not in json.dumps(body) and "49.9" not in json.dumps(body)
    # order_id: the contract (internal -> aggregate) wins over result_keys; sku: declared nowhere
    assert {"customer_id", "amount", "sku", "order_id"} <= set(body["hidden_keys"])


def test_metadata_only_clamps_result_keys(app):
    gw, _ = gateway(app)  # T3 default: metadata_only
    body = call(gw, "lookup_order", {"order_id": "ORD-1"}).content
    assert "status" in body["hidden_keys"] and body["result"]["ticket_ref"].startswith("tok_")


def test_token_arguments_are_resolved_for_the_app(app):
    gw, up = gateway(app, mode="contract")
    token = call(gw, "lookup_order", {"order_id": "ORD-7"}).content["result"]["ticket_ref"]
    call(gw, "lookup_order", {"order_id": token})
    assert up.calls[-1] == ("lookup_order", {"order_id": "TCK-ORD-7"})


def test_dry_run_preview_is_shaped_for_the_agent_not_the_approver(app):
    gw, _ = gateway(app, mode="contract", level="L2")
    res = call(gw, "create_refund_request",
               {"order_id": "ORD-1", "amount": 49.9, "reason": "goodwill", "request_id": "r-1"})
    assert res.content["status"] == "approval_required"
    assert "49.9" not in json.dumps(res.content["preview"])
    approval = gw.approvals.list()[0]
    assert approval.preview["would_refund"] == 49.9  # the approver sees the real preview


def test_policy_without_data_safety_changes_nothing(app):
    data = make_policy(app).model_dump()
    data["data_safety"] = None
    gw = Gateway(CompiledPolicy.model_validate(data), LedgerUpstream())
    assert gw.vault is None
    assert call(gw, "lookup_order", {"order_id": "ORD-1"}).content["customer_id"] == "CUS-88123"


# --------------------------------------------------------------------------- GET /results


@pytest.fixture
def results_app(app, tmp_path):
    tokens = tmp_path / "tokens.json"
    tokens.write_text(json.dumps({
        "ui-alice": {"subject": "alice", "client_id": "refunds-ui", "tenant": "DE01"},
        "agent-alice": {"subject": "alice", "client_id": "refunds-agent", "tenant": "DE01"},
        "ui-mallory": {"subject": "mallory", "client_id": "refunds-ui", "tenant": "DE01"},
    }))
    gw, _ = gateway(app, vault={"reader_clients": ["refunds-ui"], "ttl_seconds": 3600,
                                "max_bytes_per_result": 5000000, "model_preview_rows": 20})
    handle = call(gw, "query_ledger", {"query": OPEX_Q3}).content["result_handle"]
    return gw, Starlette(routes=results_routes(gw, StaticTokenVerifier(tokens))), handle


def get(asgi, path, token=None):
    async def go():
        headers = {"authorization": f"Bearer {token}"} if token else {}
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=asgi), base_url="https://gw.test") as c:
            r = await c.get(path, headers=headers)
            return r.status_code, r.json()
    return run(go())


def test_ui_reads_its_users_result(results_app):
    gw, asgi, handle = results_app
    status, body = get(asgi, f"/results/{handle}", "ui-alice")
    assert status == 200 and body["content"]["rows"][0][1] == "180.00"
    assert gw.audit.read()[-1]["event"] == "result_read"


def test_agent_client_cannot_read_results(results_app):
    gw, asgi, handle = results_app
    status, body = get(asgi, f"/results/{handle}", "agent-alice")
    assert (status, body["error"]) == (403, "RESULT_READER_NOT_ALLOWED")
    assert gw.audit.read()[-1]["event"] == "result_read_refused"


def test_other_users_and_anonymous_get_nothing(results_app):
    _, asgi, handle = results_app
    assert get(asgi, f"/results/{handle}", "ui-mallory")[0] == 404
    assert get(asgi, f"/results/{handle}")[0] == 401
    assert get(asgi, "/results/res_000", "ui-alice")[0] == 404


def test_serve_refuses_a_shared_vault_without_a_key(app, monkeypatch, capsys):
    import argparse

    from aof.gateway.cli import _vault

    monkeypatch.delenv("AOF_VAULT_KEY", raising=False)
    args = argparse.Namespace(vault_url=None, state_url="redis://localhost:6379/0")
    assert _vault(args, make_policy(app)) == 2
    assert "AOF_VAULT_KEY" in capsys.readouterr().err
    local = _vault(argparse.Namespace(vault_url=None, state_url=None), make_policy(app))
    assert isinstance(local, ResultVault) and local.ephemeral
