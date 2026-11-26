"""End to end over MCP: agent client -> gateway server -> the example app's MCP server."""

from __future__ import annotations

import asyncio
import importlib.util

import pytest

pytest.importorskip("mcp")

from mcp import Client  # noqa: E402

from aof.cli import main  # noqa: E402
from aof.gateway import APPROVAL_ARG, Gateway  # noqa: E402
from aof.gateway.mcp_proxy import McpUpstream, build_server, fixed_principal  # noqa: E402

from .conftest import EXAMPLE  # noqa: E402
from .test_gateway_core import ALICE, LEAD, REFUND, make_policy  # noqa: E402


def _example_server():
    spec = importlib.util.spec_from_file_location("refunds_server", EXAMPLE / "src" / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.mcp


async def _scenario():
    policy = make_policy("L2")
    upstream = McpUpstream(_example_server())
    gateway = Gateway(policy, upstream)
    server = build_server(gateway, fixed_principal(ALICE))
    async with upstream, Client(server) as agent:
        tools = {t.name for t in (await agent.list_tools()).tools}
        read = await agent.call_tool("lookup_order", {"order_id": "ORD-2026-000184"})
        pending = await agent.call_tool("create_refund_request", REFUND)
        aid = pending.structured_content["approval_id"]
        gateway.approvals.approve(aid, LEAD)
        done = await agent.call_tool("create_refund_request", {**REFUND, APPROVAL_ARG: aid})
        denied = await agent.call_tool("delete_customer_account", {"customer_id": "CUS-1"})
    return tools, read, pending, done, denied


def test_gateway_over_mcp():
    tools, read, pending, done, denied = asyncio.run(_scenario())
    assert tools == {"lookup_order", "summarize_refund_history", "create_refund_request", "update_ticket_status"}
    assert not read.is_error and read.structured_content["status"] == "delivered"
    assert pending.structured_content["status"] == "approval_required"
    assert pending.structured_content["preview"]["would_create"]["amount"] == 49.9
    assert not done.is_error and done.structured_content["created"] is True
    assert denied.is_error and denied.structured_content["error"] == "DENIED_BY_POLICY"


def test_operator_cli(tmp_path, capsys):
    sd = ["--state-dir", str(tmp_path)]
    assert main(["gateway", "kill", "agent:refunds-assistant", "--by", "ops", "--reason", "drill", *sd]) == 0
    assert main(["gateway", "revive", "agent:refunds-assistant", "--by", "ops", *sd]) == 0
    assert main(["gateway", "demote", "agent:refunds-assistant", "--to", "L1", "--by", "ops",
                 "--reason", "SLO", *sd]) == 0
    assert main(["gateway", "approvals", *sd]) == 0
    assert main(["gateway", "audit", "--verify", *sd]) == 0
    assert "audit.jsonl: chain OK (3 records)" in capsys.readouterr().out
