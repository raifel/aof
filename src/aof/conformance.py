"""Manifest-vs-server conformance: launch the app's MCP server and compare.

The gateway denies any tool not in the compiled policy, so drift between what the
server exposes and what the manifest declares is a build failure, not a warning.
Needs the optional extra: pip install 'aof[mcp]'.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from .enums import Access, RiskTier
from .findings import Finding, error, warning
from .models import ToolManifest


async def _list_tools(command: list[str], cwd: Path) -> list[Any]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=command[0], args=command[1:], cwd=str(cwd))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return (await session.list_tools()).tools


def _norm(s: str | None) -> str:
    return " ".join((s or "").split())


def compare(manifest: ToolManifest, server_tools: list[Any]) -> list[Finding]:
    out: list[Finding] = []
    served = {t.name: t for t in server_tools}
    declared = {t.name: t for t in manifest.tools}

    for name in declared.keys() - served.keys():
        if declared[name].risk_tier is RiskTier.T4:
            continue  # listed only so the gateway denies it explicitly
        out.append(error("AOF-C060", f"tools.manifest:{name}", "declared in the manifest but not served"))
    for name in served.keys() - declared.keys():
        out.append(error("AOF-C061", f"server:{name}", "served but not in the manifest (the gateway will deny it)"))

    for name in declared.keys() & served.keys():
        m, s = declared[name], served[name]
        schema = getattr(s, "input_schema", None) or getattr(s, "inputSchema", None) or {}
        server_params = set((schema.get("properties") or {}).keys())
        if server_params != set(m.params):
            out.append(warning("AOF-C062", f"tools.manifest:{name}",
                               f"params differ: manifest {sorted(m.params)} vs server {sorted(server_params)}"))
        if _norm(m.description) != _norm(getattr(s, "description", "")):
            out.append(warning("AOF-C063", f"tools.manifest:{name}",
                               "description differs from the server's; the model sees the server's"))
        ann = getattr(s, "annotations", None)
        read_only = _hint(ann, "read_only_hint", "readOnlyHint")
        if read_only is True and m.access is Access.WRITE:
            out.append(error("AOF-C066", f"tools.manifest:{name}",
                             "manifest says write but the server annotates it read-only"))
        elif read_only is not True and m.access is Access.READ:
            out.append(warning("AOF-C066", f"tools.manifest:{name}",
                               "read tool is not annotated read_only_hint=True on the server"))
    return out


def _hint(ann: Any, *names: str) -> bool | None:
    if ann is None:
        return None
    for n in names:
        v = ann.get(n) if isinstance(ann, dict) else getattr(ann, n, None)
        if v is not None:
            return v
    return None


def check_server(manifest: ToolManifest, command: list[str], cwd: Path) -> list[Finding]:
    try:
        import mcp  # noqa: F401
    except ImportError:
        return [error("AOF-C064", "aof.yaml", "the mcp package is not installed",
                      "pip install 'aof[mcp]'")]
    try:
        tools = asyncio.run(_list_tools(command, cwd))
    except Exception as exc:  # noqa: BLE001 - report any launch/protocol failure
        return [error("AOF-C065", "aof.yaml", f"could not list tools from {' '.join(command)}: {exc}")]
    return compare(manifest, tools)
