"""Tool-description lint, from Anthropic's agent-computer-interface guidance.

One tool, one job; clear names; an example and the boundary with similar tools;
task-shaped tools over thin CRUD wrappers; typed, enumerated parameters; dry-run for writes.
"""

from __future__ import annotations

import re

from .enums import Access, RiskTier
from .findings import Finding, error, info, warning
from .models import ToolManifest
from .platform import PlatformConfig

SNAKE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")
CRUD_VERBS = {"get", "set", "put", "post", "update", "delete", "create", "read", "list", "fetch"}
GENERIC_NOUNS = {"record", "records", "data", "item", "items", "row", "rows", "table",
                 "object", "objects", "entity", "entities", "resource", "resources", "value"}
ENUM_LIKE = {"status", "state", "mode", "type", "kind", "category", "level", "priority", "tier", "channel"}


def lint_manifest(manifest: ToolManifest, platform: PlatformConfig) -> list[Finding]:
    cfg = platform.tools
    out: list[Finding] = []

    if len(manifest.tools) > cfg.max_tools_per_server:
        out.append(warning("AOF-L009", "tools.manifest",
                           f"{len(manifest.tools)} tools exceeds {cfg.max_tools_per_server}",
                           "fewer, better tools cut both errors and tokens"))

    tokens = {t.name: set(t.name.split("_")[1:]) for t in manifest.tools}

    for t in manifest.tools:
        where = f"tools.manifest:{t.name}"
        if not SNAKE.match(t.name):
            out.append(error("AOF-L001", where, "tool names are snake_case"))
        elif "_" not in t.name:
            out.append(warning("AOF-L001", where, "name it verb_noun so the job is clear (e.g. search_orders)"))

        parts = t.name.split("_")
        if len(parts) == 2 and parts[0] in CRUD_VERBS and parts[1] in GENERIC_NOUNS:
            out.append(warning("AOF-L002", where, "thin CRUD wrapper",
                               "prefer a task-shaped tool (e.g. create_refund_request)"))

        n = len(t.description.strip())
        if n < cfg.min_description_chars:
            out.append(error("AOF-L003", where, f"description is {n} chars; minimum {cfg.min_description_chars}"))
        elif n > cfg.max_description_chars:
            out.append(warning("AOF-L003", where, f"description is {n} chars; keep under {cfg.max_description_chars}"))

        if not t.example.strip():
            out.append(error("AOF-L004", where, "add an example call to the tool"))

        similar = [o for o, toks in tokens.items() if o != t.name and toks & tokens[t.name]]
        if similar and not t.not_for:
            out.append(warning("AOF-L005", where,
                               f"similar to {', '.join(similar)} but declares no boundary",
                               "set not_for: when to use the other tool instead"))

        for pname, p in t.params.items():
            if not p.description.strip():
                out.append(error("AOF-L006", f"{where}.{pname}", "parameter needs a description"))
            last = pname.split("_")[-1]
            if p.type == "string" and last in ENUM_LIKE and not p.enum:
                out.append(warning("AOF-L007", f"{where}.{pname}", "enumerate the allowed values"))
            if pname.endswith("_id") and p.type not in ("string", "integer"):
                out.append(warning("AOF-L010", f"{where}.{pname}", "identifiers should be absolute string/integer ids"))

        if t.access is Access.WRITE and t.risk_tier is not RiskTier.T4:
            if not t.supports_dry_run:
                out.append(warning("AOF-L008", where, "write tools should offer a dry-run mode"))
            elif "dry_run" not in t.params:
                out.append(info("AOF-L008", where, "supports_dry_run is set; declare a dry_run boolean param"))
    return out
