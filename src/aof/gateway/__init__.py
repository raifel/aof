"""AOF agent gateway core: every model, tool and agent call passes here.

Transport-free pieces (engine, state, approvals, audit, telemetry, core) need only
the base install. `mcp_proxy` needs the `gateway` extra.
"""

from .approvals import APPROVAL_ARG, Approval, ApprovalError, ApprovalService
from .audit import AuditLog, verify
from .compiled import CompiledPolicy, load_policy
from .core import Gateway, ToolResult, Upstream, UpstreamTool
from .engine import Action, PolicyEngine, Verdict
from .identity import Principal
from .state import DurableStore, GatewayState

__all__ = [
    "APPROVAL_ARG", "Action", "Approval", "ApprovalError", "ApprovalService", "AuditLog",
    "CompiledPolicy", "DurableStore", "Gateway", "GatewayState", "PolicyEngine", "Principal",
    "ToolResult", "Upstream", "UpstreamTool", "Verdict", "load_policy", "verify",
]
