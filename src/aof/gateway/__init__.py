"""AOF agent gateway core: every model, tool and agent call passes here.

Transport-free pieces (engine, state, approvals, audit, telemetry, core, obo) need only
the base install (obo uses httpx2 from the `gateway` extra when it makes a request). `mcp_proxy` needs the `gateway` extra.
"""

from .approvals import APPROVAL_ARG, Approval, ApprovalError, ApprovalService
from .audit import AuditLog, verify
from .compiled import CompiledPolicy, load_policy
from .core import Gateway, ToolResult, Upstream, UpstreamTool
from .engine import Action, PolicyEngine, Verdict
from .identity import Principal
from .obo import OboBroker, TokenExchanger, TokenExchangeError
from .state import DurableStore, GatewayState

__all__ = [
    "APPROVAL_ARG", "Action", "Approval", "ApprovalError", "ApprovalService", "AuditLog",
    "CompiledPolicy", "DurableStore", "Gateway", "GatewayState", "OboBroker", "PolicyEngine", "Principal",
    "TokenExchangeError", "TokenExchanger", "ToolResult", "Upstream", "UpstreamTool", "Verdict", "load_policy", "verify",
]
