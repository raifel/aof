"""Refunds Assistant MCP server (worked example; data access is stubbed)."""

from __future__ import annotations

from typing import Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

mcp = MCPServer("refunds-assistant")

READ_ONLY = ToolAnnotations(read_only_hint=True, idempotent_hint=True)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False)

Reason = Literal["damaged_in_transit", "not_delivered", "wrong_item", "goodwill"]
TicketStatus = Literal["investigating", "pending_refund", "resolved"]


@mcp.tool(annotations=READ_ONLY)
def lookup_order(order_id: str) -> dict:
    """Look up one order by its absolute order id and return status, items, amounts, shipment events and payment method. Use before any refund decision."""
    if not order_id.startswith("ORD-"):
        return {"error": "order_id must be absolute, e.g. ORD-2026-000184"}
    return {"order_id": order_id, "status": "delivered", "amount": 49.90, "currency": "EUR"}


@mcp.tool(annotations=READ_ONLY)
def summarize_refund_history(customer_id: str) -> dict:
    """Summarise a customer's refunds over the last 12 months: count, total amount and reasons, so the agent can spot abuse or repeat issues."""
    return {"customer_id": customer_id, "count": 0, "total": 0.0, "reasons": {}}


@mcp.tool(annotations=WRITE)
def create_refund_request(
    order_id: str, amount: float, reason: Reason, request_id: str, dry_run: bool = False
) -> dict:
    """Create a refund request for an order. With dry_run=true it returns the exact refund that would be created (amount, method, ledger entries) without creating it."""
    preview = {"order_id": order_id, "amount": amount, "reason": reason, "method": "original_payment"}
    if dry_run:
        return {"dry_run": True, "would_create": preview}
    # The gateway only lets this through after a support lead approves the dry-run preview.
    return {"created": True, "refund_id": f"REF-{request_id[:8]}", **preview}


@mcp.tool(annotations=WRITE)
def update_ticket_status(ticket_id: str, status: TicketStatus, note: str, dry_run: bool = False) -> dict:
    """Set the status of the support ticket linked to a refund case and add an internal note. Customers do not see the note."""
    if len(note) > 500:
        return {"error": "note exceeds 500 chars", "max_chars": 500}
    change = {"ticket_id": ticket_id, "status": status, "note": note}
    return {"dry_run": True, "would_apply": change} if dry_run else {"applied": True, **change}


if __name__ == "__main__":
    mcp.run()
