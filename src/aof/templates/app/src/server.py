"""{{app_title}} MCP server (artefact 1).

Tool names, parameters and descriptions must match aof/tools.manifest.yaml:
`aof check-server` launches this file and compares them.

Rules for every tool (agent-computer interface):
  - one tool, one job; task-shaped, not thin CRUD
  - typed, enumerated parameters; absolute identifiers
  - compact structured results; errors the model can act on
  - read data only through governed data products, as the calling user (never a shared account)
"""

from __future__ import annotations

from typing import Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

mcp = MCPServer("{{app_name}}")
READ_ONLY = ToolAnnotations(read_only_hint=True, idempotent_hint=True)


@mcp.tool(annotations=READ_ONLY)
def search_documents(query: str, limit: int = 5) -> dict:
    """Search the team's approved internal documents and return the most relevant passages with their titles and links. Use for policy, process and how-to questions."""
    if not 1 <= limit <= 10:
        return {"error": "limit must be between 1 and 10", "retry_with": {"limit": 5}}
    # TODO: query the governed search service (e.g. Cortex Search) with the user's token.
    return {"query": query, "results": []}


@mcp.tool(annotations=READ_ONLY)
def answer_metric_question(
    question: str,
    period: Literal["day", "week", "month", "quarter", "year"] = "month",
) -> dict:
    """Answer a question about sales metrics using the governed semantic view, returning the figure, its definition, the period and the SQL that produced it."""
    # TODO: call the semantic layer (e.g. Cortex Analyst over the sales_metrics view) as the user.
    return {"question": question, "period": period, "value": None, "definition": None, "sql": None}


if __name__ == "__main__":
    mcp.run()
