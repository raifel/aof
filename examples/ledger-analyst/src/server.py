"""Ledger Analyst MCP server (worked example; DuckDB over the fixture CSVs in data/).

The gateway compiles and guards every query before it arrives here: the app receives
plain SQL with the caller's company filter already applied, and returns the rows. The
gateway keeps those rows in its result vault; the model never sees them.
"""

from __future__ import annotations

import datetime as dt
import decimal
from pathlib import Path

import duckdb
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

DATA = Path(__file__).resolve().parents[1] / "data"
READ_ONLY = ToolAnnotations(read_only_hint=True, idempotent_hint=True)

mcp = MCPServer("ledger-analyst")


def connect() -> duckdb.DuckDBPyConnection:
    db = duckdb.connect()
    db.execute(f"""CREATE TABLE gl_journal_lines AS SELECT company_code, cost_centre, account_code,
        CAST(posting_date AS DATE) AS posting_date, CAST(amount_eur AS DECIMAL(18,2)) AS amount_eur,
        NULLIF(vendor_id, '') AS vendor_id, description
        FROM read_csv('{DATA / "gl_journal_lines.csv"}', all_varchar = true)""")
    db.execute(f"""CREATE TABLE budget_lines AS SELECT company_code, cost_centre, account_code,
        CAST(fiscal_year AS INTEGER) AS fiscal_year, CAST(fiscal_period AS INTEGER) AS fiscal_period,
        CAST(budget_eur AS DECIMAL(18,2)) AS budget_eur
        FROM read_csv('{DATA / "budget_lines.csv"}', all_varchar = true)""")
    return db


DB = connect()


def _json(v):
    if isinstance(v, decimal.Decimal):
        return float(v)
    if isinstance(v, (dt.date, dt.datetime)):
        return v.isoformat()[:10]
    return v


def run(query: str) -> dict:
    cur = DB.cursor().execute(query)
    return {"columns": [d[0].lower() for d in cur.description], "rows": [[_json(v) for v in r] for r in cur.fetchall()]}


@mcp.tool(annotations=READ_ONLY)
def query_ledger(query: str) -> dict:
    """Answer a finance question with a semantic query over the general ledger (view gl_journal_lines; metrics revenue, opex, personnel_cost, travel, software, rent, lines; dimensions company, cost_centre, account, vendor, posting_date with :month or :quarter) or budgets (view budget_lines; metric budget; dimensions company, cost_centre, account, fiscal_year, fiscal_period). Returns a result handle, the columns and a row-count range; the user sees the figures."""
    return run(query)


@mcp.tool(annotations=READ_ONLY)
def query_ledger_sql(query: str) -> dict:
    """Run one read-only SQL SELECT over the views gl_journal_lines and budget_lines. The gateway checks it and adds your company filter. Returns a result handle, the columns and a row-count range."""
    return run(query)


if __name__ == "__main__":
    mcp.run()
