"""Natural-language queries over governed data, checked before they run (docs/data-safety.md).

The model writes a semantic query (`form: ir`) or SQL (`form: sql`); `prepare_query`
compiles the first and guards both. Pure: no I/O, no warehouse drivers. Needs `sqlglot`
(the `query` or `gateway` extra).
"""

from __future__ import annotations

from typing import Callable, Iterable, Literal, Mapping

from .guard import Claims, GuardConfig, GuardedQuery, OutputColumn, QueryRejected, guard_sql
from ..datasafety import ColumnSchema, ViewSchema, view_from_contract, views_from_contracts
from .semantic import SemanticQuery, compile_semantic, fiscal_range, parse_query


def prepare_query(query: str | dict, *, form: Literal["ir", "sql"], views: Mapping[str, ViewSchema],
                  allowed_views: Iterable[str], claims: Claims, config: GuardConfig,
                  resolve_literal: Callable[[str], str | None] | None = None,
                  count_groups: bool = False) -> GuardedQuery:
    """Compile (IR) and guard a model-written query. Raises `QueryRejected` with a stable code."""
    allowed = [v.lower() for v in allowed_views]
    if form == "ir":
        q = parse_query(query)
        name = q.view.lower()
        if name not in allowed or name not in views:
            raise QueryRejected("SQL_VIEW_NOT_ALLOWED",
                                f"{q.view} is not a view this tool may read ({', '.join(sorted(allowed))})")
        sql = compile_semantic(q, views[name], config.dialect)
    else:
        if not isinstance(query, str):
            raise QueryRejected("QUERY_INVALID", "form sql needs the query as a string")
        sql = query
    return guard_sql(sql, views=views, allowed_views=allowed, claims=claims, config=config,
                     resolve_literal=resolve_literal, count_groups=count_groups)


__all__ = [
    "Claims", "ColumnSchema", "GuardConfig", "GuardedQuery", "OutputColumn", "QueryRejected",
    "SemanticQuery", "ViewSchema", "compile_semantic", "fiscal_range", "guard_sql", "parse_query",
    "prepare_query", "view_from_contract", "views_from_contracts",
]
