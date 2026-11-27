"""SQL guard: check and rewrite a model-written query before it reaches the warehouse.

Pure (no I/O). Works on the sqlglot syntax tree, never on strings. In order:

1. one statement, a read-only query (no DML, DDL, SELECT INTO, locks, commands);
2. no parameters, table functions, recursive CTEs or CTEs that shadow a view;
3. every table is an unqualified semantic view the tool may read;
4. every function is on the platform allowlist;
5. every column exists in its view (sqlglot `qualify`, which also expands `*`);
6. predicates (WHERE, HAVING, JOIN ... ON, QUALIFY, and GROUP BY expressions other than a
   bare column) may use a column only if it is a declared dimension or exposed
   `aggregate`/`allowed`; `token`/`masked` columns only in equality or IN; measures and
   hidden columns never (stops bisection on hidden values);
7. the row filter from the data contract is applied around every view, bound from the
   caller's verified claims (fail closed when a claim is missing);
8. LIMIT is set to at most `max_rows`.

It also works out how much of each output column the model may see (`OutputColumn`), so
the gateway's result vault knows what to hide: an output is as exposed as the least
exposed column it is computed from, ORDER BY on a hidden column hides every column (row
order leaks it), and a raw `aggregate` column is hidden unless the query aggregates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Sequence

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, SqlglotError, TokenError
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import Scope, traverse_scope

from ..enums import Exposure
from ..datasafety import ViewSchema


class QueryRejected(Exception):
    """A query the guard or compiler refused. `code` is stable; the model can act on it."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class GuardConfig:
    dialect: str
    max_rows: int
    allowed_functions: frozenset[str]

    @classmethod
    def of(cls, dialect: str, max_rows: int, allowed_functions: Iterable[str]) -> "GuardConfig":
        return cls(dialect, max_rows, frozenset(f.upper() for f in allowed_functions))


@dataclass(frozen=True)
class OutputColumn:
    name: str
    exposure: Exposure


@dataclass(frozen=True)
class GuardedQuery:
    sql: str  # the rewritten query to run
    views: tuple[str, ...]
    columns: tuple[OutputColumn, ...]
    aggregated: bool  # the outer query aggregates (GROUP BY or aggregate functions)
    max_rows: int
    group_rows_column: str | None = None  # added COUNT(*) per group, for min_group_size


Claims = Mapping[str, "str | Sequence[str]"]

_WRITE_NODES = tuple(getattr(exp, n) for n in (
    "Insert", "Update", "Delete", "Merge", "Create", "Drop", "Alter", "Command", "Into",
    "Copy", "Use", "Set", "Lock", "Transaction", "Commit", "Rollback", "LoadData", "Grant",
) if hasattr(exp, n))
_FORBIDDEN_NODES = tuple(getattr(exp, n) for n in (
    "Placeholder", "Parameter", "Lateral", "TableFromRows", "Unnest",
) if hasattr(exp, n))
# Func subclasses that are operators or syntax, not function calls.
_OPERATOR_NODES = tuple(getattr(exp, n) for n in (
    "Connector", "Binary", "Unary", "Predicate", "Paren", "Distinct", "Star", "Interval",
) if hasattr(exp, n))


@dataclass(frozen=True)
class _Info:
    exposure: Exposure
    filterable: bool  # derived only from declared dimensions


_OPEN = _Info(Exposure.ALLOWED, True)


GROUP_ROWS = "aof_group_rows"


def guard_sql(sql: str, *, views: Mapping[str, ViewSchema], allowed_views: Iterable[str],
              claims: Claims, config: GuardConfig,
              resolve_literal: Callable[[str], str | None] | None = None,
              count_groups: bool = False) -> GuardedQuery:
    """`resolve_literal` maps a string literal to its real value (gateway tokens) on the
    syntax tree, so a value can never change the query's structure. `count_groups` adds
    COUNT(*) per group to an aggregated query, so small groups can be suppressed."""
    allowed = {v.lower() for v in allowed_views}
    stmt = _parse_one(sql, config.dialect)
    if resolve_literal is not None:
        for lit in list(stmt.find_all(exp.Literal)):
            if lit.is_string:
                real = resolve_literal(lit.this)
                if real is not None:
                    lit.replace(exp.convert(real))
    _check_structure(stmt, allowed, {v.lower() for v in views})
    _check_functions(stmt, config.allowed_functions)

    schema = {name: {c: _type(col.type, config.dialect) for c, col in views[name].columns.items()}
              for name in allowed if name in views}
    try:
        stmt = qualify(stmt, schema=schema, dialect=config.dialect, validate_qualify_columns=True,
                       quote_identifiers=False)
    except SqlglotError as exc:
        raise QueryRejected("SQL_COLUMN_NOT_ALLOWED", f"unknown or ambiguous column: {exc}") from None

    analysis = _Analysis(views)
    for scope in traverse_scope(stmt):
        analysis.visit(scope)
    outputs = analysis.outputs(stmt)
    aggregated = _is_aggregated(_first_select(stmt))
    group_col = None
    if count_groups and aggregated and isinstance(stmt, exp.Select):
        if any(n == GROUP_ROWS for n, _ in outputs):
            raise QueryRejected("SQL_CONSTRUCT_NOT_ALLOWED", f"{GROUP_ROWS} is a reserved column name")
        stmt.append("expressions", exp.alias_(exp.Count(this=exp.Star()), GROUP_ROWS))
        group_col = GROUP_ROWS

    used = _apply_row_filters(stmt, views, claims, config.dialect)
    _apply_limit(stmt, config.max_rows)
    return GuardedQuery(
        sql=stmt.sql(dialect=config.dialect),
        views=tuple(sorted(used)),
        columns=tuple(OutputColumn(n, i.exposure) for n, i in outputs),
        aggregated=aggregated,
        max_rows=config.max_rows,
        group_rows_column=group_col,
    )


# --------------------------------------------------------------------------- structure


def _parse_one(sql: str, dialect: str) -> exp.Expression:
    try:
        stmts = [s for s in sqlglot.parse(sql, read=dialect) if s is not None]
    except (ParseError, TokenError) as exc:
        raise QueryRejected("SQL_UNPARSEABLE", str(exc).splitlines()[0]) from None
    if len(stmts) != 1:
        raise QueryRejected("SQL_NOT_READ_ONLY", f"expected exactly one statement, got {len(stmts)}")
    stmt = stmts[0]
    if not isinstance(stmt, exp.Query):
        raise QueryRejected("SQL_NOT_READ_ONLY", f"only SELECT queries are allowed, got {stmt.key.upper()}")
    return stmt


def _check_structure(stmt: exp.Expression, allowed: set[str], known_views: set[str]) -> None:
    for node in stmt.walk():
        if isinstance(node, _WRITE_NODES):
            raise QueryRejected("SQL_NOT_READ_ONLY", f"{node.key.upper()} is not allowed in a query")
        if isinstance(node, _FORBIDDEN_NODES):
            raise QueryRejected("SQL_CONSTRUCT_NOT_ALLOWED", f"{node.key.upper()} is not allowed")
        if isinstance(node, exp.With) and node.args.get("recursive"):
            raise QueryRejected("SQL_CONSTRUCT_NOT_ALLOWED", "recursive CTEs are not allowed")

    ctes = {c.alias_or_name.lower() for c in stmt.find_all(exp.CTE)}
    shadow = ctes & (allowed | known_views)
    if shadow:
        raise QueryRejected("SQL_CONSTRUCT_NOT_ALLOWED", f"CTE name shadows a view: {sorted(shadow)}")
    for table in stmt.find_all(exp.Table):
        if not isinstance(table.this, exp.Identifier):
            raise QueryRejected("SQL_CONSTRUCT_NOT_ALLOWED", "table functions are not allowed")
        name = table.name.lower()
        if table.args.get("db") or table.args.get("catalog"):
            raise QueryRejected("SQL_VIEW_NOT_ALLOWED",
                                f"{table.sql()}: use the semantic view name without database or schema")
        if name not in ctes and name not in allowed:
            raise QueryRejected("SQL_VIEW_NOT_ALLOWED",
                                f"{name} is not a view this tool may read ({', '.join(sorted(allowed))})")


def _check_functions(stmt: exp.Expression, allowed: frozenset[str]) -> None:
    for fn in stmt.find_all(exp.Func):
        if isinstance(fn, _OPERATOR_NODES):
            continue
        names = [fn.name.upper()] if isinstance(fn, exp.Anonymous) else [n.upper() for n in fn.sql_names()]
        if not names or any(n in allowed for n in names):
            continue
        raise QueryRejected("SQL_FUNCTION_NOT_ALLOWED", f"function {names[0]} is not allowed")


def _type(type_str: str, dialect: str) -> str:
    try:
        return exp.DataType.build(type_str, dialect=dialect).sql(dialect=dialect)
    except SqlglotError:
        return "TEXT"


# --------------------------------------------------------------------------- exposure


def _is_aggregated(select: exp.Select | None) -> bool:
    if select is None:
        return False
    if select.args.get("group"):
        return True
    return any(_has_plain_agg(p) for p in select.expressions)


def _has_plain_agg(node: exp.Expression) -> bool:
    """An aggregate function that is not a window function, outside nested queries."""
    for n in _walk_local(node):
        if isinstance(n, exp.AggFunc) and not isinstance(n.parent, exp.Window):
            return True
    return False


def _walk_local(node: exp.Expression):
    """Walk `node` without descending into nested queries (they have their own scope)."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        if n is not node and isinstance(n, exp.Query):
            continue
        stack.extend(n.iter_expressions())


def _first_select(q: exp.Expression) -> exp.Select | None:
    while isinstance(q, (exp.SetOperation, exp.Subquery)):
        q = q.this
    return q if isinstance(q, exp.Select) else None


def _min(infos: list[_Info], default: _Info) -> _Info:
    if not infos:
        return default
    return _Info(min(i.exposure for i in infos), all(i.filterable for i in infos))


class _Analysis:
    def __init__(self, views: Mapping[str, ViewSchema]):
        self.views = views
        self._out: dict[int, list[tuple[str, _Info]]] = {}

    def outputs(self, q: exp.Expression) -> list[tuple[str, _Info]]:
        if isinstance(q, exp.Subquery):
            return self.outputs(q.this)
        if isinstance(q, exp.SetOperation):
            left, right = self.outputs(q.this), self.outputs(q.expression)
            return [(n, _min([a, b], _OPEN)) for (n, a), (_, b) in zip(left, right)]
        if id(q) not in self._out:
            raise QueryRejected("SQL_CONSTRUCT_NOT_ALLOWED", f"unsupported query shape: {q.key}")
        return self._out[id(q)]

    def _query_info(self, q: exp.Expression) -> _Info:
        return _min([i for _, i in self.outputs(q)], _OPEN)

    def _column(self, scope: Scope, col: exp.Column, aggregated: bool,
                aliases: dict[str, _Info]) -> _Info:
        table, name = col.table.lower(), col.name.lower()
        if not table:
            if name in aliases:
                return aliases[name]
            raise QueryRejected("SQL_COLUMN_NOT_ALLOWED", f"cannot resolve column {col.sql()}")
        s: Scope | None = scope
        while s is not None:
            for alias, src in s.sources.items():
                if alias.lower() != table:
                    continue
                if isinstance(src, exp.Table):
                    view = self.views[src.name.lower()]
                    c = view.column(name)
                    if c is None:
                        raise QueryRejected("SQL_COLUMN_NOT_ALLOWED", f"{view.name} has no column {name}")
                    is_dim = any(d.field.lower() == name for d in view.dimensions)
                    e = c.exposure
                    if e is Exposure.AGGREGATE and not aggregated:
                        e = Exposure.NONE  # a raw read of an aggregate-only column
                    return _Info(e, is_dim)
                for out_name, info in self.outputs(src.expression):
                    if out_name == name:
                        return info
                raise QueryRejected("SQL_COLUMN_NOT_ALLOWED", f"cannot resolve column {col.sql()}")
            s = s.parent
        raise QueryRejected("SQL_COLUMN_NOT_ALLOWED", f"cannot resolve column {col.sql()}")

    def _operands(self, scope: Scope, node: exp.Expression, aggregated: bool,
                  aliases: dict[str, _Info]):
        """(node, info) for every column and nested query inside `node`."""
        for n in _walk_local(node):
            if n is node and isinstance(n, exp.Query):
                continue
            if isinstance(n, exp.Column):
                yield n, self._column(scope, n, aggregated, aliases)
            elif isinstance(n, exp.Query) and n is not node:
                if isinstance(n.parent, exp.Exists):
                    continue  # EXISTS leaks only existence; its own predicates are checked
                yield n, self._query_info(n)

    def visit(self, scope: Scope) -> None:
        select = scope.expression
        if not isinstance(select, exp.Select):
            return  # set operations are combined from their branches in outputs()
        aggregated = _is_aggregated(select)
        outs: list[tuple[str, _Info]] = []
        for proj in select.expressions:
            infos = [i for _, i in self._operands(scope, proj, aggregated, {})]
            has_agg = _has_plain_agg(proj)
            default = _Info(Exposure.AGGREGATE if has_agg else Exposure.ALLOWED, not has_agg)
            info = _min(infos, default) if infos else default
            if has_agg:
                info = _Info(info.exposure, False)
            outs.append((proj.alias_or_name.lower(), info))
        aliases = dict(outs)

        order = select.args.get("order")
        if order is not None:
            cap = _min([i for _, i in self._operands(scope, order, aggregated, aliases)], _OPEN)
            outs = [(n, _Info(min(i.exposure, cap.exposure), i.filterable and cap.filterable))
                    for n, i in outs]
        self._out[id(select)] = outs

        predicates = [select.args.get(k) for k in ("where", "having", "qualify")]
        predicates += [j.args.get("on") for j in select.args.get("joins") or []]
        for pred in filter(None, predicates):
            for node, info in self._operands(scope, pred, aggregated, aliases):
                _check_predicate_operand(node, info)
        # Grouping by an expression over a hidden value turns the group count into a
        # bisection channel (GROUP BY CASE WHEN amount > 1000 ...). Bare columns are fine.
        group = select.args.get("group")
        for item in group.expressions if group is not None else []:
            if isinstance(item, exp.Column):
                continue
            for node, info in self._operands(scope, item, aggregated, aliases):
                _check_predicate_operand(node, info)


def _check_predicate_operand(node: exp.Expression, info: _Info) -> None:
    if info.filterable or info.exposure >= Exposure.AGGREGATE:
        return
    parent = node.parent
    while isinstance(parent, (exp.Paren, exp.Subquery)):
        parent = parent.parent
    if info.exposure >= Exposure.TOKEN and isinstance(parent, (exp.EQ, exp.NEQ, exp.In)):
        return
    what = node.sql() if isinstance(node, exp.Column) else "a subquery"
    raise QueryRejected(
        "SQL_FILTER_NOT_ALLOWED",
        f"cannot filter on {what}: filter on declared dimensions only "
        f"({'equality only for token columns' if info.exposure >= Exposure.TOKEN else 'its values are hidden'})",
    )


# --------------------------------------------------------------------------- rewrites


def _apply_row_filters(stmt: exp.Expression, views: Mapping[str, ViewSchema], claims: Claims,
                       dialect: str) -> set[str]:
    used: set[str] = set()
    ctes = {c.alias_or_name.lower() for c in stmt.find_all(exp.CTE)}
    for table in list(stmt.find_all(exp.Table)):
        name = table.name.lower()
        if name in ctes:
            continue
        used.add(name)
        view = views[name]
        if not view.row_filter:
            continue
        conds = []
        for rf in view.row_filter:
            if rf.claim not in claims or claims[rf.claim] is None:
                raise QueryRejected("ROW_FILTER_UNBOUND",
                                    f"{view.name} is filtered by claim {rf.claim!r}, which the caller lacks")
            values = claims[rf.claim]
            values = [values] if isinstance(values, str) else list(values)
            col = exp.column(rf.column)
            conds.append(col.isin(*[exp.convert(v) for v in values]) if values
                         else exp.EQ(this=exp.Literal.number(1), expression=exp.Literal.number(0)))
        inner = exp.select("*").from_(exp.Table(this=table.this.copy())).where(exp.and_(*conds))
        table.replace(inner.subquery(table.alias_or_name))
    return used


def _apply_limit(stmt: exp.Expression, max_rows: int) -> None:
    if stmt.args.get("fetch") is not None:
        stmt.set("fetch", None)
    limit = stmt.args.get("limit")
    n = max_rows
    if limit is not None:
        value = limit.args.get("expression")
        if isinstance(value, exp.Literal) and value.is_int:
            n = min(int(value.this), max_rows)
    stmt.set("limit", exp.Limit(expression=exp.Literal.number(n)))
