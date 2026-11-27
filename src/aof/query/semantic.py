"""Semantic query IR: the model fills in metrics, dimensions, filters and a period, and this
module compiles it to SQL against one semantic view. Pure (no I/O).

The model never writes a join, function or column the compiler doesn't know. The SQL it
produces still goes through `guard.guard_sql`, so row filters, limits and exposure rules
are applied in one place.

    {"view": "gl_journal_lines", "metrics": ["opex"], "dimensions": ["cost_centre"],
     "filters": [{"dimension": "company", "op": "eq", "value": "DE01"}],
     "period": {"fiscal_year": 2026, "quarter": 3}}
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any, Literal

from pydantic import Field, PositiveInt, ValidationError, model_validator
from sqlglot import exp

from ..models.base import Strict
from ..models.data_contract import Condition, FiscalCalendar, Measure, Op, check_value
from .guard import QueryRejected
from ..datasafety import ViewSchema

Grain = Literal["day", "week", "month", "quarter", "year"]
GRAINS = ("day", "week", "month", "quarter", "year")


class Filter(Strict):
    dimension: str
    op: Op
    value: Any

    @model_validator(mode="after")
    def _value_shape(self) -> "Filter":
        check_value(self.op, self.value)
        return self


class Period(Strict):
    """A fiscal period (year, optionally quarter or period 1-12) or an inclusive date range."""

    fiscal_year: int | None = None
    quarter: int | None = Field(default=None, ge=1, le=4)
    period: int | None = Field(default=None, ge=1, le=12)  # fiscal month number
    start: dt.date | None = None
    end: dt.date | None = None  # inclusive

    @model_validator(mode="after")
    def _one_form(self) -> "Period":
        fiscal = self.fiscal_year is not None
        dates = self.start is not None or self.end is not None
        if fiscal == dates:
            raise ValueError("give either fiscal_year (with optional quarter or period) or start and end")
        if dates and (self.start is None or self.end is None or self.end < self.start):
            raise ValueError("a date range needs start <= end")
        if self.quarter and self.period:
            raise ValueError("give quarter or period, not both")
        if not fiscal and (self.quarter or self.period):
            raise ValueError("quarter and period need fiscal_year")
        return self


class OrderBy(Strict):
    field: str  # a metric or dimension in this query
    desc: bool = False


class SemanticQuery(Strict):
    view: str
    metrics: list[str] = Field(min_length=1)
    dimensions: list[str] = []  # "cost_centre", or "posting_date:month" for a time grain
    filters: list[Filter] = []
    period: Period | None = None
    order_by: list[OrderBy] = []
    limit: PositiveInt | None = None


def parse_query(raw: str | dict | SemanticQuery) -> SemanticQuery:
    if isinstance(raw, SemanticQuery):
        return raw
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        return SemanticQuery.model_validate(data)
    except (ValueError, ValidationError) as exc:
        raise QueryRejected("QUERY_INVALID", _first_error(exc)) from None


def _first_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        e = exc.errors()[0]
        return f"{'.'.join(str(p) for p in e['loc']) or 'query'}: {e['msg']}"
    return str(exc)


# --------------------------------------------------------------------------- fiscal calendar


def _add_months(d: dt.date, months: int) -> dt.date:
    y, m = divmod(d.month - 1 + months, 12)
    return dt.date(d.year + y, m + 1, 1)


def fiscal_range(cal: FiscalCalendar, fiscal_year: int, quarter: int | None = None,
                 period: int | None = None) -> tuple[dt.date, dt.date]:
    """[start, end) of a fiscal year, quarter or period."""
    start_year = fiscal_year
    if cal.year_named_by == "end" and cal.year_start_month != 1:
        start_year -= 1
    start = dt.date(start_year, cal.year_start_month, 1)
    if quarter:
        start = _add_months(start, 3 * (quarter - 1))
        return start, _add_months(start, 3)
    if period:
        start = _add_months(start, period - 1)
        return start, _add_months(start, 1)
    return start, _add_months(start, 12)


def period_range(p: Period, cal: FiscalCalendar | None) -> tuple[dt.date, dt.date]:
    if p.fiscal_year is not None:
        return fiscal_range(cal or FiscalCalendar(), p.fiscal_year, p.quarter, p.period)
    return p.start, p.end + dt.timedelta(days=1)  # type: ignore[operator]


# --------------------------------------------------------------------------- compile


def _condition(col: exp.Expression, op: str, value: Any) -> exp.Expression:
    v = exp.convert
    if op == "eq":
        return exp.EQ(this=col, expression=v(value))
    if op == "ne":
        return exp.NEQ(this=col, expression=v(value))
    if op == "in":
        return col.isin(*[v(x) for x in value])
    if op == "not_in":
        return exp.Not(this=col.isin(*[v(x) for x in value]))
    if op == "between":
        return exp.Between(this=col, low=v(value[0]), high=v(value[1]))
    cls = {"gt": exp.GT, "gte": exp.GTE, "lt": exp.LT, "lte": exp.LTE}[op]
    return cls(this=col, expression=v(value))


def _measure_expr(m: Measure) -> exp.Expression:
    value: exp.Expression = exp.column(m.field) if m.field else exp.Literal.number(1)
    if m.filter:
        cond = exp.and_(*[_condition(exp.column(c.column), c.op, c.value) for c in m.filter])
        value = exp.Case().when(cond, value)
    if m.agg == "sum":
        agg: exp.Expression = exp.Sum(this=value)
    elif m.agg == "avg":
        agg = exp.Avg(this=value)
    elif m.agg == "min":
        agg = exp.Min(this=value)
    elif m.agg == "max":
        agg = exp.Max(this=value)
    elif m.agg == "count_distinct":
        agg = exp.Count(this=exp.Distinct(expressions=[value]))
    else:  # count
        agg = exp.Count(this=value if (m.field or m.filter) else exp.Star())
    if m.sign == -1:
        agg = exp.Neg(this=exp.Paren(this=agg))
    return agg


def compile_semantic(q: SemanticQuery, view: ViewSchema, dialect: str) -> str:
    """SQL for one semantic query. Run it through `guard_sql` before executing."""
    if q.view.lower() != view.name.lower():
        raise QueryRejected("QUERY_INVALID", f"query is for {q.view}, not {view.name}")

    projections: list[exp.Expression] = []
    group: list[exp.Expression] = []
    selected: set[str] = set()
    grouped_dims: set[str] = set()
    for spec in q.dimensions:
        name, _, grain = spec.partition(":")
        d = view.dimension(name)
        if d is None:
            raise QueryRejected("QUERY_UNKNOWN_FIELD",
                                f"unknown dimension {name}; known: {', '.join(x.name for x in view.dimensions)}")
        col: exp.Expression = exp.column(d.field)
        alias = name
        if grain:
            if not d.time or grain not in GRAINS:
                raise QueryRejected("QUERY_INVALID", f"grain {grain!r} needs a time dimension and one of {GRAINS}")
            col = exp.DateTrunc(this=col, unit=exp.Literal.string(grain.upper()))
            alias = f"{name}_{grain}"
        projections.append(exp.alias_(col, alias))
        group.append(col.copy())
        selected.add(alias)
        grouped_dims.add(name)

    for mname in q.metrics:
        m = view.measure(mname)
        if m is None:
            raise QueryRejected("QUERY_UNKNOWN_FIELD",
                                f"unknown metric {mname}; known: {', '.join(x.name for x in view.measures)}")
        projections.append(exp.alias_(_measure_expr(m), mname))
        selected.add(mname)

    where: list[exp.Expression] = []
    filtered: set[str] = set()
    for f in q.filters:
        d = view.dimension(f.dimension)
        if d is None:
            raise QueryRejected("QUERY_UNKNOWN_FIELD", f"unknown dimension {f.dimension} in filters")
        where.append(_condition(exp.column(d.field), f.op, f.value))
        filtered.add(d.name)
    if q.period is not None:
        time_dim = next((d for d in view.dimensions if d.time), None)
        if time_dim is None:
            raise QueryRejected("QUERY_INVALID", f"{view.name} has no time dimension for a period")
        start, end = period_range(q.period, view.fiscal_calendar)
        col = exp.column(time_dim.field)
        where += [exp.GTE(this=col, expression=exp.Literal.string(start.isoformat())),
                  exp.LT(this=col.copy(), expression=exp.Literal.string(end.isoformat()))]
        filtered.add(time_dim.name)

    for d in view.dimensions:
        if d.required and d.name not in filtered and d.name not in grouped_dims:
            hint = f" ({d.description})" if d.description else ""
            raise QueryRejected("QUERY_NEEDS_CLARIFICATION",
                                f"ask the user which {d.name}{hint} they mean, then filter or group by it")

    select = exp.select(*projections).from_(exp.to_table(view.name))
    if where:
        select = select.where(exp.and_(*where))
    if group:
        select = select.group_by(*group)
    for o in q.order_by:
        if o.field not in selected:
            raise QueryRejected("QUERY_UNKNOWN_FIELD", f"order_by {o.field} is not a metric or dimension in this query")
        select = select.order_by(exp.Ordered(this=exp.column(o.field), desc=o.desc))
    if q.limit:
        select = select.limit(q.limit)
    return select.sql(dialect=dialect)


__all__ = ["Condition", "Filter", "OrderBy", "Period", "SemanticQuery", "compile_semantic",
           "fiscal_range", "parse_query", "period_range"]
