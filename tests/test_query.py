"""Semantic queries and the SQL guard (D4, docs/data-safety.md).

Guarded SQL is executed against an in-memory DuckDB ledger, so row filters, limits and
compiled metrics are checked on real results, not on SQL text."""

from __future__ import annotations

import datetime as dt

import pytest

from aof.datasafety import views_from_contracts
from aof.enums import DataSafetyMode, Exposure
from aof.models.data_contract import DataContract, FiscalCalendar
from aof.platform import load_platform
from aof.query import GuardConfig, QueryRejected, fiscal_range, guard_sql, prepare_query

duckdb = pytest.importorskip("duckdb")

GL = DataContract.model_validate({
    "name": "gl_journal_lines", "owner": "finance-data", "source": "duckdb:gl",
    "semantic_view": "gl_journal_lines", "freshness_sla": "1h", "classification": "confidential",
    "fields": [
        {"name": "company_code", "type": "string", "classification": "public", "llm_exposure": "allowed"},
        {"name": "account_code", "type": "string"},  # internal -> aggregate by default
        {"name": "cost_centre", "type": "string"},
        {"name": "posting_date", "type": "date"},
        {"name": "amount_eur", "type": "number(18,2)", "classification": "confidential"},
        {"name": "vendor_id", "type": "string", "pii": True, "llm_exposure": "token"},
    ],
    "row_filter": [{"column": "company_code", "claim": "tenant"}],
    "measures": [
        {"name": "opex", "field": "amount_eur", "agg": "sum",
         "filter": [{"column": "account_code", "op": "between", "value": ["6000", "7999"]}]},
        {"name": "revenue", "field": "amount_eur", "agg": "sum", "sign": -1,  # credits are negative
         "filter": [{"column": "account_code", "op": "between", "value": ["4000", "4999"]}]},
        {"name": "lines", "agg": "count"},
    ],
    "dimensions": [
        {"name": "company", "field": "company_code", "required": True, "description": "legal entity"},
        {"name": "cost_centre", "field": "cost_centre"},
        {"name": "account", "field": "account_code"},
        {"name": "posting_date", "field": "posting_date", "time": True},
    ],
    "fiscal_calendar": {"year_start_month": 4},
})

ROWS = [  # company, account, cost centre, date, amount (debit +, credit -), vendor
    ("DE01", "6100", "CC10", "2025-10-15", 100.00, "V1"),
    ("DE01", "6200", "CC10", "2025-11-03", 50.00, "V2"),
    ("DE01", "6100", "CC20", "2025-12-20", 30.00, "V1"),
    ("DE01", "4000", "CC10", "2025-10-31", -500.00, None),
    ("DE01", "6100", "CC10", "2026-01-05", 999.00, "V3"),   # Q4 FY2026: outside Q3
    ("DE02", "6100", "CC10", "2025-10-15", 7000.00, "V9"),  # other entity
]
FUNCS = load_platform().data_safety.query.allowed_functions


@pytest.fixture
def db():
    con = duckdb.connect()
    con.execute("CREATE TABLE gl_journal_lines (company_code VARCHAR, account_code VARCHAR, cost_centre VARCHAR,"
                " posting_date DATE, amount_eur DECIMAL(18,2), vendor_id VARCHAR)")
    con.executemany("INSERT INTO gl_journal_lines VALUES (?, ?, ?, ?, ?, ?)", ROWS)
    return con


def views(mode=DataSafetyMode.CONTRACT):
    return views_from_contracts([GL], load_platform().data_safety.default_exposure, mode)


CFG = GuardConfig.of("duckdb", 100, FUNCS)
DE01 = {"tenant": ["DE01"]}


def guard(sql, claims=DE01, mode=DataSafetyMode.CONTRACT, cfg=CFG):
    return guard_sql(sql, views=views(mode), allowed_views=["gl_journal_lines"], claims=claims, config=cfg)


def ir(query, claims=DE01, cfg=CFG):
    return prepare_query(query, form="ir", views=views(), allowed_views=["gl_journal_lines"],
                         claims=claims, config=cfg)


def run(db, guarded):
    return db.execute(guarded.sql).fetchall()


# --------------------------------------------------------------------------- fiscal calendar


@pytest.mark.parametrize("cal,fy,q,p,expected", [
    (FiscalCalendar(year_start_month=4), 2026, None, None, ("2025-04-01", "2026-04-01")),
    (FiscalCalendar(year_start_month=4), 2026, 3, None, ("2025-10-01", "2026-01-01")),
    (FiscalCalendar(year_start_month=4), 2026, None, 12, ("2026-03-01", "2026-04-01")),
    (FiscalCalendar(year_start_month=4, year_named_by="start"), 2026, 1, None, ("2026-04-01", "2026-07-01")),
    (FiscalCalendar(), 2026, 4, None, ("2026-10-01", "2027-01-01")),
])
def test_fiscal_range(cal, fy, q, p, expected):
    start, end = fiscal_range(cal, fy, q, p)
    assert (start.isoformat(), end.isoformat()) == expected


# --------------------------------------------------------------------------- semantic queries


def test_opex_by_cost_centre_for_a_fiscal_quarter(db):
    g = ir({"view": "gl_journal_lines", "metrics": ["opex"], "dimensions": ["cost_centre"],
            "filters": [{"dimension": "company", "op": "eq", "value": "DE01"}],
            "period": {"fiscal_year": 2026, "quarter": 3}, "order_by": [{"field": "cost_centre"}]})
    assert [(cc, float(v)) for cc, v in run(db, g)] == [("CC10", 150.0), ("CC20", 30.0)]
    assert g.aggregated and g.views == ("gl_journal_lines",)


def test_sign_convention_makes_revenue_positive(db):
    g = ir({"view": "gl_journal_lines", "metrics": ["revenue", "lines"], "dimensions": ["company"],
            "period": {"start": "2025-10-01", "end": "2025-12-31"}})
    assert [(c, float(r), n) for c, r, n in run(db, g)] == [("DE01", 500.0, 4)]


def test_time_grain(db):
    g = ir({"view": "gl_journal_lines", "metrics": ["opex"], "dimensions": ["company", "posting_date:month"],
            "period": {"fiscal_year": 2026, "quarter": 3}, "order_by": [{"field": "posting_date_month"}]})
    assert [(m.month, float(v)) for _, m, v in run(db, g)] == [(10, 100.0), (11, 50.0), (12, 30.0)]


def test_row_filter_wins_over_the_query(db):
    g = ir({"view": "gl_journal_lines", "metrics": ["opex"], "dimensions": ["company"],
            "filters": [{"dimension": "company", "op": "eq", "value": "DE02"}]})
    assert run(db, g) == []


def test_missing_required_dimension_asks_the_user():
    with pytest.raises(QueryRejected) as e:
        ir({"view": "gl_journal_lines", "metrics": ["opex"], "period": {"fiscal_year": 2026}})
    assert e.value.code == "QUERY_NEEDS_CLARIFICATION" and "company" in e.value.message


@pytest.mark.parametrize("query,code", [
    ({"view": "gl_journal_lines", "metrics": ["ebitda"], "dimensions": ["company"]}, "QUERY_UNKNOWN_FIELD"),
    ({"view": "gl_journal_lines", "metrics": ["opex"], "dimensions": ["region"]}, "QUERY_UNKNOWN_FIELD"),
    ({"view": "gl_journal_lines", "metrics": ["opex"], "dimensions": ["company"],
      "order_by": [{"field": "revenue"}]}, "QUERY_UNKNOWN_FIELD"),
    ({"view": "gl_journal_lines", "metrics": ["opex"], "dimensions": ["company:month"]}, "QUERY_INVALID"),
    ({"view": "gl_journal_lines", "metrics": []}, "QUERY_INVALID"),
    ({"view": "gl_journal_lines", "metrics": ["opex"], "period": {"fiscal_year": 2026, "start": "2025-01-01"}},
     "QUERY_INVALID"),
    ("{not json", "QUERY_INVALID"),
    ({"view": "payroll", "metrics": ["opex"]}, "SQL_VIEW_NOT_ALLOWED"),
])
def test_bad_semantic_queries(query, code):
    with pytest.raises(QueryRejected) as e:
        ir(query)
    assert e.value.code == code


def test_filter_values_are_literals_not_sql(db):
    g = ir({"view": "gl_journal_lines", "metrics": ["lines"], "dimensions": ["company"],
            "filters": [{"dimension": "cost_centre", "op": "eq", "value": "x' OR '1'='1"}]})
    assert run(db, g) == []


# --------------------------------------------------------------------------- SQL guard: rejections


@pytest.mark.parametrize("sql,code", [
    ("DELETE FROM gl_journal_lines", "SQL_NOT_READ_ONLY"),
    ("UPDATE gl_journal_lines SET amount_eur = 0", "SQL_NOT_READ_ONLY"),
    ("DROP TABLE gl_journal_lines", "SQL_NOT_READ_ONLY"),
    ("SELECT 1; SELECT 2", "SQL_NOT_READ_ONLY"),
    ("SELECT cost_centre INTO copy FROM gl_journal_lines", "SQL_NOT_READ_ONLY"),
    ("SELECT * FROM main.gl_journal_lines", "SQL_VIEW_NOT_ALLOWED"),
    ("SELECT * FROM payroll", "SQL_VIEW_NOT_ALLOWED"),
    ("SELECT * FROM read_csv('/etc/passwd')", "SQL_CONSTRUCT_NOT_ALLOWED"),
    ("SELECT current_setting('x')", "SQL_FUNCTION_NOT_ALLOWED"),
    ("SELECT nope FROM gl_journal_lines", "SQL_COLUMN_NOT_ALLOWED"),
    ("WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM r) SELECT n FROM r",
     "SQL_CONSTRUCT_NOT_ALLOWED"),
    ("WITH gl_journal_lines AS (SELECT 1 AS company_code) SELECT * FROM gl_journal_lines",
     "SQL_CONSTRUCT_NOT_ALLOWED"),
    ("SELECT * FROM gl_journal_lines WHERE company_code = $1", "SQL_CONSTRUCT_NOT_ALLOWED"),
    ("SELEC * FROM", "SQL_UNPARSEABLE"),
])
def test_guard_rejects(sql, code):
    with pytest.raises(QueryRejected) as e:
        guard(sql)
    assert e.value.code == code


@pytest.mark.parametrize("sql", [
    # bisection on a hidden amount, directly and through a CTE, HAVING, a join or a subquery
    "SELECT count(*) FROM gl_journal_lines WHERE amount_eur > 1000",
    "WITH x AS (SELECT amount_eur AS a FROM gl_journal_lines) SELECT count(*) FROM x WHERE a > 1000",
    "SELECT cost_centre FROM gl_journal_lines GROUP BY cost_centre HAVING sum(amount_eur) > 1000",
    "SELECT count(*) FROM gl_journal_lines a JOIN gl_journal_lines b ON a.amount_eur > b.amount_eur",
    "SELECT count(*) FROM gl_journal_lines WHERE cost_centre IN "
    "(SELECT cost_centre FROM gl_journal_lines ORDER BY amount_eur DESC LIMIT 1)",
    "SELECT count(*) FROM gl_journal_lines GROUP BY CASE WHEN amount_eur > 1000 THEN 1 ELSE 0 END",
    "SELECT count(*) FROM gl_journal_lines a JOIN gl_journal_lines b USING (amount_eur)",
    "SELECT cost_centre FROM gl_journal_lines QUALIFY row_number() OVER (ORDER BY amount_eur DESC) = 1",
    # token columns: equality only
    "SELECT count(*) FROM gl_journal_lines WHERE vendor_id LIKE 'V%'",
    "SELECT count(*) FROM gl_journal_lines WHERE vendor_id > 'V5'",
])
def test_guard_rejects_filters_on_hidden_values(sql):
    with pytest.raises(QueryRejected) as e:
        guard(sql)
    assert e.value.code == "SQL_FILTER_NOT_ALLOWED"


def test_dimensions_are_filterable_even_when_hidden(db):
    g = guard("SELECT count(*) AS n FROM gl_journal_lines "
              "WHERE posting_date >= '2025-10-01' AND cost_centre = 'CC10'", mode=DataSafetyMode.METADATA_ONLY)
    assert run(db, g) == [(4,)]


def test_token_equality_is_allowed(db):
    g = guard("SELECT count(*) AS n FROM gl_journal_lines WHERE vendor_id IN ('V1', 'V2')")
    assert run(db, g) == [(3,)]


# --------------------------------------------------------------------------- SQL guard: rewrites


def test_row_filter_applies_to_every_reference(db):
    sql = ("WITH x AS (SELECT company_code FROM gl_journal_lines) "
           "SELECT (SELECT count(*) FROM x) AS a, (SELECT count(*) FROM gl_journal_lines g "
           "JOIN gl_journal_lines h ON g.vendor_id = h.vendor_id) AS b")
    assert run(db, guard(sql)) == [(5, 6)]  # DE01 only: 5 lines; V1 joins twice -> 4 + 1 + 1


def test_row_filter_beats_a_where_clause(db):
    assert run(db, guard("SELECT count(*) FROM gl_journal_lines WHERE company_code = 'DE02'")) == [(0,)]


def test_row_filter_with_several_values_and_with_none(db):
    assert run(db, guard("SELECT count(*) FROM gl_journal_lines", claims={"tenant": ["DE01", "DE02"]})) == [(6,)]
    assert run(db, guard("SELECT count(*) FROM gl_journal_lines", claims={"tenant": []})) == [(0,)]


def test_missing_claim_fails_closed():
    with pytest.raises(QueryRejected) as e:
        guard("SELECT count(*) FROM gl_journal_lines", claims={})
    assert e.value.code == "ROW_FILTER_UNBOUND"


def test_limit_is_capped(db):
    cfg = GuardConfig.of("duckdb", 2, FUNCS)
    assert len(run(db, guard("SELECT cost_centre FROM gl_journal_lines LIMIT 1000", cfg=cfg))) == 2
    assert len(run(db, guard("SELECT cost_centre FROM gl_journal_lines", cfg=cfg))) == 2
    assert len(run(db, guard("SELECT cost_centre FROM gl_journal_lines LIMIT 1", cfg=cfg))) == 1


def test_snowflake_dialect():
    cfg = GuardConfig.of("snowflake", 50, FUNCS)
    g = guard("select cost_centre, sum(amount_eur) as total from gl_journal_lines group by 1", cfg=cfg)
    assert "LIMIT 50" in g.sql and "company_code IN ('DE01')" in g.sql


# --------------------------------------------------------------------------- output exposure


def exposures(g):
    return {c.name: c.exposure for c in g.columns}


def test_grouped_aggregate_columns_stay_aggregate():
    g = guard("SELECT account_code, count(*) AS n FROM gl_journal_lines GROUP BY account_code")
    assert exposures(g) == {"account_code": Exposure.AGGREGATE, "n": Exposure.AGGREGATE}


def test_raw_read_of_an_aggregate_column_is_hidden():
    g = guard("SELECT account_code, company_code FROM gl_journal_lines")
    assert exposures(g) == {"account_code": Exposure.NONE, "company_code": Exposure.ALLOWED}


def test_hidden_measure_and_token_columns():
    g = guard("SELECT vendor_id, sum(amount_eur) AS total FROM gl_journal_lines GROUP BY vendor_id")
    assert exposures(g) == {"vendor_id": Exposure.TOKEN, "total": Exposure.NONE}


def test_ordering_by_a_hidden_value_hides_every_column():
    g = guard("SELECT company_code FROM gl_journal_lines ORDER BY amount_eur DESC")
    assert exposures(g) == {"company_code": Exposure.NONE}


def test_star_is_expanded_with_per_column_exposure():
    g = guard("SELECT * FROM gl_journal_lines")
    assert exposures(g)["company_code"] is Exposure.ALLOWED
    assert exposures(g)["amount_eur"] is Exposure.NONE


def test_metadata_only_hides_everything_but_tokens():
    g = guard("SELECT company_code, vendor_id, count(*) AS n FROM gl_journal_lines GROUP BY 1, 2",
              mode=DataSafetyMode.METADATA_ONLY)
    assert exposures(g) == {"company_code": Exposure.NONE, "vendor_id": Exposure.TOKEN, "n": Exposure.AGGREGATE}


def test_union_takes_the_least_exposure():
    g = guard("SELECT company_code AS c FROM gl_journal_lines UNION ALL SELECT account_code FROM gl_journal_lines")
    assert exposures(g) == {"c": Exposure.NONE}


def test_dates_parse_in_period():
    from aof.query.semantic import Period

    assert Period(start="2025-10-01", end="2025-10-31").end == dt.date(2025, 10, 31)
