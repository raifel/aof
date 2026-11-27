"""Data contracts: what a tool may read, and at what classification.

The semantic-model parts (`measures`, `dimensions`, `fiscal_calendar`, `glossary`) are
metadata the model may see so it can write correct queries without seeing rows.
`llm_exposure` and `row_filter` are the data-safety controls (docs/data-safety.md).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from ..enums import Classification, Exposure
from .base import Strict

Op = Literal["eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "between"]


class ContractField(Strict):
    name: str
    type: str
    classification: Classification = Classification.INTERNAL
    pii: bool = False
    description: str = ""
    # How much of the value the model may see. Unset: the platform's default for the
    # field's classification (data_safety.default_exposure).
    llm_exposure: Exposure | None = None
    free_text: bool = False  # user- or customer-written text: a leak and injection risk


class RowFilter(Strict):
    """Row-level security: keep rows whose `column` is in the caller's `claim` values.

    The claim is read from the verified token at run time, never from the query.
    """

    column: str
    claim: str  # "sub", "tenant", or a name in platform data_safety.row_filter_claims


class Condition(Strict):
    """A predicate on one column, used by measure filters."""

    column: str
    op: Op
    value: Any

    @model_validator(mode="after")
    def _value_shape(self) -> "Condition":
        check_value(self.op, self.value)
        return self


def check_value(op: str, value: Any) -> None:
    if op in ("in", "not_in"):
        if not isinstance(value, list) or not value:
            raise ValueError(f"op {op} needs a non-empty list")
    elif op == "between":
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError("op between needs [low, high]")
    elif isinstance(value, (list, dict)):
        raise ValueError(f"op {op} needs a single value")


class Measure(Strict):
    """A named metric: an aggregate over one field, optionally over a subset of rows.

    Accounting example: opex = sum(amount_eur) where account_code between 6000 and 7999,
    sign -1 if amounts are stored credit-positive.
    """

    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    field: str | None = None  # None only for agg: count (count of rows)
    agg: Literal["sum", "avg", "min", "max", "count", "count_distinct"]
    filter: list[Condition] = []
    sign: Literal[1, -1] = 1  # multiply the result, for debit/credit sign conventions
    description: str = ""

    @model_validator(mode="after")
    def _field_needed(self) -> "Measure":
        if self.field is None and self.agg != "count":
            raise ValueError(f"measure {self.name}: agg {self.agg} needs a field")
        return self


class Dimension(Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    field: str
    time: bool = False  # the date the fiscal period filter applies to
    required: bool = False  # a query must filter or group by it; otherwise ask the user
    description: str = ""


class FiscalCalendar(Strict):
    year_start_month: int = Field(default=1, ge=1, le=12)
    # FY2026 with an April start: "end" = Apr 2025 - Mar 2026, "start" = Apr 2026 - Mar 2027
    year_named_by: Literal["start", "end"] = "end"


class DataContract(Strict):
    name: str  # data product name
    owner: str
    description: str = ""
    source: str  # e.g. "snowflake:ANALYTICS.SALES.ORDERS"
    semantic_view: str  # what tools reference in `reads`
    freshness_sla: str = Field(pattern=r"^\d+(m|h|d)$")  # e.g. 15m, 24h, 7d
    classification: Classification
    fields: list[ContractField] = Field(min_length=1)
    quality: list[str] = []  # quality SLAs / checks
    row_filter: list[RowFilter] = []
    measures: list[Measure] = []
    dimensions: list[Dimension] = []
    fiscal_calendar: FiscalCalendar | None = None
    glossary: dict[str, str] = {}  # business terms -> definitions, shown to the model

    def field(self, name: str) -> ContractField | None:
        return next((f for f in self.fields if f.name == name), None)
