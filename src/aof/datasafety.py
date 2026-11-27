"""Data safety: how much of each field the model may see, and the semantic view schema.

A `ViewSchema` is built from a data contract and the platform's data-safety settings at
compile time, and written into the compiled policy (`data_safety.views`), so the gateway
can check queries without the contracts. Pure: no I/O, and no sqlglot (`aof validate`
imports it).
"""

from __future__ import annotations

from typing import Iterable

from pydantic import BaseModel, ConfigDict

from .enums import Classification, DataSafetyMode, Exposure
from .models.data_contract import (
    ContractField,
    DataContract,
    Dimension,
    FiscalCalendar,
    Measure,
    RowFilter,
)


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ColumnSchema(_Frozen):
    type: str
    exposure: Exposure


class ViewSchema(_Frozen):
    name: str
    columns: dict[str, ColumnSchema]  # keys are lower case
    row_filter: list[RowFilter] = []
    measures: list[Measure] = []
    dimensions: list[Dimension] = []
    fiscal_calendar: FiscalCalendar | None = None
    glossary: dict[str, str] = {}

    def column(self, name: str) -> ColumnSchema | None:
        return self.columns.get(name.lower())

    def measure(self, name: str) -> Measure | None:
        return next((m for m in self.measures if m.name == name), None)

    def dimension(self, name: str) -> Dimension | None:
        return next((d for d in self.dimensions if d.name == name), None)

    def describe(self) -> dict:
        """Metadata the model may see: names, types, exposures, the semantic model. No values."""
        return {
            "view": self.name,
            "columns": {n: {"type": c.type, "exposure": c.exposure.value} for n, c in self.columns.items()},
            "measures": [m.model_dump(exclude_defaults=True) for m in self.measures],
            "dimensions": [d.model_dump(exclude_defaults=True) for d in self.dimensions],
            "fiscal_calendar": self.fiscal_calendar.model_dump() if self.fiscal_calendar else None,
            "glossary": self.glossary,
        }


def effective_classification(f: ContractField) -> Classification:
    """PII is at least confidential, whatever the field says."""
    if f.pii and f.classification < Classification.CONFIDENTIAL:
        return Classification.CONFIDENTIAL
    return f.classification


def effective_exposure(f: ContractField, default_exposure: dict[Classification, Exposure],
                       mode: DataSafetyMode) -> Exposure:
    declared = f.llm_exposure or default_exposure[effective_classification(f)]
    if mode is DataSafetyMode.METADATA_ONLY:
        return Exposure.TOKEN if declared is Exposure.TOKEN else Exposure.NONE
    return declared


def view_from_contract(dc: DataContract, default_exposure: dict[Classification, Exposure],
                       mode: DataSafetyMode) -> ViewSchema:
    return ViewSchema(
        name=dc.semantic_view,
        columns={f.name.lower(): ColumnSchema(type=f.type, exposure=effective_exposure(f, default_exposure, mode))
                 for f in dc.fields},
        row_filter=dc.row_filter,
        measures=dc.measures,
        dimensions=dc.dimensions,
        fiscal_calendar=dc.fiscal_calendar,
        glossary=dc.glossary,
    )


def views_from_contracts(contracts: Iterable[DataContract], default_exposure: dict[Classification, Exposure],
                         mode: DataSafetyMode) -> dict[str, ViewSchema]:
    return {dc.semantic_view.lower(): view_from_contract(dc, default_exposure, mode) for dc in contracts}
