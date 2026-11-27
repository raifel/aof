"""Eval suite definition, case formats and the results files gates read."""

from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import Field, NonNegativeInt, field_validator, model_validator

from ..enums import DATA_SAFETY_RISKS
from .base import Open, Strict

REQUIRED_METRICS = ("task_success", "tool_call_accuracy")


class EvalUser(Strict):
    """Who the eval cases run as. Row filters need the claims they are bound to."""

    tenant: str | None = None
    roles: list[str] = []
    claims: dict[str, Any] = {}  # extra verified claims (data_safety.row_filter_claims)


class EvalSuite(Strict):
    golden_set: str  # JSONL of GoldenCase, path relative to repo root
    safety_cases: str  # JSONL of SafetyCase
    metrics: list[str] = Field(min_length=1)
    runner: str | None = None  # deepeval | ragas | openai-evals | custom
    user: EvalUser = EvalUser()


class GoldenCase(Strict):
    id: str
    input: str
    expected: Any = None  # compared with the agent's final `result`
    # Compared with the rows of the agent's vaulted query result (execution accuracy,
    # docs/data-safety.md): the gateway's record, not the agent's claim.
    expected_rows: list[dict[str, Any]] | None = None
    ordered: bool = False  # expected_rows must come in this order
    expected_tools: list[str] = []
    tags: list[str] = []  # include "edge_case" for edge cases
    harvested_from: str | None = None  # the production incident group (aof/harvest.py)

    @model_validator(mode="after")
    def _something_expected(self) -> "GoldenCase":
        if self.expected is None and self.expected_rows is None:
            raise ValueError(f"case {self.id}: give expected, expected_rows or both")
        return self


class SafetyCase(Strict):
    id: str
    input: str
    asi: list[str] = Field(min_length=1)  # ASI01..ASI10
    ds: list[str] = []  # data-safety categories DS01..DS07
    expected: str  # refuse | no_write | block | ask_approval | no_leak
    harvested_from: str | None = None  # the production incident group (aof/harvest.py)

    @field_validator("ds")
    @classmethod
    def _known_ds(cls, v: list[str]) -> list[str]:
        bad = [x for x in v if x not in DATA_SAFETY_RISKS]
        if bad:
            raise ValueError(f"unknown data-safety categories {bad}; use {', '.join(DATA_SAFETY_RISKS)}")
        return v


class EvalResults(Open):
    """Written by whatever runner the app uses; read by the evaluate gate."""

    run_at: dt.datetime
    cases_run: NonNegativeInt
    task_success: float = Field(ge=0, le=1)
    tool_call_accuracy: float = Field(ge=0, le=1)
    safety_pass_rate: float = Field(ge=0, le=1)
    cost_per_task_usd: float | None = None
    steps_per_task: float | None = None
    no_leak_rate: float | None = Field(default=None, ge=0, le=1)  # cases where no hidden value reached the model


class PilotResults(Open):
    """Shadow-mode outcome: agent proposals vs what humans did."""

    window_start: dt.date
    window_end: dt.date
    proposals: NonNegativeInt
    agreement_rate: float = Field(ge=0, le=1)
    incidents: NonNegativeInt
    # aof/outcomes.py measures from the audit log: {measure: {n, median, p90, mean} | {n, value}}
    measures: dict[str, dict[str, float]] | None = None
