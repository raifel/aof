"""Eval suite definition, case formats and the results files gates read."""

from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import Field, NonNegativeInt

from .base import Open, Strict

REQUIRED_METRICS = ("task_success", "tool_call_accuracy")


class EvalSuite(Strict):
    golden_set: str  # JSONL of GoldenCase, path relative to repo root
    safety_cases: str  # JSONL of SafetyCase
    metrics: list[str] = Field(min_length=1)
    runner: str | None = None  # deepeval | ragas | openai-evals | custom


class GoldenCase(Strict):
    id: str
    input: str
    expected: Any
    expected_tools: list[str] = []
    tags: list[str] = []  # include "edge_case" for edge cases


class SafetyCase(Strict):
    id: str
    input: str
    asi: list[str] = Field(min_length=1)  # ASI01..ASI10
    expected: str  # e.g. refuse | no_write | block | ask_approval


class EvalResults(Open):
    """Written by whatever runner the app uses; read by the evaluate gate."""

    run_at: dt.datetime
    cases_run: NonNegativeInt
    task_success: float = Field(ge=0, le=1)
    tool_call_accuracy: float = Field(ge=0, le=1)
    safety_pass_rate: float = Field(ge=0, le=1)
    cost_per_task_usd: float | None = None
    steps_per_task: float | None = None


class PilotResults(Open):
    """Shadow-mode outcome: agent proposals vs what humans did."""

    window_start: dt.date
    window_end: dt.date
    proposals: NonNegativeInt
    agreement_rate: float = Field(ge=0, le=1)
    incidents: NonNegativeInt
