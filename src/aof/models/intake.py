"""Use-case card (stage 1) and readiness scorecard (stage 2)."""

from __future__ import annotations

import datetime as dt

from typing import Literal

from pydantic import Field, model_validator

from ..enums import AutonomyLevel, Dimension, ReadinessStatus, RiskTier
from .base import Strict


class Actions(Strict):
    read: list[str] = Field(min_length=1)
    write: list[str] = []


class Triage(Strict):
    """Filled by the platform team when it accepts the card."""

    accepted_by: str
    date: dt.date
    assigned_risk_tier: RiskTier


class Target(Strict):
    max: float | None = None  # the measure must stay at or below
    min: float | None = None  # or at or above

    @model_validator(mode="after")
    def _one(self) -> "Target":
        if (self.max is None) == (self.min is None):
            raise ValueError("give exactly one of max or min")
        return self


class OutcomeMetric(Strict):
    """The business outcome in a form the pilot can measure (aof/outcomes.py)."""

    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    measure: Literal["case_minutes", "agent_minutes", "approval_wait_minutes", "steps_per_run",
                     "cost_usd_per_run", "denials_per_run", "approval_rate", "rework_rate"]
    stat: Literal["median", "p90", "mean"] = "median"  # ignored for the two rates
    target: Target
    baseline: float | None = None  # the value before the app, for the report


class UseCaseCard(Strict):
    title: str
    business_outcome: str
    users: list[str] = Field(min_length=1)
    systems_touched: list[str] = Field(min_length=1)
    actions: Actions
    cost_of_error: str
    errors_reversible: bool
    requested_autonomy: AutonomyLevel
    triage: Triage | None = None
    outcome_metrics: list[OutcomeMetric] = []  # how business_outcome is measured in the pilot


class DimensionScore(Strict):
    status: ReadinessStatus
    evidence: list[str] = []
    notes: str = ""
    remediation: str | None = None  # required when not ready


class Readiness(Strict):
    assessed_by: str
    date: dt.date
    dimensions: dict[Dimension, DimensionScore]
