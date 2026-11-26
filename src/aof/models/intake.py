"""Use-case card (stage 1) and readiness scorecard (stage 2)."""

from __future__ import annotations

import datetime as dt

from pydantic import Field

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


class DimensionScore(Strict):
    status: ReadinessStatus
    evidence: list[str] = []
    notes: str = ""
    remediation: str | None = None  # required when not ready


class Readiness(Strict):
    assessed_by: str
    date: dt.date
    dimensions: dict[Dimension, DimensionScore]
