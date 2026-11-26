"""Data contracts: what a tool may read, and at what classification."""

from __future__ import annotations

from pydantic import Field

from ..enums import Classification
from .base import Strict


class ContractField(Strict):
    name: str
    type: str
    classification: Classification = Classification.INTERNAL
    pii: bool = False
    description: str = ""


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
