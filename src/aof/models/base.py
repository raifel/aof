from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, ConfigDict


class Strict(BaseModel):
    """AOF-owned artefacts reject unknown keys so typos fail CI."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False)


class Open(BaseModel):
    """Artefacts that follow an external spec (MCP Registry, A2A) keep unknown keys."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class Signoff(Strict):
    by: str
    date: dt.date
    ref: str | None = None  # ticket, minutes or review link
