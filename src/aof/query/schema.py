"""Re-export of the view schema (it lives in `aof.datasafety`, which has no sqlglot)."""

from ..datasafety import (  # noqa: F401
    ColumnSchema,
    ViewSchema,
    effective_classification,
    effective_exposure,
    view_from_contract,
    views_from_contracts,
)
