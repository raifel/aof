"""Answer templates (docs/data-safety.md, phase D6). Pure: no I/O.

Under `results: enforce` the model never sees the figures, so it writes its answer as a
template that names cells of vaulted results:

    Q3 opex was {{res_8f3a….opex | money:EUR}}, {{res_8f3a….rows[1].delta | pct}} over budget.

The user's UI sends the template to `POST /render` with the user's token, and the gateway
fills it in from the vault. The numbers the user sees come straight from the query.

Paths are the ones value references use (`amount`, `rows[0].opex`, `opex` on a one-row
result). Filters: `money[:CUR]` (2 decimals, thousands separators), `number[:digits]`,
`int`, `pct[:digits]` (a fraction: 0.125 -> 12.5%), `date` (YYYY-MM-DD). A placeholder
that can't be filled renders as `[unavailable]` and is listed in `missing`.

`stray_numbers` is the template-fidelity check the evals use: numbers written into the
answer as literals rather than placeholders.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Callable

PLACEHOLDER = re.compile(
    r"\{\{\s*(res_[0-9a-f]{8,})\.([A-Za-z_]\w*(?:\[\d+\]|\.[A-Za-z_]\w*)*)"
    r"\s*(?:\|\s*([a-z]+)(?::([A-Za-z0-9_.-]+))?)?\s*\}\}")
UNAVAILABLE = "[unavailable]"
FILTERS = ("money", "number", "int", "pct", "date")


@dataclass
class Rendered:
    text: str
    references: int = 0
    handles: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)  # placeholders that couldn't be filled


class RenderError(Exception):
    pass


def _decimal(value: Any) -> Decimal:
    if isinstance(value, bool):
        raise RenderError("not a number")
    try:
        return Decimal(str(value))
    except InvalidOperation:
        raise RenderError("not a number") from None


def _grouped(d: Decimal, digits: int) -> str:
    q = d.quantize(Decimal(1).scaleb(-digits), rounding=ROUND_HALF_UP) if digits >= 0 else d
    return f"{q:,.{digits}f}" if digits >= 0 else f"{q:,}"


def apply_filter(value: Any, name: str | None, arg: str | None) -> str:
    if name is None:
        if isinstance(value, float):
            return format(Decimal(str(value)).normalize(), "f")
        return "" if value is None else str(value)
    if value is None:
        raise RenderError("no value")
    if name == "money":
        out = _grouped(_decimal(value), 2)
        return f"{out} {arg}" if arg else out
    if name == "number":
        return _grouped(_decimal(value), int(arg)) if arg else f"{_decimal(value).normalize():,f}"
    if name == "int":
        return _grouped(_decimal(value), 0)
    if name == "pct":
        return _grouped(_decimal(value) * 100, int(arg) if arg else 1) + "%"
    if name == "date":
        text = str(value)
        if not re.match(r"^\d{4}-\d{2}-\d{2}", text):
            raise RenderError("not a date")
        return text[:10]
    raise RenderError(f"unknown filter {name}; use {', '.join(FILTERS)}")


def render(template: str, lookup: Callable[[str, str], Any]) -> Rendered:
    """Fill every placeholder. `lookup(handle, path)` returns the value or raises."""
    out = Rendered(text="")
    handles: list[str] = []

    def sub(m: re.Match) -> str:
        handle, path, name, arg = m.groups()
        out.references += 1
        if handle not in handles:
            handles.append(handle)
        try:
            return apply_filter(lookup(handle, path), name, arg)
        except Exception:  # noqa: BLE001 - any failure renders as unavailable, never as a value
            out.missing.append(m.group(0))
            return UNAVAILABLE

    out.text = PLACEHOLDER.sub(sub, template)
    out.handles = handles
    return out


# --------------------------------------------------------------------------- template fidelity

_NUMBER = re.compile(r"(?<![\w.])[-+]?\d[\d,]*(?:\.\d+)?%?(?![\w])")


def _norm(token: str) -> str:
    t = token.rstrip("%").replace(",", "").lstrip("+")
    try:
        return format(Decimal(t).normalize(), "f")
    except InvalidOperation:
        return t


def stray_numbers(answer: str, allowed: str = "") -> list[str]:
    """Numbers written into `answer` as literals, outside placeholders, that look like
    figures: with a decimal point or a percent sign, or 100 and above, except years
    (1900-2100) and numbers that appear in `allowed` (the user's question)."""
    known = {_norm(t) for t in _NUMBER.findall(allowed)}
    text = PLACEHOLDER.sub(" ", answer)
    text = re.sub(r"\b(?:res|tok)_[0-9a-z_]+", " ", text)  # handles and tokens are ids
    out = []
    for token in _NUMBER.findall(text):
        n = _norm(token)
        if n in known:
            continue
        try:
            value = abs(Decimal(n))
        except InvalidOperation:
            continue
        figure = "." in token or token.endswith("%") or value >= 100
        year = token.isdigit() and 1900 <= value <= 2100
        if figure and not year:
            out.append(token)
    return out
