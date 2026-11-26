"""Findings: the single result type every check returns.

Code prefixes:
  AOF-S  schema and parsing        AOF-C  cross-artefact contract
  AOF-P  policy compiler           AOF-L  tool-design lint
  AOF-E  evaluation                AOF-G  lifecycle gate
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    artefact: str
    message: str
    hint: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    def __str__(self) -> str:
        s = f"{self.severity.value.upper():7} {self.code} [{self.artefact}] {self.message}"
        if self.hint:
            s += f"\n        hint: {self.hint}"
        return s


def error(code: str, artefact: str, message: str, hint: str | None = None) -> Finding:
    return Finding(code, Severity.ERROR, artefact, message, hint)


def warning(code: str, artefact: str, message: str, hint: str | None = None) -> Finding:
    return Finding(code, Severity.WARNING, artefact, message, hint)


def info(code: str, artefact: str, message: str, hint: str | None = None) -> Finding:
    return Finding(code, Severity.INFO, artefact, message, hint)


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)

    def extend(self, items: list[Finding]) -> None:
        self.findings.extend(items)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.WARNING]

    def ok(self, strict: bool = False) -> bool:
        return not self.errors and not (strict and self.warnings)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok(),
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "findings": [f.to_dict() for f in self.findings],
        }
