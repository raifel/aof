"""OpenTelemetry GenAI spans for tool execution.

Uses only opentelemetry-api: spans are no-ops until the host process configures an
SDK and exporter (for example an OTLP exporter to the OTel Collector). Attribute
names follow the GenAI semantic conventions, which are still in Development status:
pin the version the platform emits (platform.yaml telemetry.genai_semconv_version).
"""

from __future__ import annotations

import contextlib
from typing import Any, Iterator

try:
    from opentelemetry import trace
    from opentelemetry.trace import SpanKind, Status, StatusCode

    _tracer = trace.get_tracer("aof.gateway")
except ImportError:  # pragma: no cover - opentelemetry-api ships with the gateway extra
    _tracer = None


class _NoSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_error(self, error_type: str) -> None:
        pass


class _Span:
    def __init__(self, span):
        self._span = span

    def set_attribute(self, key: str, value: Any) -> None:
        if value is not None:
            self._span.set_attribute(key, value)

    def set_error(self, error_type: str) -> None:
        self._span.set_attribute("error.type", error_type)
        self._span.set_status(Status(StatusCode.ERROR, error_type))


@contextlib.contextmanager
def tool_span(tool: str, *, agent_id: str, call_id: str | None, run_id: str, user_id: str) -> Iterator[Any]:
    if _tracer is None:
        yield _NoSpan()
        return
    attrs = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": tool,
        "gen_ai.tool.call.id": call_id,
        "gen_ai.agent.id": agent_id,
        "aof.run_id": run_id,
        "enduser.id": user_id,
    }
    with _tracer.start_as_current_span(
        f"execute_tool {tool}", kind=SpanKind.INTERNAL,
        attributes={k: v for k, v in attrs.items() if v is not None},
    ) as span:
        yield _Span(span)
