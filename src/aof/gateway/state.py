"""Gateway state.

Durable (shared across processes through a locked JSON file, so `aof gateway kill`
from an operator's shell takes effect in a running gateway on its next call):
  kill switches, autonomy demotions, approvals.
Ephemeral (per gateway process):
  rate-limit windows, per-run step/cost budgets, policy-violation windows.

The file store is a reference implementation; swap DurableStore for Redis or a
database when running more than one gateway replica.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from ..enums import AutonomyLevel

_EMPTY = {"killed": {}, "demotions": {}, "approvals": {}}


class DurableStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._mem: dict[str, Any] = json.loads(json.dumps(_EMPTY))

    @contextlib.contextmanager
    def _locked(self, exclusive: bool) -> Iterator[None]:
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path.with_suffix(".lock"), "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _load(self) -> dict[str, Any]:
        if self.path is None:
            return self._mem
        if not self.path.exists():
            return json.loads(json.dumps(_EMPTY))
        data = json.loads(self.path.read_text())
        for k, v in _EMPTY.items():
            data.setdefault(k, dict(v))
        return data

    def read(self) -> dict[str, Any]:
        if self.path is None:
            return self._mem
        with self._locked(exclusive=False):
            return self._load()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[dict[str, Any]]:
        if self.path is None:
            yield self._mem
            return
        with self._locked(exclusive=True):
            data = self._load()
            yield data
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, default=str))
            os.replace(tmp, self.path)


class SlidingCounter:
    """Timestamps per key; counts events inside a trailing window."""

    def __init__(self) -> None:
        self._events: dict[tuple, deque[float]] = defaultdict(deque)

    def count(self, key: tuple, window_s: float, now: float) -> int:
        q = self._events[key]
        while q and q[0] <= now - window_s:
            q.popleft()
        return len(q)

    def add(self, key: tuple, now: float) -> None:
        self._events[key].append(now)

    def reset(self, key: tuple) -> None:
        self._events.pop(key, None)


@dataclass
class RunState:
    run_id: str
    steps: int = 0
    cost_usd: float = 0.0
    last_seen: float = field(default_factory=time.time)


class GatewayState:
    RUN_IDLE_TTL_S = 24 * 3600

    def __init__(self, store: DurableStore | None = None):
        self.store = store or DurableStore()
        self.calls = SlidingCounter()  # (agent, user, tool) -> calls
        self.writes = SlidingCounter()  # (agent, user, tool) -> executed writes (limits)
        self.violations = SlidingCounter()  # (agent,) -> policy violations
        self._runs: dict[str, RunState] = {}

    # ---- kill switch
    def killed(self, agent_id: str) -> dict | None:
        return self.store.read()["killed"].get(agent_id)

    def kill(self, agent_id: str, by: str, reason: str) -> None:
        with self.store.transaction() as d:
            d["killed"][agent_id] = {"by": by, "reason": reason, "at": time.time()}

    def revive(self, agent_id: str) -> bool:
        with self.store.transaction() as d:
            return d["killed"].pop(agent_id, None) is not None

    # ---- autonomy demotion (can only lower the compiled level)
    def demoted_level(self, agent_id: str) -> AutonomyLevel | None:
        entry = self.store.read()["demotions"].get(agent_id)
        return AutonomyLevel(entry["level"]) if entry else None

    def demote(self, agent_id: str, level: AutonomyLevel, by: str, reason: str) -> None:
        with self.store.transaction() as d:
            d["demotions"][agent_id] = {"level": level.value, "by": by, "reason": reason, "at": time.time()}

    def clear_demotion(self, agent_id: str) -> bool:
        with self.store.transaction() as d:
            return d["demotions"].pop(agent_id, None) is not None

    # ---- runs
    def run(self, run_id: str, now: float) -> RunState:
        for rid in [r for r, s in self._runs.items() if now - s.last_seen > self.RUN_IDLE_TTL_S]:
            del self._runs[rid]
        state = self._runs.setdefault(run_id, RunState(run_id))
        state.last_seen = now
        return state
