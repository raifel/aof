"""Gateway state, behind one Store interface so several replicas can share it.

What lives in the store:
  documents   kill switches, autonomy demotions, approvals, A2A task owners
  counters    per-run steps, model calls, delegations and cost (atomic increments)
  windows     sliding-window logs for rate limits, write limits and policy violations

Every check that guards a budget is atomic in the store, so concurrent replicas cannot
both pass the last slot: windows use acquire (count-and-add in one step), run budgets
use reserve (increment, then roll back if over the limit), approvals change state
with an atomic read-modify-write, and auto-demotion only moves from the level it saw.

Backends:
  DurableStore()         in memory: tests and single-process use
  DurableStore(path)     documents in a locked JSON file, counters in memory: one host
                         (an operator's `aof gateway kill` reaches a running gateway)
  RedisStore(client)     everything in Redis: any number of replicas

Cost is the exception that cannot be reserved: the price of a call is known only after
it, so concurrent calls of one run can each pass the cost check and overshoot together.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

from ..enums import AutonomyLevel

_EMPTY = {"killed": {}, "demotions": {}, "approvals": {}}


class Abort(Exception):
    """Raised inside an update function to leave the document unchanged."""


class Store(Protocol):
    # documents: JSON objects by namespace and key
    def get(self, ns: str, key: str) -> dict | None: ...

    def put(self, ns: str, key: str, value: dict, ttl: float | None = None) -> None: ...

    def put_if_absent(self, ns: str, key: str, value: dict, ttl: float | None = None) -> bool: ...

    def delete(self, ns: str, key: str) -> bool: ...

    def all(self, ns: str) -> dict[str, dict]: ...

    def update(self, ns: str, key: str, fn: Callable[[dict | None], dict | None],
               ttl: float | None = None) -> dict | None: ...

    # counters
    def incr(self, key: str, amount: float, ttl: float) -> float: ...

    def counter(self, key: str) -> float: ...

    # sliding windows
    def window_count(self, key: str, now: float, window: float) -> int: ...

    def window_add(self, key: str, now: float, window: float) -> None: ...

    def window_acquire(self, key: str, now: float, window: float, limit: int) -> tuple[bool, int]: ...

    def window_reset(self, key: str) -> None: ...


# --------------------------------------------------------------------------- local backends


class _LocalCounters:
    """In-process counters and windows (one process)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counters: dict[str, tuple[float, float]] = {}  # key -> (value, expires_at)
        self._windows: dict[str, deque[float]] = defaultdict(deque)

    def incr(self, key: str, amount: float, ttl: float) -> float:
        with self._lock:
            value, expires = self._counters.get(key, (0.0, 0.0))
            now = time.time()
            if expires and expires < now:
                value = 0.0
            value += amount
            self._counters[key] = (value, now + ttl)
            return value

    def counter(self, key: str) -> float:
        with self._lock:
            value, expires = self._counters.get(key, (0.0, 0.0))
            return 0.0 if expires and expires < time.time() else value

    def _trim(self, key: str, now: float, window: float) -> deque[float]:
        q = self._windows[key]
        while q and q[0] <= now - window:
            q.popleft()
        return q

    def window_count(self, key: str, now: float, window: float) -> int:
        with self._lock:
            return len(self._trim(key, now, window))

    def window_add(self, key: str, now: float, window: float) -> None:
        with self._lock:
            self._trim(key, now, window).append(now)

    def window_acquire(self, key: str, now: float, window: float, limit: int) -> tuple[bool, int]:
        with self._lock:
            q = self._trim(key, now, window)
            if len(q) >= limit:
                return False, len(q)
            q.append(now)
            return True, len(q)

    def window_reset(self, key: str) -> None:
        with self._lock:
            self._windows.pop(key, None)


class DurableStore(_LocalCounters):
    """Documents in memory, or in a JSON file shared by processes on one host (flock)."""

    def __init__(self, path: str | Path | None = None):
        super().__init__()
        self.path = Path(path) if path else None
        self._mem: dict[str, Any] = json.loads(json.dumps(_EMPTY))

    # ---- file plumbing
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
            with self._lock:
                yield self._mem
            return
        with self._lock, self._locked(exclusive=True):
            data = self._load()
            yield data
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, default=str))
            os.replace(tmp, self.path)

    # ---- documents (ttl is not enforced by the file store)
    def get(self, ns: str, key: str) -> dict | None:
        return self.read().get(ns, {}).get(key)

    def put(self, ns: str, key: str, value: dict, ttl: float | None = None) -> None:
        with self.transaction() as d:
            d.setdefault(ns, {})[key] = value

    def put_if_absent(self, ns: str, key: str, value: dict, ttl: float | None = None) -> bool:
        with self.transaction() as d:
            docs = d.setdefault(ns, {})
            if key in docs:
                return False
            docs[key] = value
            return True

    def delete(self, ns: str, key: str) -> bool:
        with self.transaction() as d:
            return d.setdefault(ns, {}).pop(key, None) is not None

    def all(self, ns: str) -> dict[str, dict]:
        return dict(self.read().get(ns, {}))

    def update(self, ns: str, key: str, fn, ttl: float | None = None) -> dict | None:
        with self.transaction() as d:
            docs = d.setdefault(ns, {})
            current = docs.get(key)
            new = fn(json.loads(json.dumps(current)) if current is not None else None)  # may raise Abort
            if new is None:
                docs.pop(key, None)
            else:
                docs[key] = new
            return new


# --------------------------------------------------------------------------- Redis


class RedisStore:
    """All state in Redis, for any number of replicas. `client` is a redis.Redis (sync).

    Atomic steps use optimistic transactions (WATCH/MULTI), so no server-side scripts are
    needed. Keys: <prefix>doc:<ns>:<key>, <prefix>idx:<ns>, <prefix>ctr:<key>, <prefix>win:<key>.
    """

    def __init__(self, client: Any, prefix: str = "aof:", max_retries: int = 50):
        self.r = client
        self.prefix = prefix
        self.max_retries = max_retries

    @classmethod
    def from_url(cls, url: str, prefix: str = "aof:") -> "RedisStore":
        import redis

        return cls(redis.Redis.from_url(url), prefix)

    def _doc(self, ns: str, key: str) -> str:
        return f"{self.prefix}doc:{ns}:{key}"

    def _idx(self, ns: str) -> str:
        return f"{self.prefix}idx:{ns}"

    def _optimistic(self, keys: list[str], body: Callable[[Any], Any]) -> Any:
        import redis

        for _ in range(self.max_retries):
            with self.r.pipeline() as pipe:
                try:
                    pipe.watch(*keys)
                    return body(pipe)
                except redis.WatchError:
                    continue
        raise RuntimeError(f"state contention on {keys}: gave up after {self.max_retries} retries")

    # ---- documents
    def get(self, ns: str, key: str) -> dict | None:
        raw = self.r.get(self._doc(ns, key))
        return json.loads(raw) if raw is not None else None

    def put(self, ns: str, key: str, value: dict, ttl: float | None = None) -> None:
        with self.r.pipeline() as p:
            p.set(self._doc(ns, key), json.dumps(value, default=str), ex=int(ttl) if ttl else None)
            p.sadd(self._idx(ns), key)
            p.execute()

    def put_if_absent(self, ns: str, key: str, value: dict, ttl: float | None = None) -> bool:
        ok = self.r.set(self._doc(ns, key), json.dumps(value, default=str), nx=True, ex=int(ttl) if ttl else None)
        if ok:
            self.r.sadd(self._idx(ns), key)
        return bool(ok)

    def delete(self, ns: str, key: str) -> bool:
        with self.r.pipeline() as p:
            p.delete(self._doc(ns, key))
            p.srem(self._idx(ns), key)
            deleted, _ = p.execute()
        return bool(deleted)

    def all(self, ns: str) -> dict[str, dict]:
        keys = sorted(k.decode() if isinstance(k, bytes) else k for k in self.r.smembers(self._idx(ns)))
        if not keys:
            return {}
        values = self.r.mget([self._doc(ns, k) for k in keys])
        out, gone = {}, []
        for k, raw in zip(keys, values):
            if raw is None:
                gone.append(k)  # expired: drop it from the index
            else:
                out[k] = json.loads(raw)
        if gone:
            self.r.srem(self._idx(ns), *gone)
        return out

    def update(self, ns: str, key: str, fn, ttl: float | None = None) -> dict | None:
        doc = self._doc(ns, key)

        def body(pipe):
            raw = pipe.get(doc)
            new = fn(json.loads(raw) if raw is not None else None)  # may raise Abort
            pipe.multi()
            if new is None:
                pipe.delete(doc)
                pipe.srem(self._idx(ns), key)
            else:
                if ttl:
                    pipe.set(doc, json.dumps(new, default=str), ex=int(ttl))
                else:
                    pipe.set(doc, json.dumps(new, default=str), keepttl=True)  # keep the document's expiry
                pipe.sadd(self._idx(ns), key)
            pipe.execute()
            return new

        return self._optimistic([doc], body)

    # ---- counters
    def incr(self, key: str, amount: float, ttl: float) -> float:
        k = f"{self.prefix}ctr:{key}"
        with self.r.pipeline() as p:
            p.incrbyfloat(k, amount)
            p.expire(k, int(ttl))
            value, _ = p.execute()
        return float(value)

    def counter(self, key: str) -> float:
        raw = self.r.get(f"{self.prefix}ctr:{key}")
        return float(raw) if raw is not None else 0.0

    # ---- windows (sorted set of timestamps)
    def _win(self, key: str) -> str:
        return f"{self.prefix}win:{key}"

    def window_count(self, key: str, now: float, window: float) -> int:
        return int(self.r.zcount(self._win(key), f"({now - window}", "+inf"))

    def window_add(self, key: str, now: float, window: float) -> None:
        k = self._win(key)
        with self.r.pipeline() as p:
            p.zremrangebyscore(k, "-inf", now - window)
            p.zadd(k, {f"{now}:{secrets.token_hex(4)}": now})
            p.expire(k, int(window) + 1)
            p.execute()

    def window_acquire(self, key: str, now: float, window: float, limit: int) -> tuple[bool, int]:
        k = self._win(key)

        def body(pipe):
            used = int(pipe.zcount(k, f"({now - window}", "+inf"))
            if used >= limit:
                pipe.unwatch()
                return False, used
            pipe.multi()
            pipe.zremrangebyscore(k, "-inf", now - window)
            pipe.zadd(k, {f"{now}:{secrets.token_hex(4)}": now})
            pipe.expire(k, int(window) + 1)
            pipe.execute()
            return True, used + 1

        return self._optimistic([k], body)

    def window_reset(self, key: str) -> None:
        self.r.delete(self._win(key))


def open_store(url: str | None, state_dir: str | Path | None = None) -> Store:
    """redis://... or rediss://... -> RedisStore; otherwise the file store in state_dir."""
    if url and url.startswith(("redis://", "rediss://", "unix://")):
        return RedisStore.from_url(url)
    if url:
        raise ValueError(f"unsupported state URL {url!r}: use redis:// or rediss://")
    return DurableStore(Path(state_dir) / "state.json" if state_dir else None)


# --------------------------------------------------------------------------- views


def _k(key: tuple) -> str:
    return "|".join(str(part) for part in key)


class SlidingCounter:
    """A named family of sliding windows in the store, keyed by tuples."""

    def __init__(self, store: Store | None = None, name: str = "w"):
        self.store = store if store is not None else DurableStore()
        self.name = name

    def _key(self, key: tuple) -> str:
        return f"{self.name}|{_k(key)}"

    def count(self, key: tuple, window_s: float, now: float) -> int:
        return self.store.window_count(self._key(key), now, window_s)

    def add(self, key: tuple, now: float, window_s: float = 86400) -> None:
        self.store.window_add(self._key(key), now, window_s)

    def acquire(self, key: tuple, window_s: float, limit: int, now: float) -> tuple[bool, int]:
        return self.store.window_acquire(self._key(key), now, window_s, limit)

    def reset(self, key: tuple) -> None:
        self.store.window_reset(self._key(key))


class RunState:
    """Counters of one agent run, read from and written to the store."""

    FIELDS = ("steps", "model_calls", "delegations", "cost_usd")

    def __init__(self, store: Store, run_id: str, ttl: float):
        self.store, self.run_id, self.ttl = store, run_id, ttl

    def _key(self, name: str) -> str:
        return f"run|{self.run_id}|{name}"

    def add(self, name: str, amount: float = 1) -> float:
        return self.store.incr(self._key(name), amount, self.ttl)

    def reserve(self, name: str, limit: float) -> bool:
        """Atomically take one unit of `name` if that keeps it within `limit`."""
        if self.add(name, 1) > limit:
            self.add(name, -1)
            return False
        return True

    def _get(self, name: str) -> float:
        return self.store.counter(self._key(name))

    steps = property(lambda self: int(self._get("steps")))  # tool calls
    model_calls = property(lambda self: int(self._get("model_calls")))
    delegations = property(lambda self: int(self._get("delegations")))  # A2A tasks started
    cost_usd = property(lambda self: self._get("cost_usd"))


class GatewayState:
    RUN_IDLE_TTL_S = 24 * 3600

    def __init__(self, store: Store | None = None):
        self.store: Store = store if store is not None else DurableStore()
        self.calls = SlidingCounter(self.store, "calls")  # (agent, user, tool) -> calls (rate limits)
        self.writes = SlidingCounter(self.store, "writes")  # (agent, user, tool) -> executed writes (limits)
        self.violations = SlidingCounter(self.store, "violations")  # (agent,) -> policy violations

    # ---- kill switch
    def killed(self, agent_id: str) -> dict | None:
        return self.store.get("killed", agent_id)

    def kill(self, agent_id: str, by: str, reason: str) -> None:
        self.store.put("killed", agent_id, {"by": by, "reason": reason, "at": time.time()})

    def revive(self, agent_id: str) -> bool:
        return self.store.delete("killed", agent_id)

    # ---- autonomy demotion (can only lower the compiled level)
    def demoted_level(self, agent_id: str) -> AutonomyLevel | None:
        entry = self.store.get("demotions", agent_id)
        return AutonomyLevel(entry["level"]) if entry else None

    def demote(self, agent_id: str, level: AutonomyLevel, by: str, reason: str) -> None:
        self.store.put("demotions", agent_id, {"level": level.value, "by": by, "reason": reason, "at": time.time()})

    def demote_from(self, agent_id: str, compiled: AutonomyLevel, seen: AutonomyLevel, to: AutonomyLevel,
                    by: str, reason: str) -> bool:
        """Demote only if the agent is still at `seen`: two replicas breaching the SLO at the
        same moment demote once, not twice."""
        def fn(entry):
            current = min(compiled, AutonomyLevel(entry["level"])) if entry else compiled
            if current != seen:
                raise Abort
            return {"level": to.value, "by": by, "reason": reason, "at": time.time()}

        try:
            self.store.update("demotions", agent_id, fn)
            return True
        except Abort:
            return False

    def clear_demotion(self, agent_id: str) -> bool:
        return self.store.delete("demotions", agent_id)

    # ---- runs
    def run(self, run_id: str, now: float | None = None) -> RunState:
        return RunState(self.store, run_id, self.RUN_IDLE_TTL_S)
