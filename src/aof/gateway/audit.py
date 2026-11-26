"""Append-only, hash-chained audit log (JSONL).

Each record carries the hash of the previous one, so editing or deleting a line
breaks the chain and `verify` reports where. Arguments are recorded as a hash plus
their keys, not their values, so the log does not become a second copy of PII.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def args_digest(args: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(args).encode()).hexdigest()


def _hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(canonical(body).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []  # in-memory mode

    def _last(self) -> tuple[int, str]:
        if self.path is None:
            return (self.records[-1]["seq"], self.records[-1]["hash"]) if self.records else (0, GENESIS)
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        with open(self.path, "rb") as f:
            f.seek(0, 2)
            pos = f.tell() - 1
            while pos > 0:
                f.seek(pos - 1)
                if f.read(1) == b"\n":
                    break
                pos -= 1
            f.seek(max(pos, 0))
            last = json.loads(f.readline())
        return last["seq"], last["hash"]

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        if self.path is None:
            return self._append_locked(event, fields)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path.with_suffix(".lock"), "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                return self._append_locked(event, fields)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _append_locked(self, event: str, fields: dict[str, Any]) -> dict[str, Any]:
        seq, prev = self._last()
        record = {"seq": seq + 1, "ts": time.time(), "event": event, **fields, "prev": prev}
        record["hash"] = _hash(record)
        if self.path is None:
            self.records.append(record)
        else:
            with open(self.path, "a") as f:
                f.write(canonical(record) + "\n")
        return record

    def read(self) -> list[dict[str, Any]]:
        if self.path is None:
            return list(self.records)
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]


def verify(records: list[dict[str, Any]]) -> tuple[bool, int | None]:
    """Return (ok, first bad seq)."""
    prev = GENESIS
    for i, r in enumerate(records, start=1):
        if r.get("seq") != i or r.get("prev") != prev or r.get("hash") != _hash(r):
            return False, r.get("seq", i)
        prev = r["hash"]
    return True, None
