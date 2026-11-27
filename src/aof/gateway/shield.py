"""Data shield: keeps governed data away from the model (docs/data-safety.md, phase D2).

Around every tool call that reads governed data (a `query:` tool, or any tool with `reads`):

  before   tokens in the arguments are swapped back for real values (same user and run);
           a query tool's query is compiled and guarded (`aof.query.prepare_query`) and
           the guarded SQL replaces it; the per-run query budget is reserved.
  after    the result goes into the vault; the agent gets a handle, the columns with
           their exposure, a bucketed row count, and only the values it may see:
           `allowed` as is, `token` as tokens, `masked` partly, `aggregate` only from an
           aggregated query over groups of at least `min_group_size` rows. A failed query
           returns a generic error, never the warehouse's message (it can echo values).

Value references (DS8): an argument may name a vaulted value it never saw,
`{{res_<id>.amount}}` or `{{res_<id>.rows[0].opex}}`. The gateway resolves it (same user)
before the policy check, so limits and approvers see the real value; a call that used a
reference has its result shaped too, so the app can't echo the value back. Verdicts are
typed outputs (boolean or a few named values) the app computes; they are shown in every
mode, and any value outside the declared type is dropped.

`data_safety.results` sets the mode: `enforce` returns the shaped result, `shadow` vaults
and audits but returns the result unchanged (for rollout), `off` skips the vault. Query
tools are always guarded when the policy has a data_safety section.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..datasafety import ViewSchema
from ..enums import Exposure
from .compiled import CompiledPolicy, ToolRule
from .identity import Principal
from .state import RunState
from .vault import ResultVault, VaultError

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}")
REF_RE = re.compile(r"\{\{(res_[0-9a-f]{8,})\.([A-Za-z_]\w*(?:\[\d+\]|\.[A-Za-z_]\w*)*)\}\}")
_PATH_PART = re.compile(r"[A-Za-z_]\w*|\[\d+\]")
HIDDEN_ERROR = {"error": "QUERY_FAILED",
                "reason": "the query failed to run; check the columns and filters against describe, then retry"}
# An app error after a call that used a vault reference can quote the resolved value.
HIDDEN_TOOL_ERROR = {"error": "TOOL_FAILED",
                     "reason": "the app refused the call; the user can see why in the app"}


def bucket(n: int, buckets: list[int]) -> str:
    """'0', '1-9', '10-99', ... '10000+': a row count the model may see."""
    edges = sorted(set(buckets) | {0})
    if n <= 0:
        return "0"
    for lo, hi in zip(edges, edges[1:]):
        if lo <= n < hi:
            return f"{lo}-{hi - 1}" if hi - 1 > lo else str(lo)
    return f"{edges[-1]}+"


def _count(value: Any) -> int:
    """A group row count; warehouses may return numbers as strings. Unreadable counts as 0."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def mask(value: Any) -> Any:
    if isinstance(value, str):
        if _DATE.match(value):
            return value[:4]
        return "****" + value[-4:] if len(value) > 4 else "****"
    return "****"


def rows_of(content: Any) -> list[dict[str, Any]] | None:
    """Rows from the common result shapes: [{...}], {"rows": [{...}]}, {"columns": [...], "rows": [[...]]}."""
    if isinstance(content, list) and all(isinstance(r, dict) for r in content):
        return content
    if isinstance(content, dict) and isinstance(content.get("rows"), list):
        rows, cols = content["rows"], content.get("columns")
        if all(isinstance(r, dict) for r in rows):
            return rows
        if isinstance(cols, list) and all(isinstance(r, list) for r in rows):
            names = [c if isinstance(c, str) else str(c.get("name")) for c in cols]
            return [dict(zip(names, r)) for r in rows]
    return None


def valid_verdict(spec: dict[str, Any], value: Any) -> bool:
    if spec.get("type") == "boolean":
        return isinstance(value, bool)
    return isinstance(value, str) and value in spec.get("values", [])


def _follow(content: Any, path: str, handle: str) -> Any:
    """`amount`, `items[0].sku`, `rows[2].opex`; on a one-row query result, `opex`."""
    rows = rows_of(content)
    value: Any = {"rows": rows} if rows is not None else content
    parts = _PATH_PART.findall(path)
    if rows is not None and parts and parts[0] != "rows":
        if len(rows) != 1:
            raise VaultError("REFERENCE_INVALID", f"{handle} has {len(rows)} rows; name one: rows[0].{path}")
        value = rows[0]
    for part in parts:
        if part.startswith("["):
            i = int(part[1:-1])
            ok = isinstance(value, list) and i < len(value)
            value = value[i] if ok else None
        else:
            ok = isinstance(value, dict) and part in value
            if not ok and isinstance(value, dict):  # column names are case-blind
                match = next((k for k in value if str(k).lower() == part.lower()), None)
                ok, part = match is not None, match
            value = value[part] if ok else None
        if not ok:
            raise VaultError("REFERENCE_INVALID", f"{handle}.{path} names nothing in that result")
    if isinstance(value, (dict, list)):
        raise VaultError("REFERENCE_INVALID", f"{handle}.{path} is not a single value")
    return value


@dataclass
class Prepared:
    args: dict[str, Any]  # what the upstream gets
    guarded: Any = None  # GuardedQuery for query tools


class DataShield:
    def __init__(self, policy: CompiledPolicy, vault: ResultVault):
        ds = policy.data_safety or {}
        self.policy = policy
        self.vault = vault
        self.enabled = bool(ds)
        self.results = ds.get("results", "off")
        self.views = {k: ViewSchema.model_validate(v) for k, v in ds.get("views", {}).items()}
        self.min_group = int(ds.get("min_group_size", 10))
        self.buckets = list(ds.get("row_count_buckets", [0, 1, 10, 100, 1000, 10000]))
        self.claim_paths: dict[str, str] = dict(ds.get("row_filter_claims", {}))
        self.functions = list(ds.get("allowed_functions", []))
        self.max_queries = int(ds.get("max_queries_per_run", 20))
        self.preview_rows = int((ds.get("vault") or {}).get("model_preview_rows", 20))
        self.egress = None  # set by the gateway: remembers hidden values for the egress guard

    def governed(self, rule: ToolRule) -> bool:
        return self.enabled and self.results != "off" and bool(rule.query or rule.reads or rule.verdicts)

    # ------------------------------------------------------------------ value references

    def resolve_refs(self, principal: Principal, args: Any) -> tuple[Any, int]:
        """Replace `{{res_<id>.<path>}}` with the vaulted value. An argument that is exactly
        one reference takes the value's type; a reference inside text becomes text.
        Raises VaultError (RESULT_NOT_FOUND, REFERENCE_INVALID)."""
        if not self.enabled or self.results == "off":
            return args, 0
        cache: dict[str, Any] = {}
        count = 0

        def lookup(handle: str, path: str) -> Any:
            if handle not in cache:
                cache[handle] = self.vault.get(handle, principal).content
            return _follow(cache[handle], path, handle)

        def walk(value: Any) -> Any:
            nonlocal count
            if isinstance(value, str):
                whole = REF_RE.fullmatch(value.strip())
                if whole:
                    count += 1
                    return lookup(whole.group(1), whole.group(2))

                def sub(m: re.Match) -> str:
                    nonlocal count
                    count += 1
                    return str(lookup(m.group(1), m.group(2)))

                return REF_RE.sub(sub, value)
            if isinstance(value, dict):
                return {k: walk(v) for k, v in value.items()}
            if isinstance(value, list):
                return [walk(v) for v in value]
            return value

        out = walk(args)
        return out, count

    # ------------------------------------------------------------------ before the call

    def claims(self, principal: Principal) -> dict[str, Any]:
        out: dict[str, Any] = {"sub": principal.user_id}
        if principal.tenant is not None:
            out["tenant"] = principal.tenant
        for name, path in self.claim_paths.items():
            value: Any = principal.claims
            for part in path.split("."):
                value = value.get(part) if isinstance(value, dict) else None
            if value is not None:
                out[name] = value
        return out

    def prepare(self, principal: Principal, rule: ToolRule, args: dict[str, Any], run_id: str,
                run: RunState) -> Prepared:
        """Upstream arguments. Raises QueryRejected for a refused query."""
        if not self.enabled:
            return Prepared(args)
        real = self.vault.detokenize(args, principal, run_id)
        if not rule.query:
            return Prepared(real)
        from ..query import GuardConfig, QueryRejected, prepare_query

        q = rule.query
        if not run.reserve("queries", self.max_queries):
            raise QueryRejected("QUERY_BUDGET", f"this run used its {self.max_queries} queries",)
        raw = real.get(q["param"])
        if raw is None:
            raise QueryRejected("QUERY_INVALID", f"missing the {q['param']!r} argument")

        def resolve(text: str) -> str | None:
            found, value = self.vault.resolve(text, principal, run_id)
            return value if found else None

        guarded = prepare_query(
            raw, form=q.get("form", "ir"), views=self.views, allowed_views=rule.reads, claims=self.claims(principal),
            config=GuardConfig.of(q.get("dialect", "snowflake"), int(q.get("max_rows") or 1000), self.functions),
            resolve_literal=resolve, count_groups=True)
        return Prepared({**real, q["param"]: guarded.sql}, guarded)

    # ------------------------------------------------------------------ after the call

    def _exposures(self, rule: ToolRule) -> dict[str, Exposure]:
        out: dict[str, Exposure] = {}
        for view in rule.reads:
            v = self.views.get(view.lower())
            for name, col in (v.columns.items() if v else []):
                out[name] = min(out[name], col.exposure) if name in out else col.exposure
        for key, e in rule.result_keys.items():
            out.setdefault(key.lower(), Exposure(e))  # a contract field keeps its contract exposure
        return out

    def _visible(self, value: Any, exposure: Exposure, column: str, principal: Principal, run_id: str,
                 aggregate_ok: bool) -> tuple[bool, Any]:
        if exposure is Exposure.ALLOWED:
            return True, value
        if exposure is Exposure.TOKEN and not isinstance(value, (dict, list)):
            return True, self.vault.tokenize(principal, run_id, column, value)
        if exposure is Exposure.MASKED and not isinstance(value, (dict, list)):
            return True, mask(value)
        if exposure is Exposure.AGGREGATE and aggregate_ok:
            return True, value
        return False, None

    def shape_query(self, principal: Principal, run_id: str, rule: ToolRule, content: Any, guarded,
                    handle: str) -> dict[str, Any]:
        rows = rows_of(content)
        exposures = {c.name: c.exposure for c in guarded.columns}
        out: dict[str, Any] = {
            "result_handle": handle,
            "columns": [{"name": c.name, "exposure": c.exposure.value} for c in guarded.columns],
        }
        if rows is None:
            out["note"] = "the result is in the vault; its shape could not be read"
            return out
        out["row_count"] = bucket(len(rows), self.buckets)
        visible = [n for n, e in exposures.items() if e is not Exposure.NONE]
        preview, suppressed = [], 0
        for row in rows[: self.preview_rows] if visible else []:
            low = {str(k).lower(): v for k, v in row.items()}
            group_ok = guarded.aggregated and (guarded.group_rows_column is None
                                               or _count(low.get(guarded.group_rows_column)) >= self.min_group)
            shown = {}
            for name in visible:
                ok, v = self._visible(low.get(name), exposures[name], name, principal, run_id, group_ok)
                if ok:
                    shown[name] = v
                elif exposures[name] is Exposure.AGGREGATE:
                    suppressed += 1
            preview.append(shown)
        if preview and any(preview):
            out["rows"] = preview
            out["rows_shown"] = len(preview)
        if suppressed:
            out["suppressed_small_groups"] = True
        out["next"] = (f"Values are hidden from you. Show the user the table from {handle}, and write numbers "
                       f"as {{{{{handle}.<column>}}}} placeholders; never state them yourself. To pass a value "
                       f"to a tool, use {{{{{handle}.rows[<n>].<column>}}}} as the argument.")
        return out

    def shape_json(self, principal: Principal, run_id: str, rule: ToolRule, content: Any,
                   handle: str) -> dict[str, Any]:
        exposures = self._exposures(rule)
        verdicts = {k.lower(): v for k, v in rule.verdicts.items()}
        hidden: set[str] = set()

        def walk(value: Any, key: str | None) -> tuple[bool, Any]:
            if key is not None and key.lower() in verdicts:
                if valid_verdict(verdicts[key.lower()], value):
                    return True, value
                hidden.add(key)  # not the declared type: the app may be returning a value
                return False, None
            e = exposures.get(key.lower()) if key is not None else None
            if e is not None and e is not Exposure.ALLOWED:
                ok, v = self._visible(value, e, key.lower(), principal, run_id, aggregate_ok=False)
                if not ok:
                    hidden.add(key)
                return ok, v
            if e is Exposure.ALLOWED:
                return True, value
            if isinstance(value, dict):
                return True, {k: v for k, (ok, v) in ((k, walk(v, k)) for k, v in value.items()) if ok}
            if isinstance(value, list):
                return True, [v for ok, v in (walk(v, key) for v in value) if ok]
            if key is None:
                hidden.add("(value)")
                return False, None
            hidden.add(key)  # not a contract field and not declared in result_keys
            return False, None

        ok, shown = walk(content, None)
        out: dict[str, Any] = {"result_handle": handle}
        if ok:
            out["result"] = shown
        if hidden:
            out["hidden_keys"] = sorted(hidden)
            key = sorted(hidden)[0]
            out["next"] = (f"Hidden values stay hidden from you. To pass one to a tool, write "
                           f"{{{{{handle}.{key}}}}} as the argument; the gateway fills it in.")
        return out

    def store(self, principal: Principal, run_id: str, tool: str, content: Any, guarded=None) -> str:
        meta = {"columns": [{"name": c.name, "exposure": c.exposure.value} for c in guarded.columns]} \
            if guarded is not None else {}
        return self.vault.put(principal, agent_id=self.policy.agent.id, run_id=run_id, tool=tool,
                              content=content, meta=meta)

    def hidden_values(self, rule: ToolRule, content: Any, guarded=None) -> list[Any]:
        """Raw values the agent is not shown as they are (everything but `allowed`)."""
        out: list[Any] = []
        if guarded is not None:
            rows = rows_of(content)
            if rows is None:
                return out
            exposures = {c.name: c.exposure for c in guarded.columns}
            for row in rows:
                for k, v in row.items():
                    if exposures.get(str(k).lower()) is not Exposure.ALLOWED:
                        out.append(v)
            return out
        exposures = self._exposures(rule)

        def walk(value: Any, key: str | None) -> None:
            if key is not None and exposures.get(key.lower()) is Exposure.ALLOWED:
                return
            if isinstance(value, dict):
                for k, v in value.items():
                    walk(v, k)
            elif isinstance(value, list):
                for v in value:
                    walk(v, key)
            else:
                out.append(value)

        walk(content, None)
        return out

    def shape(self, principal: Principal, run_id: str, rule: ToolRule, content: Any, guarded=None
              ) -> tuple[str, dict[str, Any]]:
        """Vault the content; return (handle, what the agent may see)."""
        handle = self.store(principal, run_id, rule.name, content, guarded)
        if guarded is not None:
            shaped = self.shape_query(principal, run_id, rule, content, guarded, handle)
        else:
            shaped = self.shape_json(principal, run_id, rule, content, handle)
        if self.egress is not None:
            # A value the agent was shown (a visible group key such as a month or an
            # account) is not a leak when it comes back: only fingerprint what stayed hidden.
            self.egress.remember(principal, self.hidden_values(rule, content, guarded), shown=shaped)
        return handle, shaped
