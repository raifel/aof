"""Egress guard: checks a model request before it leaves for the provider (docs/data-safety.md, D3).

The vault keeps tool results away from the model, but values can still arrive another
way: the user pastes them, a document contains them, or an agent copies data it got some
other way into its prompt. Before `POST /v1/messages` goes out:

1. **Vault fingerprints.** When the shield vaults a result, it records keyed hashes of the
   distinctive values the agent wasn't shown (longer strings, amounts with decimals,
   larger numbers). If one turns up in the system prompt, an assistant turn, a tool input
   or a tool result, vaulted data is about to reach the model: `DATA_EGRESS_BLOCKED`.
   Text the user typed is not checked against fingerprints (the user may name values).
2. **Pattern detectors** on all text, the user's included: IBAN (mod-97), card numbers
   (Luhn), e-mail, international phone numbers, and platform `custom_patterns`. Each
   detector `redact`s (the match becomes a vault token the agent can pass to tools), or
   `block`s (`SENSITIVE_DATA_BLOCKED`), or is `off`.
3. **Content the guard cannot read** (images, documents) is blocked by default
   (`NON_TEXT_BLOCKED`).

In `shadow` mode nothing is changed or blocked; findings are audited. The audit records
detector names and counts, never the matched text. This is a tripwire with heuristics,
not a proof: a value reworded by the agent ("one hundred eighty") passes.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Iterable

from .identity import Principal
from .vault import ResultVault

_FP_NS = "vault_fingerprints"

# ---------------------------------------------------------------------- normalising values

_NUM = re.compile(r"(?<![\w.])-?\d{1,3}(?:,\d{3})+(?:\.\d+)?(?![\w])|(?<![\w.])-?\d+(?:\.\d+)?(?![\w])")
_WORDISH = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-.@/]{5,}")
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-.@/']*")


def _number(text: str) -> Decimal | None:
    try:
        return Decimal(text.replace(",", ""))
    except InvalidOperation:
        return None


def _distinctive_number(d: Decimal, written: str) -> bool:
    """Amounts (written with a decimal point) and larger numbers; not small counts or
    plausible years. `written` is how the number appeared: 180.00 counts, 180 doesn't."""
    if "." in written:
        return True
    n = abs(int(d))
    return n >= 1000 and not 1900 <= n <= 2100


def _norm_number(d: Decimal) -> str:
    s = format(d.normalize(), "f")
    return s.rstrip("0").rstrip(".") if "." in s else s


def _norm_text(s: str) -> str:
    return " ".join(s.lower().split())


def value_keys(value: Any) -> set[str]:
    """Normalised forms of a hidden value worth fingerprinting (empty if not distinctive)."""
    if isinstance(value, bool) or value is None:
        return set()
    if isinstance(value, (int, float, Decimal)):
        d = _number(str(value))
        return {"n:" + _norm_number(d)} if d is not None and _distinctive_number(d, str(value)) else set()
    if isinstance(value, str):
        s = value.strip()
        d = _number(s) if _NUM.fullmatch(s) else None
        if d is not None:
            return {"n:" + _norm_number(d)} if _distinctive_number(d, s) else set()
        t = _norm_text(s)
        return {"s:" + t} if len(t) >= 6 else set()
    return set()


def text_keys(text: str) -> set[str]:
    """Candidate normalised forms found in a piece of text."""
    out: set[str] = set()
    for m in _NUM.finditer(text):
        d = _number(m.group())
        if d is not None and _distinctive_number(d, m.group()):
            out.add("n:" + _norm_number(d))
    for m in _WORDISH.finditer(text):
        out.add("s:" + m.group().lower().rstrip("."))
    words = [w.lower() for w in _WORD.findall(text)]
    for n in (2, 3, 4):  # multi-word values: names, addresses
        for i in range(len(words) - n + 1):
            phrase = " ".join(words[i:i + n])
            if len(phrase) >= 6:
                out.add("s:" + phrase)
    return out


# ---------------------------------------------------------------------- detectors


def _iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    digits = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(digits) % 97 == 1


def _luhn_ok(raw: str) -> bool:
    digits = [int(c) for c in raw if c.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _phone_ok(raw: str) -> bool:
    return 8 <= sum(c.isdigit() for c in raw) <= 15


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: re.Pattern
    valid: Callable[[str], bool] = lambda s: True


BUILTIN = {
    "iban": Detector("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), _iban_ok),
    "card_number": Detector("card_number", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), _luhn_ok),
    "email": Detector("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    "phone": Detector("phone", re.compile(r"\+\d[\d ()-]{6,18}\d"), _phone_ok),
}


# ---------------------------------------------------------------------- walking a request


_NON_TEXT = {"image", "document", "container_upload", "file"}
_SKIP = {"thinking", "redacted_thinking"}  # signed by the provider; never altered


def _walk_strings(value: Any, fn: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, dict):
        return {k: _walk_strings(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk_strings(v, fn) for v in value]
    return value


@dataclass
class Segment:
    """A piece of request text, where it came from, and how to write it back."""
    text: str
    origin: str  # system | user_text | assistant_text | tool_input | tool_result
    set: Callable[[str], None]


def segments(params: dict[str, Any]) -> tuple[list[Segment], int]:
    """Every text segment of a (copied) request, and the number of non-text blocks."""
    out: list[Segment] = []
    non_text = 0

    def add_blocks(blocks: list, origin: str) -> None:
        nonlocal non_text
        for block in blocks:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind in _SKIP:
                continue
            if kind in _NON_TEXT:
                non_text += 1
            elif kind == "tool_use" or kind == "server_tool_use":
                def set_input(new, b=block):
                    b["input"] = new
                for seg in _json_segments(block.get("input"), "tool_input", set_input):
                    out.append(seg)
            elif kind == "tool_result":
                content = block.get("content")
                if isinstance(content, str):
                    out.append(Segment(content, "tool_result", lambda t, b=block: b.__setitem__("content", t)))
                elif isinstance(content, list):
                    add_blocks(content, "tool_result")
            elif isinstance(block.get("text"), str):
                out.append(Segment(block["text"], origin, lambda t, b=block: b.__setitem__("text", t)))

    system = params.get("system")
    if isinstance(system, str):
        out.append(Segment(system, "system", lambda t: params.__setitem__("system", t)))
    elif isinstance(system, list):
        add_blocks(system, "system")
    for msg in params.get("messages") or []:
        if not isinstance(msg, dict):
            continue
        origin = "assistant_text" if msg.get("role") == "assistant" else "user_text"
        content = msg.get("content")
        if isinstance(content, str):
            out.append(Segment(content, origin, lambda t, m=msg: m.__setitem__("content", t)))
        elif isinstance(content, list):
            add_blocks(content, origin)
    return out, non_text


def _json_segments(value: Any, origin: str, write: Callable[[Any], None]) -> Iterable[Segment]:
    """Tool inputs are JSON: expose their strings one by one, writing the whole value back."""
    holder = {"v": value}
    strings: list[tuple[list, Any]] = []

    def collect(v, path):
        if isinstance(v, str):
            strings.append((path, v))
        elif isinstance(v, dict):
            for k, x in v.items():
                collect(x, path + [k])
        elif isinstance(v, list):
            for i, x in enumerate(v):
                collect(x, path + [i])

    collect(value, [])
    for path, text in strings:
        def setter(new, p=path):
            if not p:
                holder["v"] = new
            else:
                target = holder["v"]
                for k in p[:-1]:
                    target = target[k]
                target[p[-1]] = new
            write(holder["v"])
        yield Segment(text, origin, setter)


# ---------------------------------------------------------------------- the guard


@dataclass
class EgressResult:
    params: dict[str, Any]
    findings: dict[str, int] = field(default_factory=dict)  # detector -> matches; never the text
    blocked: tuple[str, str] | None = None  # (code, message)


class EgressGuard:
    def __init__(self, data_safety: dict[str, Any], vault: ResultVault, agent_id: str):
        cfg = data_safety.get("egress") or {}
        self.vault = vault
        self.agent_id = agent_id
        self.mode = data_safety.get("results", "off")
        self.actions: dict[str, str] = dict(cfg.get("detectors") or {})
        self.detectors = {n: d for n, d in BUILTIN.items() if self.actions.get(n, "off") != "off"}
        for name, spec in (cfg.get("custom_patterns") or {}).items():
            self.detectors[name] = Detector(name, re.compile(spec["regex"]))
            self.actions[name] = spec.get("action", "block")
        self.non_text = cfg.get("non_text", "block")
        self.fingerprints = bool(cfg.get("fingerprints", True))
        self.max_fingerprints = int(cfg.get("max_fingerprints_per_user", 20000))
        self._key = hmac.new(vault._mac_key, b"aof-egress-fingerprint", hashlib.sha256).digest()

    @property
    def active(self) -> bool:
        return self.mode != "off"

    # ---- fingerprints (written by the shield, read here)

    def _fp(self, key: str) -> str:
        return hmac.new(self._key, key.encode(), hashlib.sha256).hexdigest()[:24]

    def _fp_doc(self, principal: Principal) -> str:
        return f"{self.agent_id}:{principal.tenant}:{principal.user_id}"

    def remember(self, principal: Principal, values: Iterable[Any], shown: Any = None) -> int:
        """Fingerprint hidden values, except those that also appear in `shown` (what the
        agent was given)."""
        visible = text_keys(json.dumps(shown, default=str)) if shown is not None else set()
        fps = {self._fp(k) for v in values for k in value_keys(v) if k not in visible}
        if not fps or not self.fingerprints:
            return 0

        def add(doc):
            known = list((doc or {}).get("fps", []))
            seen = set(known)
            known += [f for f in fps if f not in seen]
            return {"fps": known[-self.max_fingerprints:]}

        self.vault.store.update(_FP_NS, self._fp_doc(principal), add, ttl=self.vault.ttl)
        return len(fps)

    def _known(self, principal: Principal) -> set[str]:
        doc = self.vault.store.get(_FP_NS, self._fp_doc(principal)) if self.fingerprints else None
        return set((doc or {}).get("fps", []))

    def hidden_hits(self, principal: Principal, text: str, known: set[str] | None = None) -> int:
        """How many distinctive values from this user's vaulted results appear in `text`."""
        known = self._known(principal) if known is None else known
        return sum(1 for k in text_keys(text) if self._fp(k) in known) if known else 0

    # ---- inspection

    def inspect(self, principal: Principal, run_id: str, params: dict[str, Any]) -> EgressResult:
        if not self.active:
            return EgressResult(params)
        work = copy.deepcopy(params)
        segs, non_text = segments(work)
        findings: dict[str, int] = {}
        enforce = self.mode == "enforce"

        if non_text:
            findings["non_text_blocks"] = non_text
            if enforce and self.non_text == "block":
                return EgressResult(params, findings, ("NON_TEXT_BLOCKED",
                                    f"{non_text} image or document block(s): the gateway cannot check them for data"))

        known = self._known(principal)
        if known:
            hits = sum(self.hidden_hits(principal, s.text, known) for s in segs if s.origin != "user_text")
            if hits:
                findings["vault_fingerprint"] = hits
                if enforce:
                    return EgressResult(params, findings, (
                        "DATA_EGRESS_BLOCKED",
                        "the request contains values from vaulted results; refer to them by result handle "
                        "or {{handle.column}} placeholders instead"))

        redact: list[Detector] = []
        for det in self.detectors.values():
            count = sum(1 for s in segs for m in det.pattern.finditer(s.text) if det.valid(m.group()))
            if not count:
                continue
            findings[det.name] = count
            if enforce and self.actions.get(det.name) == "block":
                return EgressResult(params, findings, ("SENSITIVE_DATA_BLOCKED",
                                    f"the request contains {det.name.replace('_', ' ')} data, which may not be "
                                    "sent to the model"))
            if self.actions.get(det.name) == "redact":
                redact.append(det)

        if not enforce or not redact:
            return EgressResult(params, findings)
        for seg in segs:
            text = seg.text
            for det in redact:
                text = det.pattern.sub(
                    lambda m, d=det: self.vault.tokenize(principal, run_id, d.name, m.group())
                    if d.valid(m.group()) else m.group(), text)
            if text != seg.text:
                seg.set(text)
        return EgressResult(work, findings)
