"""Egress guard on POST /v1/messages (D3, docs/data-safety.md)."""

from __future__ import annotations

import asyncio
import json

import pytest

from aof.gateway import Gateway
from aof.gateway.egress import segments, text_keys, value_keys
from aof.gateway.llm import LlmProxy

from .test_gateway_llm import FakeProvider
from .test_gateway_vault import ALICE, MALLORY, OPEX_Q3, LedgerUpstream, app, call, make_policy  # noqa: F401

pytest.importorskip("duckdb")

IBAN = "DE89 3704 0044 0532 0130 00"  # valid check digits
CARD = "4111 1111 1111 1111"          # valid Luhn


def proxy(app, results="enforce", mode="contract", **egress):
    policy = make_policy(app, results=results, mode=mode)
    if egress:
        policy.data_safety["egress"].update(egress)
    gw = Gateway(policy, LedgerUpstream())
    return LlmProxy(gw, FakeProvider()), gw


def ask(p, messages, who=ALICE, run_id="run-1", system=None):
    body = {"model": "claude-opus-5-5", "max_tokens": 256, "messages": messages}
    if system is not None:
        body["system"] = system
    return asyncio.run(p.handle(who, body, run_id=run_id))


def user(text):
    return {"role": "user", "content": text}


def sent(p):
    return json.dumps(p.provider.calls[-1][0])


# --------------------------------------------------------------------------- normalising


def test_value_keys_skip_small_and_common_values():
    assert value_keys(42) == value_keys(180) == value_keys(2026) == value_keys("DE01") == set()
    assert value_keys("180.00") == value_keys(180.0) == {"n:180"}  # written as an amount
    assert value_keys(4711) == {"n:4711"} and value_keys("ACME Supplies GmbH") == {"s:acme supplies gmbh"}
    assert "n:180" not in text_keys("about 180 rows") and "n:180" in text_keys("total 180.00 EUR")


def test_text_keys_find_numbers_ids_and_phrases():
    keys = text_keys("Total was 4,711.50 EUR for ACME Supplies GmbH (ref INV-2026-00042).")
    assert {"n:4711.5", "s:acme supplies gmbh", "s:inv-2026-00042"} <= keys


def test_segments_cover_system_turns_tool_io_and_skip_thinking():
    params = {"system": [{"type": "text", "text": "sys"}], "messages": [
        user("u"),
        {"role": "assistant", "content": [{"type": "thinking", "thinking": "secret", "signature": "x"},
                                          {"type": "text", "text": "a"},
                                          {"type": "tool_use", "id": "t1", "name": "q", "input": {"q": "in"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "out"},
                                     {"type": "image", "source": {}}]},
    ]}
    segs, non_text = segments(params)
    assert [(s.origin, s.text) for s in segs] == [("system", "sys"), ("user_text", "u"), ("assistant_text", "a"),
                                                   ("tool_input", "in"), ("tool_result", "out")]
    assert non_text == 1


# --------------------------------------------------------------------------- vault fingerprints


def _vault_opex(gw):
    """A query whose total (180.00) is hidden from the agent but now known to the gateway."""
    return call(gw, "query_ledger", {"query": OPEX_Q3}).content


def test_vaulted_value_in_a_tool_result_is_blocked(app):
    p, gw = proxy(app)
    _vault_opex(gw)
    res = ask(p, [user("opex?"),
                  {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "x", "input": {}}]},
                  {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t",
                                                "content": "opex for DE01 is 180.00"}]}])
    assert res.status == 403 and "DATA_EGRESS_BLOCKED" in res.body["error"]["message"]
    assert p.provider.calls == []
    rec = gw.audit.read()[-1]
    assert rec["event"] == "llm_denied" and rec["egress"] == {"vault_fingerprint": 1}
    assert "180" not in json.dumps(rec)


def test_vaulted_value_in_the_system_prompt_is_blocked(app):
    p, gw = proxy(app)
    _vault_opex(gw)
    assert ask(p, [user("hi")], system="Context: Q3 opex 180.00 EUR").status == 403


def test_the_user_may_name_a_value_themselves(app):
    p, gw = proxy(app)
    _vault_opex(gw)
    assert ask(p, [user("is opex above 180.00?")]).status == 200


def test_fingerprints_are_per_user(app):
    p, gw = proxy(app)
    _vault_opex(gw)
    res = ask(p, [{"role": "assistant", "content": "earlier: 180.00"}, user("ok")], who=MALLORY)
    assert res.status == 200


def test_handles_and_shaped_results_pass(app):
    p, gw = proxy(app)
    shaped = _vault_opex(gw)
    res = ask(p, [user("opex?"),
                  {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "query_ledger",
                                                     "input": {"query": OPEX_Q3}}]},
                  {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t",
                                                "content": json.dumps(shaped)}]}])
    assert res.status == 200


# --------------------------------------------------------------------------- detectors


def test_iban_is_redacted_to_a_token_the_tools_can_use(app):
    p, gw = proxy(app)
    res = ask(p, [user(f"refund to {IBAN} please")])
    assert res.status == 200
    out = sent(p)
    assert "DE89" not in out and "tok_" in out
    token = next(w for w in out.replace('"', " ").split() if w.startswith("tok_"))
    assert gw.vault.resolve(token, ALICE, "run-1") == (True, IBAN)
    assert gw.audit.read()[-1]["egress"] == {"iban": 1}


def test_invalid_iban_is_left_alone(app):
    p, _ = proxy(app)
    ask(p, [user("ref DE00 3704 0044 0532 0130 00")])  # bad check digits
    assert "DE00 3704" in sent(p)


def test_card_number_is_blocked(app):
    p, _ = proxy(app)
    res = ask(p, [user(f"card {CARD}")])
    assert res.status == 403 and "SENSITIVE_DATA_BLOCKED" in res.body["error"]["message"]
    assert ask(p, [user("order 1234 5678 9012 3456")]).status == 200  # fails Luhn: not a card


def test_email_and_phone_redacted_everywhere(app):
    p, _ = proxy(app)
    ask(p, [user("mail jane.doe@example.com"),
            {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "x",
                                               "input": {"to": "+49 30 1234 5678"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": "sent"}]}])
    out = sent(p)
    assert "jane.doe" not in out and "1234 5678" not in out


def test_custom_pattern(app):
    p, _ = proxy(app, custom_patterns={"tax_id": {"regex": r"\bDE\d{9}\b", "action": "block"}})
    res = ask(p, [user("VAT DE123456789")])
    assert res.status == 403 and "tax id" in res.body["error"]["message"]


def test_images_are_blocked_unless_allowed(app):
    msg = [{"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                                                      "data": "AAAA"}},
                                        {"type": "text", "text": "what is this"}]}]
    p, _ = proxy(app)
    res = ask(p, msg)
    assert res.status == 403 and "NON_TEXT_BLOCKED" in res.body["error"]["message"]
    p2, _ = proxy(app, non_text="allow")
    assert ask(p2, msg).status == 200


def test_thinking_blocks_are_never_altered(app):
    p, _ = proxy(app)
    thinking = {"type": "thinking", "thinking": "user email jane.doe@example.com", "signature": "sig"}
    ask(p, [user("hi"), {"role": "assistant", "content": [thinking, {"type": "text", "text": "ok"}]}, user("go")])
    assert p.provider.calls[-1][0]["messages"][1]["content"][0] == thinking


def test_refused_requests_cost_no_budget(app):
    p, gw = proxy(app)
    ask(p, [user(f"card {CARD}")])
    assert gw.state.run("run-1").model_calls == 0


# --------------------------------------------------------------------------- modes


def test_shadow_mode_audits_but_changes_nothing(app):
    p, gw = proxy(app, results="shadow")
    _vault_opex(gw)
    res = ask(p, [{"role": "assistant", "content": "180.00"}, user(f"card {CARD}, iban {IBAN}")])
    assert res.status == 200 and IBAN in sent(p) and CARD in sent(p)
    egress = gw.audit.read()[-1]["egress"]
    assert egress == {"vault_fingerprint": 1, "iban": 1, "card_number": 1}


def test_off_mode_skips_the_guard(app):
    p, gw = proxy(app, results="off")
    assert ask(p, [user(f"card {CARD}")]).status == 200
    assert "egress" not in gw.audit.read()[-1]
