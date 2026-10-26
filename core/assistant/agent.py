"""One turn of a conversation: ask the provider, run the tools it asks for, ask again, until it answers.

Runs on a worker thread (the panel's QThread) inside `db.within(org)`, so every tool reads that organization's files. The
panel hears about progress through `on_event(kind, payload)`: ("text", piece of the answer), ("tool", "Reading core-sw1's
history…"), ("done", {...}), ("stopped", None) or ("error", message).
"""
import threading
from datetime import datetime

from core import db
from core import assistant as AI
from core.assistant import prices, providers, store, tools as T

MAX_ROUNDS = 15                 # tool rounds in one turn before the Assistant is told to answer with what it has

SYSTEM = """You are the Assistant inside Toner, a network monitoring program used by a managed service provider (MSP) to look after
its clients' networks. You are talking to the network engineer who runs Toner. Today is {now}.

You are looking at the organization "{org}"{scope}. Everything you know about its network comes from the tools: the device list,
each device's latest check results and history, configuration backups (passwords masked) and their differences, the Firmware
Transfer check results, the audit log, terminal session logs, and what is on screen right now. Use them before answering a question
about this network, and say plainly when the data does not hold the answer. Never guess a value you could read.

You can only read. You cannot run commands on devices, change settings or send anything; when asked to, say that this version of
the Assistant reads only, and suggest what the person can do in Toner instead.

Passwords, keys and community strings are masked as **** wherever they appear; never try to reconstruct them and never ask for one.

Answer in plain, concrete words for a network engineer who is busy: lead with the finding, name the devices and values, and keep
it short. Use a short list or table when comparing several devices. Do not mention tool names."""


def system_prompt(org):
    name = db.org_name(org)
    scope = " (Global: every organization's devices are listed, each marked with its organization)" if not org else ""
    return SYSTEM.format(now=datetime.now().strftime("%A %d %B %Y, %H:%M"), org=name, scope=scope)


def run_turn(conv_id, org, question, screen, on_event, cancel=None, provider=None):
    """Ask one question in a conversation and run it to the answer. Returns the 'done' payload, or None when stopped or failed."""
    with db.within(org):
        return _run(conv_id, question, screen, on_event, cancel or threading.Event(), provider)


def _run(conv_id, question, screen, on_event, cancel, provider):
    conv = store.get(conv_id)
    if conv is None:
        on_event("error", "This conversation no longer exists.")
        return None
    if AI.spend_reached():
        on_event("error", AI.limit_text())
        return None
    prov = provider or AI.make(conv["provider"], model=conv.get("model") or None)
    history = list(conv["history"])
    history += prov.user_message(question)
    store.set_title(conv_id, question)
    store.add_turn(conv_id, "user", question)
    system = system_prompt(db.target())
    secrets = T.secrets()
    tokens_in = tokens_out = 0
    cost = 0.0
    text, model, outcome = "", prov.model, ""
    try:
        for _round in range(MAX_ROUNDS):
            reply = prov.complete(system, history, T.TOOLS, lambda piece: on_event("text", piece), cancel)
            history += reply.native
            tokens_in += reply.tokens_in
            tokens_out += reply.tokens_out
            model = reply.model or model
            cost += prices.cost(model, reply.tokens_in, reply.tokens_out)
            text += reply.text
            if reply.stop == "tool":
                results = []
                for call in reply.calls:
                    if cancel.is_set():
                        raise providers.Cancelled()
                    step = T.BY_NAME[call[1]].step(call[2]) if call[1] in T.BY_NAME else f"Reading {call[1]}…"
                    on_event("tool", step)
                    store.add_turn(conv_id, "tool", step)
                    results.append((call, T.run(call[1], call[2], screen, secrets)))
                history += prov.tool_results(reply, results)
                continue
            if reply.stop == "refusal":
                outcome = "refusal"
            elif reply.stop == "length":
                outcome = "length"
            break
        else:
            outcome = "rounds"
    except providers.Cancelled:
        store.set_history(conv_id, history)
        if text:
            store.add_turn(conv_id, "assistant", text, model, tokens_in, tokens_out, cost)
        store.add_turn(conv_id, "note", "Stopped.")
        on_event("stopped", None)
        return None
    except providers.ProviderError as e:
        store.set_history(conv_id, history)
        store.add_turn(conv_id, "note", str(e))
        on_event("error", str(e))
        return None
    except Exception as e:                                                # noqa: BLE001  (shown in the panel, never raised into Qt)
        store.set_history(conv_id, history)
        store.add_turn(conv_id, "note", f"{type(e).__name__}: {e}")
        on_event("error", f"{type(e).__name__}: {e}")
        return None
    store.set_history(conv_id, history)
    store.add_turn(conv_id, "assistant", text, model, tokens_in, tokens_out, cost)
    note = ""
    if outcome == "refusal":
        note = AI.REFUSED
    elif outcome == "length":
        note = AI.CUT_SHORT
    elif outcome == "rounds":
        note = AI.TOO_MANY_STEPS
    if note:
        store.add_turn(conv_id, "note", note)
    done = {"text": text, "model": model, "tokens_in": tokens_in, "tokens_out": tokens_out, "cost": cost, "note": note,
            "priced": prices.known(model)}
    on_event("done", done)
    return done
