"""Conversations and what they cost, kept in each organization's database (Global has its own).

A conversation holds the provider's own message history (so a provider's thinking blocks and reasoning items go back exactly
as they came) and a transcript: the questions, the answers with their tokens and cost, and the tool steps in between.
Monthly totals are summed from the transcript, per organization and across every organization for the spend limit.
"""
import json
import zlib
from datetime import datetime

from core import db

TITLE_LENGTH = 80


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def month_key(when=None):
    """'2026-10' for this month (the totals are per calendar month, local time)."""
    return (when or datetime.now()).strftime("%Y-%m")


def title_of(question):
    """The conversation's title: the first question, on one line, cut short."""
    text = " ".join((question or "").split())
    return text if len(text) <= TITLE_LENGTH else text[:TITLE_LENGTH - 1].rstrip() + "…"


# ---------------------------------------------------------------- conversations
def create(provider, model, question=""):
    """A new conversation in the organization being written to. Returns its id."""
    now = _now()
    with db.connect() as c:
        return c.execute("INSERT INTO ai_conversations(provider, model, title, started, updated, history) VALUES(?,?,?,?,?,?)",
                         (provider, model, title_of(question), now, now, _pack([]))).lastrowid


def get(conv_id, org=None):
    with db.within(org):
        with db.connect() as c:
            row = c.execute("SELECT * FROM ai_conversations WHERE id=?", (conv_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["history"] = _unpack(d["history"])
    return d


def list_conversations(limit=200):
    """Newest first, without their histories, each with 'org'."""
    def here():
        with db.connect() as c:
            return [dict(r) for r in c.execute("SELECT id, provider, model, title, started, updated, turns, tokens_in, tokens_out, cost "
                                               "FROM ai_conversations ORDER BY id DESC LIMIT ?", (limit,))]
    rows = db.gather(here)
    if len({r["org"] for r in rows}) > 1:
        rows.sort(key=lambda r: (r["updated"], r["id"]), reverse=True)
    return rows[:limit]


def delete(conv_id, org=None):
    with db.within(org):
        with db.connect() as c:
            c.execute("DELETE FROM ai_turns WHERE conversation_id=?", (conv_id,))
            c.execute("DELETE FROM ai_conversations WHERE id=?", (conv_id,))


def set_history(conv_id, history):
    with db.connect() as c:
        c.execute("UPDATE ai_conversations SET history=?, updated=? WHERE id=?", (_pack(history), _now(), conv_id))


def set_title(conv_id, question):
    with db.connect() as c:
        c.execute("UPDATE ai_conversations SET title=? WHERE id=? AND title=''", (title_of(question), conv_id))


# ---------------------------------------------------------------- the transcript
def add_turn(conv_id, kind, text, model="", tokens_in=0, tokens_out=0, cost=0.0):
    """One line of the transcript: 'user', 'assistant' (with its tokens and cost), 'tool' (a step) or 'note' (a stop, an error)."""
    now = _now()
    with db.connect() as c:
        tid = c.execute("INSERT INTO ai_turns(conversation_id, at, kind, text, model, tokens_in, tokens_out, cost) VALUES(?,?,?,?,?,?,?,?)",
                        (conv_id, now, kind, text, model, int(tokens_in or 0), int(tokens_out or 0), float(cost or 0))).lastrowid
        if kind == "assistant":
            c.execute("UPDATE ai_conversations SET turns=turns+1, tokens_in=tokens_in+?, tokens_out=tokens_out+?, cost=cost+?, updated=? WHERE id=?",
                      (int(tokens_in or 0), int(tokens_out or 0), float(cost or 0), now, conv_id))
        else:
            c.execute("UPDATE ai_conversations SET updated=? WHERE id=?", (now, conv_id))
    return tid


def turns(conv_id, org=None):
    with db.within(org):
        with db.connect() as c:
            return [dict(r) for r in c.execute("SELECT * FROM ai_turns WHERE conversation_id=? ORDER BY id", (conv_id,))]


# ---------------------------------------------------------------- what it cost
def month_totals(month=None):
    """This month in the organization being written to: {'conversations', 'turns', 'tokens_in', 'tokens_out', 'tokens', 'cost'}."""
    month = month or month_key()
    with db.connect() as c:
        t = c.execute("SELECT COUNT(*) AS n, IFNULL(SUM(tokens_in),0) AS i, IFNULL(SUM(tokens_out),0) AS o, IFNULL(SUM(cost),0) AS cost "
                      "FROM ai_turns WHERE kind='assistant' AND at LIKE ?", (month + "%",)).fetchone()
        n = c.execute("SELECT COUNT(*) FROM ai_conversations WHERE started LIKE ?", (month + "%",)).fetchone()[0]
    return {"conversations": n, "turns": t["n"], "tokens_in": t["i"], "tokens_out": t["o"], "tokens": t["i"] + t["o"], "cost": float(t["cost"])}


def every_org_totals(month=None):
    """This month for Global and every organization (archived ones too: their spend counts): [(org id, name, totals)] by name,
    Global first."""
    out = []
    for org in [db.GLOBAL] + [r["id"] for r in db.org_rows()]:
        with db.within(org):
            out.append((org, db.org_name(org), month_totals(month)))
    return out


def all_totals(month=None):
    """This month across every organization: {'tokens', 'cost', 'conversations', 'turns'}."""
    rows = [t for _o, _n, t in every_org_totals(month)]
    return {"tokens": sum(t["tokens"] for t in rows), "tokens_in": sum(t["tokens_in"] for t in rows), "tokens_out": sum(t["tokens_out"] for t in rows),
            "cost": sum(t["cost"] for t in rows), "conversations": sum(t["conversations"] for t in rows), "turns": sum(t["turns"] for t in rows)}


def _pack(history):
    return zlib.compress(json.dumps(history, ensure_ascii=False).encode("utf-8"), 6)


def _unpack(blob):
    if not blob:
        return []
    try:
        return json.loads(zlib.decompress(blob).decode("utf-8"))
    except (zlib.error, ValueError):
        return []
