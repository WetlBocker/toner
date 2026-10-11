"""A plain record of what was changed and by whom, kept in the database."""
import getpass
from datetime import datetime, timedelta

from core import db
from core import quiet


def actor():
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def log(action, detail="", who=None):
    """Record one event. Never raises: an audit failure must not stop the thing being audited."""
    try:
        with db.connect() as c:
            c.execute("INSERT INTO audit(at, actor, action, detail) VALUES(?,?,?,?)",
                      (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), who or actor(), action, str(detail)[:2000]))
    except Exception:
        quiet.ignored()


def recent(limit=500, text=""):
    q, args = "SELECT * FROM audit", []
    if text:
        q += " WHERE action LIKE ? OR detail LIKE ? OR actor LIKE ?"
        args = [f"%{text}%"] * 3
    q += " ORDER BY id DESC LIMIT ?"
    with db.connect() as c:
        return [dict(r) for r in c.execute(q, args + [limit])]


def purge(days):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with db.connect() as c:
        c.execute("DELETE FROM audit WHERE at < ?", (cutoff,))
