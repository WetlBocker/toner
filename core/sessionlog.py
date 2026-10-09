"""Audit logging for SSH console sessions: a timestamped transcript file plus an index row in the DB.

Only what the device sends is recorded. The device echoes the commands you type, but it does not echo
a password typed at a hidden prompt (e.g. 'enable'), so those never reach the log. The SSH login
password is never written anywhere.
"""
import codecs
import getpass
import os
import re
from datetime import datetime
from pathlib import Path

from core import db

_ESC = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[()][A-Z0-9]|\x1b[=>78MDEHc]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def log_dir() -> Path:
    p = db.db_path().parent / "ssh-logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def clean(text):
    """Make terminal output readable: drop escape codes, apply backspaces, drop bare carriage returns."""
    text = _ESC.sub("", text).replace("\r\n", "\n").replace("\r", "")
    while "\x08" in text:
        i = text.index("\x08")
        text = text[:max(i - 1, 0)] + text[i + 1:]
    return _CTRL.sub("", text)


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class SessionLog:
    """One session's log. Raises OSError from the constructor if logging is not possible."""

    def __init__(self, device, host, port, username):
        self.started = datetime.now()
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", device or host)[:60]
        base = f"{self.started:%Y-%m-%d_%H%M%S}_{safe}"
        folder = log_dir()
        for n in range(1, 1000):                    # never reuse a name: two sessions can start in one second
            self.path = folder / (f"{base}.log" if n == 1 else f"{base}_{n}.log")
            try:
                self.file = open(self.path, "x", encoding="utf-8", newline="\n")
                break
            except FileExistsError:
                continue
        else:
            raise OSError("could not find a free log file name")
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.pending, self.bytes, self.closed, self.failed = "", 0, False, False
        operator = getpass.getuser()
        self.file.write(
            "# Toner SSH session log\n"
            f"# Started:  {self.started:%Y-%m-%d %H:%M:%S}\n"
            f"# Device:   {device}\n# Host:     {host}:{port}\n# User:     {username}\n"
            f"# Operator: {operator}\n"
            "# Output only; hidden password prompts are not echoed by the device.\n#\n")
        self.file.flush()
        with db.connect() as c:
            self.id = c.execute(
                "INSERT INTO ssh_sessions(started_at, device, host, port, username, operator, log_path) "
                "VALUES(?,?,?,?,?,?,?)",
                (self.started.strftime("%Y-%m-%d %H:%M:%S"), device, host, port, username, operator,
                 str(self.path))).lastrowid

    def write(self, data: bytes) -> bool:
        """Append device output. Returns False if the log could not be written."""
        if self.closed:
            return True
        try:
            self.bytes += len(data)
            self.pending += clean(self.decoder.decode(data))
            *lines, self.pending = self.pending.split("\n")
            ts = datetime.now().strftime("%H:%M:%S")
            for line in lines:
                self.file.write(f"[{ts}] {line}\n")
            self.file.flush()
            return True
        except (OSError, ValueError):
            self.failed = True
            return False

    def close(self, reason):
        if self.closed:
            return
        try:
            if self.pending:
                self.file.write(f"[{datetime.now():%H:%M:%S}] {self.pending}\n")
            secs = int((datetime.now() - self.started).total_seconds())
            self.file.write(f"#\n# Ended:    {_now()}\n# Duration: {secs // 3600}h {secs % 3600 // 60}m {secs % 60}s\n"
                            f"# Result:   {reason}\n")
            self.file.close()
        except (OSError, ValueError):
            pass
        self.closed = True
        try:
            with db.connect() as c:
                c.execute("UPDATE ssh_sessions SET ended_at=?, reason=?, bytes=? WHERE id=?",
                          (_now(), reason, self.bytes, self.id))
        except Exception:
            pass


def list_sessions(limit=500):
    with db.connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM ssh_sessions ORDER BY id DESC LIMIT ?", (limit,))]


def delete_closed():
    """Delete every finished session log. A session still open is left alone. Returns how many."""
    with db.connect() as c:
        done = c.execute("SELECT id, log_path FROM ssh_sessions WHERE ended_at IS NOT NULL").fetchall()
        for r in done:
            try:
                os.remove(r["log_path"])
            except OSError:
                pass
            c.execute("DELETE FROM ssh_sessions WHERE id=?", (r["id"],))
    return len(done)


def purge(days):
    """Delete session logs (files and index rows) older than `days`."""
    cutoff_s = datetime.fromtimestamp(datetime.now().timestamp() - days * 86400).strftime("%Y-%m-%d %H:%M:%S")
    with db.connect() as c:
        old = c.execute("SELECT id, log_path FROM ssh_sessions WHERE started_at < ?", (cutoff_s,)).fetchall()
        for r in old:
            try:
                os.remove(r["log_path"])
            except OSError:
                pass
            c.execute("DELETE FROM ssh_sessions WHERE id=?", (r["id"],))
    return len(old)
