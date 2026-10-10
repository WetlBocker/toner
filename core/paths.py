"""Where Toner keeps its data.

Normally in %APPDATA%\\NetCheck. A portable copy has a file named portable.flag next to the program, and then everything
(database, settings, logs, session logs, saved host keys, downloaded updates) lives in a `data` folder beside it, so the whole
folder can be copied to a USB drive or another computer. If that folder cannot be written to (Program Files, a read-only
drive) Toner falls back to %APPDATA% rather than failing to start.

Passwords are the exception: they stay in Windows Credential Manager on whichever computer Toner runs on, so they do not
travel with a portable copy."""
import os
import sys
from pathlib import Path

FLAG = "portable.flag"


def frozen():
    return bool(getattr(sys, "frozen", False))


def app_dir():
    """The folder the program is in."""
    return os.path.dirname(sys.executable) if frozen() else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def is_portable():
    return os.path.exists(os.path.join(app_dir(), FLAG))


def _writable(folder):
    try:
        folder.mkdir(parents=True, exist_ok=True)
        probe = folder / ".write-test"
        probe.write_text("x")
        probe.unlink()
        return True
    except OSError:
        return False


def data_dir():
    if is_portable():
        d = Path(app_dir()) / "data"
        if _writable(d):
            return d
    d = Path(os.environ.get("APPDATA", Path.home())) / "NetCheck"
    d.mkdir(parents=True, exist_ok=True)
    return d
