"""Where Toner keeps its data.

Normally in %APPDATA%\\NetCheck. A portable copy has a file named portable.flag next to the program, and then everything
(database, settings, logs, session logs, saved host keys, downloaded updates) lives in a `data` folder beside it, so the whole
folder can be copied to a USB drive or another computer. If that folder cannot be written to (Program Files, a read-only
drive) Toner falls back to %APPDATA% rather than failing to start.

Passwords travel too: they are in Toner's vault (netcheck.vault, beside the database), opened with the master password. Only
"Remember on this computer" stays behind, since Windows protects it for one user on one computer."""
import os
import sys
import threading
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
        probe = folder / f".write-test-{os.getpid()}-{threading.get_ident()}"   # one per thread: checks running side
        probe.write_text("x")                                                    # by side must not trip over each other
        probe.unlink()
        return True
    except OSError:
        return False


# Portable data folders found writable. Every database connection asks for data_dir(), and checks run many at once; testing
# the folder each time could fail now and then (OneDrive or a virus scanner holding the test file) and send that one
# connection to an empty database in %APPDATA% ("no such table: devices"). Once writable, the folder stays the answer.
_confirmed = set()


def data_dir():
    if is_portable():
        d = Path(app_dir()) / "data"
        if d in _confirmed or _writable(d):
            _confirmed.add(d)
            return d
    from core.platforms import user_data_root
    d = user_data_root() / "NetCheck"          # %APPDATA%, ~/.local/share or ~/Library/Application Support
    d.mkdir(parents=True, exist_ok=True)
    return d
