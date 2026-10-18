"""What differs between Windows, Linux and macOS, in one place.

Toner was written for Windows; on Linux and macOS the same code runs, and the few things that really differ (program names,
hidden console windows, where data lives, locking a file) are asked here instead of being decided in each module."""
import os
import subprocess
import sys
from pathlib import Path

WINDOWS = sys.platform == "win32"
MAC = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")
NAME = "Windows" if WINDOWS else "macOS" if MAC else "Linux"

# Started from Toner's window, a console program must not flash a black window on Windows; elsewhere there is none to hide.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def exe(name):
    """A program's file name here: 'nmap' -> 'nmap.exe' on Windows, 'nmap' elsewhere."""
    return name if not WINDOWS or name.lower().endswith(".exe") else name + ".exe"


def user_data_root():
    """Where programs keep their own data for this user: %APPDATA% on Windows, ~/Library/Application Support on macOS,
    $XDG_DATA_HOME (normally ~/.local/share) on Linux. An APPDATA set by hand (the tests do) wins everywhere."""
    if os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"])
    if MAC:
        return Path.home() / "Library" / "Application Support"
    if not WINDOWS:
        return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return Path.home()


class FileLock:
    """One process at a time (Toner's window and its scheduled service both write the vault): a lock on a file, held for the
    `with` block. Waits up to about 5 s, then goes ahead rather than hang."""

    def __init__(self, path):
        self.path = Path(path)

    def __enter__(self):
        import time
        self.f = open(self.path, "a+b")
        for _ in range(50):
            try:
                if WINDOWS:
                    import msvcrt
                    self.f.seek(0)
                    msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.locked = True
                return self
            except OSError:
                time.sleep(0.1)
        self.locked = False
        return self

    def __exit__(self, *exc):
        try:
            if self.locked:
                if WINDOWS:
                    import msvcrt
                    self.f.seek(0)
                    msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        self.f.close()
