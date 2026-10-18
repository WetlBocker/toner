"""Starting Toner when you sign in, on Linux: a desktop entry in ~/.config/autostart (the freedesktop autostart standard, which
GNOME, KDE, Xfce and the others follow). On Windows the installer does this with a Startup shortcut, so nothing here runs there.

Toner starts with --minimized, so it waits in the tray when background running is on (as the Windows shortcut does)."""
import os
import shlex
import sys
from pathlib import Path

FILE = "toner.desktop"


def folder():
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "autostart"


def path():
    return folder() / FILE


def command():
    """How to start this copy of Toner: the AppImage it runs from, the frozen program, or Python with app.py."""
    if os.environ.get("APPIMAGE"):
        argv = [os.environ["APPIMAGE"]]
    elif getattr(sys, "frozen", False):
        argv = [sys.executable]
    else:
        argv = [sys.executable, str(Path(__file__).resolve().parent.parent / "app.py")]
    return " ".join(shlex.quote(a) for a in argv) + " --minimized"


def enabled():
    return path().is_file()


def set_enabled(on):
    """Add or remove the autostart entry. Raises OSError when the folder can't be written."""
    if not on:
        try:
            path().unlink()
        except FileNotFoundError:
            pass
        return
    folder().mkdir(parents=True, exist_ok=True)
    path().write_text("[Desktop Entry]\nType=Application\nName=Toner\n"
                      "Comment=Check, document and troubleshoot a multi-vendor network from one window.\n"
                      f"Exec={command()}\nIcon=toner\nTerminal=false\nX-GNOME-Autostart-enabled=true\n", encoding="utf-8")
