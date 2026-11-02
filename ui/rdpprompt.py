"""Starting Remote Desktop in the system's own client. On Linux, FreeRDP has no window to ask for the password in, so Toner asks
(user name and password) and hands the password to FreeRDP on standard input; it is never stored or put on a command line."""
from PySide6.QtWidgets import QMessageBox

from ui.signin import SignInDialog

from core import sessions


class SignIn(SignInDialog):
    def __init__(self, s, parent=None):
        super().__init__("Remote Desktop", f"Sign in to {s['host']}", parent, username=s.get("username") or "", ok_text="Connect", require_both=False)


def start(parent, s):
    """Start Remote Desktop for session `s`. Returns the .rdp file's path, None (FreeRDP) or False (cancelled or failed)."""
    password = None
    if sessions.rdp_client(s) == "freerdp" and not sessions.find_rdp_client(s) and _offer_install(
            parent, "Remote Desktop", "No Remote Desktop client was found. Install FreeRDP (for example: sudo apt install freerdp3-x11), "
            "then try again.", "freerdp") is False:
        return False
    if sessions.asks_for_password(s):
        dlg = SignIn(s, parent)
        if not dlg.exec():
            return False
        s = {**s, "username": dlg.user.text().strip()}
        password = dlg.password.text()
    try:
        return sessions.launch_rdp(s, password)
    except OSError as e:
        QMessageBox.warning(parent, "Remote Desktop", str(e))
        return False


def _offer_install(parent, title, text, tool):
    """'No client' with Install... beside OK when Toner can install it here. True when it was installed, else False."""
    from ui import installdlg
    if not installdlg.offered(tool):
        QMessageBox.warning(parent, title, text)
        return False
    box = QMessageBox(QMessageBox.Icon.Warning, title, text, parent=parent)
    inst = box.addButton("Install...", QMessageBox.ButtonRole.ActionRole)
    box.addButton(QMessageBox.StandardButton.Ok)
    box.exec()
    return bool(box.clickedButton() is inst and installdlg.install(tool, parent))


def start_vnc(parent, s):
    """Open a VNC session in the viewer (it asks for the password). True when it started."""
    from core.platforms import LINUX
    if LINUX and not sessions.find_vnc_viewer() and not _offer_install(
            parent, "VNC", "No VNC viewer was found. Install TigerVNC (for example: sudo apt install tigervnc-viewer), then try again.", "vnc"):
        return False
    try:
        sessions.launch_vnc(s)
        return True
    except OSError as e:
        QMessageBox.warning(parent, "VNC", str(e))
        return False
