"""Get an API key or token from the device itself with an administrator's sign-in, instead of making it in a browser (Palo Alto, Proxmox)."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QApplication, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit, QVBoxLayout)

from core import panos, pvekey


def _palo(dev, user, password):
    return panos.keygen(dev, user, password), ""


KEYS = {
    "paloalto": dict(button="Get API key from the firewall...", title="Get an API key from the firewall", what="the firewall", secret="API key", user_hint="admin",
                     intro="The user name and password are sent once, over HTTPS, and are not kept: only the key is, in the API key box, and it is saved "
                           "with the device. The administrator needs permission to use the XML API (Device > Admin Roles).",
                     fetch=_palo),
    "proxmox": dict(button="Get API token from Proxmox...", title="Get an API token from Proxmox", what="Proxmox", secret="API token", user_hint="root@pam",
                    intro="The user name (with its realm) and password are sent once, over HTTPS, and are not kept. Toner makes a token called 'toner' and "
                          "gives it the read-only PVEAuditor role, so it can read what Toner checks and change nothing. The token goes in the API token "
                          "box and is saved with the device. An account with two-factor sign-in cannot be used.",
                    fetch=pvekey.create_token),
}


class KeyDialog(QDialog):
    def __init__(self, dev, kind="paloalto", parent=None):
        super().__init__(parent)
        self.dev, self.spec = dev, KEYS[kind]
        self.key = self.note = ""
        self.setWindowTitle(self.spec["title"])
        self.setMinimumWidth(480)
        self.user, self.password = QLineEdit(), QLineEdit()
        self.user.setPlaceholderText(self.spec["user_hint"])
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color: #d32f2f;")
        intro = QLabel(f"Toner asks {self.spec['what']} at <b>{dev.get('host', '')}</b> for a key with an administrator's sign-in. " + self.spec["intro"])
        intro.setWordWrap(True)
        form = QFormLayout()
        form.addRow("User name", self.user)
        form.addRow("Password", self.password)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Get key")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(intro)
        lay.addLayout(form)
        lay.addWidget(self.status)
        lay.addWidget(self.buttons)

    def accept(self):
        self.status.setText("")
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self.key, self.note = self.spec["fetch"](self.dev, self.user.text(), self.password.text())
        except ValueError as e:
            self.status.setText(str(e))
            return                                   # stay open: a wrong password can be typed again
        except Exception as e:
            self.status.setText(f"Could not get a key: {e}")
            return
        finally:
            QApplication.restoreOverrideCursor()
        self.password.clear()
        super().accept()
