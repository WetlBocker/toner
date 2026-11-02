"""The one dialog that asks for a user name and a password for a single use and keeps neither: Remote Desktop through
FreeRDP on Linux (the password goes to FreeRDP on standard input), and signing in to manage a Windows computer's
services over WinRM when it reports by agent and so has no stored login."""
from PySide6.QtWidgets import QDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QVBoxLayout


class SignInDialog(QDialog):
    def __init__(self, title, intro, parent=None, username="", placeholder="", ok_text="Sign in", require_both=True, width=380):
        """`intro` may be rich text. `require_both`: refuse OK until both boxes are filled (otherwise a blank user name passes)."""
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(width)
        self.require_both = require_both
        self.user, self.password = QLineEdit(username), QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.user.setAccessibleName("User name")
        self.password.setAccessibleName("Password")
        if placeholder:
            self.user.setPlaceholderText(placeholder)
        text = QLabel(intro)
        text.setWordWrap(True)
        form = QFormLayout()
        form.addRow("User name", self.user)
        form.addRow("Password", self.password)
        ok, cancel = QPushButton(ok_text), QPushButton("Cancel")
        ok.setProperty("primary", True)
        ok.setDefault(True)
        ok.clicked.connect(self._accept)
        cancel.clicked.connect(self.reject)
        bar = QHBoxLayout()
        bar.addStretch()
        bar.addWidget(cancel)
        bar.addWidget(ok)
        lay = QVBoxLayout(self)
        lay.addWidget(text)
        lay.addLayout(form)
        lay.addLayout(bar)
        (self.password if username else self.user).setFocus()

    def _accept(self):
        if self.require_both and (not self.user.text().strip() or not self.password.text()):
            QMessageBox.warning(self, self.windowTitle(), "Enter the user name and the password.")
            return
        self.accept()

    def username(self):
        return self.user.text().strip()
