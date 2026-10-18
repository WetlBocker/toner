"""Install...: a missing tool installed from Toner on Linux (core/installer.py). The person picks apt, pip or npm (only those on
this computer are offered); the install's output shows as it runs."""
from PySide6.QtCore import QProcess, Qt
from PySide6.QtWidgets import (QApplication, QButtonGroup, QDialog, QDialogButtonBox, QLabel, QPlainTextEdit, QPushButton,
                               QRadioButton, QVBoxLayout)

from core import audit, installer

NO_PASSWORD_WINDOW = "Toner can't ask for the administrator password here. Copy the command and run it in a terminal."


def offered(tool):
    """True when Install... should be shown for this tool here (Linux, and some installer for it is on this computer)."""
    return bool(installer.methods(tool))


def button(tool, parent=None, done=None):
    """An Install... button for a missing tool; `done()` is called after a successful install."""
    b = QPushButton("Install...")
    b.setVisible(offered(tool))
    b.clicked.connect(lambda: install(tool, parent or b.window(), done))
    return b


def install(tool, parent=None, done=None):
    dlg = InstallDialog(tool, parent)
    dlg.exec()
    if dlg.ok and done:
        done()
    return dlg.ok


class InstallDialog(QDialog):
    def __init__(self, tool, parent=None):
        super().__init__(parent)
        self.tool, self.ok, self.proc = tool, False, None
        label = installer.TOOLS[tool]["label"]
        self.label = label
        self.setWindowTitle(f"Install {label}")
        self.setMinimumWidth(520)
        self.methods = installer.methods(tool)
        self.choice = QButtonGroup(self)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"Toner can install {label} for you. Choose how:"))
        for i, m in enumerate(self.methods):
            r = QRadioButton(m.text)
            self.choice.addButton(r, i)
            lay.addWidget(r)
            if i == 0:
                r.setChecked(True)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMinimumHeight(140)
        self.output.hide()
        self.result = QLabel("")
        self.result.setWordWrap(True)
        lay.addWidget(self.output)
        lay.addWidget(self.result)
        self.buttons = QDialogButtonBox()
        self.go = self.buttons.addButton("Install", QDialogButtonBox.ButtonRole.ActionRole)
        self.go.setProperty("primary", True)
        self.copy = self.buttons.addButton("Copy command", QDialogButtonBox.ButtonRole.ActionRole)
        self.cancel = self.buttons.addButton("Cancel", QDialogButtonBox.ButtonRole.ActionRole)   # (one role: they stay in this order)
        self.go.clicked.connect(self.start)
        self.copy.clicked.connect(self.copy_command)
        self.cancel.clicked.connect(self.reject)
        lay.addWidget(self.buttons)
        self.choice.idToggled.connect(lambda *_: self._check_root())
        self._check_root()

    def method(self):
        return self.methods[self.choice.checkedId()] if self.methods else None

    def _check_root(self):
        m = self.method()
        blocked = bool(m and m.root and not installer.can_elevate())
        self.go.setEnabled(bool(m) and not blocked and self.proc is None)
        self.result.setText(NO_PASSWORD_WINDOW if blocked else "")

    def copy_command(self):
        m = self.method()
        if m:
            QApplication.clipboard().setText(m.shown)

    def start(self):
        m = self.method()
        if not m or self.proc is not None:
            return
        argv = installer.command(m)
        self.output.show()
        self.output.appendPlainText("$ " + m.shown)
        self.go.setEnabled(False)
        for b in self.choice.buttons():
            b.setEnabled(False)
        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.proc.readyReadStandardOutput.connect(self._read)
        self.proc.finished.connect(self._finished)
        self.proc.errorOccurred.connect(lambda _e: self._finished(-1, None))
        self.proc.start(argv[0], argv[1:])

    def _read(self):
        text = bytes(self.proc.readAllStandardOutput()).decode("utf-8", "replace")
        for line in text.splitlines():
            if line.strip():
                self.output.appendPlainText(line)

    def _finished(self, code, _status):
        if self.proc is None:
            return
        log = self.output.toPlainText()
        self.proc = None
        if code == 0 and installer.installed(self.tool):
            self.ok = True
            self.result.setText(f"{self.label} is installed.")
            audit.log("tool installed", f"{self.label} ({self.method().shown})")
            self.cancel.setText("Close")
            return
        if installer.needs_terminal(log):
            self.result.setText(NO_PASSWORD_WINDOW)
        else:
            last = next((l for l in reversed(log.splitlines()) if l.strip() and not l.startswith("$ ")), "it stopped")
            self.result.setText(f"The install didn't finish: {last}")
        for b in self.choice.buttons():
            b.setEnabled(True)
        self._check_root()

    def reject(self):
        if self.proc is not None:
            self.proc.kill()
            self.proc.waitForFinished(2000)
            self.proc = None
        super().reject()
