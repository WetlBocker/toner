"""Inventory > device > Windows > Get agent script: the PowerShell script that makes a Windows computer report to Toner."""
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QVBoxLayout)
from PySide6.QtGui import QFontDatabase
from core import agents, audit, db


class AgentScriptDialog(QDialog):
    def __init__(self, device, parent=None):
        super().__init__(parent)
        self.device = device
        self.setWindowTitle(f"Agent script for {device}")
        self.setMinimumWidth(560)
        self.host = QLineEdit(agents.address())
        self.host.setToolTip("How the Windows computer reaches this computer: a DNS name or IP address it can resolve.")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(int(db.get_setting("agent_port") or agents.DEFAULT_PORT))
        self.minutes = QSpinBox()
        self.minutes.setRange(1, 60)
        self.minutes.setValue(5)
        self.minutes.setSuffix(" minutes")
        self.rotate = QCheckBox("Make a new token (the agent already installed on this computer stops working)")
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setProperty("muted", True)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.preview.setMinimumHeight(180)
        self.preview.setPlaceholderText("The script appears here. The token in it is private: keep the file safe.")
        form = QFormLayout()
        form.addRow("Toner's address", self.host)
        form.addRow("Port", self.port)
        form.addRow("Report every", self.minutes)
        form.addRow("", self.rotate)
        intro = QLabel("The script sends one report about the Windows computer to Toner over HTTPS on a schedule. It only sends: it opens no port "
                       "and accepts no commands. It trusts only this copy of Toner (the certificate's fingerprint is inside it), and Toner "
                       "accepts only this computer's token. Copy it to the computer and run it as Administrator with -Install.")
        intro.setWordWrap(True)
        make, self.save_btn, self.copy_btn = QPushButton("Create script"), QPushButton("Save as..."), QPushButton("Copy")
        make.setProperty("primary", True)
        make.setAutoDefault(False)
        close = QPushButton("Close")
        buttons = QHBoxLayout()
        buttons.addWidget(make)
        buttons.addWidget(self.save_btn)
        buttons.addWidget(self.copy_btn)
        buttons.addStretch()
        buttons.addWidget(close)
        lay = QVBoxLayout(self)
        lay.addWidget(intro)
        lay.addLayout(form)
        lay.addWidget(self.status)
        lay.addWidget(self.preview, 1)
        lay.addLayout(buttons)
        make.clicked.connect(self.create)
        self.save_btn.clicked.connect(self.save)
        self.copy_btn.clicked.connect(self.copy)
        close.clicked.connect(self.accept)
        self.script = ""
        self.save_btn.setEnabled(False)
        self.copy_btn.setEnabled(False)
        self._status()

    def _status(self):
        s = agents.status()
        parts = [("Toner is listening on port %d." % s["port"]) if s["running"] else
                 "Toner is not listening yet: turn on Settings > Agents, or the agent will have nobody to report to."]
        if s["error"]:
            parts.append(s["error"])
        report, age = agents.latest(self.device)
        if report is not None:
            parts.append(f"This computer last reported {age:.0f} minute(s) ago.")
        self.status.setText(" ".join(parts))

    def create(self):
        host = self.host.text().strip()
        if not host:
            QMessageBox.warning(self, "Agent script", "Enter the address the Windows computer should use to reach Toner.")
            return
        if self.rotate.isChecked() and QMessageBox.question(
                self, "New token", "The agent already installed on this computer will be turned away until it is given the new script. Continue?"
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            self.script = agents.script_for(self.device, self.minutes.value(), host, self.port.value(), rotate=self.rotate.isChecked())
        except Exception as e:
            QMessageBox.warning(self, "Agent script", f"The script could not be made: {e}")
            return
        self.preview.setPlainText(self.script)
        self.save_btn.setEnabled(True)
        self.copy_btn.setEnabled(True)
        self.rotate.setChecked(False)
        audit.log("agent script created", self.device)

    def save(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save agent script", "toner-agent.ps1", "PowerShell script (*.ps1)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="\r\n") as f:          # a BOM so Windows PowerShell reads it as UTF-8
                f.write(self.script)

    def copy(self):
        QApplication.clipboard().setText(self.script)
