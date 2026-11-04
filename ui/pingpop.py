"""A quick ping: right-click a device anywhere > Ping opens a small window that sends five echoes and shows each reply as it
comes, with the count and the times at the end. Ping Again sends five more; OK closes it. Uses the system's ping (core.pinger),
so no admin rights are needed."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout

from core import pinger                        # the worker pings through this module; tests patch pinger.ping_once here
from ui.pingworker import PingWorker

COUNT = 5
TIMEOUT_MS = 1000


def line(i, ms, host):
    """One echo's line: 'Reply from 10.0.0.15: 3 ms' or 'No reply from 10.0.0.15 (waited 1 s)'."""
    if ms is None:
        return f"{i}. No reply from {host} (waited {TIMEOUT_MS // 1000} s)"
    return f"{i}. Reply from {host}: {ms:g} ms" if ms >= 1 else f"{i}. Reply from {host}: under 1 ms"


def summary(times):
    """'5 sent, 5 answered, 2 to 4 ms' / '5 sent, 3 answered, 2 lost, 2 to 4 ms' / '5 sent, none answered'."""
    got = [t for t in times if t is not None]
    lost = len(times) - len(got)
    if not got:
        return f"{len(times)} sent, none answered"
    span = f"{min(got):g} ms" if min(got) == max(got) else f"{min(got):g} to {max(got):g} ms"
    return f"{len(times)} sent, {len(got)} answered" + (f", {lost} lost" if lost else "") + f", {span}"


class PingPopup(QDialog):
    def __init__(self, name, host, parent=None):
        super().__init__(parent)
        self.name, self.host = name, host
        self.setWindowTitle(f"Ping {name}" if name and name != host else f"Ping {host}")
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.resize(420, 260)
        self.worker = None
        self.times = []
        self.head = QLabel(f"<b>{name}</b> ({host})" if name and name != host else f"<b>{host}</b>")
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.result = QLabel("")
        self.result.setProperty("muted", True)
        self.again = QPushButton("Ping Again")
        self.again.clicked.connect(self.start)
        self.ok = QPushButton("OK")
        self.ok.setProperty("primary", True)
        self.ok.setDefault(True)
        self.ok.clicked.connect(self.accept)
        row = QHBoxLayout()
        row.addWidget(self.result, 1)
        row.addWidget(self.again)
        row.addWidget(self.ok)
        lay = QVBoxLayout(self)
        lay.addWidget(self.head)
        lay.addWidget(self.text, 1)
        lay.addLayout(row)
        self.start()

    def start(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.times = []
        self.text.clear()
        self.result.setText(f"Pinging {self.host}…")
        self.again.setEnabled(False)
        self.worker = PingWorker(self.host, count=COUNT, interval=0, timeout_ms=TIMEOUT_MS)
        self.worker.sample.connect(self._reply)
        self.worker.finished.connect(self._done)
        self.worker.start()

    def _reply(self, i, ms):
        self.times.append(ms)
        self.text.appendPlainText(line(i, ms, self.host))

    def _done(self):
        self.result.setText(summary(self.times) if self.times else "")
        self.again.setEnabled(True)

    def closeEvent(self, e):
        if self.worker is not None and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(3000)
        super().closeEvent(e)


def ping_popup(parent, name, host):
    """Open the quick-ping window for a device (it stays open beside the page; several can be open at once)."""
    dlg = PingPopup(name, host, parent)
    dlg.setModal(False)
    dlg.show()
    return dlg
