"""Asking for a proxy's one-time code. A connection is made on a worker thread, and a window can only be shown by the
main thread, so a worker hands the question over and waits for the answer."""
import threading

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import QApplication, QInputDialog, QLineEdit

from core import proxy

WAIT_SECONDS = 180


def _dialog(title, text):
    dlg = QInputDialog(QApplication.activeWindow())
    dlg.setWindowTitle(title)
    dlg.setLabelText(text + "\nType the current code from your authenticator app.")
    dlg.setTextEchoMode(QLineEdit.EchoMode.Normal)
    dlg.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)       # it may have been asked while Toner sits in the tray
    return dlg.textValue() if dlg.exec() else ""


class _Asker(QObject):
    wanted = Signal(object)

    def __init__(self):
        super().__init__()
        self.wanted.connect(self._show)

    def _show(self, job):
        try:
            job["code"] = _dialog(job["title"], job["text"])
        finally:
            job["done"].set()


_asker = None


def ask(title, text):
    app = QApplication.instance()
    if app is None:
        return ""
    if QThread.currentThread() == app.thread():                       # a Test button: already on the main thread
        return _dialog(title, text)
    job = {"title": title, "text": text, "code": "", "done": threading.Event()}
    _asker.wanted.emit(job)
    job["done"].wait(WAIT_SECONDS)
    return job["code"]


def install():
    """Call once, on the main thread, after the QApplication exists."""
    global _asker
    if _asker is None:
        _asker = _Asker()
    proxy.set_code_prompt(ask)
