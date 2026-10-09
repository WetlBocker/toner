"""Runs notification work off the GUI thread, so a slow mail server never freezes the window."""
import threading

from PySide6.QtCore import QObject, Signal

from core import alerts, notify


class Notifier(QObject):
    desktop = Signal(str, str)           # title, body -> shown by the tray icon in the GUI thread

    def __init__(self, tray_available=True):
        super().__init__()
        self.tray_available = tray_available
        self.last = ""                   # outcome of the most recent run, for diagnostics

    def handle_run(self, results, ran, scheduled):
        threading.Thread(target=self._work, args=(list(results), list(ran), scheduled), daemon=True).start()

    def _work(self, results, ran, scheduled):
        try:
            self.last = notify.process_run(results, ran, scheduled,
                                           desktop=self.desktop.emit if self.tray_available else None)
        except Exception as e:           # never let a notification problem touch the health checks
            self.last = f"error: {e}"
            try:
                alerts.log_delivery("(notifier)", False, 0, f"{type(e).__name__}: {e}")
            except Exception:
                pass
