"""A short confirmation that fades by itself ("Saved", "Changed 3 devices"), for results that need no click to acknowledge.
Anything the person must read carefully (where a secret was written, a list of what an import skipped) stays a message box."""
from PySide6.QtCore import QPropertyAnimation, QTimer, Qt
from PySide6.QtWidgets import QGraphicsOpacityEffect, QLabel

SHOWN_MS = 4000
history = []                                  # the last few texts shown, newest last (what the tests read)
FADE_MS = 400


class Toast(QLabel):
    def __init__(self, window):
        super().__init__(window)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)      # never in the way of what is underneath
        self.setWordWrap(True)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setObjectName("toast")
        self.effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.effect)
        self.fade = QPropertyAnimation(self.effect, b"opacity", self)
        self.fade.setDuration(FADE_MS)
        self.fade.finished.connect(self._faded)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self._start_fade)
        self.hide()

    def show_text(self, text, problem=False):
        # the reverse of the window's own colours, so it stands out in the light and the dark look alike
        bg, fg = ("#b3261e", "#ffffff") if problem else ("palette(window-text)", "palette(window)")
        self.setStyleSheet(f"#toast {{ background:{bg}; color:{fg}; border-radius:8px; padding:10px 16px; font-weight:600; }}")
        self.setText(text)
        self.fade.stop()
        self.effect.setOpacity(1.0)
        room = max(240, min(560, self.parentWidget().width() - 48))
        wide = self.fontMetrics().horizontalAdvance(text) + 44                   # one line if it fits, else wrapped at the room there is
        self.setFixedWidth(max(140, min(room, wide)))
        inner = self.width() - 32                                                  # minus the 16 px of padding either side
        self.setFixedHeight(self.fontMetrics().boundingRect(0, 0, inner, 10000, int(Qt.TextFlag.TextWordWrap), text).height() + 22)
        self.place()
        self.show()
        self.raise_()
        self.timer.start(SHOWN_MS)

    def place(self):
        p = self.parentWidget()
        self.move((p.width() - self.width()) // 2, p.height() - self.height() - 28)

    def _start_fade(self):
        self.fade.setStartValue(1.0)
        self.fade.setEndValue(0.0)
        self.fade.start()

    def _faded(self):
        if self.effect.opacity() == 0.0:
            self.hide()


def toast(widget, text, problem=False):
    """Show `text` at the bottom of the window that holds `widget` (one at a time: a new one replaces the last)."""
    win = widget.window() if widget is not None else None
    if win is None:
        return None
    t = win.findChild(Toast, "toast", Qt.FindChildOption.FindDirectChildrenOnly)
    if t is None:
        t = Toast(win)
    t.show_text(text, problem)
    history.append(text)
    del history[:-20]
    return t
