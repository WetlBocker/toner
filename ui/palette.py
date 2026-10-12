"""Ctrl+K: type to jump to a section, tool, device, setting, check or action."""
from PySide6.QtCore import QEvent, Qt
from PySide6.QtWidgets import QApplication, QDialog, QLineEdit, QListWidget, QListWidgetItem, QVBoxLayout


class CommandPalette(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint)      # a popup: a click anywhere else, or Esc, closes it
        self.setMinimumWidth(560)
        self.entries = []                       # (label, hint, callable)
        self.box = QLineEdit()
        self.box.setPlaceholderText("Go to a section, tool, device or setting, or run an action...")
        self.list = QListWidget()
        self.list.setMinimumHeight(320)
        self.list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        lay = QVBoxLayout(self)
        lay.addWidget(self.box)
        lay.addWidget(self.list)
        self.box.textChanged.connect(self.filter)
        self.box.installEventFilter(self)
        self.list.itemActivated.connect(self.run_item)
        self.list.itemClicked.connect(self.run_item)

    def set_entries(self, entries):
        self.entries = entries

    def popup(self):
        self.box.clear()
        self.filter("")
        if self.parent():
            g = self.parent().geometry()
            self.move(g.center().x() - self.width() // 2, g.top() + 90)
        QApplication.instance().installEventFilter(self)        # to see a click anywhere else in Toner
        self.show()
        self.raise_()
        self.activateWindow()
        self.box.setFocus()

    def hideEvent(self, e):
        QApplication.instance().removeEventFilter(self)
        super().hideEvent(e)

    def filter(self, text):
        words = text.lower().split()
        self.list.clear()
        shown = 0
        for label, hint, fn in self.entries:
            hay = f"{label} {hint}".lower()
            if all(w in hay for w in words):
                it = QListWidgetItem(f"{label}    {hint}" if hint else label)
                it.setData(Qt.ItemDataRole.UserRole, fn)
                self.list.addItem(it)
                shown += 1
                if shown >= 60:
                    break
        if self.list.count():
            self.list.setCurrentRow(0)

    def run_item(self, item):
        fn = item.data(Qt.ItemDataRole.UserRole)
        self.hide()
        if fn:
            fn()

    def eventFilter(self, obj, ev):
        if self.isVisible() and ev.type() == QEvent.Type.MouseButtonPress and hasattr(ev, "globalPosition"):
            if not self.frameGeometry().contains(ev.globalPosition().toPoint()):      # a click outside the search closes it (the click still goes through)
                self.hide()
            return False
        if obj is self.box and ev.type() == QEvent.Type.KeyPress:
            k = ev.key()
            if k in (Qt.Key.Key_Down, Qt.Key.Key_Up):
                row = self.list.currentRow() + (1 if k == Qt.Key.Key_Down else -1)
                self.list.setCurrentRow(max(0, min(self.list.count() - 1, row)))
                return True
            if k in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                if self.list.currentItem():
                    self.run_item(self.list.currentItem())
                return True
            if k == Qt.Key.Key_Escape:
                self.hide()
                return True
        return super().eventFilter(obj, ev)
