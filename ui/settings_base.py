"""What every Settings page shares: the page base class and a few small helpers."""

from PySide6.QtWidgets import QDoubleSpinBox, QFormLayout, QHBoxLayout, QLabel, QSpinBox, QVBoxLayout, QWidget


class TrimSpin(QDoubleSpinBox):
    """A decimal box that shows 70 for 70.0 and 0.5 for 0.5 (it still accepts decimals)."""

    def __init__(self, decimals=2):
        super().__init__()
        self.setDecimals(decimals)

    def textFromValue(self, value):
        text = f"{value:.{self.decimals()}f}"
        return text.rstrip("0").rstrip(".") if "." in text else text



def spin(lo, hi, suffix=""):
    s = QSpinBox()
    s.setRange(lo, hi)
    if suffix:
        s.setSuffix(suffix)
    return s



def note(text):
    lab = QLabel(text)
    lab.setWordWrap(True)
    lab.setProperty("muted", True)
    return lab



def row_of(*widgets):
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    for x in widgets:
        h.addWidget(x)
    return w



class Page(QWidget):
    title = ""

    def __init__(self):
        super().__init__()
        self.form = QFormLayout()
        self.lay = QVBoxLayout(self)
        self.lay.addLayout(self.form)
        self.lay.addStretch()

    def load(self):
        """Show the stored values."""

    def validate(self):
        """Return a list of problems that stop a save."""
        return []

    def save(self):
        """Write the shown values."""

    def refresh(self):
        """Inventory or data changed elsewhere; update lists that depend on it."""
