"""What every Settings page shares: the page base class and a few small helpers."""

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import QDoubleSpinBox, QFormLayout, QHBoxLayout, QLabel, QMenu, QSpinBox, QToolButton, QVBoxLayout, QWidget

CHOICE_ARROW = 24                     # the drop-down arrow of a number box with common values, as wide as a drop-down's (ui/theme.py)


class TrimSpin(QDoubleSpinBox):
    """A decimal box that shows 70 for 70.0 and 0.5 for 0.5 (it still accepts decimals)."""

    def __init__(self, decimals=2):
        super().__init__()
        self.setDecimals(decimals)

    def textFromValue(self, value):
        text = f"{value:.{self.decimals()}f}"
        return text.rstrip("0").rstrip(".") if "." in text else text



class Choices(QObject):
    """Common values for a number box (offer): its two small arrows become one drop-down arrow that lists them, in the box's own
    words ("30 days"). Any other number can still be typed, and the arrow keys still step."""

    def __init__(self, box, values, text=None):
        super().__init__(box)
        self.words = text                                     # for a box whose own words change with its number ("1 minute", "5 minutes")
        self.box, self.values = box, [v for v in values if box.minimum() <= v <= box.maximum()]
        box.setProperty("choices", True)                      # the theme draws the one arrow
        box.installEventFilter(self)

    def text(self, value):
        b = self.box
        if self.words:
            return self.words(value)
        if value == b.minimum() and b.specialValueText():
            return b.specialValueText()
        return b.prefix() + b.textFromValue(value) + b.suffix()

    def menu(self):
        m = QMenu(self.box)
        for v in self.values:
            m.addAction(self.text(v), lambda v=v: self.box.setValue(v))
        m.setMinimumWidth(self.box.width())
        return m

    def open(self):
        self.menu().exec(self.box.mapToGlobal(self.box.rect().bottomLeft()))

    def eventFilter(self, obj, e):
        kind = e.type()
        on_arrow = kind in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonDblClick) and e.position().x() >= obj.width() - CHOICE_ARROW
        by_key = kind == QEvent.Type.KeyPress and (e.key() == Qt.Key.Key_F4 or (e.key() == Qt.Key.Key_Down and e.modifiers() & Qt.KeyboardModifier.AltModifier))
        if on_arrow or by_key:                                # (F4 and Alt+Down: as on a drop-down)
            self.open()
            return True
        return False


def offer(box, values, text=None):
    """Give a number box a list of common values to pick from. Returns the box."""
    Choices(box, values, text)
    return box


def choices_menu(box):
    """The list a box made with offer() opens."""
    return box.findChild(Choices).menu()


def spin(lo, hi, suffix="", choices=()):
    s = QSpinBox()
    s.setRange(lo, hi)
    if suffix:
        s.setSuffix(suffix)
    return offer(s, choices) if choices else s



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



def compact_row(*widgets):
    """Widgets side by side at their own size, left aligned, with the spare room at the end (not spread between them)."""
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    for x in widgets:
        h.addWidget(x)
    h.addStretch(1)
    return w


def tidy(page, combo_min=360):
    """Stop buttons and boxes from stretching across a wide window: a drop-down, a number box or a button is only as wide as what it says.
    Text boxes and tables are left alone, so they still take the room."""
    from PySide6.QtWidgets import QComboBox, QDoubleSpinBox, QPushButton, QToolButton
    for w in page.findChildren(QComboBox):
        w.setMaximumWidth(max(combo_min, w.sizeHint().width() + 40))
    for w in page.findChildren(QSpinBox) + page.findChildren(QDoubleSpinBox):
        w.setMaximumWidth(max(180, w.sizeHint().width() + 30))
    for w in page.findChildren(QPushButton) + page.findChildren(QToolButton):
        if hasattr(w, "set_labels"):                      # a group picker: its text changes with what is ticked
            continue
        if w.maximumWidth() >= 16777215 and w.text():
            w.setMaximumWidth(w.sizeHint().width() + 60)


class Collapsible(QWidget):
    """A heading with an arrow that shows or hides what is under it, for the details most people never need to change."""

    def __init__(self, title, content, opened=False):
        super().__init__()
        self.toggle = QToolButton()
        self.toggle.setText(title)
        self.toggle.setCheckable(True)
        self.toggle.setProperty("notSetting", True)                    # opening a section is not a change to the settings
        self.toggle.setChecked(opened)
        self.toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.toggle.setStyleSheet("QToolButton { border: none; font-weight: 600; padding: 4px 2px; }")
        self.toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.content = content
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.toggle, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(content)
        self.toggle.toggled.connect(self._show)
        self._show(opened)

    def _show(self, on):
        self.toggle.setArrowType(Qt.ArrowType.DownArrow if on else Qt.ArrowType.RightArrow)
        self.content.setVisible(on)

    def open(self):
        self.toggle.setChecked(True)


class Page(QWidget):
    title = ""
    track = True                                  # False: the boxes on this page are not settings, so Save and the unsaved marks ignore them

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
