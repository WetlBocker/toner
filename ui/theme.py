"""Application look: colour tokens -> palette + one stylesheet. Light, dark, or follow Windows."""
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication
from ui import icons

THEMES = ["System", "Light", "Dark"]
ACCENTS = {                      # name -> (light-mode accent, dark-mode accent)
    "Blue": ("#2563eb", "#5b9dff"), "Teal": ("#0d9488", "#2dd4bf"), "Violet": ("#7c3aed", "#a78bfa"),
    "Green": ("#16a34a", "#4ade80"), "Orange": ("#ea580c", "#fb923c"), "Rose": ("#e11d48", "#fb7185"),
}
DEFAULT_ACCENT = "Blue"
BASE_POINT_SIZE = 10             # the text size when Settings says "default"
_current = {}


def is_dark(app, theme):
    if theme == "Dark":
        return True
    if theme == "Light":
        return False
    try:
        return app.styleHints().colorScheme() == Qt.ColorScheme.Dark
    except Exception:
        return False


def tokens(dark, accent=DEFAULT_ACCENT):
    light_acc, dark_acc = ACCENTS.get(accent, ACCENTS[DEFAULT_ACCENT])
    a = QColor(dark_acc if dark else light_acc)
    soft = QColor(a)
    soft.setAlpha(46 if dark else 30)
    t = dict(
        bg="#14161a" if dark else "#f4f5f7", surface="#1c1f25" if dark else "#ffffff",
        surface2="#23272f" if dark else "#f1f3f6", border="#2c313a" if dark else "#e1e4e9",
        text="#e8eaed" if dark else "#1d2127", muted="#9aa2ae" if dark else "#68707c",
        hover="#272b34" if dark else "#eceff3", accent=a.name(),
        accent_hover=a.lighter(112).name() if dark else a.darker(110).name(),
        accent_text="#0b0d10" if dark and a.lightness() > 150 else "#ffffff",
        accent_soft=f"rgba({a.red()},{a.green()},{a.blue()},{soft.alpha()})",
        input="#171a1f" if dark else "#ffffff", scroll="#3a404b" if dark else "#c7ccd4",
    )
    t["chev_down"] = icons.png_path("chev-down", t["muted"])
    t["check"] = icons.png_path("check", t["accent_text"])
    t["chev_up"] = icons.png_path("chev-up", t["muted"])
    return t


def palette(t):
    p = QPalette()
    c = QColor
    roles = {
        QPalette.ColorRole.Window: c(t["bg"]), QPalette.ColorRole.WindowText: c(t["text"]),
        QPalette.ColorRole.Base: c(t["surface"]), QPalette.ColorRole.AlternateBase: c(t["surface2"]),
        QPalette.ColorRole.Text: c(t["text"]), QPalette.ColorRole.Button: c(t["surface"]),
        QPalette.ColorRole.ButtonText: c(t["text"]), QPalette.ColorRole.BrightText: c("#ff5555"),
        QPalette.ColorRole.Highlight: c(t["accent"]), QPalette.ColorRole.HighlightedText: c(t["accent_text"]),
        QPalette.ColorRole.ToolTipBase: c(t["surface2"]), QPalette.ColorRole.ToolTipText: c(t["text"]),
        QPalette.ColorRole.PlaceholderText: c(t["muted"]), QPalette.ColorRole.Link: c(t["accent"]),
        QPalette.ColorRole.Mid: c(t["border"]), QPalette.ColorRole.Midlight: c(t["hover"]),
        QPalette.ColorRole.Dark: c(t["border"]), QPalette.ColorRole.Light: c(t["surface"]),
    }
    for role, col in roles.items():
        p.setColor(role, col)
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText, QPalette.ColorRole.WindowText):
        p.setColor(QPalette.ColorGroup.Disabled, role, c(t["muted"]))
    return p


def stylesheet(t):
    return """
* { outline: 0; }
QToolTip { background: %(surface2)s; color: %(text)s; border: 1px solid %(border)s; padding: 5px 8px; }

/* ---- buttons ---- */
QPushButton, QToolButton {
    background: %(surface)s; color: %(text)s; border: 1px solid %(border)s; border-radius: 8px;
    padding: 6px 14px; min-height: 20px;
}
QPushButton:hover, QToolButton:hover { background: %(hover)s; }
QPushButton:pressed, QToolButton:pressed { background: %(surface2)s; }
QPushButton:disabled, QToolButton:disabled { color: %(muted)s; background: %(bg)s; }
QPushButton:focus { border-color: %(accent)s; }
QPushButton[primary="true"], QPushButton:default {
    background: %(accent)s; color: %(accent_text)s; border: 1px solid %(accent)s; font-weight: 600;
}
QPushButton[primary="true"]:hover, QPushButton:default:hover { background: %(accent_hover)s; border-color: %(accent_hover)s; }
QPushButton[primary="true"]:disabled { background: %(surface2)s; color: %(muted)s; border-color: %(border)s; }
QPushButton[flat="true"], QPushButton[ghost="true"] { background: transparent; border-color: transparent; color: %(muted)s; }
QPushButton[ghost="true"]:hover { background: %(hover)s; color: %(text)s; }
QToolButton[popupMode="2"] { padding-right: 26px; }
QToolButton::menu-indicator { image: url(%(chev_down)s); subcontrol-origin: padding; subcontrol-position: center right; right: 8px; width: 12px; height: 12px; }

/* ---- inputs ---- */
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox, QAbstractSpinBox {
    background: %(input)s; color: %(text)s; border: 1px solid %(border)s; border-radius: 8px;
    padding: 5px 9px; min-height: 20px; selection-background-color: %(accent)s; selection-color: %(accent_text)s;
}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
    border: 1px solid %(accent)s;
}
QLineEdit:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled, QComboBox:disabled { color: %(muted)s; background: %(bg)s; }
QComboBox { padding-right: 26px; }
QComboBox::drop-down { border: 0; width: 26px; subcontrol-origin: padding; subcontrol-position: center right; }
QComboBox::down-arrow { image: url(%(chev_down)s); width: 12px; height: 12px; }
QComboBox QAbstractItemView {
    background: %(surface)s; border: 1px solid %(border)s; border-radius: 8px; padding: 4px;
    selection-background-color: %(accent_soft)s; selection-color: %(text)s; outline: 0;
}
QSpinBox, QDoubleSpinBox { padding-right: 24px; min-width: 70px; max-width: 170px; }
QSpinBox::up-button, QDoubleSpinBox::up-button { subcontrol-origin: border; subcontrol-position: top right; width: 22px; border: 0; background: transparent; margin-top: 2px; }
QSpinBox::down-button, QDoubleSpinBox::down-button { subcontrol-origin: border; subcontrol-position: bottom right; width: 22px; border: 0; background: transparent; margin-bottom: 2px; }
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow { image: url(%(chev_up)s); width: 10px; height: 10px; }
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow { image: url(%(chev_down)s); width: 10px; height: 10px; }
QSpinBox::up-button:hover, QSpinBox::down-button:hover, QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover { background: %(hover)s; border-radius: 5px; }
QPlainTextEdit, QTextEdit { padding: 8px; }

/* ---- check boxes ---- */
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1.5px solid %(muted)s; border-radius: 5px; background: %(input)s; }
QCheckBox::indicator:hover { border-color: %(accent)s; }
QCheckBox::indicator:checked { background: %(accent)s; border-color: %(accent)s; image: url(%(check)s); }
QCheckBox::indicator:disabled { border-color: %(border)s; background: %(bg)s; }

/* ---- lists, tables, trees ---- */
QTreeView, QTableView, QListView, QTreeWidget, QTableWidget, QListWidget {
    background: %(surface)s; alternate-background-color: %(surface)s; border: 1px solid %(border)s; border-radius: 10px;
    gridline-color: transparent; selection-background-color: %(accent_soft)s; selection-color: %(text)s;
}
QTreeView::item, QTableView::item, QListView::item { padding: 5px 6px; border: 0; }
QTreeView::item:hover, QTableView::item:hover, QListView::item:hover { background: %(hover)s; }
QTreeView::item:selected, QTableView::item:selected, QListView::item:selected {
    background: %(accent_soft)s; color: %(text)s;
}
QHeaderView { background: transparent; }
QHeaderView::section {
    background: %(surface)s; color: %(muted)s; border: 0; border-bottom: 1px solid %(border)s;
    padding: 8px 10px; font-weight: 600;
}
QTableCornerButton::section { background: %(surface)s; border: 0; }

/* ---- tabs (nested pages such as Tools) ---- */
QTabWidget::pane { border: 0; border-top: 1px solid %(border)s; top: -1px; }
QTabBar { background: transparent; }
QTabBar::tab {
    background: transparent; color: %(muted)s; padding: 9px 16px; margin-right: 2px; border: 0;
    border-bottom: 2px solid transparent;
}
QTabBar::tab:hover { color: %(text)s; }
QTabBar::tab:selected { color: %(accent)s; border-bottom: 2px solid %(accent)s; font-weight: 600; }

/* ---- group boxes, labels ---- */
QGroupBox { border: 1px solid %(border)s; border-radius: 10px; margin-top: 14px; padding: 14px 10px 8px 10px; background: transparent; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: %(muted)s; font-weight: 600; }
QLabel[muted="true"] { color: %(muted)s; }
QLabel[title="true"] { font-size: 15pt; font-weight: 600; }

/* ---- scrollbars ---- */
QScrollBar:vertical { background: transparent; width: 12px; margin: 2px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 2px; }
QScrollBar::handle { background: %(scroll)s; border-radius: 4px; min-height: 28px; min-width: 28px; }
QScrollBar::handle:hover { background: %(muted)s; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; background: none; border: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

/* ---- menus ---- */
QMenu { background: %(surface)s; border: 1px solid %(border)s; border-radius: 10px; padding: 6px; }
QMenu::item { padding: 7px 24px 7px 14px; border-radius: 6px; }
QMenu::item:selected { background: %(accent_soft)s; color: %(text)s; }
QMenu::item:disabled { color: %(muted)s; }
QMenu::separator { height: 1px; background: %(border)s; margin: 5px 8px; }

QSplitter::handle { background: transparent; }
QProgressBar { background: %(surface2)s; border: 0; border-radius: 4px; height: 8px; text-align: center; }
QProgressBar::chunk { background: %(accent)s; border-radius: 4px; }
QDialog { background: %(bg)s; }

/* ---- dashboard cards ---- */
QFrame[card="true"] { background: %(surface)s; border: 1px solid %(border)s; border-radius: 12px; }
QFrame[card="true"] QLabel { background: transparent; border: 0; }
QFrame[card="true"] QTableWidget, QFrame[card="true"] QTreeWidget { border: 0; border-radius: 0; background: transparent; }

/* ---- sidebar ---- */
QWidget#sidebar { background: %(surface)s; border-right: 1px solid %(border)s; }
QLabel#brand { font-size: 14pt; font-weight: 700; color: %(text)s; padding: 0; }
QLabel#brandMark { background: %(accent)s; color: %(accent_text)s; border-radius: 9px; font-weight: 800; font-size: 12pt; }
QListWidget#nav { background: transparent; border: 0; border-radius: 0; }
QListWidget#nav::item { padding: 10px 12px; margin: 2px 0; border-radius: 9px; color: %(muted)s; }
QListWidget#nav::item:hover { background: %(hover)s; color: %(text)s; }
QListWidget#nav::item:selected { background: %(accent_soft)s; color: %(accent)s; font-weight: 600; }
QListWidget#settingsNav { background: transparent; border: 0; border-right: 1px solid %(border)s; border-radius: 0; }
QListWidget#settingsNav::item { padding: 9px 12px; margin: 1px 6px; border-radius: 8px; color: %(muted)s; }
QListWidget#settingsNav::item:selected { background: %(accent_soft)s; color: %(accent)s; font-weight: 600; }
QListWidget#settingsNav::item:hover { background: %(hover)s; color: %(text)s; }
QFrame#statusChip { border-radius: 11px; }
""" % t


def apply(app: QApplication, theme="System", font_size=0, accent=DEFAULT_ACCENT):
    # Tell Qt which scheme we want so window frames and native pop-ups follow it (Qt 6.8+).
    try:
        app.styleHints().setColorScheme({"Dark": Qt.ColorScheme.Dark, "Light": Qt.ColorScheme.Light}
                                        .get(theme, Qt.ColorScheme.Unknown))
    except Exception:
        pass
    dark = is_dark(app, theme)
    t = tokens(dark, accent)
    _current.clear()
    _current.update(t, dark=dark)
    app.setStyle("Fusion")                               # one style everywhere, so the stylesheet looks the same
    app.setPalette(palette(t))
    font = QFont(app.font())
    font.setFamilies(["Segoe UI Variable Text", "Segoe UI", "Inter", "Helvetica Neue", "Arial"])
    font.setPointSize(int(font_size) if font_size and font_size > 0 else BASE_POINT_SIZE)
    app.setFont(font)
    app.setStyleSheet(stylesheet(t))


def current():
    """The colour tokens in use (for widgets that paint themselves)."""
    return dict(_current)
