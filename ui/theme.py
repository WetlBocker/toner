"""Application look: colour tokens -> palette + one stylesheet. Light, dark, or follow Windows."""
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication
from ui import icons

THEMES = ["System", "Light", "Dark"]
ACCENT = ("#0e7490", "#22d3ee")  # the Toner theme's accent (light mode, dark mode); there is no accent setting
STYLES = ["Standard", "Ops console"]       # Ops console: denser, flatter, monospace data; made for watching many devices at once
OPS = "Ops console"
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


def tokens(dark, style="Standard"):
    ops = style == OPS
    a = QColor(ACCENT[1] if dark else ACCENT[0])
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
        icon="#c4cad3" if dark else "#5f6773",            # icons: brighter than muted text in dark mode, so they don't wash out
    )
    if ops:
        t.update(dict(bg="#0a0d12", surface="#10141b", surface2="#161b24", border="#222a36", text="#d5dae3", muted="#7b8697", hover="#182030", input="#0c1017",
                      scroll="#2b3442", icon="#b3bcc8") if dark else
                 dict(bg="#eceff3", surface="#ffffff", surface2="#f3f5f8", border="#d6dbe3", text="#161b22", muted="#5b6675", hover="#e8ecf1", input="#ffffff",
                      scroll="#c3cad4"))
    from ui import toner_theme_tokens                      # the Toner look (Midnight and Daylight): its own surfaces, text and accent shades
    t.update(toner_theme_tokens.overrides(dark, ops))
    t["ops"] = ops
    # the selected row of a list or table: the accent mixed into the surface as one opaque colour (a see-through one is painted twice on a
    # table row and comes out too strong)
    surf = QColor(t["surface"])
    mix = 0.18 if dark else 0.11
    t["select"] = QColor(int(surf.red() + (a.red() - surf.red()) * mix), int(surf.green() + (a.green() - surf.green()) * mix),
                         int(surf.blue() + (a.blue() - surf.blue()) * mix)).name()
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
    background: transparent; color: %(text)s; border: 1px solid %(border)s; border-radius: 6px;
    padding: 6px 14px; min-height: 20px;
}
QPushButton:hover, QToolButton:hover { background: %(hover)s; }
QPushButton:pressed, QToolButton:pressed { background: %(surface2)s; }
QPushButton:disabled, QToolButton:disabled { color: %(muted)s; background: transparent; }
QPushButton:focus { border-color: %(accent)s; }
QPushButton[primary="true"], QPushButton:default {
    background: %(accent)s; color: %(accent_text)s; border: 1px solid %(accent)s;
}
QPushButton[primary="true"] { font-weight: 600; }
/* (only a button marked primary is bold: a dialog makes a button its default after sizing it, so bold text there would not fit) */
QPushButton[primary="true"]:hover, QPushButton:default:hover { background: %(accent_hover)s; border-color: %(accent_hover)s; }
QPushButton[primary="true"]:disabled, QPushButton:default:disabled { background: %(surface2)s; color: %(muted)s; border-color: %(border)s; }
QPushButton:checked { background: %(accent_soft)s; border-color: %(accent)s; }
QPushButton[segment="true"] { padding: 3px 9px; border-radius: 0; background: %(surface2)s; color: %(muted)s; border: 1px solid %(border)s; margin-left: -1px; }
QPushButton[segment="true"]:checked { background: %(surface)s; color: %(text)s; border-bottom: 2px solid %(accent)s; }
QPushButton[flat="true"], QPushButton[ghost="true"] { background: transparent; border-color: transparent; color: %(muted)s; }
QPushButton[ghost="true"]:hover { background: %(hover)s; color: %(text)s; }
QToolButton[popupMode="2"] { padding-right: 26px; }
QToolButton::menu-indicator { image: url(%(chev_down)s); subcontrol-origin: padding; subcontrol-position: center right; right: 8px; width: 12px; height: 12px; }

/* ---- inputs ---- */
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox, QAbstractSpinBox {
    background: %(input)s; color: %(text)s; border: 1px solid %(border)s; border-radius: 6px;
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
    background: %(surface)s; border: 1px solid %(border)s; border-radius: 6px; padding: 4px;
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
QRadioButton { spacing: 8px; }
QRadioButton::indicator { width: 16px; height: 16px; border: 1.5px solid %(muted)s; border-radius: 9px; background: %(input)s; }
QRadioButton::indicator:hover { border-color: %(accent)s; }
QRadioButton::indicator:checked { border-color: %(accent)s; background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5, stop:0 %(accent)s, stop:0.42 %(accent)s, stop:0.5 %(input)s, stop:1 %(input)s); }
QRadioButton::indicator:disabled { border-color: %(border)s; background: %(bg)s; }
QListView::indicator, QTreeView::indicator, QTableView::indicator { width: 16px; height: 16px; border: 1.5px solid %(muted)s; border-radius: 5px; background: %(input)s; }
QListView::indicator:hover, QTreeView::indicator:hover, QTableView::indicator:hover { border-color: %(accent)s; }
QListView::indicator:checked, QTreeView::indicator:checked, QTableView::indicator:checked { background: %(accent)s; border-color: %(accent)s; image: url(%(check)s); }

/* ---- lists, tables, trees ---- */
QTreeView, QTableView, QListView, QTreeWidget, QTableWidget, QListWidget {
    background: %(surface)s; alternate-background-color: %(surface)s; border: 1px solid %(border)s; border-radius: 8px;
    gridline-color: transparent; selection-background-color: %(select)s; selection-color: %(text)s;
}
QTreeView::item, QTableView::item, QListView::item { padding: 5px 6px; border: 0; }
QTreeView::item, QTableView::item { padding: 6px 8px; border-bottom: 1px solid %(border)s; }
QTreeView::item:hover, QTableView::item:hover, QListView::item:hover { background: %(hover)s; }
QTreeView::item:selected, QTableView::item:selected, QListView::item:selected {
    background: %(select)s; color: %(text)s;
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
QTabBar::tab:selected { color: %(text)s; border-bottom: 2px solid %(accent)s; font-weight: 600; }

/* ---- group boxes, labels ---- */
QGroupBox { border: 1px solid %(border)s; border-radius: 8px; margin-top: 14px; padding: 14px 10px 8px 10px; background: transparent; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: %(muted)s; font-weight: 600; }
QLabel[muted="true"] { color: %(muted)s; }
QLabel[title="true"] { font-size: 16pt; font-weight: 700; }

/* ---- scrollbars ---- */
QScrollBar:vertical { background: transparent; width: 12px; margin: 2px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 2px; }
QScrollBar::handle { background: %(scroll)s; border-radius: 4px; min-height: 28px; min-width: 28px; }
QScrollBar::handle:hover { background: %(muted)s; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; background: none; border: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

/* ---- menus ---- */
QMenu { background: %(surface)s; border: 1px solid %(border)s; border-radius: 8px; padding: 6px; }
QMenu::item { padding: 7px 24px 7px 14px; border-radius: 4px; }
QMenu::item:selected { background: %(accent_soft)s; color: %(text)s; }
QMenu::item:disabled { color: %(muted)s; }
QMenu::separator { height: 1px; background: %(border)s; margin: 5px 8px; }

QSplitter::handle { background: transparent; }
QProgressBar { background: %(surface2)s; border: 0; border-radius: 4px; height: 8px; text-align: center; }
QProgressBar::chunk { background: %(accent)s; border-radius: 4px; }
QDialog { background: %(bg)s; }

/* ---- dashboard cards ---- */
QFrame[card="true"] { background: %(surface)s; border: 1px solid %(border)s; border-radius: 8px; }
QFrame[card="true"] QLabel { background: transparent; border: 0; }
QFrame[card="true"] QTableWidget, QFrame[card="true"] QTreeWidget { border: 0; border-radius: 0; background: transparent; }

/* ---- top bar: the sections as tabs, the current one underlined ---- */
QWidget#topbar { background: %(surface)s; border-bottom: 1px solid %(border)s; }
QLabel#brand { font-size: 13pt; font-weight: 700; color: %(text)s; padding: 0; }
QLabel#brandMark { background: %(accent)s; color: %(accent_text)s; border-radius: 9px; font-weight: 800; font-size: 12pt; }
QListWidget#nav { background: transparent; border: 0; border-radius: 0; }
QListWidget#nav::item { padding: 0 10px; margin: 0; border: 0; border-bottom: 2px solid transparent; color: %(muted)s; background: transparent; }
QListWidget#nav::item:hover { color: %(text)s; background: transparent; }
QListWidget#nav::item:selected { background: transparent; color: %(text)s; border-bottom: 2px solid %(accent)s; font-weight: 600; }
QListWidget#settingsNav { background: transparent; border: 0; border-right: 1px solid %(border)s; border-radius: 0; }
QListWidget#settingsNav::item { padding: 9px 12px; margin: 1px 6px; border-radius: 8px; color: %(muted)s; }
QListWidget#settingsNav::item:selected { background: %(accent_soft)s; color: %(accent)s; font-weight: 600; }
QListWidget#settingsNav::item:hover { background: %(hover)s; color: %(text)s; }
QFrame#statusChip { border-radius: 11px; }
""" % t + (OPS_QSS % t if t.get("ops") else "")


# The Ops console look: the same widgets, tighter and flatter. Rows are 22 px, data is monospace, corners are 3 px, headers are small capitals.
OPS_QSS = """
QPushButton, QToolButton { border-radius: 3px; padding: 3px 10px; min-height: 16px; background: %(surface2)s; }
QPushButton:hover, QToolButton:hover { background: %(hover)s; border-color: %(muted)s; }
QPushButton[primary="true"] { font-weight: 700; }
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QAbstractSpinBox { border-radius: 3px; padding: 2px 7px; min-height: 16px; }
QPlainTextEdit, QTextEdit { border-radius: 3px; padding: 6px; }
QComboBox QAbstractItemView, QMenu { border-radius: 4px; }
QMenu::item { padding: 4px 20px 4px 12px; border-radius: 3px; }
QFrame[card="true"] { border-radius: 4px; }
QGroupBox { border-radius: 4px; }
QTreeView, QTableView, QListView, QTreeWidget, QTableWidget, QListWidget { border-radius: 4px; font-family: "Cascadia Mono", Consolas, "Courier New"; }
QTreeView::item, QTableView::item { padding: 1px 6px; border-bottom: 1px solid %(bg)s; }
QHeaderView::section { padding: 4px 8px; font-size: 8pt; font-family: "Segoe UI Variable Text", "Segoe UI"; }
QListWidget#nav, QListWidget#settingsNav { font-family: "Segoe UI Variable Text", "Segoe UI"; }
QListWidget#settingsNav::item { border-radius: 3px; padding: 5px 10px; margin: 0 6px; }
QListWidget#settingsNav::item:selected { background: %(select)s; border-left: 2px solid %(accent)s; }
QTabBar::tab { padding: 6px 12px; }
QFrame#statusChip { border-radius: 2px; }
QLabel[title="true"] { font-size: 13pt; font-weight: 700; }
QLabel#brand { font-size: 13pt; }
QCheckBox::indicator, QListView::indicator, QTreeView::indicator, QTableView::indicator { border-radius: 2px; width: 13px; height: 13px; }
QRadioButton::indicator { width: 13px; height: 13px; border-radius: 8px; }
QProgressBar { border-radius: 2px; }
QProgressBar::chunk { border-radius: 2px; }
"""


def is_ops():
    """True while the Ops console style is in use (widgets that draw themselves ask, so they match)."""
    return bool(_current.get("ops"))


def apply(app: QApplication, theme="System", font_size=0, style="Standard"):
    # Tell Qt which scheme we want so window frames and native pop-ups follow it (Qt 6.8+).
    try:
        app.styleHints().setColorScheme({"Dark": Qt.ColorScheme.Dark, "Light": Qt.ColorScheme.Light}
                                        .get(theme, Qt.ColorScheme.Unknown))
    except Exception:
        pass
    dark = is_dark(app, theme)
    t = tokens(dark, style)
    _current.clear()
    _current.update(t, dark=dark)
    app.setStyle("Fusion")                               # one style everywhere, so the stylesheet looks the same
    app.setPalette(palette(t))
    font = QFont(app.font())
    font.setFamilies(["Segoe UI Variable Text", "Segoe UI", "Inter", "Helvetica Neue", "Arial"])
    font.setPointSize(int(font_size) if font_size and font_size > 0 else (BASE_POINT_SIZE - 1 if t["ops"] else BASE_POINT_SIZE))
    app.setFont(font)
    app.setStyleSheet(stylesheet(t))


def current():
    """The colour tokens in use (for widgets that paint themselves)."""
    return dict(_current)
