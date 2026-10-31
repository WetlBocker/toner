"""Application look: a chosen theme plus the knobs (Look, Panels, Contrast, Motion) -> colour tokens -> palette + one stylesheet.

The themes and the colour maths live in ui/themes.py. This module adds what Qt needs: the derived colours (hover row, selected
row, soft accent), the shape and type tokens of each Look, the palette and the stylesheet, and `current()` for widgets that paint
themselves."""
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication
from ui import icons, themes

BASE_POINT_SIZE = 10             # the text size when Settings says "default"
LOOK_KEYS = tuple(themes.DEFAULT_LOOK)
_current = {}

# ---- the shape and type of each Look: corner radii, paddings and fonts
_LOOKS = {
    "Standard": dict(r_btn=6, r_input=6, r_card=8, r_list=8, r_menu=8, r_item=4, r_check=5, r_nav=8, r_chip=11, r_bar=4,
                     pad_btn="6px 14px", min_btn=20, pad_input="5px 9px", min_input=20, pad_text="8px", pad_row="6px 8px", pad_cell="5px 6px",
                     pad_header="8px 10px", header_font="", pad_menu="7px 24px 7px 14px", pad_tab="9px 16px", pad_nav="9px 12px", margin_nav="1px 6px",
                     title_pt=16, brand_pt=13, check_px=16, radio_px=16, data_font="", row_line="%(border)s", btn_bg="transparent", point_delta=0),
    "Soft":     dict(r_btn=12, r_input=12, r_card=14, r_list=12, r_menu=12, r_item=8, r_check=7, r_nav=12, r_chip=12, r_bar=6,
                     pad_btn="6px 16px", min_btn=20, pad_input="5px 11px", min_input=20, pad_text="9px", pad_row="6px 8px", pad_cell="5px 6px",
                     pad_header="8px 10px", header_font="", pad_menu="7px 24px 7px 14px", pad_tab="9px 16px", pad_nav="9px 12px", margin_nav="1px 6px",
                     title_pt=16, brand_pt=13, check_px=16, radio_px=16, data_font="", row_line="%(border)s", btn_bg="transparent", point_delta=0),
    "Sharp":    dict(r_btn=2, r_input=2, r_card=2, r_list=2, r_menu=2, r_item=2, r_check=2, r_nav=2, r_chip=3, r_bar=2,
                     pad_btn="6px 14px", min_btn=20, pad_input="5px 9px", min_input=20, pad_text="8px", pad_row="6px 8px", pad_cell="5px 6px",
                     pad_header="8px 10px", header_font="", pad_menu="7px 24px 7px 14px", pad_tab="9px 16px", pad_nav="9px 12px", margin_nav="1px 6px",
                     title_pt=16, brand_pt=13, check_px=16, radio_px=16, data_font="", row_line="%(border)s", btn_bg="transparent", point_delta=0),
    # Terminal: the former Ops console. Rows are 22 px, data is monospace, corners are square, headers are small capitals.
    "Terminal": dict(r_btn=0, r_input=0, r_card=0, r_list=0, r_menu=0, r_item=0, r_check=0, r_nav=0, r_chip=2, r_bar=0,
                     pad_btn="3px 10px", min_btn=16, pad_input="2px 7px", min_input=16, pad_text="6px", pad_row="1px 6px", pad_cell="2px 6px",
                     pad_header="4px 8px", header_font='font-size: 8pt; font-family: "Segoe UI Variable Text", "Segoe UI";',
                     pad_menu="4px 20px 4px 12px", pad_tab="6px 12px", pad_nav="5px 10px", margin_nav="0 6px",
                     title_pt=13, brand_pt=13, check_px=13, radio_px=13, data_font='font-family: "Cascadia Mono", Consolas, "Courier New";',
                     row_line="%(bg)s", btn_bg="%(surface2)s", point_delta=-1),
}
TERMINAL = "Terminal"


def _legacy_look(theme_or_dark, style=None):
    """The old ways of asking: a theme name ("Dark", "Light", "System") or a dark flag, plus a style ("Ops console")."""
    if isinstance(theme_or_dark, dict):
        return dict(theme_or_dark)
    if isinstance(theme_or_dark, bool):
        name = "Midnight" if theme_or_dark else "Daylight"
    else:
        name = themes.legacy_name(str(theme_or_dark or themes.SYSTEM))
    return dict(themes.DEFAULT_LOOK, theme=name, look=TERMINAL if style == "Ops console" else "Standard")


def tokens(look=None, ctx=None):
    """The colour, shape and type tokens for a look: {theme, look, panels, contrast, ...} (see themes.DEFAULT_LOOK). For old callers
    `tokens(dark: bool, style)` still works. ctx is what the interactive themes read (themes.resolve)."""
    if not isinstance(look, dict):
        look, ctx = _legacy_look(look, ctx if isinstance(ctx, str) else None), (ctx if isinstance(ctx, dict) else None)
    t = themes.resolve(look, ctx)
    a = QColor(t["accent"])
    dark = t["dark"]
    t["accent_soft"] = themes.rgba(t["accent"], 0.18 if dark else 0.12)
    # the selected row of a list or table: the accent mixed into the surface as one opaque colour (a see-through one is painted twice on a
    # table row and comes out too strong)
    t["select"] = themes.mix(t["surface"], t["accent"], 0.18 if dark else 0.11)
    t["row_hover"] = themes.mix(t["surface"], t["hover"], 0.35)       # a row under the mouse: a third of the hover colour, so it never looks selected
    t["panel_edge"] = themes.mix(t["border"], "#000000" if dark else "#000000", 0.35) if t["panels"] == "Raised" else t["border"]
    t["card_border"] = t["border"]
    t["chev_down"] = icons.png_path("chev-down", t["muted"])
    t["check"] = icons.png_path("check", t["accent_text"])
    t["chev_up"] = icons.png_path("chev-up", t["muted"])
    shape = dict(_LOOKS.get(t["look"], _LOOKS["Standard"]))
    shape["row_line"] = shape["row_line"] % t
    shape["btn_bg"] = shape["btn_bg"] % t
    t.update(shape)
    t["terminal"] = t["look"] == TERMINAL
    t["ops"] = t["terminal"]                                    # the old name, for anything still asking
    t["raised"] = t["panels"] == "Raised"
    t["card_bottom"] = f"border-bottom: 2px solid {t['panel_edge']};" if t["raised"] else ""
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
    background: %(btn_bg)s; color: %(text)s; border: 1px solid %(border)s; border-radius: %(r_btn)spx;
    padding: %(pad_btn)s; min-height: %(min_btn)spx;
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
    background: %(input)s; color: %(text)s; border: 1px solid %(border)s; border-radius: %(r_input)spx;
    padding: %(pad_input)s; min-height: %(min_input)spx; selection-background-color: %(accent)s; selection-color: %(accent_text)s;
}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
    border: 1px solid %(accent)s;
}
QLineEdit:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled, QComboBox:disabled { color: %(muted)s; background: %(bg)s; }
QComboBox { padding-right: 26px; }
QComboBox::drop-down { border: 0; width: 26px; subcontrol-origin: padding; subcontrol-position: center right; }
QComboBox::down-arrow { image: url(%(chev_down)s); width: 12px; height: 12px; }
QComboBox QAbstractItemView {
    background: %(surface)s; border: 1px solid %(border)s; border-radius: %(r_menu)spx; padding: 4px;
    selection-background-color: %(accent_soft)s; selection-color: %(text)s; outline: 0;
}
QSpinBox, QDoubleSpinBox { padding-right: 24px; min-width: 70px; max-width: 170px; }
QSpinBox::up-button, QDoubleSpinBox::up-button { subcontrol-origin: border; subcontrol-position: top right; width: 22px; border: 0; background: transparent; margin-top: 2px; }
QSpinBox::down-button, QDoubleSpinBox::down-button { subcontrol-origin: border; subcontrol-position: bottom right; width: 22px; border: 0; background: transparent; margin-bottom: 2px; }
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow { image: url(%(chev_up)s); width: 10px; height: 10px; }
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow { image: url(%(chev_down)s); width: 10px; height: 10px; }
QSpinBox::up-button:hover, QSpinBox::down-button:hover, QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover { background: %(hover)s; border-radius: 5px; }
QPlainTextEdit, QTextEdit { padding: %(pad_text)s; }

/* ---- check boxes ---- */
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: %(check_px)spx; height: %(check_px)spx; border: 1.5px solid %(muted)s; border-radius: %(r_check)spx; background: %(input)s; }
QCheckBox::indicator:hover { border-color: %(accent)s; }
QCheckBox::indicator:checked { background: %(accent)s; border-color: %(accent)s; image: url(%(check)s); }
QCheckBox::indicator:disabled { border-color: %(border)s; background: %(bg)s; }
QRadioButton { spacing: 8px; }
QRadioButton::indicator { width: %(radio_px)spx; height: %(radio_px)spx; border: 1.5px solid %(muted)s; border-radius: 8px; background: %(input)s; }
QRadioButton::indicator:hover { border-color: %(accent)s; }
QRadioButton::indicator:checked { border-color: %(accent)s; background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5, stop:0 %(accent)s, stop:0.42 %(accent)s, stop:0.5 %(input)s, stop:1 %(input)s); }
QRadioButton::indicator:disabled { border-color: %(border)s; background: %(bg)s; }
QListView::indicator, QTreeView::indicator, QTableView::indicator { width: %(check_px)spx; height: %(check_px)spx; border: 1.5px solid %(muted)s; border-radius: %(r_check)spx; background: %(input)s; }
QListView::indicator:hover, QTreeView::indicator:hover, QTableView::indicator:hover { border-color: %(accent)s; }
QListView::indicator:checked, QTreeView::indicator:checked, QTableView::indicator:checked { background: %(accent)s; border-color: %(accent)s; image: url(%(check)s); }

/* ---- lists, tables, trees ---- */
QTreeView, QTableView, QListView, QTreeWidget, QTableWidget, QListWidget {
    background: %(surface)s; alternate-background-color: %(surface)s; border: 1px solid %(border)s; border-radius: %(r_list)spx;
    gridline-color: transparent; selection-background-color: %(select)s; selection-color: %(text)s; %(data_font)s
}
QTreeView::item, QTableView::item, QListView::item { padding: %(pad_cell)s; border: 0; }
QTreeView::item, QTableView::item { padding: %(pad_row)s; border-bottom: 1px solid %(row_line)s; }
QTreeView::item:hover, QTableView::item:hover, QListView::item:hover { background: %(row_hover)s; }
QTreeView::item:selected, QTableView::item:selected, QListView::item:selected {
    background: %(select)s; color: %(text)s;
}
QHeaderView { background: transparent; }
QHeaderView::section {
    background: %(surface)s; color: %(muted)s; border: 0; border-bottom: 1px solid %(border)s;
    padding: %(pad_header)s; font-weight: 600; %(header_font)s
}
QTableCornerButton::section { background: %(surface)s; border: 0; }

/* ---- tabs (nested pages such as Tools) ---- */
QTabWidget::pane { border: 0; border-top: 1px solid %(border)s; top: -1px; }
QTabBar { background: transparent; }
QTabBar::tab {
    background: transparent; color: %(muted)s; padding: %(pad_tab)s; margin-right: 2px; border: 0;
    border-bottom: 2px solid transparent;
}
QTabBar::tab:hover { color: %(text)s; }
QTabBar::tab:selected { color: %(text)s; border-bottom: 2px solid %(accent)s; font-weight: 600; }

/* ---- group boxes, labels ---- */
QGroupBox { border: 1px solid %(border)s; border-radius: %(r_card)spx; margin-top: 14px; padding: 14px 10px 8px 10px; background: transparent; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: %(muted)s; font-weight: 600; }
QLabel[muted="true"] { color: %(muted)s; }
QLabel[title="true"] { font-size: %(title_pt)spt; font-weight: 700; }

/* ---- scrollbars ---- */
QScrollBar:vertical { background: transparent; width: 12px; margin: 2px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 2px; }
QScrollBar::handle { background: %(scroll)s; border-radius: 4px; min-height: 28px; min-width: 28px; }
QScrollBar::handle:hover { background: %(muted)s; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; background: none; border: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

/* ---- menus ---- */
QMenu { background: %(surface)s; border: 1px solid %(border)s; border-radius: %(r_menu)spx; padding: 6px; }
QMenu::item { padding: %(pad_menu)s; border-radius: %(r_item)spx; }
QMenu::item:selected { background: %(accent_soft)s; color: %(text)s; }
QMenu::item:disabled { color: %(muted)s; }
QMenu::separator { height: 1px; background: %(border)s; margin: 5px 8px; }

QSplitter::handle { background: transparent; }
QProgressBar { background: %(surface2)s; border: 0; border-radius: %(r_bar)spx; height: 8px; text-align: center; }
QProgressBar::chunk { background: %(accent)s; border-radius: %(r_bar)spx; }
QDialog { background: %(bg)s; }

/* ---- dashboard cards ---- */
QFrame[card="true"] { background: %(surface)s; border: 1px solid %(card_border)s; border-radius: %(r_card)spx; %(card_bottom)s }
QFrame[card="true"] QLabel { background: transparent; border: 0; }
QFrame[card="true"] QTableWidget, QFrame[card="true"] QTreeWidget { border: 0; border-radius: 0; background: transparent; }

/* ---- top bar: the sections as tabs, the current one underlined ---- */
QWidget#topbar { background: %(surface)s; border-bottom: 1px solid %(border)s; }
QLabel#brand { font-size: %(brand_pt)spt; font-weight: 700; color: %(text)s; padding: 0; }
QLabel#brandMark { background: %(accent)s; color: %(accent_text)s; border-radius: 9px; font-weight: 800; font-size: 12pt; }
QListWidget#nav { background: transparent; border: 0; border-radius: 0; }
QListWidget#nav::item { padding: 0 10px; margin: 0; border: 0; border-bottom: 2px solid transparent; color: %(muted)s; background: transparent; }
QListWidget#nav::item:hover { color: %(text)s; background: transparent; }
QListWidget#nav::item:selected { background: transparent; color: %(text)s; border-bottom: 2px solid %(accent)s; font-weight: 600; }
QListWidget#settingsNav { background: transparent; border: 0; border-right: 1px solid %(border)s; border-radius: 0; }
QListWidget#settingsNav::item { padding: %(pad_nav)s; margin: %(margin_nav)s; border-radius: %(r_nav)spx; color: %(muted)s; }
QListWidget#settingsNav::item:selected { background: %(accent_soft)s; color: %(accent)s; font-weight: 600; }
QListWidget#settingsNav::item:hover { background: %(hover)s; color: %(text)s; }
QFrame#statusChip { border-radius: %(r_chip)spx; }
""" % t + (TERMINAL_QSS % t if t.get("terminal") else "")


# What only the Terminal look has: the section names in the UI font over monospace lists, a left bar on the chosen Settings page.
TERMINAL_QSS = """
QPushButton:hover, QToolButton:hover { border-color: %(muted)s; }
QPushButton[primary="true"] { font-weight: 700; }
QListWidget#nav, QListWidget#settingsNav { font-family: "Segoe UI Variable Text", "Segoe UI"; }
QListWidget#settingsNav::item:selected { background: %(select)s; border-left: 2px solid %(accent)s; }
"""


def is_terminal():
    """True while the Terminal look is in use (widgets that draw themselves ask, so they match)."""
    return bool(_current.get("terminal"))


is_ops = is_terminal                 # the old name


def look_name():
    return _current.get("look") or "Standard"


def saved_look():
    """The look chosen in Settings > Appearance, as the dict themes.resolve takes. Theme names written before 1.12 still work."""
    from core import db
    look = {k: db.get_setting(k) for k in LOOK_KEYS}
    look["theme"] = themes.legacy_name(str(look.get("theme") or themes.SYSTEM))
    return look


def context(app=None):
    """What the interactive themes read: Windows' light or dark, the hour, the worst status on the network, the organization's colour."""
    from core import db
    from ui import status as st
    app = app or QApplication.instance()
    system_dark = False
    try:
        system_dark = app.styleHints().colorScheme() == Qt.ColorScheme.Dark
    except Exception:
        pass
    worst, colour = None, ""
    try:
        rank = {"ERROR": 0, "FAIL": 1, "WARN": 2, "OK": 3}
        states = [v.get("status") for v in db.device_health().values() if v.get("status") in rank]
        worst = min(states, key=rank.get) if states else None
    except Exception:
        pass
    try:
        home = db.home()
        if home:
            colour = next((r.get("colour") or "" for r in db.org_rows() if r["id"] == home), "")
    except Exception:
        pass
    from datetime import datetime
    hour = datetime.now().hour
    dark = bool(_current.get("dark", True))
    status = {s: st.ink(s) for s in ("OK", "WARN", "FAIL", "ERROR")} if _current else None
    return dict(system_dark=system_dark, hour=hour, period=themes.period(hour), worst=worst, org_colour=colour, status=status)


def apply(app: QApplication, look=None, font_size=0, style=None, ctx=None):
    """Paint the whole app in a look. `look` is the dict Settings keeps (theme, look, panels, contrast, motion, ...); the old form
    apply(app, "Dark", 11, "Ops console") still works."""
    if not isinstance(look, dict):
        look = _legacy_look(look, style)
    t = tokens(look, ctx)
    try:                                                 # window frames and native pop-ups follow (Qt 6.8+)
        app.styleHints().setColorScheme(Qt.ColorScheme.Dark if t["dark"] else Qt.ColorScheme.Light)
    except Exception:
        pass
    _current.clear()
    _current.update(t)
    app.setStyle("Fusion")                               # one style everywhere, so the stylesheet looks the same
    app.setPalette(palette(t))
    font = QFont(app.font())
    font.setFamilies(["Segoe UI Variable Text", "Segoe UI", "Inter", "Helvetica Neue", "Arial"])
    font.setPointSize(int(font_size) if font_size and int(font_size) > 0 else BASE_POINT_SIZE + t["point_delta"])
    app.setFont(font)
    app.setStyleSheet(stylesheet(t))


def current():
    """The colour tokens in use (for widgets that paint themselves)."""
    return dict(_current)
