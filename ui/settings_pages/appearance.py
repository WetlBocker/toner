"""Settings pages: Appearance, Terminal and Reports."""

import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QCheckBox, QColorDialog, QComboBox, QFileDialog, QFontComboBox, QLineEdit, QPushButton
from core import db, reports, trends
from ui import terminal, theme
from ui.settings_base import Page, compact_row, note, row_of, spin


# ------------------------------------------------------------------ Appearance
class AppearancePage(Page):
    title = "Appearance"
    STATUSES = ["OK", "WARN", "FAIL", "ERROR"]
    preview = Signal(str)                   # the theme to show at once, before Save; Settings puts it back if not saved

    def __init__(self):
        super().__init__()
        self.theme = QComboBox()
        self.theme.addItems(theme.THEMES)
        self.font = spin(0, 24, " pt")
        self.font.setSpecialValueText("default")
        self.preset = QComboBox()
        self.preset.addItems(reports.COLOR_PRESETS)
        self.colors = {}
        self.swatch = {}
        for s in self.STATUSES:
            b = QPushButton(s)
            b.clicked.connect(lambda _=False, s=s: self.pick(s))
            self.swatch[s] = b
        self.ui_style = QComboBox()
        for name, tip in (("Standard", "Roomy rows, rounded pills and large numbers"),
                          ("Ops console", "Dense and flat for watching many devices: 22 px rows, monospace data, small tags, a lower top bar")):
            self.ui_style.addItem(name)
            self.ui_style.setItemData(self.ui_style.count() - 1, tip, Qt.ItemDataRole.ToolTipRole)
        self.ui_style.setToolTip("How much fits on screen, and how it looks. Works with the light and the dark theme.")
        self.form.addRow("Style", self.ui_style)
        self.form.addRow("Theme", self.theme)
        self.form.addRow("Text size", self.font)
        self.form.addRow("Status colours", self.preset)
        self.form.addRow("", compact_row(*self.swatch.values()))
        self.lay.insertWidget(1, note("Style: Standard has roomy rows and rounded pills; Ops console is denser and flatter, with monospace data, for watching many "
                                      "devices at once. Both follow Theme."))
        self.lay.insertWidget(2, note("Click a status to choose its colour. Text on top of each colour is "
                                      "switched between dark and white automatically so it stays readable. "
                                      "The status word is always shown, so colour is never the only signal."))
        self.preset.currentTextChanged.connect(self.use_preset)
        self.theme.currentTextChanged.connect(lambda _t: self.preview.emit(self.theme.currentText()))

    def use_preset(self, name):
        self.colors = dict(reports.COLOR_PRESETS.get(name, reports.DEFAULT_COLORS))
        self.paint()

    def paint(self):
        for s, b in self.swatch.items():
            bg = self.colors[s]
            b.setStyleSheet(f"background:{bg}; color:{reports.fg_for(bg)}; padding:6px 14px; "
                            "border:1px solid #888; border-radius:3px;")

    def pick(self, status):
        c = QColorDialog.getColor(QColor(self.colors[status]), self, f"Colour for {status}")
        if c.isValid():
            self.colors[status] = c.name()
            self.paint()

    def load(self):
        self.ui_style.setCurrentText(db.get_setting("ui_style"))
        self.theme.blockSignals(True)
        self.theme.setCurrentText(db.get_setting("theme"))
        self.theme.blockSignals(False)
        self.font.setValue(int(db.get_setting("font_size")))
        self.preset.blockSignals(True)
        self.preset.setCurrentText(db.get_setting("color_preset"))
        self.preset.blockSignals(False)
        self.colors = {**reports.COLOR_PRESETS.get(self.preset.currentText(), reports.DEFAULT_COLORS),
                       **db.get_setting("status_colors")}
        self.paint()

    def save(self):
        preset = self.preset.currentText()
        base = reports.COLOR_PRESETS.get(preset, reports.DEFAULT_COLORS)
        db.set_setting("ui_style", self.ui_style.currentText())
        db.set_setting("theme", self.theme.currentText())
        db.set_setting("font_size", self.font.value())
        db.set_setting("color_preset", preset)
        db.set_setting("status_colors", {s: c for s, c in self.colors.items() if c != base[s]})


# ------------------------------------------------------------------ Terminal
class TerminalPage(Page):
    title = "Terminal"

    def __init__(self):
        super().__init__()
        self.family = QFontComboBox()
        self.family.setFontFilters(QFontComboBox.FontFilter.MonospacedFonts)
        self.size = spin(6, 32, " pt")
        self.scrollback = spin(100, 100_000, " lines")
        self.scheme = QComboBox()
        self.scheme.addItems(terminal.SCHEMES)
        self.paging = QLineEdit()
        self.rdp = QComboBox()
        self.rdp.addItem("Inside Toner, as a tab in Sessions", True)
        self.rdp.addItem("In Windows' own Remote Desktop window", False)
        self.rdp.setToolTip("Inside Toner uses the Remote Desktop control Windows ships. If this computer cannot host it, Windows' own client is used instead.")
        for label, w in (("Font", self.family), ("Size", self.size), ("Colours", self.scheme),
                         ("Scrollback", self.scrollback), ("Paging command", self.paging), ("Remote Desktop", self.rdp)):
            self.form.addRow(label, w)
        self.lay.insertWidget(1, note("Font, size and colours apply to the console straight away. A new "
                                      "scrollback length applies from the next connection. Each vendor "
                                      "has its own paging command; the one here is used for every vendor once you change it "
                                      "from the default, and is sent after login when 'Disable paging' is ticked."))

    def load(self):
        self.family.setCurrentFont(QFont(db.get_setting("term_font")))
        self.size.setValue(int(db.get_setting("term_font_size")))
        self.scheme.setCurrentText(db.get_setting("term_scheme"))
        self.scrollback.setValue(int(db.get_setting("term_scrollback")))
        self.paging.setText(db.get_setting("paging_cmd"))
        self.rdp.setCurrentIndex(0 if db.get_setting("rdp_embedded") else 1)

    def save(self):
        db.set_setting("rdp_embedded", bool(self.rdp.currentData()))
        db.set_setting("term_font", self.family.currentFont().family())
        db.set_setting("term_font_size", self.size.value())
        db.set_setting("term_scheme", self.scheme.currentText())
        db.set_setting("term_scrollback", self.scrollback.value())
        db.set_setting("paging_cmd", self.paging.text().strip() or "terminal length 0")


# ------------------------------------------------------------------ Reports
class ReportsPage(Page):
    title = "Reports"

    def __init__(self):
        super().__init__()
        self.report_title, self.org, self.folder = QLineEdit(), QLineEdit(), QLineEdit()
        self.org.setPlaceholderText("shown under the title, e.g. your company or site name")
        self.folder.setPlaceholderText("where the Save dialog opens (blank = wherever it opened last)")
        browse = QPushButton("Browse...")
        browse.clicked.connect(self.browse)
        self.include_all = QCheckBox("Include the full per-device listing (not just 'Needs attention')")
        self.trend = QComboBox()
        for label, key in trends.SCHEDULES:
            self.trend.addItem(label, key)
        self.trend.setToolTip("A weekly or monthly trend report is saved into the default folder (a PDF from the window, HTML from the "
                              "background service) while Toner is running.")
        self.form.addRow("Report title", self.report_title)
        self.form.addRow("Organisation", self.org)
        self.form.addRow("Default folder", row_of(self.folder, browse))
        self.form.addRow("", self.include_all)
        self.form.addRow("Trend report", self.trend)

    def browse(self):
        d = QFileDialog.getExistingDirectory(self, "Default report folder", self.folder.text())
        if d:
            self.folder.setText(d)

    def load(self):
        self.report_title.setText(db.get_setting("report_title"))
        self.org.setText(db.get_setting("report_org"))
        self.folder.setText(db.get_setting("report_folder"))
        self.include_all.setChecked(bool(db.get_setting("report_include_all")))
        self.trend.setCurrentIndex(max(0, self.trend.findData(db.get_setting("trend_schedule"))))

    def validate(self):
        f = self.folder.text().strip()
        if f and not os.path.isdir(f):
            return [f"Reports: the folder '{f}' does not exist."]
        if self.trend.currentData() and not f:
            return ["Reports: choose a default folder to save the scheduled trend report into."]
        return []

    def save(self):
        db.set_setting("report_title", self.report_title.text().strip() or "Toner Health Report")
        db.set_setting("report_org", self.org.text().strip())
        db.set_setting("report_folder", self.folder.text().strip())
        db.set_setting("report_include_all", self.include_all.isChecked())
        db.set_setting("trend_schedule", self.trend.currentData())
