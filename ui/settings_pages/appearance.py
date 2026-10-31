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
    preview = Signal(object)                # the look to show at once, before Save (a dict: theme, look, panels...); Settings puts it back if not saved

    def __init__(self):
        super().__init__()
        from PySide6.QtCore import QTimer
        from ui import themes
        from ui.themecards import ThemeGrid
        self.grid = ThemeGrid()
        self.grid.picked.connect(self._picked)
        # Your colour's own controls: shown only while that theme is chosen
        self.accent_btn = QPushButton("Accent\u2026")
        self.accent_btn.clicked.connect(self.pick_accent)
        self.accent_btn.setProperty("notSetting", True)
        self.custom_accent = themes.DEFAULT_LOOK["custom_accent"]
        self.base = QComboBox()
        self.base.addItems(themes.BASES)
        self.base.setToolTip("Dark or light surfaces behind your accent")
        self.tint = QCheckBox("Tinted base")
        self.tint.setToolTip("Tints the background and panels faintly toward the accent")
        self.custom_row = compact_row(self.accent_btn, self.base, self.tint)
        self.look = QComboBox()
        self.look.addItems(themes.LOOKS)
        self.motion = QComboBox()
        self.motion.addItems(themes.MOTIONS)
        self.panels = QComboBox()
        self.panels.addItems(themes.PANELS)
        self.contrast = QComboBox()
        self.contrast.addItems(themes.CONTRASTS)
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
        self.form.addRow("Theme", self.grid)
        self.form.addRow("", self.custom_row)
        self.form.addRow("Look", self.look)
        self.form.addRow("Motion", self.motion)
        self.form.addRow("Panels", self.panels)
        self.form.addRow("Contrast", self.contrast)
        self.form.addRow("Text size", self.font)
        self.form.addRow("Status colours", self.preset)
        self.form.addRow("", compact_row(*self.swatch.values()))
        self.lay.insertWidget(1, note("Look: Standard is what Toner has had so far; Soft rounds every corner; Sharp squares them; Terminal is monospace "
                                      "with no rounding and tighter rows, for people who live in a console."))
        self.lay.insertWidget(2, note("Motion: Subtle fades and grows things as they change; Lively adds the Aurora wash, a drifting backdrop and a "
                                      "heartbeat on the logo. Everything is still when Windows' animation effects are turned off."))
        self.lay.insertWidget(3, note("Panels: Raised panels cast a soft shadow; Flat panels have no border."))
        self.lay.insertWidget(4, note("Click a status to choose its colour. Text on top of each colour is "
                                      "switched between dark and white automatically so it stays readable. "
                                      "The status word is always shown, so colour is never the only signal."))
        self.preset.currentTextChanged.connect(self.use_preset)
        self._debounce = QTimer(self)                         # a quick flick through the boxes restyles the window once
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(120)
        self._debounce.timeout.connect(lambda: self.preview.emit(self.look_dict()))
        for box in (self.look, self.motion, self.panels, self.contrast, self.base):
            box.currentTextChanged.connect(lambda _t: self._preview())
        self.tint.toggled.connect(lambda _on: self._preview())
        self._loading = False
        self._show_custom()

    # ---- the look as one dict
    def look_dict(self):
        return dict(theme=self.grid.current(), look=self.look.currentText(), motion=self.motion.currentText(), panels=self.panels.currentText(),
                    contrast=self.contrast.currentText(), custom_accent=self.custom_accent, custom_base=self.base.currentText(),
                    custom_tint=self.tint.isChecked())

    def _picked(self, _name):
        self._show_custom()
        self._preview()

    def _preview(self):
        if not self._loading:
            self.grid.set_custom(self.custom_accent, self.base.currentText(), self.tint.isChecked())
            self._debounce.start()

    def _show_custom(self):
        on = self.grid.current() == "Your colour"
        self.custom_row.setVisible(on)
        self.form.setRowVisible(self.custom_row, on)

    def pick_accent(self):
        c = QColorDialog.getColor(QColor(self.custom_accent), self, "Accent colour")
        if c.isValid():
            self.custom_accent = c.name()
            self.paint_accent()
            self._preview()

    def paint_accent(self):
        from ui import themes
        self.accent_btn.setStyleSheet(f"background:{self.custom_accent}; color:{themes.text_on(self.custom_accent)}; padding:6px 14px; "
                                      "border:1px solid #888; border-radius:3px;")

    def describe_extra(self):
        """The theme and the accent are not boxes, so Settings is told about them here (the unsaved dot, the Save list)."""
        out = [("Theme", self.grid.current())]
        if self.grid.current() == "Your colour":
            out.append(("Accent", self.custom_accent))
        return out

    def restyle(self):
        self.grid.restyle()
        self.paint()
        self.paint_accent()

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
        from ui import themes
        self._loading = True
        for box, key in ((self.look, "look"), (self.motion, "motion"), (self.panels, "panels"), (self.contrast, "contrast"), (self.base, "custom_base")):
            box.blockSignals(True)
            box.setCurrentText(str(db.get_setting(key)))
            box.blockSignals(False)
        self.tint.blockSignals(True)
        self.tint.setChecked(bool(db.get_setting("custom_tint")))
        self.tint.blockSignals(False)
        self.custom_accent = str(db.get_setting("custom_accent") or themes.DEFAULT_LOOK["custom_accent"])
        self.grid.set_custom(self.custom_accent, self.base.currentText(), self.tint.isChecked())
        self.grid.set_current(themes.legacy_name(str(db.get_setting("theme"))))
        self._loading = False
        self._show_custom()
        self.paint_accent()
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
        for key, value in self.look_dict().items():
            db.set_setting(key, value)
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
        self.syntax = QCheckBox("Colour command output by vendor")
        self.paging = QLineEdit()
        self.rdp = QComboBox()
        self.rdp.addItem("Inside Toner, as a tab in Sessions", True)
        self.rdp.addItem("In Windows' own Remote Desktop window", False)
        self.rdp.setToolTip("Inside Toner uses the Remote Desktop control Windows ships. If this computer cannot host it, Windows' own client is used instead.")
        for label, w in (("Font", self.family), ("Size", self.size), ("Colours", self.scheme), ("", self.syntax),
                         ("", note("Comments, keywords, addresses, numbers, interface names, permit and deny, up and down are coloured "
                                   "to fit the scheme above, by the vendor of the session's inventory device (Cisco-style when it has "
                                   "none). Colours a device sends itself are kept.")),
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
        self.syntax.setChecked(bool(db.get_setting("term_syntax")))
        self.scrollback.setValue(int(db.get_setting("term_scrollback")))
        self.paging.setText(db.get_setting("paging_cmd"))
        self.rdp.setCurrentIndex(0 if db.get_setting("rdp_embedded") else 1)

    def save(self):
        db.set_setting("rdp_embedded", bool(self.rdp.currentData()))
        db.set_setting("term_font", self.family.currentFont().family())
        db.set_setting("term_font_size", self.size.value())
        db.set_setting("term_scheme", self.scheme.currentText())
        db.set_setting("term_syntax", self.syntax.isChecked())
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
