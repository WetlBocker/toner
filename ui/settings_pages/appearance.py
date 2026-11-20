"""Settings pages: Appearance, Terminal and Reports."""

import os
import threading

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QCheckBox, QColorDialog, QComboBox, QFileDialog, QFontComboBox, QLabel, QLineEdit, QPushButton, QSlider
from core import db, reports, scanreports, trends
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
        self.opacity = spin(*themes.OPACITY_RANGE, " %")
        self.opacity.setSingleStep(5)
        self.opacity.setToolTip("100 is solid. Lower it to let the background show through the panels, lists and boxes.")
        self.opacity_slider = QSlider(Qt.Orientation.Horizontal)
        self.opacity_slider.setRange(*themes.OPACITY_RANGE)
        self.opacity_slider.setProperty("notSetting", True)
        self.opacity_slider.setFixedWidth(180)
        self.opacity_slider.valueChanged.connect(self.opacity.setValue)
        self.opacity.valueChanged.connect(self.opacity_slider.setValue)
        self.font = spin(0, 24, " pt")
        self.font.setSpecialValueText("default")
        self.icons_folder = QLineEdit()
        self.icons_folder.setPlaceholderText("blank = Documents\\Vendor Icons when that folder exists")
        self.icons_browse = QPushButton("Browse...")
        self.icons_browse.clicked.connect(self.browse_icons)
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
        self.form.addRow("Panel opacity", compact_row(self.opacity_slider, self.opacity))
        self.form.addRow("Text size", self.font)
        self.form.addRow("Vendor icons folder", row_of(self.icons_folder, self.icons_browse))
        self.form.addRow("Status colours", self.preset)
        self.form.addRow("", compact_row(*self.swatch.values()))
        self.lay.insertWidget(1, note("Look: Standard is what Toner has had so far; Soft rounds every corner; Sharp squares them; Terminal is monospace "
                                      "with no rounding and tighter rows, for people who live in a console."))
        self.lay.insertWidget(2, note("Motion: Subtle fades and grows things as they change; Lively adds the Constellation wash, a drifting backdrop and a "
                                      "heartbeat on the logo. Everything is still when Windows' animation effects are turned off."))
        self.lay.insertWidget(3, note("Panels: Raised panels cast a soft shadow; Flat panels have no border."))
        self.lay.insertWidget(4, note("Panel opacity: lower it to let the background show through the panels, lists and boxes."))
        self.lay.insertWidget(5, note("Vendor icons: PNG files named after the vendor (CISCO.png, PALO ALTO.png) are shown beside a device's name in its window "
                                      "and in the details pane. A vendor without a file gets the mark Toner has built in."))
        self.lay.insertWidget(6, note("Click a status to choose its colour. Text on top of each colour is "
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
        self.opacity.valueChanged.connect(lambda _v: self._preview())
        self._loading = False
        self._show_custom()

    # ---- the look as one dict
    def look_dict(self):
        return dict(theme=self.grid.current(), look=self.look.currentText(), motion=self.motion.currentText(), panels=self.panels.currentText(),
                    contrast=self.contrast.currentText(), custom_accent=self.custom_accent, custom_base=self.base.currentText(),
                    custom_tint=self.tint.isChecked(), panel_opacity=self.opacity.value())

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

    def browse_icons(self):
        d = QFileDialog.getExistingDirectory(self, "Vendor icons folder", self.icons_folder.text() or os.path.expanduser("~"))
        if d:
            self.icons_folder.setText(d)

    def validate(self):
        f = self.icons_folder.text().strip()
        return [f"Appearance: the vendor icons folder '{f}' does not exist."] if f and not os.path.isdir(f) else []

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
        self.opacity.blockSignals(True)
        try:
            self.opacity.setValue(int(db.get_setting("panel_opacity") or 100))
        except (TypeError, ValueError):
            self.opacity.setValue(100)
        self.opacity_slider.setValue(self.opacity.value())
        self.opacity.blockSignals(False)
        self.custom_accent = str(db.get_setting("custom_accent") or themes.DEFAULT_LOOK["custom_accent"])
        self.grid.set_custom(self.custom_accent, self.base.currentText(), self.tint.isChecked())
        self.grid.set_current(themes.legacy_name(str(db.get_setting("theme"))))
        self._loading = False
        self._show_custom()
        self.paint_accent()
        self.font.setValue(int(db.get_setting("font_size")))
        self.icons_folder.setText(str(db.get_setting("vendor_icons_folder") or ""))
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
        theme.write_plain(self.grid.current())      # the sign-in windows wear it
        db.set_setting("font_size", self.font.value())
        db.set_setting("vendor_icons_folder", self.icons_folder.text().strip())
        from ui import brandicons
        brandicons.forget_vendor_icons()
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
        self.scrollback = spin(100, 100_000, " lines", choices=(1000, 5000, 10000, 50000))
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
    NOTE = ("Each report is saved to the default folder and emailed to its addresses through the first Email channel in Settings > Notifications. "
            "The vulnerability and hardening reports use the latest scan.")
    sent = Signal(str, str)                 # report, the text beside its Send now button (from the worker thread)

    def __init__(self):
        super().__init__()
        self.report_title, self.org, self.folder = QLineEdit(), QLineEdit(), QLineEdit()
        self.org.setPlaceholderText("shown under the title, e.g. your company or site name")
        self.folder.setPlaceholderText("where the Save dialog opens (blank = wherever it opened last)")
        browse = QPushButton("Browse...")
        browse.clicked.connect(self.browse)
        self.include_all = QCheckBox("Include the full per-device listing (not just 'Needs attention')")
        self.form.addRow("Report title", self.report_title)
        self.form.addRow("Organisation", self.org)
        self.form.addRow("Default folder", row_of(self.folder, browse))
        self.form.addRow("", self.include_all)
        self.schedule, self.email, self.send, self.result, self._sending = {}, {}, {}, {}, set()
        for report, label in (("trend", "Trend report"), *((k, v[0]) for k, v in scanreports.KINDS.items())):
            box, email, btn, res = QComboBox(), QLineEdit(), QPushButton("Send now"), QLabel("")
            for text, key in trends.SCHEDULES:
                box.addItem(text, key)
            email.setPlaceholderText("a@example.com, b@example.com")
            res.setWordWrap(True)                          # a long result beside the button wraps instead of squeezing the box
            btn.setProperty("notSetting", True)
            btn.setAutoDefault(False)
            btn.clicked.connect(lambda _=False, r=report: self.send_now(r))
            email.textChanged.connect(lambda _t, r=report: self._enable(r))
            res.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.form.addRow(label, box)
            row = row_of(email, btn, res)
            row.layout().setStretch(0, 3)
            row.layout().setStretch(2, 2)
            self.form.addRow("Email it to", row)
            self.schedule[report], self.email[report], self.send[report], self.result[report] = box, email, btn, res
            self._enable(report)
            if report == "trend":
                self.per_org = QCheckBox("Also one report per organization")      # Global, with organizations: one file each beside it
                self.form.addRow("", self.per_org)
        self.trend, self.trend_email = self.schedule["trend"], self.email["trend"]
        self.trend.setToolTip("A weekly or monthly trend report is saved into the default folder (a PDF from the window, HTML from the "
                              "background service) while Toner is running.")
        self.form.addRow("", note(self.NOTE))
        self.sent.connect(self._sent)

    def _enable(self, report):
        self.send[report].setEnabled(bool(self.email[report].text().strip()) and report not in self._sending)

    def send_now(self, report):
        """Make the report now and mail it to the addresses in its box, on a worker thread (its last time is left alone)."""
        problems = self._address_problems(report)
        if problems:
            self.result[report].setText(" ".join(problems))
            return
        to, kind, org = self.email[report].text().strip(), self.schedule[report].currentData(), db.home()
        self._sending.add(report)
        self._enable(report)
        self.result[report].setText("")

        def work():
            # shortcut: Global reads whatever the window shows when the thread runs (within(0) would narrow it to Global's own file); pin it if
            # switching organization mid-send ever matters
            try:
                with db.within(org or None):
                    text = scanreports.send_now(report, kind, to)
            except Exception as e:                       # (mail_files catches its own; this is making the file)
                text = f"Couldn't send the report: {type(e).__name__}: {e}"
            try:
                self.sent.emit(report, text)
            except RuntimeError:                         # Settings was closed meanwhile: nobody to tell
                pass
        threading.Thread(target=work, daemon=True).start()

    def _sent(self, report, text):
        self._sending.discard(report)
        self._enable(report)
        self.result[report].setText(text)

    def browse(self):
        d = QFileDialog.getExistingDirectory(self, "Default report folder", self.folder.text())
        if d:
            self.folder.setText(d)

    def load(self):
        self.report_title.setText(db.get_setting("report_title"))
        self.org.setText(db.get_setting("report_org"))
        self.folder.setText(db.get_setting("report_folder"))
        self.include_all.setChecked(bool(db.get_setting("report_include_all")))
        for report, box in self.schedule.items():
            box.setCurrentIndex(max(0, box.findData(db.get_setting(f"{report}_schedule"))))
            self.email[report].setText(db.get_setting(f"{report}_email"))
            self.result[report].setText("")
        self.per_org.setChecked(bool(db.get_setting("trend_per_org")))
        self.per_org.setVisible(db.home() == db.GLOBAL and bool(db.org_rows()))

    def _name(self, report):
        return "trend report" if report == "trend" else scanreports.KINDS[report][0].lower()

    def _address_problems(self, report):
        text = self.email[report].text()
        if not text.strip():
            return []
        from core import notify
        wrong = notify.bad_addresses(text)
        if wrong:
            return [f"Reports: '{a}' is not a valid email address." for a in wrong]
        if not notify.email_channel():
            return [f"Reports: add an Email channel in Settings > Notifications before emailing the {self._name(report)}."]
        return []

    def validate(self):
        f = self.folder.text().strip()
        if f and not os.path.isdir(f):
            return [f"Reports: the folder '{f}' does not exist."]
        for report, box in self.schedule.items():
            if box.currentData() and not f:
                return [f"Reports: choose a default folder to save the scheduled {self._name(report)} into."]
            problems = self._address_problems(report)
            if problems:
                return problems
        return []

    def save(self):
        db.set_setting("report_title", self.report_title.text().strip() or "Toner Health Report")
        db.set_setting("report_org", self.org.text().strip())
        db.set_setting("report_folder", self.folder.text().strip())
        db.set_setting("report_include_all", self.include_all.isChecked())
        for report, box in self.schedule.items():
            db.set_setting(f"{report}_schedule", box.currentData())
            db.set_setting(f"{report}_email", self.email[report].text().strip())
        db.set_setting("trend_per_org", self.per_org.isChecked())
