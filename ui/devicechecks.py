"""Edit device > Checks: this device's own list of checks and its own thresholds. Anything left alone follows Settings > Checks and
Settings > Thresholds, so a device with nothing set here behaves exactly as before."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QPushButton,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)
from PySide6.QtWidgets import QMessageBox
from core import checks, db, ifaces
from ui.interfacepicker import InterfacePicker
from ui.settings_base import TrimSpin, note

KEY = Qt.ItemDataRole.UserRole


class DeviceChecks(QWidget):
    def __init__(self):
        super().__init__()
        self.vendor = ""
        self._own = None                                   # the device's own list of check keys, or None to follow the global one
        self._limits = {}                                  # threshold key -> {'warn', 'fail'} this device overrides
        self._ifs = []                                     # the interfaces this device is limited to (empty: all of them)
        self.fetch_interfaces = None                       # set by the device dialog: asks the device for its interfaces
        self.own = QCheckBox("Choose which checks run on this device")
        self.own.setToolTip("Off: the list in Settings > Checks decides, like every other device of this type.")
        self.listing = QListWidget()
        self.listing.setMinimumHeight(120)
        self.listing.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.state = QLabel("")
        self.state.setProperty("muted", True)
        self.pick_ifs = QCheckBox("Check only some of this device's interfaces")
        self.pick_ifs.setToolTip("Off: every interface is checked, and any one that is down is a FAIL. On: only the ones you choose are read, "
                                 "so ports that are meant to be empty or unused stop counting.")
        self.if_choose = QPushButton("Choose interfaces...")
        self.if_choose.setAutoDefault(False)
        self.if_summary = QLabel("")
        self.if_summary.setWordWrap(True)
        self.if_summary.setProperty("muted", True)
        self.if_box = QWidget()
        ib = QVBoxLayout(self.if_box)
        ib.setContentsMargins(0, 6, 0, 10)
        row = QHBoxLayout()
        row.addWidget(self.pick_ifs)
        row.addWidget(self.if_choose)
        row.addStretch()
        ib.addLayout(row)
        ib.addWidget(self.if_summary)
        self.limits = QTableWidget(0, 4)
        self.limits.setHorizontalHeaderLabels(["Own limits", "Check", "WARN", "FAIL"])
        self.limits.verticalHeader().setVisible(False)
        self.limits.horizontalHeader().setStretchLastSection(True)
        self.limits.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.limits.setMinimumHeight(170)
        self.spins = {}
        for key in db.DEFAULT_THRESHOLDS:
            r = self.limits.rowCount()
            self.limits.insertRow(r)
            box = QTableWidgetItem("")
            box.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            box.setCheckState(Qt.CheckState.Unchecked)
            box.setData(KEY, key)
            label = QTableWidgetItem(db.THRESHOLD_LABELS.get(key, key))
            label.setFlags(Qt.ItemFlag.ItemIsEnabled)
            warn, fail = TrimSpin(), TrimSpin()
            for s in (warn, fail):
                s.setRange(0, 1_000_000)
                s.setDecimals(0 if key == "port_errors" else 2)
                s.setEnabled(False)
            self.spins[key] = (warn, fail)
            for col, w in ((0, box), (1, label)):
                self.limits.setItem(r, col, w)
            self.limits.setCellWidget(r, 2, warn)
            self.limits.setCellWidget(r, 3, fail)
        self.limits.resizeColumnsToContents()
        self.limits.itemChanged.connect(self._tick)
        reset = QPushButton("Use the global settings for everything")
        reset.setAutoDefault(False)
        reset.clicked.connect(self.reset)
        lay = QVBoxLayout(self)
        lay.addWidget(note("A device with nothing chosen here uses the global checks and thresholds (Settings > Checks and "
                           "Settings > Thresholds). What you set here applies to this device only."))
        lay.addWidget(self.own)
        lay.addWidget(self.listing)
        lay.addWidget(self.state)
        lay.addWidget(self.if_box)
        lay.addWidget(QLabel("<b>Thresholds</b>  (tick a row to give this device its own limits; the others stay global)"))
        lay.addWidget(self.limits, 1)
        bar = QHBoxLayout()
        bar.addWidget(reset)
        bar.addStretch()
        lay.addLayout(bar)
        self.own.toggled.connect(self._own_toggled)
        self.pick_ifs.toggled.connect(self._pick_toggled)
        self.if_choose.clicked.connect(self.choose_interfaces)
        self._refresh_globals()
        self._show_ifs()

    # ---------- what is shown
    def _refresh_globals(self):
        """Untouched rows show the global limits, so it is clear what 'follow the global setting' means."""
        base = db.get_thresholds()
        for key, (warn, fail) in self.spins.items():
            if key not in self._limits:
                warn.setValue(base[key]["warn"])
                fail.setValue(base[key]["fail"])

    def set_vendor(self, vendor):
        self.vendor = vendor
        self._fill_list()
        self._show_ifs()

    # ---------- which interfaces
    def _show_ifs(self):
        """The interface choice, for the kinds of device that have an interfaces check."""
        self.if_box.setVisible(ifaces.available(self.vendor))
        self.if_choose.setEnabled(self.pick_ifs.isChecked())
        n = len(self._ifs)
        self.if_summary.setText(
            ("All interfaces are checked." if not self.pick_ifs.isChecked() else
             "No interface is chosen yet: all of them are checked until you choose." if not n else
             f"{n} chosen: " + ", ".join(self._ifs[:8]) + (f" and {n - 8} more" if n > 8 else "") + ". The others are not read."))

    def _pick_toggled(self, on):
        self._show_ifs()
        if on and not self._ifs:
            self.choose_interfaces()
            if not self._ifs:                              # nothing chosen: back to checking all of them
                self.pick_ifs.blockSignals(True)
                self.pick_ifs.setChecked(False)
                self.pick_ifs.blockSignals(False)
                self._show_ifs()

    def choose_interfaces(self):
        """Ask the device for its interfaces and let the person tick the ones to check."""
        if self.fetch_interfaces is None:
            return
        try:
            found = self.fetch_interfaces()
        except Exception as e:
            QMessageBox.warning(self, "Interfaces", f"Could not get the list of interfaces from the device:\n\n{e}\n\n"
                                "Check the address and login on the General tab first.")
            return
        dlg = InterfacePicker(found, self._ifs, parent=self)
        if dlg.exec():
            self._ifs = dlg.selected()
            self._show_ifs()

    def _fill_list(self):
        off = set(db.get_setting("disabled_checks"))
        items = checks.CATALOG.get(self.vendor, [])
        self.listing.clear()
        for key, label in items:
            it = QListWidgetItem(label)
            it.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            on = (key in self._own) if (self.own.isChecked() and self._own is not None) else checks.key(self.vendor, key) not in off   # else today's global state
            it.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
            it.setData(KEY, key)
            self.listing.addItem(it)
        usable = bool(items)
        self.own.setEnabled(usable)
        self.listing.setEnabled(usable and self.own.isChecked())
        self.state.setText("" if usable else "This kind of device has no checks to choose from.")

    def _own_toggled(self, on):
        if on and self._own is None:
            self._own = self._global_list()
        self._fill_list()

    def _global_list(self):
        off = set(db.get_setting("disabled_checks"))
        return [k for k, _l in checks.CATALOG.get(self.vendor, []) if checks.key(self.vendor, k) not in off]

    def _tick(self, item):
        if item.column() != 0:
            return
        key = item.data(KEY)
        warn, fail = self.spins[key]
        on = item.checkState() == Qt.CheckState.Checked
        warn.setEnabled(on)
        fail.setEnabled(on)
        if on:
            self._limits[key] = {"warn": warn.value(), "fail": fail.value()}
        else:
            self._limits.pop(key, None)
            self._refresh_globals()

    def reset(self):
        self._own, self._limits, self._ifs = None, {}, []
        self.pick_ifs.setChecked(False)
        self.own.setChecked(False)
        for r in range(self.limits.rowCount()):
            self.limits.item(r, 0).setCheckState(Qt.CheckState.Unchecked)
        self._fill_list()
        self._refresh_globals()

    # ---------- the device's values
    def load(self, opts):
        opts = db.normalize_checkopts(opts)
        self._own = list(opts["checks"]) if "checks" in opts else None
        self._limits = {}
        self._ifs = list(opts.get("interfaces", []))
        self.pick_ifs.blockSignals(True)
        self.pick_ifs.setChecked(bool(self._ifs))
        self.pick_ifs.blockSignals(False)
        self._show_ifs()
        self.own.blockSignals(True)
        self.own.setChecked(self._own is not None)
        self.own.blockSignals(False)
        self._refresh_globals()
        self.limits.blockSignals(True)
        for r in range(self.limits.rowCount()):
            key = self.limits.item(r, 0).data(KEY)
            pair = opts.get("thresholds", {}).get(key)
            warn, fail = self.spins[key]
            self.limits.item(r, 0).setCheckState(Qt.CheckState.Checked if pair else Qt.CheckState.Unchecked)
            warn.setEnabled(bool(pair))
            fail.setEnabled(bool(pair))
            if pair:
                warn.setValue(pair["warn"])
                fail.setValue(pair["fail"])
                self._limits[key] = dict(pair)
        self.limits.blockSignals(False)
        self._fill_list()

    def values(self):
        """The device's own settings, or {} when it follows the global ones."""
        out = {}
        if self.own.isChecked() and checks.CATALOG.get(self.vendor):
            out["checks"] = [self.listing.item(i).data(KEY) for i in range(self.listing.count())
                             if self.listing.item(i).checkState() == Qt.CheckState.Checked]
        elif self.own.isChecked() and self._own is not None:
            out["checks"] = list(self._own)
        if self.pick_ifs.isChecked() and self._ifs and ifaces.available(self.vendor):
            out["interfaces"] = list(self._ifs)
        th = {}
        for r in range(self.limits.rowCount()):
            if self.limits.item(r, 0).checkState() == Qt.CheckState.Checked:
                key = self.limits.item(r, 0).data(KEY)
                warn, fail = self.spins[key]
                th[key] = {"warn": warn.value(), "fail": fail.value()}
        if th:
            out["thresholds"] = th
        return db.normalize_checkopts(out)

    def problems(self):
        return [f"{db.THRESHOLD_LABELS.get(k, k)}: WARN and FAIL contradict each other."
                for k, p in self.values().get("thresholds", {}).items() if db.bad_pair(k, p["warn"], p["fail"])]
