"""Edit device > Checks: this device's own list of checks and its own thresholds. Anything left alone follows Settings > Checks and
Settings > Thresholds, so a device with nothing set here behaves exactly as before."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QPushButton,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)
from core import checks, db
from ui.settings_base import TrimSpin, note

KEY = Qt.ItemDataRole.UserRole


class DeviceChecks(QWidget):
    def __init__(self):
        super().__init__()
        self.vendor = ""
        self._own = None                                   # the device's own list of check keys, or None to follow the global one
        self._limits = {}                                  # threshold key -> {'warn', 'fail'} this device overrides
        self.own = QCheckBox("Choose which checks run on this device")
        self.own.setToolTip("Off: the list in Settings > Checks decides, like every other device of this type.")
        self.listing = QListWidget()
        self.listing.setMinimumHeight(120)
        self.listing.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.state = QLabel("")
        self.state.setProperty("muted", True)
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
        lay.addWidget(QLabel("<b>Thresholds</b>  (tick a row to give this device its own limits; the others stay global)"))
        lay.addWidget(self.limits, 1)
        bar = QHBoxLayout()
        bar.addWidget(reset)
        bar.addStretch()
        lay.addLayout(bar)
        self.own.toggled.connect(self._own_toggled)
        self._refresh_globals()

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
        self._own, self._limits = None, {}
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
