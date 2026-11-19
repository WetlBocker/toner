"""Settings page: monitoring profiles. A profile is a set of checks and limits for one vendor, assigned to groups or single devices;
a device it applies to follows it instead of Settings > Checks and Settings > Thresholds (core/db.py profile_for)."""
import copy

from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLineEdit, QMessageBox,
                               QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout)
from core import checks, db, display
from ui.devicechecks import DeviceChecks
from ui.settings_base import Page, note
from ui.widgets import GroupPicker


class MonitoringProfileDialog(QDialog):
    def __init__(self, profile=None, others=(), parent=None):
        super().__init__(parent)
        self.others = {str(n).lower() for n in others}               # the names the other profiles have
        self.setWindowTitle("Edit monitoring profile" if profile else "New monitoring profile")
        self.setMinimumWidth(560)
        self.resize(640, 760)
        self.setProperty("notSetting", True)                        # its boxes are the profile's, not settings of the page that opened it
        self.name = QLineEdit()
        self.vendor = QComboBox()
        for v in checks.CATALOG:                                    # the kinds of device Settings > Checks lists
            if v != "all":
                self.vendor.addItem(display.type_name(v), v)
        self.checks = DeviceChecks(for_profile=True)
        self.scope = GroupPicker(all_text="Choose groups", noun="groups", clear_text="Clear selection")
        self.form, self.below = QFormLayout(), QFormLayout()
        self.form.addRow("Name", self.name)
        self.form.addRow("Vendor", self.vendor)
        self.below.addRow("Applies to", self.scope)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(self.form)
        lay.addWidget(self.checks, 1)
        lay.addLayout(self.below)
        lay.addWidget(buttons)
        if profile:
            self.name.setText(profile["name"])
            if self.vendor.findData(profile["vendor"]) < 0:
                self.vendor.addItem(display.type_name(profile["vendor"]), profile["vendor"])
            self.vendor.setCurrentIndex(self.vendor.findData(profile["vendor"]))
            self.vendor.setEnabled(False)                           # its checks and devices belong to that vendor
        self.checks.set_vendor(self.vendor.currentData())
        self.checks.load({"checks": profile["checks"], "thresholds": profile["thresholds"]} if profile else None)
        self._vendor_changed()
        self.scope.set_selected(profile["scopes"] if profile else [])
        self.vendor.currentIndexChanged.connect(lambda _: self._vendor_changed())

    def _vendor_changed(self):
        """The vendor's checks, and where a profile for it can apply: the groups, and the single devices of that vendor."""
        v = self.vendor.currentData()
        if self.checks.vendor != v:
            self.checks.set_vendor(v)
        self.scope.set_labels([g for g in db.group_labels() if not g.startswith("Vendor: ")]
                              + [f"Device: {d['name']}" for d in db.list_devices() if d["vendor"] == v])

    def values(self):
        v = self.checks.values()
        return {"name": self.name.text().strip(), "vendor": self.vendor.currentData(), "checks": v.get("checks", []),
                "thresholds": v.get("thresholds", {}), "scopes": self.scope.selected()}

    def problems(self):
        name = self.name.text().strip()
        if not name:
            return ["Give the profile a name."]
        if name.lower() in self.others:
            return [f"A profile named '{name}' already exists."]
        return self.checks.problems()

    def accept(self):
        bad = self.problems()
        if bad:
            QMessageBox.warning(self, "Monitoring profile", bad[0])
            return
        super().accept()


class MonitoringProfilesPage(Page):
    title = "Monitoring profiles"

    def __init__(self):
        super().__init__()
        self.items = []                                             # the profiles as shown; stored on Save
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Name", "Vendor", "Applies to", "Checks"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(220)
        self.table.doubleClicked.connect(lambda *_: self.edit())
        bar = QHBoxLayout()
        for text, fn in (("Add...", self.add), ("Edit...", self.edit), ("Duplicate", self.duplicate), ("Remove", self.remove)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            bar.addWidget(b)
        bar.addStretch()
        self.form.addRow(self.table)
        self.form.addRow(bar)
        self.lay.insertWidget(0, note("A monitoring profile is a set of checks and limits for one vendor. Assign it to a group, a tag or "
                                      "single devices. Devices without one use Settings > Checks and Settings > Thresholds."))

    @staticmethod
    def _check_names(p):
        known = dict(checks.CATALOG.get(p["vendor"], []))
        return [known[k] for k in p["checks"] if k in known]

    def _show(self, select=None):
        self.table.setRowCount(len(self.items))
        for r, p in enumerate(self.items):
            for c, text in enumerate([p["name"], display.type_name(p["vendor"]), ", ".join(p["scopes"]),
                                      f"{len(self._check_names(p))} of {len(checks.CATALOG.get(p['vendor'], []))}"]):
                self.table.setItem(r, c, QTableWidgetItem(text))
        self.table.resizeColumnsToContents()
        if select is not None:
            self.table.selectRow(select)

    def load(self):
        """What is stored is not trusted: only an entry a run would use (db.profile_for) is listed, cleaned."""
        self.items = [{"name": str(p.get("name") or ""), "vendor": str(p["vendor"]), "checks": [str(k) for k in p["checks"]],
                       "thresholds": db.normalize_checkopts({"thresholds": p.get("thresholds")}).get("thresholds", {}),
                       "scopes": [str(s) for s in p["scopes"]]}
                      for p in db.get_setting("monitoring_profiles")
                      if isinstance(p, dict) and p.get("vendor") and isinstance(p.get("checks"), list) and isinstance(p.get("scopes"), list)]
        self._show()

    def save(self):
        db.set_setting("monitoring_profiles", copy.deepcopy(self.items))

    def describe_extra(self):
        """The profiles, for the unsaved mark and the list of changes shown before saving."""
        rows = []
        for p in self.items:
            limits = "; ".join(f"{db.THRESHOLD_LABELS.get(k, k)} WARN {t['warn']:g} / FAIL {t['fail']:g}" for k, t in p["thresholds"].items())
            rows.append((f"Profile: {p['name']}", f"{display.type_name(p['vendor'])}. Checks: {', '.join(self._check_names(p)) or 'none'}. "
                                                  f"Limits: {limits or 'none'}. Applies to: {', '.join(p['scopes']) or 'nothing'}."))
        return rows

    def current(self):
        r = self.table.currentRow()
        return r if 0 <= r < len(self.items) else None

    def _names(self, skip=None):
        return [p["name"] for i, p in enumerate(self.items) if i != skip]

    def add(self):
        dlg = MonitoringProfileDialog(None, self._names(), self)
        if dlg.exec():
            self.items.append(dlg.values())
            self._show(len(self.items) - 1)

    def edit(self):
        r = self.current()
        if r is None:
            return
        dlg = MonitoringProfileDialog(self.items[r], self._names(r), self)
        if dlg.exec():
            self.items[r] = dlg.values()
            self._show(r)

    def duplicate(self):
        """A copy under a new name, assigned to nothing: two profiles for one vendor in the same place would leave the copy unused."""
        r = self.current()
        if r is None:
            return
        p, taken, n = copy.deepcopy(self.items[r]), {x.lower() for x in self._names()}, 1
        name = f"{p['name']} (copy)"
        while name.lower() in taken:
            n += 1
            name = f"{p['name']} (copy {n})"
        p.update(name=name, scopes=[])
        self.items.append(p)
        self._show(len(self.items) - 1)

    def remove(self):
        r = self.current()
        if r is None:
            return
        if QMessageBox.question(self, "Remove profile", f"Remove the profile '{self.items[r]['name']}'? Its devices go back to the global "
                                "checks and thresholds.") == QMessageBox.StandardButton.Yes:
            del self.items[r]
            self._show()
