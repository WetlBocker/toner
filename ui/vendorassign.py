"""Importing sessions from MobaXterm, PuTTY or SecureCRT: say which vendor each SSH, Telnet and Remote Desktop entry is, so it can
also be a device that Toner monitors.

The rows are grouped by organization, then folder. Choosing a vendor for an organization's or folder's row applies to everything
in it; single rows can still be changed. Remote Desktop entries start as Windows, the rest with no vendor. Detect Vendors works
out what it can (core/vendordetect.py) for the selected rows, or every row still without a vendor; a vendor already there is
never replaced. A row left without a vendor is still added, to be edited later."""
import threading

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout)

from core import db, display, vendors

ROLE = Qt.ItemDataRole.UserRole
NO_FOLDER = "(no folder)"
SESSIONS_ONLY = 2                             # exec()'s answer for Sessions only
OFFERED = [v for v in vendors.listed() if v not in ("wifi", "cloud")]        # what an imported host can be


def vendor_text(v):
    return display.vendor_name(v) if v else "(no vendor)"


class _Relay(QObject):
    """Carries what the detection thread finds back to the window's thread."""
    found = Signal(object, str, str)
    finished = Signal()


class VendorAssignDialog(QDialog):
    def __init__(self, rows, passwords=None, parent=None, detect=None):
        """rows: [{'name', 'host', 'port', 'kind', 'username', 'org', 'folder': [parts]}]. passwords: {row index: password}, for
        Detect Vendors to sign in with. vendors() then gives (vendor, platform) for each row, in the same order."""
        super().__init__(parent)
        from core import vendordetect
        self.detect_all = detect or vendordetect.detect_all
        self.setWindowTitle("Choose each device's vendor")
        self.resize(760, 560)
        self.rows, self.passwords = rows, passwords or {}
        from core import sessionimport
        self.chosen = [(sessionimport.first_vendor(r), "winrm" if sessionimport.first_vendor(r) == "windows" else "") for r in rows]
        self.cancel = None
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Host", "Vendor"])
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.header().setStretchLastSection(True)
        bold = None
        orgs, folders = {}, {}
        for i, r in enumerate(rows):
            org = db.target() if r.get("org") is None else r["org"]          # None: the organization being written to
            o = orgs.get(org)
            if o is None:
                o = orgs[org] = QTreeWidgetItem([db.org_name(org), "", ""])
                bold = bold or o.font(0)
                bold.setBold(True)
                o.setFont(0, bold)
                o.setData(0, ROLE, None)
                self.tree.addTopLevelItem(o)
                o.setExpanded(True)
            path = "/".join(r.get("folder") or []) or NO_FOLDER
            f = folders.get((org, path))
            if f is None:
                f = folders[(org, path)] = QTreeWidgetItem([path, "", ""])
                f.setFont(0, bold)
                f.setData(0, ROLE, None)
                o.addChild(f)
            child = QTreeWidgetItem([r["name"] or r["host"], r["host"], ""])
            child.setData(0, ROLE, i)
            f.addChild(child)
        self.pick = QComboBox()
        self.pick.addItem(vendor_text(""), "")
        for v in OFFERED:
            self.pick.addItem(vendor_text(v), v)
        apply_btn = QPushButton("Apply to selected")
        apply_btn.clicked.connect(self.apply)
        self.detect_btn = QPushButton("Detect Vendors")
        self.detect_btn.clicked.connect(self.start_detect)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_detect)
        self.stop_btn.hide()
        self.progress = QLabel("")
        self.progress.setWordWrap(True)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Apply to selected:"))
        bar.addWidget(self.pick)
        bar.addWidget(apply_btn)
        bar.addStretch(1)
        bar.addWidget(self.detect_btn)
        bar.addWidget(self.stop_btn)
        self.add_btn = QPushButton("Add devices")
        self.add_btn.setDefault(True)
        self.add_btn.clicked.connect(self.accept)
        only = QPushButton("Sessions only")
        only.clicked.connect(lambda: self.done(SESSIONS_ONLY))
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        for b in (self.add_btn, only, cancel):
            bottom.addWidget(b)
        note = QLabel("Pick rows (an organization's or folder's row picks everything in it), choose a vendor, and press Apply to selected. "
                      "Devices left without a vendor are still added: edit them later to choose one. Remote Desktop sessions start as "
                      "Windows. Detect Vendors checks the selected rows (or every row without a vendor): first what each device shows "
                      "without signing in, then, using its user name and password, what it says after signing in over SSH.")
        note.setWordWrap(True)
        lay = QVBoxLayout(self)
        lay.addWidget(note)
        lay.addWidget(self.tree, 1)
        lay.addLayout(bar)
        lay.addWidget(self.progress)
        lay.addLayout(bottom)
        self.show_vendors()
        for item in self._items():
            item.setExpanded(True)                           # every device shows, so the columns fit every name and address
        self.tree.itemExpanded.connect(lambda _i: self._fit())
        self._fit()

    def _fit(self):
        """The Name and Host columns wide enough for what they show, and the window widened to match while the screen has room."""
        for col in (0, 1):
            self.tree.resizeColumnToContents(col)
        want = self.tree.columnWidth(0) + self.tree.columnWidth(1) + 240       # the Vendor column, the borders and the scroll bar
        screen = self.screen().availableGeometry().width() if self.screen() else 1600
        if want > self.width():
            self.resize(min(want, int(screen * 0.9)), self.height())

    # ---------------------------------------------------------------- showing and choosing
    def _items(self):
        out, todo = [], [self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())]
        while todo:
            it = todo.pop()
            out.append(it)
            todo += [it.child(i) for i in range(it.childCount())]
        return out

    def show_vendors(self):
        def fill(item):
            i = item.data(0, ROLE)
            if i is not None:
                item.setText(2, vendor_text(self.chosen[i][0]))
                return {self.chosen[i][0]}
            seen = set()
            for c in range(item.childCount()):
                seen |= fill(item.child(c))
            item.setText(2, vendor_text(next(iter(seen))) if len(seen) == 1 else "(several)")
            return seen
        for t in range(self.tree.topLevelItemCount()):
            fill(self.tree.topLevelItem(t))

    def selected_rows(self):
        """The row indexes picked: a group's row stands for everything in it."""
        out = set()

        def take(item):
            i = item.data(0, ROLE)
            if i is not None:
                out.add(i)
            for c in range(item.childCount()):
                take(item.child(c))
        for item in self.tree.selectedItems():
            take(item)
        return sorted(out)

    def apply(self, vendor=None):
        """The vendor chosen below goes to every selected row."""
        v = self.pick.currentData() if vendor is None or isinstance(vendor, bool) else vendor
        platform = "winrm" if v == "windows" else vendors.default_platform(v)
        for i in self.selected_rows():
            self.chosen[i] = (v, platform)
        self.show_vendors()

    def vendors(self):
        return list(self.chosen)

    # ---------------------------------------------------------------- Detect Vendors
    def start_detect(self):
        picked = self.selected_rows() or range(len(self.rows))
        todo = [i for i in picked if not self.chosen[i][0]]                 # a vendor already there is never replaced
        if not todo:
            return
        self.total, self.done_count, self.found = len(todo), 0, 0
        self.cancel = threading.Event()
        self.relay = _Relay()
        self.relay.found.connect(self._found)
        self.relay.finished.connect(self._finished)
        self.detect_btn.setEnabled(False)
        self.add_btn.setEnabled(False)
        self.stop_btn.show()
        self._show_progress()
        entries = {i: self.rows[i] for i in todo}
        passwords = {i: self.passwords.get(i, "") for i in todo}
        relay, cancel = self.relay, self.cancel

        def work():
            try:
                self.detect_all(entries, passwords, on_done=lambda k, v, p: relay.found.emit(k, v, p), cancel=cancel)
            finally:
                relay.finished.emit()
        self.worker = threading.Thread(target=work, name="detect-vendors", daemon=True)
        self.worker.start()

    def _show_progress(self):
        self.progress.setText(f"Detecting vendors: {self.done_count} of {self.total}...")

    def _found(self, i, vendor, platform):
        self.done_count += 1
        if vendor and not self.chosen[i][0]:
            self.chosen[i] = (vendor, platform or ("winrm" if vendor == "windows" else vendors.default_platform(vendor)))
            self.found += 1
            self.show_vendors()
        self._show_progress()

    def _finished(self):
        self.stop_btn.hide()
        self.detect_btn.setEnabled(True)
        self.add_btn.setEnabled(True)
        self.progress.setText(f"Detected {self.found} of {self.total}. The rest still have no vendor: choose one, or leave them to edit later.")
        self.cancel = None

    def stop_detect(self):
        if self.cancel is not None:
            self.cancel.set()

    def done(self, result):
        self.stop_detect()                                   # closing the window stops a detection still running
        super().done(result)


def choose(rows, passwords=None, parent=None):
    """(answer, [(vendor, platform)] per row): answer is 'devices', 'sessions' (Sessions only) or None (Cancel)."""
    dlg = VendorAssignDialog(rows, passwords, parent)
    result = dlg.exec()
    if result == 1:                                         # Add devices
        return "devices", dlg.vendors()
    if result == SESSIONS_ONLY:
        return "sessions", None
    return None, None
