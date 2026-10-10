import json
import sqlite3

import keyring
from PySide6.QtCore import QPointF, Qt, Signal
from PySide6.QtGui import QFont, QIcon, QKeySequence, QPainter, QPen, QPixmap, QPolygonF, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
                               QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout, QInputDialog, QLabel,
                               QLineEdit, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QStyle, QTabWidget,
                               QToolButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget, QWidgetAction)
from core import audit, bulk, db, display, importer, nettools, profiles, proxy, vendors
from ui import icons, theme
from ui.snmpfields import SnmpFields
from core.runner import run_one



class DeviceDialog(QDialog):
    def __init__(self, dev=None, parent=None, folder_id=None):
        super().__init__(parent)
        self.dev = dev or {}
        self.setWindowTitle("Edit device" if dev else "Add device")
        self.setMinimumWidth(460)
        self.name, self.host, self.username = QLineEdit(), QLineEdit(), QLineEdit()
        self.host.setPlaceholderText("10.0.0.2  or  core-sw1.corp.example.com")
        self.secret = QLineEdit()
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret.setPlaceholderText("leave blank to keep the stored value")
        self.vendor = QComboBox()
        for v in vendors.VENDORS:
            self.vendor.addItem(display.vendor_name(v), v)       # shown text, stored value
        self.platform = QComboBox()
        self.port = QSpinBox()
        self.port.setRange(0, 65535)
        self.port.setSpecialValueText("default")
        self.site = QLineEdit("default")
        self.location = QComboBox()
        self.location.setEditable(True)
        self.location.addItems(sorted({d["location"] for d in db.list_devices() if d.get("location")}))
        self.location.setCurrentText("")
        self.location.lineEdit().setPlaceholderText("e.g. Chicago (used for grouping)")
        self.folder = QComboBox()
        self.folder.addItem("(top level)", None)
        for fid, path in sorted(db.folder_paths().items(), key=lambda kv: kv[1].lower()):
            self.folder.addItem(path, fid)
        self.folder.setCurrentIndex(max(0, self.folder.findData((dev or {}).get("folder_id", folder_id))))
        self.details = QLineEdit()
        self.details.setPlaceholderText("optional notes, e.g. rack 3, core switch")
        self.preset = QComboBox()
        self.preset.addItem("(choose to fill in the address)", "")
        from drivers.cloud import PRESETS
        for label, host in PRESETS:
            self.preset.addItem(f"{label}  -  {host}", (label, host))
        self.preset.currentIndexChanged.connect(self._preset)
        self.verify = QCheckBox("Verify SSL certificate")
        self.verify.setChecked(bool(db.get_setting("default_verify_ssl")) and not dev)   # default for new devices
        self.ha = QCheckBox("HA pair expected")
        self.enabled = QCheckBox("Enabled")
        self.enabled.setChecked(True)
        self.profile = QComboBox()
        self.profile.addItem("(none - use the values below)", None)
        for p in profiles.list_profiles():
            self.profile.addItem(p["name"], p["id"])
        self.profile.setToolTip("A credential profile supplies the username, secret and SNMP settings; "
                                "anything you fill in here overrides it.")
        self.jump = QComboBox()
        self.jump.addItem("(connect directly)", "")
        for d in db.list_devices():
            if d["name"] != self.dev.get("name"):
                self.jump.addItem(d["name"], d["name"])
        self.jump.setToolTip("Reach this device over SSH through another inventory device (SSH checks, "
                             "backups and the console).")
        self.proxy_mode = QComboBox()
        self.proxy_mode.addItem("Use the global setting (Settings > Proxy)", "default")
        self.proxy_mode.addItem("Connect directly (no proxy)", "none")
        self.proxy_mode.addItem("Use a proxy for this device", "custom")
        self.proxy_kind = QComboBox()
        for k, label in proxy.KINDS:
            self.proxy_kind.addItem(label, k)
        self.proxy_host, self.proxy_user, self.proxy_pw = QLineEdit(), QLineEdit(), QLineEdit()
        self.proxy_host.setPlaceholderText("proxy.example.com")
        self.proxy_user.setPlaceholderText("optional")
        self.proxy_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(8080)
        self.proxy_mode.currentIndexChanged.connect(lambda *_: self._proxy_rows())
        self.use_snmp = QCheckBox("This device also answers SNMP")
        self.snmp = SnmpFields()
        self.tags = QLineEdit()
        self.tags.setPlaceholderText("comma separated, e.g. core, wan, PCI")
        self.fields = QPlainTextEdit()
        self.fields.setPlaceholderText("one per line:  serial=FDO1234  owner=Network team  support=2027-06")
        self.fields.setFixedHeight(90)

        def page(rows):
            w = QWidget()
            f = QFormLayout(w)
            for label, widget in rows:
                f.addRow(label, widget)
            return w, f
        self.page_general, self.form = page((("Name", self.name), ("Vendor", self.vendor), ("Folder", self.folder),
                                             ("Location", self.location), ("Popular pages", self.preset), ("Host / DNS name", self.host),
                                             ("Port", self.port), ("Platform", self.platform),
                                             ("Details", self.details), ("", self.enabled)))
        self.page_access, self.access = page((("Credential profile", self.profile), ("Username", self.username),
                                              ("Password", self.secret), ("Site", self.site),
                                              ("Jump host", self.jump), ("Proxy", self.proxy_mode), ("Proxy type", self.proxy_kind),
                                              ("Proxy address", self.proxy_host), ("Proxy port", self.proxy_port),
                                              ("Proxy user", self.proxy_user), ("Proxy password", self.proxy_pw),
                                              ("", self.verify), ("", self.ha)))
        self.page_snmp = QWidget()
        sl = QVBoxLayout(self.page_snmp)
        sl.addWidget(self.use_snmp)
        sl.addWidget(self.snmp)
        sl.addStretch()
        self.page_more, self.more = page((("Tags", self.tags), ("Custom fields", self.fields)))
        self.secret_label = "Password"
        self.secret_field = self.secret
        self.tabs = QTabWidget()
        self.tabs.addTab(self.page_general, "General")
        self.tabs.addTab(self.page_access, "Access")
        self.tabs.addTab(self.page_snmp, "SNMP")
        self.tabs.addTab(self.page_more, "Tags and fields")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save |
                                   QDialogButtonBox.StandardButton.Cancel)
        test = buttons.addButton("Test connection", QDialogButtonBox.ButtonRole.ActionRole)
        test.clicked.connect(self.test)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(self.tabs)
        lay.addWidget(buttons)

        snmp_have = {}
        if dev:
            self.name.setText(dev["name"])
            self.vendor.setCurrentIndex(max(0, self.vendor.findData(dev["vendor"])))
            self.host.setText(dev["host"])
            self.location.setCurrentText(dev.get("location") or "")
            self.details.setText(dev.get("details") or "")
            self.port.setValue(dev.get("port") or 0)
            self.username.setText(dev.get("username") or "")
            self.site.setText(dev.get("site") or "default")
            self.verify.setChecked(bool(dev.get("verify_ssl")))
            self.ha.setChecked(bool(dev.get("ha_expected")))
            self.enabled.setChecked(bool(dev.get("enabled", 1)))
            self.profile.setCurrentIndex(max(0, self.profile.findData(dev.get("profile_id"))))
            self.tags.setText(dev.get("tags") or "")
            self.fields.setPlainText(fields_to_text(dev.get("fields")))
            try:
                jump = json.loads(dev.get("jump") or "{}")
            except ValueError:
                jump = {}
            self.jump.setCurrentIndex(max(0, self.jump.findData(jump.get("device", ""))))
            own_proxy = proxy.device_settings(dev)
            self.proxy_mode.setCurrentIndex(max(0, self.proxy_mode.findData(own_proxy.get("mode", "default"))))
            self.proxy_kind.setCurrentIndex(max(0, self.proxy_kind.findData(own_proxy.get("kind", "http"))))
            self.proxy_host.setText(own_proxy.get("host", ""))
            self.proxy_port.setValue(int(own_proxy.get("port") or 8080))
            self.proxy_user.setText(own_proxy.get("username", ""))
            if keyring.get_password(db.SERVICE, db.secret_name(dev["name"], "proxy")):
                self.proxy_pw.setPlaceholderText("saved; leave blank to keep")
            try:
                own = json.loads(dev.get("snmp") or "{}")
            except ValueError:
                own = {}
            self.use_snmp.setChecked(bool(own))
            self.snmp.load(own)
            snmp_have = {k: bool(keyring.get_password(db.SERVICE, db.secret_name(dev["name"], k)))
                         for k in ("snmp", "snmp_auth", "snmp_priv")}
        self.snmp.set_stored(snmp_have)
        self.use_snmp.toggled.connect(lambda on: self.snmp.setEnabled(on))
        self.vendor.currentIndexChanged.connect(lambda _: self.adapt(self.vendor.currentData()))
        self.adapt(self.vendor.currentData())

    def adapt(self, vendor):
        info = vendors.get(vendor)
        snmp_only = vendors.is_snmp(vendor)
        self.platform.clear()                                    # the platforms belong to the vendor
        keep = self.platform.currentData() or self.dev.get("platform")
        for key, label in info["platforms"]:
            self.platform.addItem(label, key)
        self.platform.setCurrentIndex(max(0, self.platform.findData(keep)))
        self.form.setRowVisible(self.platform, len(info["platforms"]) > 1)
        self.access.setRowVisible(self.username, info["username"])
        self.access.setRowVisible(self.site, bool(info["site"]))
        self.access.setRowVisible(self.ha, info["ha"])
        self.access.setRowVisible(self.verify, info["kind"] == "api")
        self.access.setRowVisible(self.jump, info["kind"] == "ssh")
        login = vendors.has_login(vendor)
        self.form.setRowVisible(self.preset, vendor == "cloud")
        self.host.setPlaceholderText({"cloud": "the status page's address, e.g. www.githubstatus.com",
                                      "wifi": "localhost (this computer)"}.get(vendor, ""))
        if vendor == "wifi" and not self.host.text().strip():
            self.host.setText("localhost")
        self.access.setRowVisible(self.profile, login)
        self.access.setRowVisible(self.secret, not snmp_only and login)
        self.tabs.setTabVisible(2, login)
        if info["site"]:
            self.access.labelForField(self.site).setText(info["site"])
        self.access.labelForField(self.secret).setText(info["secret"])
        self.use_snmp.setVisible(not snmp_only and login)
        self._proxy_rows()
        if snmp_only:
            self.use_snmp.setChecked(True)
        self.snmp.setEnabled(self.use_snmp.isChecked())

    def _proxy_rows(self):
        able = vendors.get(self.vendor.currentData()).get("kind") in ("ssh", "api", "status")     # not SNMP / UDP / local
        self.access.setRowVisible(self.proxy_mode, able)
        custom = able and self.proxy_mode.currentData() == "custom"
        for w in (self.proxy_kind, self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_pw):
            self.access.setRowVisible(w, custom)

    def _proxy_values(self):
        if vendors.get(self.vendor.currentData()).get("kind") not in ("ssh", "api", "status"):
            return ""
        mode = self.proxy_mode.currentData()
        if mode == "none":
            return {"mode": "none"}
        if mode == "custom":
            return {"mode": "custom", "kind": self.proxy_kind.currentData(), "host": self.proxy_host.text().strip(),
                    "port": self.proxy_port.value(), "username": self.proxy_user.text().strip()}
        return ""

    def proxy_secrets(self):
        v = self._proxy_values()
        return {"proxy": self.proxy_pw.text()} if v and v["mode"] == "custom" and self.proxy_pw.text() else {}

    def _preset(self, *_):
        picked = self.preset.currentData()
        if picked:
            label, host = picked
            self.host.setText(host)
            if not self.name.text().strip():
                self.name.setText(label)

    def values(self):
        v = self.vendor.currentData()
        snmp_on = (self.use_snmp.isChecked() and vendors.has_login(v)) or vendors.is_snmp(v)
        return {"id": self.dev.get("id"), "name": self.name.text().strip(), "vendor": v,
                "location": self.location.currentText().strip(),
                "folder_id": self.folder.currentData(),
                "details": self.details.text().strip(),
                "host": self.host.text().strip(), "port": self.port.value(),
                "platform": self.platform.currentData() or "",
                "username": self.username.text().strip(), "site": self.site.text().strip() or "default",
                "verify_ssl": int(self.verify.isChecked()), "ha_expected": int(self.ha.isChecked()),
                "enabled": int(self.enabled.isChecked()),
                "profile_id": self.profile.currentData(), "tags": self.tags.text().strip(),
                "fields": text_to_fields(self.fields.toPlainText()),
                "snmp": self.snmp.settings() if snmp_on else "",
                "jump": {"device": self.jump.currentData()} if self.jump.currentData() else "",
                "proxy": self._proxy_values()}

    def snmp_secrets(self):
        return self.snmp.secrets() if self.use_snmp.isChecked() or vendors.is_snmp(self.vendor.currentData()) else {}

    def accept(self):
        v = self.values()
        if not v["name"] or not v["host"]:
            QMessageBox.warning(self, "Missing data", "Name and host are required.")
            return
        if v["proxy"] and v["proxy"]["mode"] == "custom" and not v["proxy"]["host"]:
            QMessageBox.warning(self, "Missing data", "Enter the proxy's address, or choose another proxy option.")
            return
        try:
            self.host.setText(nettools.check_host(v["host"]))
        except ValueError as e:
            QMessageBox.warning(self, "Invalid host", str(e))
            return
        super().accept()

    def test(self):
        dev = self.values()
        if self.secret.text():
            dev["password"] = self.secret.text()
        dev["snmp"] = json.dumps(dev["snmp"]) if dev["snmp"] else ""
        dev["jump"] = json.dumps(dev["jump"]) if dev["jump"] else ""
        dev["proxy"] = json.dumps(dev["proxy"]) if dev["proxy"] else ""
        if self.proxy_pw.text():
            dev["_proxy_secret"] = self.proxy_pw.text()
        dev["_secrets"] = {k: s for k, s in self.snmp_secrets().items() if s}        # typed but not saved yet
        QApplication.setOverrideCursor(self.cursor())
        try:
            # a test must not move the error-counter baselines that real runs compare against
            res = run_one(dev, db.thresholds_for(dev), {**db.runtime_options(), "counter_mode": "total"})
        finally:
            QApplication.restoreOverrideCursor()
        errs = [r for r in res if r.status == "ERROR"]
        if not res:
            QMessageBox.warning(self, "Test", "Connected, but no check results were returned.")
        elif errs:
            QMessageBox.warning(self, "Test", "\n".join(f"{r.check}: {r.message}" for r in errs[:5]))
        else:
            ip = nettools.resolve_host(dev["host"])
            shown = dev["host"] if ip == dev["host"] else f"{dev['host']} ({ip})"
            QMessageBox.information(self, "Test", f"Connected to {shown}. {len(res)} check results returned.")


def fields_to_text(raw):
    try:
        data = json.loads(raw) if isinstance(raw, str) and raw else (raw or {})
    except ValueError:
        data = {}
    return "\n".join(f"{k}={v}" for k, v in data.items())


def text_to_fields(text):
    out = {}
    for line in (text or "").splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip():
            out[k.strip()] = v.strip()
    return out


class BulkEditDialog(QDialog):
    """Change one or more fields on several devices at once. Only ticked rows are applied."""

    def __init__(self, count, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Edit {count} device(s)")
        self.setMinimumWidth(460)
        self.rows = {}
        form = QFormLayout()

        def row(key, label, widget):
            box = QCheckBox(label)
            widget.setEnabled(False)
            box.toggled.connect(widget.setEnabled)
            self.rows[key] = (box, widget)
            form.addRow(box, widget)
        self.folder = QComboBox()
        self.folder.addItem("(top level)", None)
        for fid, path in sorted(db.folder_paths().items(), key=lambda kv: kv[1].lower()):
            self.folder.addItem(path, fid)
        self.location = QLineEdit()
        self.add_tags, self.remove_tags = QLineEdit(), QLineEdit()
        self.add_tags.setPlaceholderText("tags to add, comma separated")
        self.remove_tags.setPlaceholderText("tags to remove")
        self.profile = QComboBox()
        self.profile.addItem("(none)", None)
        for p in profiles.list_profiles():
            self.profile.addItem(p["name"], p["id"])
        self.jump = QComboBox()
        self.jump.addItem("(connect directly)", "")
        for d in db.list_devices():
            self.jump.addItem(d["name"], d["name"])
        self.enabled = QComboBox()
        self.enabled.addItem("Enabled", True)
        self.enabled.addItem("Disabled", False)
        row("folder_id", "Move to folder", self.folder)
        row("location", "Set location", self.location)
        row("add_tags", "Add tags", self.add_tags)
        row("remove_tags", "Remove tags", self.remove_tags)
        row("profile_id", "Credential profile", self.profile)
        row("jump", "Jump host", self.jump)
        row("enabled", "Checks", self.enabled)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Tick what to change; everything else stays as it is."))
        lay.addLayout(form)
        lay.addWidget(buttons)

    def operations(self):
        ops = {}
        for key, (box, w) in self.rows.items():
            if not box.isChecked():
                continue
            ops[key] = (w.currentData() if isinstance(w, QComboBox) else w.text().strip())
        return ops


ROLE = Qt.ItemDataRole.UserRole


class DeviceTree(QTreeWidget):
    """The inventory tree. Dropping on a folder moves the dragged devices and folders into it."""
    moved = Signal(list, object)          # [("device"|"folder", id), ...], target folder id (None = top level)

    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def mousePressEvent(self, e):
        if not self.indexAt(e.position().toPoint()).isValid():     # click on empty space deselects
            self.clearSelection()
            self.setCurrentItem(None)
        super().mousePressEvent(e)

    def dropEvent(self, e):
        # Qt would move the tree items itself; we move the data instead and rebuild from it.
        target = self.itemAt(e.position().toPoint())
        tid = None
        if target is not None:
            kind, ident = self.owner.kind_of(target)
            if kind == "folder":
                tid = ident
            elif kind == "device":
                tid = self.owner.payload[target.data(0, ROLE)].get("folder_id")
            else:
                e.ignore()
                return
        moves = [k for k in (self.owner.kind_of(i) for i in self.selectedItems()) if k[0] in ("device", "folder")]
        e.setDropAction(Qt.DropAction.IgnoreAction)
        e.accept()
        if moves:
            self.moved.emit(moves, tid)


class InventoryTab(QWidget):
    changed = Signal()
    open_ssh = Signal(dict)
    open_details = Signal(dict)
    COLS = ["Name", "Vendor", "Platform", "Location", "Host", "Site", "Details", "Tags", "Enabled"]

    def __init__(self):
        super().__init__()
        self.payload = {}                       # item key -> device dict / folder id / group name
        self._building = False
        self.expanded = set(db.get_setting("inventory_expanded"))
        self.vendor_sel, self.location_sel, self.tag_sel = set(), set(), set()    # empty = all; location "" = none
        self.filter_btn = QToolButton()
        self.filter_btn.setIcon(self._filter_icon())
        self.filter_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.filter_btn.setStyleSheet("QToolButton::menu-indicator { image: none; }")
        self.filter_menu = QMenu(self.filter_btn)
        self.filter_menu.aboutToShow.connect(self._build_filter_menu)
        self.filter_btn.setMenu(self.filter_menu)
        self._update_filter_btn()

        self.table = DeviceTree(self)           # (named 'table' for older callers)
        self.table.setColumnCount(len(self.COLS))
        self.table.setHeaderLabels(self.COLS)
        self.table.header().setStretchLastSection(True)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setUniformRowHeights(True)
        self.table.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_menu)
        self.table.itemSelectionChanged.connect(self.update_buttons)
        self.table.itemDoubleClicked.connect(self.double_clicked)
        self.table.itemExpanded.connect(lambda it: (self.remember(it, True), self._autosize()))
        self.table.itemCollapsed.connect(lambda it: (self.remember(it, False), self._autosize()))
        self.table.moved.connect(self.handle_moves)
        QShortcut(QKeySequence("F2"), self.table, activated=self.rename_folder)
        QShortcut(QKeySequence("Delete"), self.table, activated=self.delete)

        bar = QHBoxLayout()
        self.buttons = {}
        for text, fn in (("Add", self.add), ("Edit", self.edit), ("Details", self.show_details), ("Delete", self.delete),
                         ("New folder", self.new_folder), ("Import...", self.import_file),
                         ("Export...", self.export_file)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            bar.addWidget(b)
            self.buttons[text] = b
        for text, fn in (("Expand all", self.expand_all), ("Collapse all", self.collapse_all)):
            b = QPushButton(text)
            b.clicked.connect(lambda _=False, fn=fn: fn())
            bar.addWidget(b)
            self.buttons[text] = b
        bar.addStretch()
        bar.addWidget(self.filter_btn)
        lay = QVBoxLayout(self)
        lay.addLayout(bar)
        lay.addWidget(self.table)
        self.refresh()

    # ---------- building the tree ----------
    def _icon(self, name, accent=False):
        t = theme.current()
        if not t:
            return QIcon()
        key = (name, t["accent"] if accent else t["muted"])
        cache = self.__dict__.setdefault("_icons", {})
        if key not in cache:
            cache[key] = icons.icon(name, key[1])
        return cache[key]

    @staticmethod
    def _filter_icon():
        from ui.widgets import filter_icon
        return filter_icon()

    def _build_filter_menu(self):
        """Vendor and Location only filter the folder tree; they never regroup it.
        Several values can be ticked: any of the ticked vendors AND any of the ticked locations."""
        m = self.filter_menu
        m.clear()
        devs = db.list_devices()
        for title, attr, values, shown in (
                ("Vendor", "vendor_sel", {d["vendor"] for d in devs}, display.vendor_name),
                ("Location", "location_sel", {d["location"] for d in devs if d.get("location")}, str),
                ("Tag", "tag_sel", {t for d in devs for t in db.split_tags(d.get("tags"))}, str)):
            sub = m.addMenu(title)
            opts = [(shown(v), v) for v in sorted(values, key=lambda v: shown(v).lower())]
            if attr == "location_sel" and any(not d.get("location") for d in devs):
                opts.append(("(none)", ""))
            for text, val in opts:
                box = QCheckBox(text)                 # a widget action keeps the menu open while ticking
                box.setChecked(val in getattr(self, attr))
                box.toggled.connect(lambda on, attr=attr, val=val: self.toggle_filter(attr, val, on))
                act = QWidgetAction(sub)
                act.setDefaultWidget(box)
                sub.addAction(act)
        m.addSeparator()
        m.addAction("Clear filter", lambda: self.set_filter(None, None)).setEnabled(self.filtering())

    def toggle_filter(self, attr, val, on):
        sel = getattr(self, attr)
        (sel.add if on else sel.discard)(val)
        self._update_filter_btn()
        self.refresh()

    def set_filter(self, attr, val):
        """Replace one filter with a single value (None = all), or clear both with attr=None."""
        if attr is None:
            self.vendor_sel, self.location_sel, self.tag_sel = set(), set(), set()
        else:
            setattr(self, attr, set() if val is None else {val})
        self._update_filter_btn()
        self.refresh()

    def _update_filter_btn(self):
        parts = [display.vendor_name(v) for v in sorted(self.vendor_sel)] + \
                [loc or "(no location)" for loc in sorted(self.location_sel)] + sorted(self.tag_sel)
        self.filter_btn.setToolTip("Filter: " + ", ".join(parts) if parts else "Filter by vendor or location")
        self.filter_btn.setText(f" {len(parts)}" if parts else "")
        self.filter_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon if parts
                                           else Qt.ToolButtonStyle.ToolButtonIconOnly)

    def expand_all(self):
        self.table.expandAll()
        self._autosize()

    def collapse_all(self):
        self.table.collapseAll()

    def _visible(self, devs):
        v, loc, tg = self.vendor_sel, self.location_sel, {x.lower() for x in self.tag_sel}
        return [d for d in devs if (not v or d["vendor"] in v) and (not loc or (d.get("location") or "") in loc)
                and (not tg or tg & {x.lower() for x in db.split_tags(d.get("tags"))})]

    def kind_of(self, item):
        key = item.data(0, ROLE) or ""
        kind, _, ident = key.partition(":")
        if kind == "folder":
            return "folder", int(ident)
        if kind == "device":
            return "device", int(ident)
        return "group", ident

    def _device_values(self, d):
        site = d["site"] if vendors.get(d["vendor"]).get("site") else "N/A"
        platform = display.platform_name(d.get("platform") or vendors.default_platform(d["vendor"])) \
            if vendors.platform_keys(d["vendor"]) else "N/A"
        return [d["name"], display.vendor_name(d["vendor"]), platform, d.get("location") or "", d["host"], site,
                d.get("details") or "", d.get("tags") or "", "yes" if d["enabled"] else "no"]

    def _device_item(self, d):
        it = QTreeWidgetItem(self._device_values(d))
        key = f"device:{d['id']}"
        it.setData(0, ROLE, key)
        self.payload[key] = d
        it.setIcon(0, self._icon("device"))
        it.setFlags((it.flags() | Qt.ItemFlag.ItemIsDragEnabled) & ~Qt.ItemFlag.ItemIsDropEnabled)
        return it

    def folders_mode(self):
        return True

    def filtering(self):
        return bool(self.vendor_sel or self.location_sel or self.tag_sel)

    def refresh(self):
        devs = self._visible(db.list_devices())
        self._building = True
        self.table.blockSignals(True)            # clearing announces 'selection changed' for rows being deleted
        self.table.clear()
        self.payload = {}
        self.table.setDragEnabled(True)
        self.table.setAcceptDrops(True)
        bold = QFont()
        bold.setBold(True)
        self._build_folders(devs, bold)
        for i in range(len(self.COLS)):
            self.table.resizeColumnToContents(i)
        self._building = False
        self.table.clearSelection()
        self.table.setCurrentItem(None)
        self.table.blockSignals(False)
        self.update_buttons()

    def _build_folders(self, devs, bold):
        folders = db.list_folders()
        known = {f["id"] for f in folders}
        kids, by_folder = {}, {}
        for f in folders:
            kids.setdefault(f["parent_id"] if f["parent_id"] in known else None, []).append(f)
        for d in devs:
            fid = d.get("folder_id")
            by_folder.setdefault(fid if fid in known else None, []).append(d)

        def count(fid):
            return len(by_folder.get(fid, [])) + sum(count(c["id"]) for c in kids.get(fid, []))

        def fill(parent_item, fid):
            for f in sorted(kids.get(fid, []), key=lambda f: f["name"].lower()):
                if self.filtering() and not count(f["id"]):
                    continue                      # while filtering, hide folders with nothing to show
                item = QTreeWidgetItem([f"{f['name']}  ({count(f['id'])})"])
                key = f"folder:{f['id']}"
                item.setData(0, ROLE, key)
                self.payload[key] = f
                item.setFont(0, bold)
                item.setIcon(0, self._icon("folder", True))
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsDragEnabled | Qt.ItemFlag.ItemIsDropEnabled)
                (parent_item.addChild if parent_item else self.table.addTopLevelItem)(item)
                fill(item, f["id"])
                item.setExpanded(f["id"] in self.expanded or self.filtering())
            for d in sorted(by_folder.get(fid, []), key=lambda d: d["name"].lower()):
                (parent_item.addChild if parent_item else self.table.addTopLevelItem)(self._device_item(d))

        fill(None, None)

    def _autosize(self):
        """Keep every column wide enough for what is showing, so opening a folder never leaves text cut off."""
        if not self._building:
            for i in range(len(self.COLS) - 1):
                self.table.resizeColumnToContents(i)

    def remember(self, item, open_):
        """Keep which folders are open, across restarts."""
        if self._building:
            return
        kind, ident = self.kind_of(item)
        if kind == "folder":
            (self.expanded.add if open_ else self.expanded.discard)(ident)
            db.set_setting("inventory_expanded", sorted(self.expanded))

    def expand_folder(self, fid):
        """Open a folder and the ones above it."""
        for item in self._all_items():
            if self.kind_of(item) == ("folder", fid):
                while item is not None:
                    item.setExpanded(True)
                    item = item.parent()
                return

    def _all_items(self):
        out, todo = [], [self.table.topLevelItem(i) for i in range(self.table.topLevelItemCount())]
        while todo:
            it = todo.pop()
            out.append(it)
            todo.extend(it.child(i) for i in range(it.childCount()))
        return out

    def select_device(self, dev_id):
        for it in self._all_items():
            if self.kind_of(it) == ("device", dev_id):
                p = it.parent()
                while p is not None:
                    p.setExpanded(True)
                    p = p.parent()
                self.table.setCurrentItem(it)
                it.setSelected(True)
                return

    # ---------- selection ----------
    def selected_devices(self):
        return [self.payload[i.data(0, ROLE)] for i in self.table.selectedItems()
                if self.kind_of(i)[0] == "device" and i.data(0, ROLE) in self.payload]

    def selected_folders(self):
        return [self.kind_of(i)[1] for i in self.table.selectedItems() if self.kind_of(i)[0] == "folder"]

    def selected(self):
        """The one selected device, or None (no selection, several, or a folder)."""
        items = self.table.selectedItems()
        devs = self.selected_devices()
        return devs[0] if len(items) == 1 and len(devs) == 1 else None

    def current_folder(self):
        """Where a new folder or device should go: the selected folder, or the selected device's folder."""
        folders, devs = self.selected_folders(), self.selected_devices()
        if len(folders) == 1 and not devs:
            return folders[0]
        if len(devs) == 1 and not folders:
            return devs[0].get("folder_id")
        return None

    def update_buttons(self):
        self.buttons["Edit"].setEnabled(self.selected() is not None)
        self.buttons["Details"].setEnabled(self.selected() is not None)
        self.buttons["Delete"].setEnabled(bool(self.selected_devices()) or len(self.selected_folders()) == 1)

    def double_clicked(self, item, _col):
        if self.kind_of(item)[0] == "device":
            self.edit()

    # ---------- devices ----------
    def _save(self, dev, secret, old_name=None, extra_secrets=None):
        try:
            db.save_device(dev)
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Duplicate", f"A device named '{dev['name']}' already exists.")
            return
        if old_name and old_name != dev["name"]:
            db.move_device_secrets(old_name, dev["name"])          # password, token and SNMP secrets follow the name
        if secret:
            db.set_secret(dev["name"], secret)
        for kind, value in (extra_secrets or {}).items():
            if value:
                db.set_secret(db.secret_name(dev["name"], kind), value)
        audit.log("device " + ("edited" if old_name else "added"), dev["name"])
        if dev.get("folder_id"):
            self.expanded.add(dev["folder_id"])
        self.refresh()
        self.changed.emit()

    def add(self):
        dlg = DeviceDialog(parent=self, folder_id=self.current_folder() if self.folders_mode() else None)
        if dlg.exec():
            self._save(dlg.values(), dlg.secret.text(), extra_secrets={**dlg.snmp_secrets(), **dlg.proxy_secrets()})

    def edit(self):
        d = self.selected()
        if d:
            self.edit_device(d)

    def edit_device(self, d):
        dlg = DeviceDialog(d, self)
        if dlg.exec():
            self._save(dlg.values(), dlg.secret.text(), old_name=d["name"], extra_secrets={**dlg.snmp_secrets(), **dlg.proxy_secrets()})

    def show_details(self):
        d = self.selected()
        if d:
            self.open_details.emit(d)

    def delete(self):
        """Delete the selected devices, or the selected folder (its contents move up, nothing else is lost)."""
        devs = self.selected_devices()
        if devs:
            what = f"{len(devs)} devices" if len(devs) > 1 else devs[0]["name"]
            if QMessageBox.question(self, "Delete", f"Delete {what}?") != QMessageBox.StandardButton.Yes:
                return
            for d in devs:
                db.delete_device(d["id"])
                db.delete_device_secrets(d["name"])
                audit.log("device deleted", d["name"])
            self.refresh()
            self.changed.emit()
        elif len(self.selected_folders()) == 1:
            self.delete_folder()

    def open_in_ssh(self):
        d = self.selected()
        if d:
            self.open_ssh.emit(d)

    # ---------- folders ----------
    def _ask_name(self, title, label, text=""):
        name, ok = QInputDialog.getText(self, title, label, text=text)
        return name.strip() if ok else None

    def new_folder(self, parent_id=None, use_selection=True):
        if not self.folders_mode():
            return
        parent = self.current_folder() if use_selection and parent_id is None else parent_id
        name = self._ask_name("New folder", "Folder name:")
        if not name:
            return
        try:
            fid = db.create_folder(name, parent)
        except ValueError as e:
            QMessageBox.warning(self, "New folder", str(e))
            return
        self.expanded.update({fid} | ({parent} if parent else set()))
        db.set_setting("inventory_expanded", sorted(self.expanded))
        self.refresh()
        self.changed.emit()

    def rename_folder(self):
        folders = self.selected_folders()
        if len(folders) != 1 or self.selected_devices():
            return
        fid = folders[0]
        name = self._ask_name("Rename folder", "New name:", self.payload[f"folder:{fid}"]["name"])
        if not name:
            return
        try:
            db.rename_folder(fid, name)
        except ValueError as e:
            QMessageBox.warning(self, "Rename folder", str(e))
            return
        self.refresh()
        self.changed.emit()

    def delete_folder(self):
        folders = self.selected_folders()
        if len(folders) != 1:
            return
        fid = folders[0]
        f = self.payload[f"folder:{fid}"]
        kids = sum(1 for x in db.list_folders() if x["parent_id"] == fid)
        devs = sum(1 for d in db.list_devices() if d.get("folder_id") == fid)
        where = db.folder_paths().get(f["parent_id"], "") or "the top level"
        if QMessageBox.question(self, "Delete folder", f"Delete the folder '{f['name']}'?\n\nIts {devs} device(s) and "
                                f"{kids} subfolder(s) move up to {where}. No device is deleted.") \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            db.delete_folder(fid)
        except ValueError as e:
            QMessageBox.warning(self, "Delete folder", str(e))
            return
        self.expanded.discard(fid)
        self.refresh()
        self.changed.emit()

    def move_selected_to(self, target_id):
        moves = [("device", d["id"]) for d in self.selected_devices()] + [("folder", i) for i in self.selected_folders()]
        self.handle_moves(moves, target_id)

    def handle_moves(self, moves, target_id):
        """Move devices and folders into a folder (None = top level), reporting anything that cannot move."""
        problems, dev_ids = [], []
        for kind, ident in moves:
            if kind == "device":
                dev_ids.append(ident)
            else:
                try:
                    db.move_folder(ident, target_id)
                except ValueError as e:
                    problems.append(str(e))
        db.move_devices(dev_ids, target_id)
        if target_id is not None:
            self.expanded.add(target_id)
            db.set_setting("inventory_expanded", sorted(self.expanded))
        self.refresh()
        self.changed.emit()
        if problems:
            QMessageBox.warning(self, "Move", "\n".join(sorted(set(problems))))

    # ---------- right-click menu ----------
    def show_menu(self, pos):
        item = self.table.itemAt(pos)
        if item is not None and not item.isSelected():
            self.table.clearSelection()
            item.setSelected(True)
        devs, folders = self.selected_devices(), self.selected_folders()
        menu = QMenu(self)
        if devs or folders:
            if len(devs) == 1 and not folders:
                menu.addAction("Details...", self.show_details)
                menu.addAction("Edit...", self.edit)
                menu.addAction("Open SSH console", self.open_in_ssh)
            if devs:
                menu.addAction("Edit selected..." if len(devs) > 1 else "Edit tags, folder, profile...", self.bulk_edit)
            if len(folders) == 1 and not devs:
                menu.addAction("New subfolder...", lambda: self.new_folder(folders[0], use_selection=False))
                menu.addAction("Rename...", self.rename_folder)
            if self.folders_mode():
                move = menu.addMenu("Move to folder")
                banned = set().union(*(db.folder_descendants(f) for f in folders)) if folders else set()
                move.addAction("(top level)", lambda: self.move_selected_to(None))
                for fid, path in sorted(db.folder_paths().items(), key=lambda kv: kv[1].lower()):
                    if fid not in banned:
                        move.addAction(path, lambda fid=fid: self.move_selected_to(fid))
            menu.addSeparator()
            menu.addAction("Delete folder..." if folders and not devs else "Delete...", self.delete)
        else:
            if self.folders_mode():
                menu.addAction("New folder...", lambda: self.new_folder(None, use_selection=False))
        menu.addSeparator()
        menu.addAction("Expand all", self.expand_all)
        menu.addAction("Collapse all", self.collapse_all)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    # ---------- export ----------
    def export_file(self):
        """Write the inventory (or just the selected devices) to a file. Passwords and keys are never included."""
        devs = self.selected_devices() or self._visible(db.list_devices())
        path, _ = QFileDialog.getSaveFileName(self, "Export devices", "devices.csv",
                                              "CSV (*.csv);;JSON (*.json);;YAML (*.yaml)")
        if not path:
            return
        try:
            importer.write_rows(importer.export_rows(devs), path)
        except (ValueError, OSError) as e:
            QMessageBox.warning(self, "Export failed", str(e))
            return
        audit.log("inventory exported", f"{len(devs)} device(s) to {path}")
        QMessageBox.information(self, "Export", f"Wrote {len(devs)} device(s) to:\n{path}\n\nPasswords, tokens and "
                                "SNMP communities are not included.")

    # ---------- bulk edit ----------
    def bulk_edit(self):
        devs = self.selected_devices()
        if not devs:
            return
        dlg = BulkEditDialog(len(devs), self)
        if dlg.exec():
            try:
                n = bulk.apply(devs, dlg.operations())
            except ValueError as e:
                QMessageBox.warning(self, "Edit devices", str(e))
                return
            self.refresh()
            self.changed.emit()
            QMessageBox.information(self, "Edit devices", f"Changed {n} of {len(devs)} device(s).")

    # ---------- import ----------
    def import_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import devices", "", importer.FILE_FILTER)
        if not path:
            return
        try:
            rows = importer.load_rows(path)
        except Exception as e:                       # unreadable file, bad syntax, wrong shape
            QMessageBox.warning(self, "Import failed", f"Could not read the file:\n{e}")
            return
        existing = {d["name"].lower() for d in db.list_devices()}
        added, dupes, bad = 0, [], []
        for i, raw in enumerate(rows, start=1):
            label = importer.label(raw, i)
            try:
                dev, secret = importer.normalize(raw)
                if dev["name"].lower() in existing:
                    dupes.append(dev["name"])
                    continue
                community = importer.finalize(dev)
                dev["folder_id"] = db.ensure_folder_path(dev.pop("folder", ""))
                db.save_device(dev)
            except sqlite3.IntegrityError:
                dupes.append(dev["name"])
                continue
            except ValueError as e:
                bad.append(f"{label}: {e}")
                continue
            existing.add(dev["name"].lower())
            if secret:
                db.set_secret(dev["name"], secret)
            if community:
                db.set_secret(db.secret_name(dev["name"], "snmp"), community)
            added += 1
        self.refresh()
        self.changed.emit()
        lines = [f"Imported {added} of {len(rows)} device(s)."]
        if dupes:
            lines.append(f"\nAlready in the inventory (skipped): {', '.join(dupes)}")
        if bad:
            lines.append(f"\nSkipped, with reasons ({len(bad)}):")
            lines += [f"  \u2022 {b}" for b in bad[:12]] + ([f"  ...and {len(bad) - 12} more"] if len(bad) > 12 else [])
        QMessageBox.information(self, "Import", "\n".join(lines))
