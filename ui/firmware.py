"""Tools > File transfer > Firmware Transfer: a page of six steps for putting a firmware image on Cisco devices.
Devices, Image server, Check devices, Clean up, Images, Transfer. The work is in core/firmware.py; this is the page."""
import threading

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QPlainTextEdit,
                               QMessageBox, QProgressBar, QPushButton, QRadioButton, QSpinBox, QStackedWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem,
                               QVBoxLayout, QWidget)

from core import db, firmware as fw
from ui.finder import FilterButton, SearchBox, device_sections, shown_devices
from ui.tools import _row
from ui.tools2 import _muted, _primary, _table

STEPS = ("Devices", "Image server", "Check devices", "Clean up", "Images", "Transfer")
PICK_ORG = "Pick an organization in the sidebar first."
SAVE_TITLE = "Save configuration on {device}?"
SAVE_ASK = ("install add needs the running configuration saved first. These lines are in the running configuration but not the "
            "startup configuration (red: only in startup, green: only in running):")
SAVE_NO_DIFF = "The two configurations differ only in timestamps or masked passwords, but the switch still asks for a save."
SAVE_BUTTON = "Save and run install add"
AT_ONCE = "Simultaneous Transfers"
AT_ONCE_TIP = ("How many devices copy their image at the same time. Each one pulls the whole image from the image server, so more at once "
               "can slow every copy on a slow link. A change applies to devices that are still waiting.")


class Job(QThread):
    """Runs one function off the window's thread and hands back (result, error)."""
    done = Signal(object, object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            result, error = self.fn(), None
        except Exception as e:                       # noqa: BLE001  (every failure is shown on the page)
            result, error = None, e
        self.done.emit(result, error)


# =============================================================================== step 1: Devices
class DevicesStep(QWidget):
    changed = Signal()
    GROUP = Qt.ItemDataRole.UserRole + 1                # the row that opens to show the devices that are not Cisco

    def __init__(self):
        super().__init__()
        self.find = SearchBox("Search devices", "Type part of a name, address, vendor, location, tag or detail. Several words must all match.",
                              page=self)
        self.funnel = FilterButton(lambda: device_sections(db.list_devices(enabled_only=True)))
        self.list = QListWidget()
        self.tick_all, self.untick_all = QPushButton("Tick all"), QPushButton("Untick all")
        self._others_open = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(_muted("Tick the Cisco devices to transfer firmware to. Devices of other vendors are listed but cannot be ticked."))
        finder = QHBoxLayout()
        finder.addStretch(1)
        finder.addWidget(self.find, 1)                 # on the right, as on Inventory and History
        finder.addWidget(self.funnel)
        lay.addLayout(finder)
        lay.addWidget(self.list, 1)
        bar = QHBoxLayout()
        bar.addWidget(self.tick_all)
        bar.addWidget(self.untick_all)
        bar.addStretch()
        lay.addLayout(bar)
        self.find.textChanged.connect(lambda _t: self.fill())
        self.funnel.changed.connect(self.fill)
        self.list.itemClicked.connect(self._clicked)
        self.list.itemChanged.connect(lambda _it: self.changed.emit())
        self.tick_all.clicked.connect(lambda: self._tick(True))
        self.untick_all.clicked.connect(lambda: self._tick(False))

    def devices(self):
        return shown_devices(db.list_devices(enabled_only=True), self.find, self.funnel)

    def fill(self):
        ticked = set(self.ticked_keys())
        self.list.blockSignals(True)
        self.list.clear()
        others = []
        for d in self.devices():
            ok, why = fw.eligible(d)
            if not ok:
                others.append((d, why))
                continue
            it = QListWidgetItem(f"{db.label_org(d['key'])}  ({d.get('host') or ''}, {fw.PLATFORM_NAMES[fw.platform_of(d)]})")
            it.setData(Qt.ItemDataRole.UserRole, d["key"])
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Checked if d["key"] in ticked else Qt.CheckState.Unchecked)
            self.list.addItem(it)
        if len(others) == 1:
            self._add_other(*others[0], indent=False)
        elif others:
            head = QListWidgetItem(("▾ " if self._others_open else "▸ ") + f"{len(others)} devices are not Cisco "
                                   f"(click to {'hide' if self._others_open else 'show'})")
            head.setData(self.GROUP, True)
            head.setFlags(Qt.ItemFlag.ItemIsEnabled)
            f = head.font()
            f.setBold(True)
            head.setFont(f)
            self.list.addItem(head)
            if self._others_open:
                for d, why in others:
                    self._add_other(d, why, indent=True)
        self.list.blockSignals(False)
        self.changed.emit()

    def _add_other(self, d, why, indent):
        it = QListWidgetItem(("    " if indent else "") + db.label_org(d["key"]))
        it.setData(Qt.ItemDataRole.UserRole, d["key"])
        it.setFlags(Qt.ItemFlag.NoItemFlags)                 # shown, greyed, with the reason as its tooltip
        it.setToolTip(why)
        self.list.addItem(it)

    def _clicked(self, item):
        if item.data(self.GROUP):
            self._others_open = not self._others_open
            self.fill()

    def _tick(self, on):
        self.list.blockSignals(True)
        for i in range(self.list.count()):
            it = self.list.item(i)
            if it.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                it.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
        self.list.blockSignals(False)
        self.changed.emit()

    def ticked_keys(self):
        return [self.list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.list.count())
                if self.list.item(i).checkState() == Qt.CheckState.Checked]

    def chosen(self):
        """The ticked devices, as the inventory has them."""
        keys = set(self.ticked_keys())
        return [d for d in db.list_devices(enabled_only=True) if d["key"] in keys and fw.eligible(d)[0]]

    def ready(self):
        return bool(self.ticked_keys())

    def reset(self):
        self.list.blockSignals(True)
        self.list.clear()
        self.list.blockSignals(False)
        self.fill()


# =============================================================================== step 2: Image server
class ServerStep(QWidget):
    changed = Signal()

    def __init__(self, servers):
        """servers(): {'ftp': .., 'sftp': .., 'tftp': ..}: Toner's own file servers (None when that page has none running)."""
        super().__init__()
        self.servers = servers
        self.files, self.listed_for, self.job = [], None, None
        self.own_btn, self.other_btn = QRadioButton("Toner's own file server"), QRadioButton("Another server")
        group = QButtonGroup(self)
        group.addButton(self.own_btn)
        group.addButton(self.other_btn)
        self.own_btn.setChecked(True)

        # Toner's own
        self.own = QComboBox()
        self.own_none = _muted(fw.NONE_RUNNING)
        self.address = QComboBox()
        self.address.setEditable(True)
        own_box = QWidget()
        ol = QVBoxLayout(own_box)
        ol.setContentsMargins(0, 0, 0, 0)
        ol.addWidget(self.own)
        ol.addWidget(self.own_none)
        ol.addLayout(_row("This computer's address as the devices see it", self.address))

        # another server
        self.proto = QComboBox()
        for p in fw.OTHER_PROTOS:
            self.proto.addItem(fw.PROTO_NAMES[p], p)
        self.host = QLineEdit()
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(21)
        self.anonymous = QCheckBox("Anonymous login")
        self.user, self.password = QLineEdit(), QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_pw = QCheckBox("Show")
        self.folder = QLineEdit()
        self.folder.setPlaceholderText("/firmware")
        self.names = QPlainTextEdit()                        # TFTP, HTTP, HTTPS: no listing, so the names are typed
        self.names.setPlaceholderText("asa9-16-4-smp-k8.bin")
        self.names.setMaximumHeight(90)
        self.insecure = QCheckBox("Don't check the server's certificate from this computer (self-signed)")
        self.remember = QCheckBox("Remember this server and login for this organization")
        self.remember.setChecked(True)
        other_box = QWidget()
        xl = QVBoxLayout(other_box)
        xl.setContentsMargins(0, 0, 0, 0)
        xl.addLayout(_row("Protocol", self.proto, "Host", self.host, "Port", self.port))
        self.login_box = QWidget()                           # hidden for TFTP, which has no login
        self.login_box.setLayout(_row(self.anonymous, "User name", self.user, "Password", self.password, self.show_pw))
        self.login_box.layout().setContentsMargins(0, 0, 0, 0)
        xl.addWidget(self.login_box)
        xl.addLayout(_row("Folder", self.folder))
        self.names_box = QWidget()
        self.names_box.setLayout(_row("Image files on the server, one per line", self.names))
        self.names_box.layout().setContentsMargins(0, 0, 0, 0)
        xl.addWidget(self.names_box)
        xl.addWidget(self.insecure)
        xl.addWidget(self.remember)
        self.where = QStackedWidget()
        self.where.addWidget(own_box)
        self.where.addWidget(other_box)

        self.vrf = QLineEdit("management")
        self.vrf_row = QWidget()
        vl = QHBoxLayout(self.vrf_row)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.addLayout(_row("NX-OS devices copy through VRF", self.vrf))
        self.vrf_row.setVisible(False)

        self.test = _primary("Test and list files")
        self.status = _muted("")
        self.table = _table(["Name", "Size", "Modified"])

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(_muted("Where the firmware images are. Each device pulls its image from here itself, so the server must be "
                             "reachable from the devices, not only from this computer. Over HTTPS each device checks the server's "
                             "certificate its own way; Toner cannot change that."))
        lay.addLayout(_row(self.own_btn, self.other_btn))
        lay.addWidget(self.where)
        lay.addWidget(self.vrf_row)
        lay.addLayout(_row(self.test))
        lay.addWidget(self.status)
        lay.addWidget(self.table, 1)

        self.own_btn.toggled.connect(self._which)
        self.proto.currentIndexChanged.connect(self._proto_changed)
        self.anonymous.toggled.connect(self._anonymous)
        self.show_pw.toggled.connect(lambda on: self.password.setEchoMode(QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        self.test.clicked.connect(self.start_test)
        for w in (self.host, self.user, self.password, self.folder, self.names):
            w.textChanged.connect(self._edited)
        for sig in (self.own.currentIndexChanged, self.address.currentTextChanged, self.port.valueChanged, self.anonymous.toggled,
                    self.insecure.toggled):
            sig.connect(self._edited)
        self.load()

    # ---- filling in
    def load(self):
        """What the organization remembered, and the servers Toner is running now."""
        saved = fw.saved() or {"proto": "ftp", "host": "", "port": 21, "anonymous": False, "user": "", "password": "", "folder": "",
                               "files": [], "insecure": False}
        self.proto.setCurrentIndex(max(0, self.proto.findData(saved["proto"])))
        self.host.setText(saved["host"])                     # (always set: another organization's login must never stay on screen)
        self.port.setValue(saved["port"] or fw.DEFAULT_PORTS[saved["proto"]])
        self.anonymous.setChecked(saved["anonymous"])
        self.user.setText(saved["user"])
        self.password.setText(saved["password"])
        self.show_pw.setChecked(False)
        self.folder.setText(saved["folder"])
        self.names.setPlainText("\n".join(saved["files"]))
        self.insecure.setChecked(saved["insecure"])
        self._proto_changed()
        self.remember.setChecked(True)
        self.vrf.setText("management")
        self.files, self.listed_for = [], None
        self.table.setRowCount(0)
        self.status.setText("")
        (self.other_btn if saved["host"] else self.own_btn).setChecked(True)
        self.address.clear()
        self.address.addItems(fw.addresses())
        self.reload_own()
        self._which()
        self._anonymous(self.anonymous.isChecked())

    def reload_own(self):
        keep = self.own.currentData()
        self.own.blockSignals(True)
        self.own.clear()
        for text, proto, _srv in fw.own_choices(self.servers()):
            self.own.addItem(text, proto)
        i = self.own.findData(keep)
        self.own.setCurrentIndex(i if i >= 0 else 0)
        self.own.blockSignals(False)
        none = self.own.count() == 0
        self.own.setVisible(not none)
        self.own_none.setVisible(none)
        self._sync()

    def _which(self, *_):
        self.where.setCurrentIndex(0 if self.own_btn.isChecked() else 1)
        self._edited()

    def _proto_changed(self, *_):
        p = self.proto.currentData()
        if self.port.value() in fw.DEFAULT_PORTS.values():
            self.port.setValue(fw.DEFAULT_PORTS[p])
        self.anonymous.setVisible(p == "ftp")
        if p != "ftp":
            self.anonymous.setChecked(False)
        self.login_box.setVisible(p != "tftp")
        self.names_box.setVisible(p in fw.NAMED)
        self.insecure.setVisible(p == "https")
        self.test.setText("Check files" if p in fw.NAMED else "Test and list files")
        self._edited()

    def _anonymous(self, on):
        self.user.setEnabled(not on)
        self.password.setEnabled(not on)
        self.show_pw.setEnabled(not on)

    def set_platforms(self, platforms):
        """The VRF box shows when an NX-OS device is ticked."""
        self.vrf_row.setVisible("cisco_nxos" in platforms)

    # ---- the source as typed
    def source(self):
        """The source dict for what the page shows, or None when it is not complete enough to try."""
        if self.own_btn.isChecked():
            proto = self.own.currentData()
            if not proto:
                return None
            srv = {"ftp": "ftp", "sftp": "sftp", "scp": "sftp", "tftp": "tftp"}[proto]
            server = self.servers().get(srv)
            if server is None or not server.running:
                return None
            return fw.own_source(proto, server, self.address.currentText().strip() or fw.addresses()[0])
        if not self.host.text().strip():
            return None
        p = self.proto.currentData()
        anonymous = self.anonymous.isChecked() and p == "ftp"
        if not anonymous and not self.user.text().strip() and p not in fw.NAMED:      # TFTP has no login; HTTP(S) may have none
            return None
        names = [l.strip() for l in self.names.toPlainText().splitlines() if l.strip()] if p in fw.NAMED else []
        if p in fw.NAMED and not names:
            return None
        user = "" if anonymous or p == "tftp" else self.user.text().strip()
        return {"own": False, "proto": p, "host": self.host.text().strip(), "port": self.port.value(),
                "user": user, "password": self.password.text() if user else "",
                "folder": self.folder.text().strip() or "/", "anonymous": anonymous, "files": names,
                "insecure": p == "https" and self.insecure.isChecked()}

    @staticmethod
    def _key(src):
        return None if src is None else tuple(sorted((k, str(v)) for k, v in src.items()))

    def _edited(self, *_):
        """Any change to the server means the list shown is no longer for it: Next waits for Test and list files again."""
        if self.listed_for is not None and self._key(self.source()) != self.listed_for:
            self.files, self.listed_for = [], None
            self.table.setRowCount(0)
            self.status.setText("")
        self._sync()

    def _sync(self):
        busy = self.job is not None and self.job.isRunning()
        self.test.setEnabled(not busy and self.source() is not None)
        self.changed.emit()

    # ---- listing
    def start_test(self):
        src = self.source()
        if src is None or (self.job is not None and self.job.isRunning()):
            return
        self.status.setText("Listing...")
        self.files, self.listed_for = [], None
        self.table.setRowCount(0)
        self.job = Job(lambda: fw.list_files(src))
        self.job.done.connect(lambda files, err, src=src: self._listed(src, files, err))
        self.job.start()
        self._sync()

    def _listed(self, src, files, err):
        if err is not None:
            self.status.setText(str(err) if isinstance(err, fw.SourceError) else f"Could not connect to {src['host']} port {src['port']}: {err}.")
            self._sync()
            return
        self.files, self.listed_for = files, self._key(src)
        self.table.setRowCount(0)
        for f in files:
            r = self.table.rowCount()
            self.table.insertRow(r)
            for c, text in enumerate((f["name"], fw.human_size(f["size"]), f["modified"].strftime("%Y-%m-%d %H:%M") if f["modified"] else "")):
                self.table.setItem(r, c, QTableWidgetItem(text))
        self.status.setText(fw.summary(src, files))
        if not src["own"]:
            if self.remember.isChecked():
                fw.remember(src)
            else:
                fw.forget()
        self._sync()

    def ready(self):
        return bool(self.files) and self.listed_for == self._key(self.source())

    def chosen(self):
        """(source, files, vrf) once ready."""
        return self.source(), list(self.files), self.vrf.text().strip() or "management"

    def busy(self):
        return self.job is not None and self.job.isRunning()

    def shutdown(self):
        if self.busy():
            self.job.wait(20000)


# =============================================================================== step 3: Check devices
class CollectJob(QThread):
    """Reads every device (core.firmware.collect_many, up to 8 at once) and hands each result back as it finishes."""
    result = Signal(object)

    def __init__(self, devices, src, vrf):
        super().__init__()
        self.devices, self.src, self.vrf = devices, src, vrf
        self.cancel = threading.Event()

    def run(self):
        fw.collect_many(self.devices, self.src, self.vrf, on_result=self.result.emit, cancel=self.cancel)


class CheckStep(QWidget):
    changed = Signal()
    COLS = ["Device", "Platform", "Version", "Mode", "Free space", "Reaches server", "Status"]

    def __init__(self):
        super().__init__()
        self.job, self.results, self.rows, self.args = None, {}, {}, None
        self.intro = _muted("Toner signs in to each device and reads its software version, mode, free space and whether it can reach the "
                            "server. Nothing is changed.")
        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(self.COLS))
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setRootIsDecorated(True)
        self.tree.header().setStretchLastSection(True)
        self.progress = _muted("")
        self.again = QPushButton("Collect again")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.intro)
        lay.addWidget(self.tree, 1)
        bar = QHBoxLayout()
        bar.addWidget(self.progress, 1)
        bar.addWidget(self.again)
        lay.addLayout(bar)
        self.again.clicked.connect(self.restart)

    def start(self, devices, src, vrf):
        if self.running():
            return
        self.args = (list(devices), src, vrf)
        self.results, self.rows = {}, {}
        self.tree.clear()
        for d in devices:
            it = QTreeWidgetItem([db.label_org(d["key"]), fw.PLATFORM_NAMES[fw.platform_of(d)], "", "", "", "", ""])
            self.tree.addTopLevelItem(it)
            self.rows[d["key"]] = it
        self.job = CollectJob(*self.args)
        self.job.result.connect(self._one)
        self.job.finished.connect(self._done)
        self.job.start()
        self._progress()
        self.changed.emit()

    def restart(self):
        if self.args and not self.running():
            self.start(*self.args)

    def _one(self, r):
        self.results[r["key"]] = r
        it = self.rows.get(r["key"])
        if it is not None:
            self._fill(it, r)
        self._progress()

    def _fill(self, it, r):
        main = r["flashes"][0] if r["flashes"] else {}
        reach = "" if r["ping"] is None else "Yes" if r["ping"] and r["port"] is not False else "No"
        values = [r["version"], r["mode"] or "–", fw.human_size(main.get("free")) if main else "", reach,
                  r["held"] or r["note"] or "Ready"]
        for col, text in enumerate(values, 2):
            it.setText(col, text)
        it.takeChildren()
        for f in r["flashes"][1:]:
            child = QTreeWidgetItem([f"Switch {f['member']} ({f['role']})", "", "", "", fw.human_size(f.get("free")), "", ""])
            it.addChild(child)
        it.setExpanded(True)
        if r["held"]:
            grey = self.palette().color(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text)
            for col in range(len(self.COLS)):
                it.setForeground(col, grey)
                it.setToolTip(col, r["held"])

    def _progress(self):
        n, done = len(self.rows), len(self.results)
        if self.running():
            self.progress.setText(f"Collecting from {min(done + 1, n)} of {n} devices...")
            return
        ready = len(self.ready_results())
        self.progress.setText(f"{n} device{'s' if n != 1 else ''}: {ready} ready, {n - ready} held back.")

    def _done(self):
        self._progress()
        try:
            from core.assistant import tools as T
            T.firmware_snapshot([self.results[k] for k in self.rows if k in self.results])    # the Assistant's firmware_check tool reads these
        except Exception:                                                              # noqa: BLE001
            pass
        self.changed.emit()

    def ready_results(self):
        """The devices that can go on, in the order they were ticked."""
        return [self.results[k] for k in self.rows if k in self.results and not self.results[k]["held"]]

    def running(self):
        return self.job is not None and self.job.isRunning()

    def ready(self):
        return not self.running() and bool(self.ready_results())

    def shutdown(self):
        if self.running():
            self.job.cancel.set()
            self.job.wait(60000)


# =============================================================================== step 4: Clean up
class CleanupJob(QThread):
    """Deletes what was confirmed, device by device (up to 8 at once), reporting each file as it goes."""
    item = Signal(str, object, str)                         # device key, 'install' or (fs, name), status

    def __init__(self, work, src_password):
        super().__init__()
        self.work, self.src_password = work, src_password  # [(result, pick)]

    def run(self):
        from concurrent.futures import ThreadPoolExecutor

        def one(job):
            r, pick = job
            with db.within(r["dev"].get("org")):
                fw.cleanup(r["dev"], r, pick, self.src_password, on_item=lambda it, st, key=r["key"]: self.item.emit(key, it, st))
        with ThreadPoolExecutor(max_workers=max(1, min(fw.CHECK_WORKERS, len(self.work)))) as pool:
            list(pool.map(one, self.work))


class CleanupStep(QWidget):
    changed = Signal()
    ITEM = Qt.ItemDataRole.UserRole                        # (device key, 'install' or (fs, name), size)

    def __init__(self):
        super().__init__()
        self.results, self.src_password, self.job, self.items = [], "", None, {}
        self.intro = _muted("Make room for the new image. Ticked files are deleted when you click Delete ticked files and confirm. Toner "
                            "pre-ticks image files that are not the running image and not in the boot statement; untick anything to keep. "
                            "IOS XE in INSTALL mode runs 'install remove inactive' instead, which removes packages no longer in use.")
        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["Name", "Size", "Note"])
        self.tree.header().setStretchLastSection(True)
        self.notice = _muted("Nothing is deleted until you confirm.")
        self.delete = QPushButton("Delete ticked files")
        self.delete.setProperty("danger", True)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.intro)
        lay.addWidget(self.tree, 1)
        bar = QHBoxLayout()
        bar.addWidget(self.notice, 1)
        bar.addWidget(self.delete)
        lay.addLayout(bar)
        self.tree.itemChanged.connect(lambda *_: self._sync())
        self.delete.clicked.connect(self.start)

    def load(self, results, src_password=""):
        """The devices that came through Check devices."""
        self.results, self.src_password, self.items = list(results), src_password, {}
        self.tree.blockSignals(True)
        self.tree.clear()
        for r in self.results:
            top = QTreeWidgetItem([f"{db.label_org(r['key'])} ({r['host']})", "", ""])
            top.setFlags(top.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)      # (Qt makes every row tickable unless told)
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            self.tree.addTopLevelItem(top)
            plan = fw.cleanup_plan(r)
            if plan["install"]:
                it = QTreeWidgetItem(["Run install remove inactive", "", ""])
                it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                it.setCheckState(0, Qt.CheckState.Checked)
                it.setData(0, self.ITEM, (r["key"], "install", 0))
                top.addChild(it)
                self.items[(r["key"], "install")] = it
            for flash in plan["flashes"]:
                fs_row = QTreeWidgetItem([fw.space_line(flash["fs"], flash["free"], flash["total"]), "", ""])
                fs_row.setFlags(fs_row.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
                top.addChild(fs_row)
                for f in flash["files"]:
                    it = QTreeWidgetItem([f["name"], fw.human_size(f["size"]), f["note"]])
                    if f["tickable"]:
                        it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                        it.setCheckState(0, Qt.CheckState.Checked if f["ticked"] else Qt.CheckState.Unchecked)
                    else:                                  # the running image and the boot statement's files: never
                        it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
                    it.setData(0, self.ITEM, (r["key"], (flash["fs"], f["name"]), f["size"]))
                    fs_row.addChild(it)
                    self.items[(r["key"], (flash["fs"], f["name"]))] = it
                fs_row.setExpanded(True)
            top.setExpanded(True)
        self.tree.blockSignals(False)
        self._sync()

    def chosen(self):
        """[(result, {'install': bool, 'files': [(fs, name, size)]})] for the devices with something ticked, in page order."""
        out = []
        for r in self.results:
            pick = {"install": False, "files": []}
            for (key, item), it in self.items.items():
                if key != r["key"] or not (it.flags() & Qt.ItemFlag.ItemIsUserCheckable) or it.checkState(0) != Qt.CheckState.Checked:
                    continue
                if item == "install":
                    pick["install"] = True
                else:
                    pick["files"].append((item[0], item[1], it.data(0, self.ITEM)[2]))
            if pick["install"] or pick["files"]:
                out.append((r, pick))
        return out

    def confirm(self, title, body):
        """The one question before anything is deleted (the tests answer it)."""
        from PySide6.QtWidgets import QMessageBox
        box = QMessageBox(QMessageBox.Icon.Warning, title, body, parent=self)
        yes = box.addButton("Delete", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        return box.clickedButton() is yes

    def start(self):
        work = self.chosen()
        if not work or self.running() or not self.confirm(*fw.confirm_text(work)):
            return
        for r, pick in work:                               # what was not confirmed can no longer be ticked
            for item in (["install"] if pick["install"] else []) + [(fs, n) for fs, n, _s in pick["files"]]:
                it = self.items[(r["key"], item)]
                it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
        self.job = CleanupJob(work, self.src_password)
        self.job.item.connect(self._status)
        self.job.finished.connect(self._done)
        self.job.start()
        self._sync()

    def _status(self, key, item, status):
        it = self.items.get((key, item if item == "install" else tuple(item)))
        if it is not None:
            it.setText(2, status)
            if status == "Deleted":
                it.setData(0, Qt.ItemDataRole.CheckStateRole, None)

    def _done(self):
        for r in self.results:                             # the free space read again after the deletions
            top = next((self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())
                        if self.tree.topLevelItem(i).text(0).startswith(db.label_org(r["key"]) + " (")), None)
            if top is None:
                continue
            rows = [top.child(i) for i in range(top.childCount()) if top.child(i).data(0, self.ITEM) is None]
            for row, flash in zip(rows, r["flashes"]):
                row.setText(0, fw.space_line(flash["fs"], flash["free"], flash["total"]))
        self._sync()

    def running(self):
        return self.job is not None and self.job.isRunning()

    def _sync(self):
        self.delete.setEnabled(not self.running() and bool(self.chosen()))
        self.changed.emit()

    def ready(self):
        return not self.running()

    def shutdown(self):
        if self.running():
            self.job.wait(120000)


# =============================================================================== step 5: Images
class ImagesStep(QWidget):
    changed = Signal()
    COLS = ["Device", "Version", "Mode", "Free space", "Reaches server", "Image", "MD5", "Fits"]
    SKIP = "(skip this device)"

    def __init__(self):
        super().__init__()
        self.results, self.files = [], []
        self.intro = _muted("Choose the image for each device and type or paste its MD5 from Cisco's download page. Toner checks the hash on "
                            "the device after the copy and stops that device if it differs.")
        self.table = _table(self.COLS)
        self.same = QPushButton("Use for all devices")
        self.problems = QLabel()
        self.problems.setWordWrap(True)
        self.problems.setTextFormat(Qt.TextFormat.PlainText)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.intro)
        lay.addWidget(self.table, 1)
        lay.addLayout(_row(self.same))
        lay.addWidget(self.problems)
        self.same.clicked.connect(self.use_for_all)
        self.table.currentCellChanged.connect(lambda *_: self._same_text())

    def load(self, results, files):
        """The devices that came through Check devices (and Clean up), and the files on the server. Choices already made are kept."""
        keep = {r["key"]: (f["name"] if f else None, typed) for r, f, typed in self.rows()}
        self.results, self.files = list(results), list(files)
        self.table.setRowCount(0)
        for r in self.results:
            row = self.table.rowCount()
            self.table.insertRow(row)
            for col, text in enumerate((db.label_org(r["key"]), r["version"], r["mode"] or "–", fw.free_text(r), "Yes")):
                self.table.setItem(row, col, QTableWidgetItem(text))
            pick = QComboBox()
            pick.addItem(self.SKIP, None)
            for f in self.files:
                pick.addItem(f["name"], f["name"])
            md5 = QLineEdit()
            name, typed = keep.get(r["key"], (None, ""))
            if name and pick.findData(name) >= 0:
                pick.setCurrentIndex(pick.findData(name))
            md5.setText(typed or "")
            self.table.setCellWidget(row, 5, pick)
            self.table.setCellWidget(row, 6, md5)
            self.table.setItem(row, 7, QTableWidgetItem(""))
            self.table.setRowHeight(row, pick.sizeHint().height() + 6)        # the editors are taller than a text row
            pick.currentIndexChanged.connect(lambda *_: self._sync())
            md5.textChanged.connect(lambda *_: self._sync())
        for col in range(5):                                # one by one: resizeColumnsToContents() undoes the stretched last column
            self.table.resizeColumnToContents(col)
        widest = max([self.table.cellWidget(i, 5).sizeHint().width() for i in range(self.table.rowCount())] or [0])
        self.table.setColumnWidth(5, widest + 12)
        self.table.setColumnWidth(6, self.table.fontMetrics().horizontalAdvance("0" * 34) + 24)
        if self.results:
            self.table.setCurrentCell(0, 5)
        self._sync()

    def _file(self, name):
        return next((f for f in self.files if f["name"] == name), None)

    def rows(self):
        """[(result, file dict or None, typed hash)] in table order."""
        out = []
        for row, r in enumerate(self.results):
            pick, md5 = self.table.cellWidget(row, 5), self.table.cellWidget(row, 6)
            if pick is None:
                continue
            out.append((r, self._file(pick.currentData()), md5.text()))
        return out

    def chosen(self):
        """[(result, {'name', 'size', 'md5'})] for the devices with an image chosen."""
        return [(r, {"name": f["name"], "size": f["size"], "md5": typed.strip()}) for r, f, typed in self.rows() if f is not None]

    def use_for_all(self):
        row = self.table.currentRow()
        if not (0 <= row < len(self.results)):
            return
        plat = self.results[row]["platform"]
        name, typed = self.table.cellWidget(row, 5).currentData(), self.table.cellWidget(row, 6).text()
        for other, r in enumerate(self.results):
            if other != row and r["platform"] == plat:
                pick = self.table.cellWidget(other, 5)
                pick.setCurrentIndex(max(0, pick.findData(name)))
                self.table.cellWidget(other, 6).setText(typed)
        self._sync()

    def _same_text(self):
        row = self.table.currentRow()
        plat = self.results[row]["platform"] if 0 <= row < len(self.results) else ""
        self.same.setText(f"Use for all {fw.PLATFORM_NAMES[plat]} devices" if plat else "Use for all devices")
        self.same.setEnabled(bool(plat))

    def _sync(self):
        for row, (r, f, _typed) in enumerate(self.rows()):
            self.table.item(row, 7).setText("" if f is None or f["size"] is None else ("No" if fw.room_for(r, f["name"], f["size"]) else "Yes"))
        self.problems.setText("\n".join(text for text, _blocks in fw.image_problems(self.rows())))
        self._same_text()
        self.changed.emit()

    def ready(self):
        return bool(self.results) and not any(blocks for _t, blocks in fw.image_problems(self.rows()))


# =============================================================================== step 6: Transfer
class TransferJob(QThread):
    """Copies to every chosen device, `limit` at once (Simultaneous Transfers, which may change while it runs), in list order,
    reporting each step as it goes."""
    step = Signal(str, str, object, str)                     # device key, step, (done, total) or None, detail

    def __init__(self, work, src, vrf, then=None, limit=fw.TRANSFER_WORKERS):
        super().__init__()
        self.work, self.src, self.vrf, self.then = work, src, vrf, then
        self.cancel = threading.Event()
        self.outcomes = {}
        self.limit, self.copying, self.turn = limit, 0, 0
        self.room = threading.Condition()

    def set_limit(self, n):
        """A raised limit starts waiting devices now; a lowered one lets running copies finish and holds the next."""
        with self.room:
            self.limit = n
            self.room.notify_all()

    def run(self):
        from concurrent.futures import ThreadPoolExecutor

        def one(i, job):
            r, choice = job
            with self.room:
                while not (self.cancel.is_set() or (self.turn == i and self.copying < self.limit)):
                    self.room.wait(0.25)                     # (Stop sets cancel without a notify; fw.transfer then reports Not started)
                self.turn += 1
                self.copying += 1
            try:
                with db.within(r["dev"].get("org")):
                    then = self.then(r, choice) if self.then else None
                    self.outcomes[r["key"]] = fw.transfer(r["dev"], r, choice, self.src, self.vrf, cancel=self.cancel, then=then,
                                                          on_step=lambda s, p, d, key=r["key"]: self.step.emit(key, s, p, d))
            finally:
                with self.room:
                    self.copying -= 1
                    self.room.notify_all()
        # a thread per device up to the most the limit can be raised to; the pool hands them out in list order, so turns never stall
        with ThreadPoolExecutor(max_workers=max(1, min(fw.TRANSFER_MAX, len(self.work)))) as pool:
            list(pool.map(one, range(len(self.work)), self.work))


class RetryJob(QThread):
    """After Verify: saves one device's configuration and runs install add again (fw.save_and_install)."""
    step = Signal(str, str, object, str)

    def __init__(self, key, fn):
        super().__init__()
        self.key, self.fn, self.result = key, fn, None

    def run(self):
        self.result = self.fn(lambda s, p, d: self.step.emit(self.key, s, p, d))


class TransferStep(QWidget):
    changed = Signal()
    COLS = ["Device", "Step", "Progress", "Detail"]

    def __init__(self):
        super().__init__()
        self.job, self.rows, self.bars, self.work = None, {}, {}, []
        self.src, self.extra, self.retries = {}, {}, {}           # extra: outcomes of the reruns after Verify
        self.table = _table(self.COLS)
        self.stop = QPushButton("Stop")
        self.copy = QPushButton("Copy summary")
        self.copy.setEnabled(False)
        self.status = _muted("")
        self.note = _muted("")
        self.note.setVisible(False)
        self.at_once = QSpinBox()
        self.at_once.setRange(1, fw.TRANSFER_MAX)
        self.at_once.setValue(fw.transfers_at_once())
        self.at_once.setToolTip(AT_ONCE_TIP)
        self.at_once.setAccessibleName(AT_ONCE)
        at_once_label = QLabel(AT_ONCE)
        at_once_label.setBuddy(self.at_once)
        at_once_label.setToolTip(AT_ONCE_TIP)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.table, 1)
        bar = QHBoxLayout()
        bar.addWidget(self.status, 1)
        bar.addWidget(at_once_label)
        bar.addWidget(self.at_once)
        bar.addWidget(self.copy)
        bar.addWidget(self.stop)
        lay.addLayout(bar)
        lay.addWidget(self.note)
        self.stop.clicked.connect(self.halt)
        self.copy.clicked.connect(self.copy_summary)
        self.at_once.valueChanged.connect(self._at_once)

    def _at_once(self, n):
        db.set_setting("firmware_transfers", n)
        if self.job is not None and self.job.isRunning():
            self.job.set_limit(n)

    def start(self, work, src, vrf, then=None):
        """work: [(result, {'name', 'size', 'md5'})]. then(result, choice): the step after a verified copy on that device, or None."""
        self.work, self.rows, self.bars = list(work), {}, {}
        self.src, self.extra, self.retries = src, {}, {}
        self.table.setRowCount(0)
        self.status.setText("")
        self.note.setText("")
        self.note.setVisible(False)
        self.copy.setEnabled(False)
        for r, _choice in self.work:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(db.label_org(r["key"])))
            self.table.setItem(row, 1, QTableWidgetItem("Waiting"))
            bar = QProgressBar()
            bar.setRange(0, 1000)
            bar.setValue(0)
            bar.setFormat("")
            self.table.setCellWidget(row, 2, bar)
            self.table.setItem(row, 3, QTableWidgetItem(""))
            self.rows[r["key"]], self.bars[r["key"]] = row, bar
        self.table.resizeColumnToContents(0)
        self.table.setColumnWidth(2, self.table.fontMetrics().horizontalAdvance("100 %  (999.9 MB of 999.9 MB)") + 24)
        self.at_once.blockSignals(True)
        self.at_once.setValue(fw.transfers_at_once())      # (the stored value, which another organization's run may have changed)
        self.at_once.blockSignals(False)
        self.job = TransferJob(self.work, src, vrf, then, limit=self.at_once.value())
        self.job.step.connect(self._step)
        self.job.finished.connect(self._done)
        self.job.start()
        self._sync()

    def _step(self, key, step, progress, detail):
        row = self.rows.get(key)
        if row is None:
            return
        self.table.item(row, 1).setText(step)
        if step == fw.VERIFY:
            b = QPushButton(fw.VERIFY)
            b.clicked.connect(lambda _=False, k=key: self.verify(k))
            self.table.setCellWidget(row, 1, b)
        elif self.table.cellWidget(row, 1) is not None:
            self.table.removeCellWidget(row, 1)
        if detail or step in ("Done", "Failed", "Stopped", "Not started (stopped)", fw.VERIFY, fw.STAGING_FAILED):
            self.table.item(row, 3).setText(detail)
            self.table.item(row, 3).setToolTip(detail)
        if progress is not None:
            done, total = progress
            bar = self.bars[key]
            bar.setValue(int(done * 1000 / total) if total else 0)
            pct = int(done * 100 / total) if total else 0
            bar.setFormat(f"{pct} %  ({fw.human_size(done)} of {fw.human_size(total)})" if total is not None else fw.human_size(done))

    # ---- Verify: unsaved changes stopped install add
    def verify(self, key):
        """Show what a save would write; on approval save the configuration and run install add again, off the window's thread."""
        o, job = self.outcomes().get(key), self.retries.get(key)
        if not o or (job is not None and job.isRunning()):
            return
        r, choice = next((r, c) for r, c in self.work if r["key"] == key)
        if not self.ask_save(self.table.item(self.rows[key], 0).text(), o.get("pending") or []):
            return
        self.table.removeCellWidget(self.rows[key], 1)
        job = RetryJob(key, lambda say, r=r, name=choice["name"]: self._retry(r, name, say))
        job.step.connect(self._step)
        job.finished.connect(lambda k=key, j=job: self._retried(k, j))
        self.retries[key] = job
        job.start()
        self._sync()

    def _retry(self, r, name, say):
        from core import profiles
        with db.within(r["dev"].get("org")):
            secrets = [self.src.get("password") or "", profiles.secret(r["dev"], "main") or ""]
            return fw.save_and_install(r["dev"], r, name, secrets, on_step=say)

    def _retried(self, key, job):
        self.extra[key] = job.result
        if not (self.job is not None and self.job.isRunning()):
            self._done()
        self._sync()

    def ask_save(self, device, lines):
        """The pending changes and the question before saving (the tests answer it)."""
        from PySide6.QtGui import QFontDatabase
        from PySide6.QtWidgets import QDialog, QDialogButtonBox
        from ui.configs import DiffHighlighter
        d = QDialog(self)
        d.setWindowTitle(SAVE_TITLE.format(device=device))
        text = QLabel(SAVE_ASK if lines else SAVE_NO_DIFF)
        text.setWordWrap(True)
        view = QPlainTextEdit("\n".join(lines))
        view.setReadOnly(True)
        view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        view.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        view.setVisible(bool(lines))
        d._colours = DiffHighlighter(view.document())
        box = QDialogButtonBox()
        box.addButton(SAVE_BUTTON, QDialogButtonBox.ButtonRole.AcceptRole)
        cancel = box.addButton(QDialogButtonBox.StandardButton.Cancel)
        cancel.setDefault(True)
        box.accepted.connect(d.accept)
        box.rejected.connect(d.reject)
        lay = QVBoxLayout(d)
        lay.addWidget(text)
        lay.addWidget(view, 1)
        lay.addWidget(box)
        d.resize(820, 520 if lines else 160)
        cancel.setFocus()                                 # saving is never the Enter key's choice
        return d.exec() == QDialog.DialogCode.Accepted

    def halt(self):
        if self.job is not None and self.job.isRunning():
            self.job.cancel.set()
            self.status.setText("Stopping: devices that are copying finish their copy; nothing else is changed on them.")
            self._sync()

    def outcomes(self):
        return {**(self.job.outcomes if self.job is not None else {}), **self.extra}

    def _done(self):
        got = self.outcomes()
        full = sum(1 for o in got.values() if o["ok"])
        staged = sum(1 for o in got.values() if not o["ok"] and o.get("staged"))      # the image is there; install add did not take
        failed = sum(1 for o in got.values() if not o["ok"] and not o["stopped"] and not o.get("staged"))
        ok, n = full + staged, len(self.work)
        line = (f"Done: {ok} of {n} device{'s' if n != 1 else ''} {'has' if ok == 1 and n == 1 else 'have'} the new image"
                + (f", {staged} failed staging" if staged else "") + (f", {failed} failed" if failed or not staged else "")
                + ". Nothing was reloaded.")
        self.status.setText(line)
        self.note.setText(fw.INSTALL_NOTE if full else "")
        self.note.setVisible(bool(full))
        self.copy.setEnabled(True)
        self._sync()

    def summary(self):
        """One line per device, the line under the table and the reminder about reloading: what Copy summary copies."""
        rows = [(self.table.item(i, 0).text(), r["host"], self.table.item(i, 1).text(), self.table.item(i, 3).text())
                for (r, _c), i in zip(self.work, range(self.table.rowCount()))]
        return fw.summary_text(rows, self.status.text(), self.note.text())

    def copy_summary(self):
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.summary())

    def running(self):
        return (self.job is not None and self.job.isRunning()) or any(j.isRunning() for j in self.retries.values())

    def _sync(self):
        self.stop.setEnabled(self.job is not None and self.job.isRunning() and not self.job.cancel.is_set())     # (a rerun cannot be stopped)
        self.changed.emit()

    def ready(self):
        return False

    def shutdown(self):
        if self.job is not None and self.job.isRunning():
            self.job.cancel.set()
            self.job.wait(3600 * 1000)
        for j in self.retries.values():
            j.wait(3600 * 1000)


# =============================================================================== the page
class FirmwareTab(QWidget):
    def __init__(self, servers=lambda: {}):
        super().__init__()
        self.org = db.target()
        self.step_line = QLabel()
        self.step_line.setProperty("title", True)
        self.pick_org = _muted(PICK_ORG)
        self.devices = DevicesStep()
        self.server = ServerStep(servers)
        self.check = CheckStep()
        self.cleanup = CleanupStep()
        self.images = ImagesStep()
        self.transfer = TransferStep()
        self.stack = QStackedWidget()
        for step in self.steps():
            self.stack.addWidget(step)
        self.restart, self.back, self.next = QPushButton("Start over"), QPushButton("Back"), _primary("Next")
        lay = QVBoxLayout(self)
        lay.addWidget(self.step_line)
        lay.addWidget(self.pick_org)
        lay.addWidget(self.stack, 1)
        bar = QHBoxLayout()
        bar.addWidget(self.restart)
        bar.addStretch()
        bar.addWidget(self.back)
        bar.addWidget(self.next)
        lay.addLayout(bar)
        for step in self.steps():
            step.changed.connect(self._sync)
        self.restart.clicked.connect(self.start_over)
        self.back.clicked.connect(lambda: self.go(self.stack.currentIndex() - 1))
        self.next.clicked.connect(self.forward)
        self.refresh()

    def steps(self):
        """The steps built so far, in order."""
        return [self.devices, self.server, self.check, self.cleanup, self.images, self.transfer]

    @staticmethod
    def blocked():
        """In Global with organizations: the wizard works inside one organization."""
        return db.several()

    def refresh(self):
        """The window's lists changed (devices, the organization being looked at)."""
        if db.target() != self.org and not self.running():
            self.org = db.target()
            self.start_over()
            return
        self.devices.fill()
        self.server.reload_own()
        self._sync()

    def start_over(self):
        self.org = db.target()
        self.devices.reset()
        self.server.load()
        self.go(0)

    def forward(self):
        """Next; from Images it is Transfer, asked first."""
        i = self.stack.currentIndex()
        if i == 4:
            work = self.images.chosen()
            src, _files, vrf = self.server.chosen()
            if not work or not self.confirm_transfer(*fw.transfer_text(work, src)):
                return
            self.stack.setCurrentIndex(5)
            self.transfer.start(work, src, vrf, then=self.after_copy)
            self._sync()
            return
        self.go(i + 1)

    def after_copy(self, r, choice):
        """What runs on a device once its image is copied and verified: install add, or the boot statement (never a reload)."""
        from core import profiles
        src, _files, _vrf = self.server.chosen()
        return fw.after_copy(r["dev"], r, choice["name"], [src.get("password") or "", profiles.secret(r["dev"], "main") or ""])

    def confirm_transfer(self, title, body):
        """The question before copying (the tests answer it)."""
        box = QMessageBox(QMessageBox.Icon.Question, title, body, parent=self)
        yes = box.addButton("Transfer", QMessageBox.ButtonRole.AcceptRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        return box.clickedButton() is yes

    def transferring(self):
        return self.transfer.running()

    def stop_question(self):
        """The question when Toner is closing while devices copy (the tests answer it). True for Stop."""
        box = QMessageBox(QMessageBox.Icon.Question, "Firmware Transfer",
                          "Stop the transfer? Devices that are copying finish their copy; nothing else is changed on them.", parent=self)
        stop = box.addButton("Stop", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Keep going", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        return box.clickedButton() is stop

    def ask_stop(self):
        """Toner is closing while devices copy: stop (they finish their copy first) or keep going. True when it may close."""
        if not self.stop_question():
            return False
        from PySide6.QtWidgets import QApplication
        self.transfer.halt()
        while self.transfer.running():                     # the copies end on their own; the window stays alive meanwhile
            QApplication.processEvents()
            self.transfer.job.wait(100)
        QApplication.processEvents()                       # the devices' last reports, so every row says how it ended
        return True

    def go(self, index):
        index = max(0, min(index, len(self.steps()) - 1))
        forward = index > self.stack.currentIndex()
        if index == 1:
            self.server.reload_own()
            self.server.set_platforms({fw.platform_of(d) for d in self.devices.chosen()})
        self.stack.setCurrentIndex(index)
        if index == 2 and forward:                        # coming from the Image server: read the devices again
            src, _files, vrf = self.server.chosen()
            self.check.start(self.devices.chosen(), src, vrf)
        if index == 3 and forward:
            src, _files, _vrf = self.server.chosen()
            self.cleanup.load(self.check.ready_results(), src.get("password") or "")
        if index == 4 and forward:
            _src, files, _vrf = self.server.chosen()
            self.images.load(self.check.ready_results(), files)
        self._sync()

    def _sync(self, *_):
        blocked = self.blocked()
        self.pick_org.setVisible(blocked)
        self.stack.setVisible(not blocked)
        self.step_line.setVisible(not blocked)
        i = self.stack.currentIndex()
        self.step_line.setText(f"Step {i + 1} of {len(STEPS)}: {STEPS[i]}")
        step = self.steps()[i]
        for b in (self.restart, self.back, self.next):
            b.setVisible(not blocked)
        busy = self.running()
        self.restart.setEnabled(not busy)
        self.back.setEnabled(0 < i < 5 and not busy)          # once copying has started there is no going back
        self.next.setText("Transfer" if i == 4 else "Next")
        self.next.setEnabled(i + 1 < len(self.steps()) and step.ready() and not busy)

    def running(self):
        return self.server.busy() or self.check.running() or self.cleanup.running() or self.transfer.running()

    def shutdown(self):
        self.server.shutdown()
        self.check.shutdown()
        self.cleanup.shutdown()
        self.transfer.shutdown()


    def screen_context(self):
        """What the Assistant is told about this page: the step it is on and what that step's table shows."""
        i = self.stack.currentIndex()
        out = {"page": "Firmware Transfer", "step": f"Step {i + 1} of {len(STEPS)}: {STEPS[i]}" if 0 <= i < len(STEPS) else ""}
        try:
            if i == 0:
                out["devices"] = [d["name"] for d in self.devices.chosen()]
            elif i == 1:
                src, files, vrf = self.server.chosen()
                out["server"] = fw.source_shown(src) if src and src.get("proto") and src.get("host") else ""
                out["files"] = [f.get("name") if isinstance(f, dict) else str(f) for f in (files or [])][:200]
            elif i == 2:
                from core.assistant import tools as T
                T.firmware_snapshot([self.check.results[k] for k in self.check.rows if k in self.check.results])
                out["results"] = (T.LATEST.get("firmware_check") or {}).get("results", [])
                out["progress"] = self.check.progress.text()
            elif i == 3:
                out["ticked_for_deletion"] = [{"device": r.get("name", ""), "install_remove_inactive": pick["install"], "files": [n for _fs, n, _s in pick["files"]]}
                                              for r, pick in (self.cleanup.chosen() or [])][:100]
            elif i == 4:
                out["images"] = [{"device": r.get("name", ""), "image": f["name"] if f else "", "md5_typed": bool(typed.strip())} for r, f, typed in (self.images.rows() or [])][:100]
            elif i == 5:
                t = self.transfer.table
                out["transfers"] = [{"device": t.item(r, 0).text() if t.item(r, 0) else "", "step": t.item(r, 1).text() if t.item(r, 1) else "",
                                     "detail": t.item(r, 3).text() if t.item(r, 3) else ""} for r in range(t.rowCount())]
        except Exception as e:                                           # noqa: BLE001
            out["note"] = f"could not read the step's table: {e}"
        return out
