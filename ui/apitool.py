"""Tools > Connect > API Tester: a small Postman. Saved requests and history on the left, the request editor and the reply on
the right. The thinking (building, sending, storing) is in core/apitool.py; this file is only the window."""
import json
import threading

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QFontDatabase, QKeySequence, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout,
                               QHeaderView, QInputDialog, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QSplitter,
                               QStackedWidget, QTableWidget, QTableWidgetItem, QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from core import apitool as A, db, profiles
from ui import status as st
from ui.orgfield import SHARED_CHOICE, choice_file, org_choices, show_row
from ui.tools2 import _muted, _primary, _table
from ui.widgets import EmptyHint, remember_sizes

ROLE = Qt.ItemDataRole.UserRole
DOTS = "•" * 8
KEEP_LABEL = "Keep the last"


def _mono():
    return QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)


def _secret_box(placeholder=""):
    box = QLineEdit()
    box.setEchoMode(QLineEdit.EchoMode.Password)
    box.setPlaceholderText(placeholder)
    return box


def _show_toggle(*boxes):
    t = QCheckBox("Show")
    t.toggled.connect(lambda on: [b.setEchoMode(QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password) for b in boxes])
    return t


# ---------------------------------------------------------------- key / value tables (Params, Headers)
class KeyValueTable(QTableWidget):
    """On / Name / Value rows with an empty row always ready to type into."""
    changed = Signal()

    def __init__(self, hint):
        super().__init__(0, 3)
        self.setHorizontalHeaderLabels(["On", "Name", "Value"])
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.setColumnWidth(0, 36)
        self.setColumnWidth(1, 220)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.setToolTip(hint)
        self._filling = False
        self.itemChanged.connect(self._changed)
        self.set_rows([])

    def _add(self, on=True, name="", value=""):
        r = self.rowCount()
        self.insertRow(r)
        tick = QTableWidgetItem()
        tick.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
        tick.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
        self.setItem(r, 0, tick)
        self.setItem(r, 1, QTableWidgetItem(name))
        self.setItem(r, 2, QTableWidgetItem(value))

    def rows(self):
        out = []
        for r in range(self.rowCount()):
            name, value = (self.item(r, 1).text() if self.item(r, 1) else ""), (self.item(r, 2).text() if self.item(r, 2) else "")
            if name.strip() or value.strip():
                out.append([self.item(r, 0).checkState() == Qt.CheckState.Checked, name, value])
        return out

    def set_rows(self, rows):
        self._filling = True
        self.setRowCount(0)
        for on, name, value in rows:
            self._add(bool(on), name, value)
        self._add(True)
        self._filling = False

    def _changed(self, item):
        if self._filling:
            return
        if item.row() == self.rowCount() - 1 and item.column() in (1, 2) and item.text():
            self._filling = True
            self._add(True)
            self._filling = False
        self.changed.emit()


# ---------------------------------------------------------------- variables
class VariablesPanel(QWidget):
    """The organization's variables: edited in place, saved as you go. A secret one shows dots and lives in the vault."""

    def __init__(self):
        super().__init__()
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Name", "Value", "Secret"])
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(2, 70)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.add_btn, self.remove_btn = QPushButton("Add"), QPushButton("Remove")
        self.add_btn.clicked.connect(self.add)
        self.remove_btn.clicked.connect(self.remove)
        self.note = _muted("Write {{name}} anywhere in the URL, parameters, headers, body or auth. Variables belong to the organization you "
                           "are looking at, so a Shared request can use each organization's own values. A secret variable is kept in the "
                           "vault and shown as dots.")
        self.hint = EmptyHint(self.table, "No variables yet", "Click Add, then type a name and a value.")
        bar = QHBoxLayout()
        bar.addWidget(self.add_btn)
        bar.addWidget(self.remove_btn)
        bar.addStretch(1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.note)
        lay.addLayout(bar)
        lay.addWidget(self.table, 1)
        self._filling = False
        self.table.itemChanged.connect(self._changed)
        self.refresh()

    def refresh(self):
        self._filling = True
        self.table.setRowCount(0)
        for v in A.list_variables():
            self._row(v["name"], DOTS if v["secret"] else v["value"], bool(v["secret"]), v["name"])
        self._filling = False
        self.hint.setVisible(self.table.rowCount() == 0)

    def _row(self, name, value, secret, stored):
        r = self.table.rowCount()
        self.table.insertRow(r)
        n = QTableWidgetItem(name)
        n.setData(ROLE, stored)                                      # the name it is stored under (None: not saved yet)
        self.table.setItem(r, 0, n)
        self.table.setItem(r, 1, QTableWidgetItem(value))
        s = QTableWidgetItem()
        s.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
        s.setCheckState(Qt.CheckState.Checked if secret else Qt.CheckState.Unchecked)
        self.table.setItem(r, 2, s)
        return r

    def add(self):
        self._filling = True
        r = self._row("", "", False, None)
        self._filling = False
        self.hint.hide()
        self.table.setCurrentCell(r, 0)
        self.table.editItem(self.table.item(r, 0))

    def remove(self):
        rows = sorted({i.row() for i in self.table.selectedIndexes()}, reverse=True)
        for r in rows:
            stored = self.table.item(r, 0).data(ROLE)
            if stored:
                A.delete_variable(stored)
        self.refresh()

    def _changed(self, item):
        if self._filling:
            return
        r = item.row()
        name_item, value_item, secret_item = self.table.item(r, 0), self.table.item(r, 1), self.table.item(r, 2)
        stored, name = name_item.data(ROLE), name_item.text().strip()
        secret = secret_item.checkState() == Qt.CheckState.Checked
        value = value_item.text()
        if not name:
            return                                                   # a new row without a name yet: nothing to save
        if item.column() == 1 and secret and value == DOTS:
            return
        try:
            if not stored and A.variable_exists(name):
                raise ValueError(f"There is already a variable named '{name}'.")
            if item.column() == 2 and stored and not secret:          # secret -> plain: the vault value becomes the stored one
                value = A.variable_values().get(stored, "")
            elif item.column() == 2 and stored and secret:            # plain -> secret: the stored value moves to the vault
                value = value if value != DOTS else ""
            elif item.column() == 0 and stored and secret:
                value = ""                                            # renaming keeps the secret
            A.set_variable(name, value, secret, old_name=stored)
        except ValueError as e:
            QMessageBox.warning(self, "Variables", str(e))
            self.refresh()
            return
        self.refresh()
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0).text() == name:
                self.table.setCurrentCell(i, 0)


# ---------------------------------------------------------------- the worker
class SendWorker(QThread):
    done = Signal(dict)

    def __init__(self, prepared):
        super().__init__()
        self.prepared = prepared
        self.cancel = threading.Event()

    def run(self):
        self.done.emit(A.send(self.prepared, self.cancel))


# ---------------------------------------------------------------- Save dialog
class SaveDialog(QDialog):
    def __init__(self, req, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Save request")
        self.name = QLineEdit(req.get("name") or "")
        self.name.setPlaceholderText("for example: FortiGate system status")
        self.folder = QComboBox()
        self.new_folder_btn = QPushButton("New folder...")
        self._fill_folders(req.get("folder_id"))
        row = QWidget()
        fl = QHBoxLayout(row)
        fl.setContentsMargins(0, 0, 0, 0)
        fl.addWidget(self.folder, 1)
        fl.addWidget(self.new_folder_btn)
        self.org = QComboBox()
        org_choices(self.org, None, SHARED_CHOICE if req.get("shared") else db.home(), others=False)
        self.org.setToolTip("Which organization this belongs to. Shared requests are seen by every organization.")
        form = QFormLayout()
        form.addRow("Name", self.name)
        form.addRow("Folder", row)
        form.addRow("Organization", self.org)
        show_row(form, self.org)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.new_folder_btn.clicked.connect(self._new_folder)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(buttons)
        self.resize(480, self.sizeHint().height())

    def _fill_folders(self, select=None):
        self.folder.clear()
        self.folder.addItem("(top level)", None)
        for fid, path in sorted(A.folder_paths().items(), key=lambda kv: kv[1].lower()):
            self.folder.addItem(path, fid)
        self.folder.setCurrentIndex(max(0, self.folder.findData(select)))

    def _new_folder(self):
        name, ok = QInputDialog.getText(self, "New folder", "Folder name:")
        if not ok or not name.strip():
            return
        try:
            fid = A.create_folder(name, self.folder.currentData())
        except ValueError as e:
            QMessageBox.warning(self, "New folder", str(e))
            return
        self._fill_folders(fid)

    def values(self):
        return {"name": self.name.text().strip(), "folder_id": self.folder.currentData(), "org": choice_file(self.org.currentData()),
                "shared": int(self.org.currentData() == SHARED_CHOICE)}


# ---------------------------------------------------------------- the tree
class RequestTree(QTreeWidget):
    """Folders and requests. Dropping on a folder moves what was dragged into it; dropping on empty space, to the top level."""
    moved = Signal(list, object)          # [("request"|"folder", id), ...], target folder id (None = top level)

    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def mousePressEvent(self, e):
        if not self.indexAt(e.position().toPoint()).isValid():
            self.clearSelection()
            self.setCurrentItem(None)
        super().mousePressEvent(e)

    def dropEvent(self, e):
        target = self.itemAt(e.position().toPoint())
        tid = None
        if target is not None:
            kind, ident, org = self.owner.kind_of(target)
            if org != db.target():
                return
            tid = ident if kind == "folder" else (self.owner.payload[target.data(0, ROLE)].get("folder_id") if kind == "request" else None)
        items = [self.owner.kind_of(i) for i in self.selectedItems()]
        e.setDropAction(Qt.DropAction.IgnoreAction)
        e.accept()
        moves = [(k, i) for k, i, org in items if k in ("request", "folder") and org == db.target()]
        if moves:
            self.moved.emit(moves, tid)


# ---------------------------------------------------------------- the page
class ApiTesterTab(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.current = None                     # the saved request being edited ({'id', 'org', ...}), or None
        self.from_history = False
        self.payload = {}                       # tree item key -> request / folder
        self._history = []
        self._baseline = None
        self._loading = False
        self._building = False
        self._syncing = False
        self._org = db.target()
        self.expanded = set()

        # ---- left: Saved and History
        self.new_btn, self.folder_btn, self.save_btn = QPushButton("New"), QPushButton("New folder"), QPushButton("Save")
        self.rename_btn, self.dup_btn, self.del_btn = QPushButton("Rename"), QPushButton("Duplicate"), QPushButton("Delete")
        self.tree = RequestTree(self)
        self.tree.setHeaderLabels(["Name", "Method"])
        self.tree.setColumnWidth(0, 240)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.tree.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.tree.setAlternatingRowColors(True)
        self.tree_hint = EmptyHint(self.tree, "No saved requests yet", "Fill in a request and click Save.")
        saved = QWidget()
        sl = QVBoxLayout(saved)
        sl.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        for b in (self.new_btn, self.folder_btn, self.save_btn):
            bar.addWidget(b)
        bar.addStretch(1)
        bar2 = QHBoxLayout()
        for b in (self.rename_btn, self.dup_btn, self.del_btn):
            bar2.addWidget(b)
        bar2.addStretch(1)
        sl.addLayout(bar)
        sl.addLayout(bar2)
        sl.addWidget(self.tree, 1)

        self.keep = QSpinBox()
        self.keep.setRange(1, 10000)
        self.keep.setValue(A.history_keep())
        self.clear_btn = QPushButton("Clear history")
        self.history = _table(["When", "Method", "URL", "Status", "Time"])
        self.history.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.history_hint = EmptyHint(self.history, "Nothing sent yet", "Requests you send appear here. Click one to load it again.")
        hist = QWidget()
        hl = QVBoxLayout(hist)
        hl.setContentsMargins(0, 0, 0, 0)
        hbar = QHBoxLayout()
        hbar.addWidget(QLabel(KEEP_LABEL))
        hbar.addWidget(self.keep)
        hbar.addWidget(QLabel("requests"))
        hbar.addStretch(1)
        hbar.addWidget(self.clear_btn)
        hl.addLayout(hbar)
        hl.addWidget(self.history, 1)
        self.left = QTabWidget()
        self.left.addTab(saved, "Saved")
        self.left.addTab(hist, "History")

        # ---- right: the request
        self.title = QLabel("New request")
        f = self.title.font()
        f.setBold(True)
        self.title.setFont(f)
        self.method = QComboBox()
        self.method.addItems(A.METHODS)
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://{{host}}/api/v1/status")
        self.url.setFont(_mono())
        self.send_btn, self.cancel_btn = _primary("Send"), QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 600)
        self.timeout.setValue(A.DEFAULT_TIMEOUT)
        self.timeout.setSuffix(" s")
        self.verify = QCheckBox("Verify certificate")
        self.verify.setChecked(True)
        self.verify.setToolTip("Untick for devices with a self-signed certificate.")
        top = QHBoxLayout()
        top.addWidget(self.method)
        top.addWidget(self.url, 1)
        top.addWidget(self.send_btn)
        top.addWidget(self.cancel_btn)
        opts = QHBoxLayout()
        opts.addWidget(QLabel("Timeout"))
        opts.addWidget(self.timeout)
        opts.addSpacing(12)
        opts.addWidget(self.verify)
        opts.addStretch(1)

        self.params = KeyValueTable("Query parameters: they are added to the URL as you type them (and the URL's own ?a=1 fills this table).")
        self.headers = KeyValueTable("Request headers, one per row.")
        self.body_type = QComboBox()
        for key, label, _ in A.BODY_TYPES:
            self.body_type.addItem(label, key)
        self.fmt_btn = QPushButton("Format JSON")
        self.body = QPlainTextEdit()
        self.body.setFont(_mono())
        self.body.setPlaceholderText('{"name": "value"}')
        body_page = QWidget()
        bl = QVBoxLayout(body_page)
        bl.setContentsMargins(0, 0, 0, 0)
        brow = QHBoxLayout()
        brow.addWidget(QLabel("Type"))
        brow.addWidget(self.body_type)
        brow.addWidget(self.fmt_btn)
        brow.addStretch(1)
        bl.addLayout(brow)
        bl.addWidget(self.body, 1)

        self.auth_type = QComboBox()
        for key, label in A.AUTH_TYPES:
            self.auth_type.addItem(label, key)
        self.token = _secret_box("the token")
        self.basic_user, self.basic_pw = QLineEdit(), _secret_box("")
        self.key_name, self.key_value = QLineEdit(), _secret_box("")
        self.key_name.setPlaceholderText("X-API-Key")
        self.key_where = QComboBox()
        for key, label in A.KEY_WHERE:
            self.key_where.addItem(label, key)
        self.profile = QComboBox()
        self.profile_as = QComboBox()
        for key, label in A.PROFILE_AS:
            self.profile_as.addItem(label, key)
        self.profile_key = QLineEdit()
        self.profile_key.setPlaceholderText("X-API-Key")
        self.auth_pages = QStackedWidget()
        self.auth_pages.addWidget(self._form([("", _muted("The request is sent without any sign-in."))]))
        self.auth_pages.addWidget(self._form([("Token", self.token), ("", _show_toggle(self.token))]))
        self.auth_pages.addWidget(self._form([("User name", self.basic_user), ("Password", self.basic_pw), ("", _show_toggle(self.basic_pw))]))
        self.auth_pages.addWidget(self._form([("Key name", self.key_name), ("Value", self.key_value), ("", _show_toggle(self.key_value)),
                                              ("Send in", self.key_where)]))
        self.auth_pages.addWidget(self._form([("Profile", self.profile), ("Send as", self.profile_as), ("Key name", self.profile_key),
                                              ("", _muted("The profile's password or token is read from the vault when you send. "
                                                          "It is never shown or saved with the request."))]))
        auth_page = QWidget()
        al = QVBoxLayout(auth_page)
        al.setContentsMargins(0, 0, 0, 0)
        arow = QHBoxLayout()
        arow.addWidget(QLabel("Type"))
        arow.addWidget(self.auth_type)
        arow.addStretch(1)
        al.addLayout(arow)
        al.addWidget(self.auth_pages)
        al.addStretch(1)
        self.variables = VariablesPanel()
        self.tabs = QTabWidget()
        self.tabs.addTab(self.params, "Params")
        self.tabs.addTab(self.headers, "Headers")
        self.tabs.addTab(body_page, "Body")
        self.tabs.addTab(auth_page, "Auth")
        self.tabs.addTab(self.variables, "Variables")

        # ---- right: the reply
        self.status = QLabel("Not sent yet.")
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.status.setWordWrap(True)
        self.pretty = QCheckBox("Pretty-print")
        self.pretty.setChecked(True)
        self.copy_btn = QPushButton("Copy body")
        self.resp_body, self.resp_headers = QPlainTextEdit(), QPlainTextEdit()
        for box in (self.resp_body, self.resp_headers):
            box.setReadOnly(True)
            box.setFont(_mono())
            box.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.resp_tabs = QTabWidget()
        self.resp_tabs.addTab(self.resp_body, "Body")
        self.resp_tabs.addTab(self.resp_headers, "Headers")
        resp = QWidget()
        rl = QVBoxLayout(resp)
        rl.setContentsMargins(0, 0, 0, 0)
        rrow = QHBoxLayout()
        rrow.addWidget(self.status, 1)
        rrow.addWidget(self.pretty)
        rrow.addWidget(self.copy_btn)
        rl.addLayout(rrow)
        rl.addWidget(self.resp_tabs, 1)

        editor = QWidget()
        el = QVBoxLayout(editor)
        el.setContentsMargins(0, 0, 0, 0)
        el.addWidget(self.title)
        el.addLayout(top)
        el.addLayout(opts)
        el.addWidget(self.tabs, 1)
        self.vsplit = QSplitter(Qt.Orientation.Vertical)
        self.vsplit.addWidget(editor)
        self.vsplit.addWidget(resp)
        self.vsplit.setSizes([360, 300])
        remember_sizes(self.vsplit, "api_tester_reply")
        self.split = QSplitter(Qt.Orientation.Horizontal)
        self.split.addWidget(self.left)
        self.split.addWidget(self.vsplit)
        self.split.setSizes([340, 840])
        self.split.setStretchFactor(0, 1)
        self.split.setStretchFactor(1, 3)
        remember_sizes(self.split, "api_tester")
        lay = QVBoxLayout(self)
        lay.addWidget(self.split, 1)

        # ---- wiring
        self.new_btn.clicked.connect(self.new_request)
        self.folder_btn.clicked.connect(self.new_folder)
        self.save_btn.clicked.connect(self.save_current)
        self.rename_btn.clicked.connect(self.rename_selected)
        self.dup_btn.clicked.connect(self.duplicate_selected)
        self.del_btn.clicked.connect(self.delete_selected)
        self.tree.itemSelectionChanged.connect(self._selected)
        self.tree.itemChanged.connect(self._item_edited)
        self.tree.itemExpanded.connect(lambda it: self._remember(it, True))
        self.tree.itemCollapsed.connect(lambda it: self._remember(it, False))
        self.tree.moved.connect(self._moved)
        here = Qt.ShortcutContext.WidgetWithChildrenShortcut
        QShortcut(QKeySequence("F2"), self.tree, activated=self.rename_selected, context=here)
        QShortcut(QKeySequence.StandardKey.Delete, self.tree, activated=self.delete_selected, context=here)
        QShortcut(QKeySequence("Ctrl+S"), self, activated=self.save_current, context=here)
        QShortcut(QKeySequence("Ctrl+Return"), self, activated=self.send_now, context=here)
        self.keep.valueChanged.connect(self._keep_changed)
        self.clear_btn.clicked.connect(self.clear_history)
        self.history.itemSelectionChanged.connect(self._history_clicked)
        self.send_btn.clicked.connect(self.send_now)
        self.cancel_btn.clicked.connect(self.cancel_send)
        self.url.returnPressed.connect(self.send_now)
        self.url.textChanged.connect(self._url_edited)
        self.params.changed.connect(self._params_edited)
        self.auth_type.currentIndexChanged.connect(lambda i: (self.auth_pages.setCurrentIndex(i), self._mark()))
        self.profile_as.currentIndexChanged.connect(self._profile_as_changed)
        self.fmt_btn.clicked.connect(self.format_body)
        self.pretty.toggled.connect(self._show_body)
        self.copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.resp_body.toPlainText()))
        for w in (self.method, self.body_type, self.key_where, self.profile):
            w.currentIndexChanged.connect(self._mark)
        for w in (self.url, self.basic_user, self.key_name, self.profile_key, self.token, self.basic_pw, self.key_value):
            w.textChanged.connect(self._mark)
        self.body.textChanged.connect(self._mark)
        self.headers.changed.connect(self._mark)
        self.timeout.valueChanged.connect(self._mark)
        self.verify.toggled.connect(self._mark)
        self._result = None
        self._fill_profiles()
        self._profile_as_changed()
        self.new_request(ask=False)
        self.refresh()

    @staticmethod
    def _form(rows):
        w = QWidget()
        form = QFormLayout(w)
        form.setContentsMargins(0, 6, 0, 0)
        for label, field in rows:
            form.addRow(label, field) if label else form.addRow(field)
        return w

    # ---------------------------------------------------------------- the editor
    def _fill_profiles(self, keep=None):
        want = keep if keep is not None else self.profile.currentData()
        self.profile.blockSignals(True)
        self.profile.clear()
        self.profile.addItem("(choose one)", None)
        for p in profiles.list_profiles():
            self.profile.addItem(p["name"] + ("  (Shared)" if p["org"] != db.target() else ""), p["id"])
        self.profile.setCurrentIndex(max(0, self.profile.findData(want)))
        self.profile.blockSignals(False)

    def _profile_as_changed(self, *_):
        self.profile_key.setEnabled(self.profile_as.currentData() in ("header", "query"))
        self._mark()

    def secret_text(self):
        """The typed token, password or key value for the auth type in view ('' when it has none)."""
        kind = self.auth_type.currentData()
        return {"bearer": self.token.text(), "basic": self.basic_pw.text(), "apikey": self.key_value.text()}.get(kind, "")

    def state(self):
        """The editor as a request dict (with the saved request's id, name, folder and organization when it came from one)."""
        base = self.current or A.blank()
        auth = {"type": self.auth_type.currentData(), "username": self.basic_user.text(), "key_name": self.key_name.text()
                if self.auth_type.currentData() == "apikey" else self.profile_key.text(), "where": self.key_where.currentData(),
                "profile_id": self.profile.currentData(), "send_as": self.profile_as.currentData()}
        return {**base, "method": self.method.currentText(), "url": self.url.text().strip(), "params": self.params.rows(),
                "headers": self.headers.rows(), "body": self.body.toPlainText(), "body_type": self.body_type.currentData(), "auth": auth,
                "timeout": self.timeout.value(), "verify": self.verify.isChecked()}

    def _signature(self):
        s = self.state()
        return json.dumps({k: v for k, v in s.items() if k not in ("id", "name", "folder_id", "org", "shared", "created", "updated")}, sort_keys=True) \
            + "|" + self.secret_text()

    def load(self, req, secret="", from_history=False):
        """Fill the editor from a saved request or a history row."""
        self._loading = True
        self.current = req if req.get("id") and not from_history else None
        self.from_history = from_history
        a = {**A.AUTH_DEFAULTS, **(req.get("auth") or {})}
        self.method.setCurrentText(req.get("method") or "GET")
        self.url.setText(req.get("url") or "")
        self.params.set_rows(req.get("params") or [])
        self.headers.set_rows(req.get("headers") or [])
        self.body_type.setCurrentIndex(max(0, self.body_type.findData(req.get("body_type") or "none")))
        self.body.setPlainText(req.get("body") or "")
        self.timeout.setValue(int(req.get("timeout") or A.DEFAULT_TIMEOUT))
        self.verify.setChecked(bool(req.get("verify", True)))
        self.auth_type.setCurrentIndex(max(0, self.auth_type.findData(a["type"])))
        self.auth_pages.setCurrentIndex(self.auth_type.currentIndex())
        self.basic_user.setText(a.get("username") or "")
        self.key_name.setText(a.get("key_name") or "" if a["type"] == "apikey" else "")
        self.profile_key.setText(a.get("key_name") or "" if a["type"] == "profile" else "")
        self.key_where.setCurrentIndex(max(0, self.key_where.findData(a.get("where") or "header")))
        self.profile_as.setCurrentIndex(max(0, self.profile_as.findData(a.get("send_as") or "bearer")))
        self._fill_profiles(a.get("profile_id"))
        if a.get("profile_id") and self.profile.findData(a["profile_id"]) < 0:        # a Shared request's Global profile, seen from an organization
            p = profiles.get(a["profile_id"], req.get("org"))
            self.profile.addItem((p["name"] if p else f"profile {a['profile_id']}") + "  (Global)", a["profile_id"])
            self.profile.setCurrentIndex(self.profile.count() - 1)
        for box in (self.token, self.basic_pw, self.key_value):
            box.setText("")
        {"bearer": self.token, "basic": self.basic_pw, "apikey": self.key_value}.get(a["type"], self.token).setText(secret or "")
        self._loading = False
        self._baseline = self._signature()
        self._set_title()

    def _set_title(self):
        if self.from_history:
            text = "From history  (not saved)"
        elif self.current:
            text = self.current["name"] + ("  (Shared, from Global)" if self.current.get("org") != db.target() else "")
        else:
            text = "New request"
        if self._baseline is not None and self._signature() != self._baseline and not self.from_history:
            text += "  (changed)"
        self.title.setText(text)

    def _mark(self, *_):
        if not self._loading:
            self._set_title()

    def dirty(self):
        return self._baseline is not None and self._signature() != self._baseline

    def _url_edited(self, text):
        if self._syncing or self._loading:
            return
        self._syncing = True
        self.params.set_rows(A.split_query(text))
        self._syncing = False

    def _params_edited(self):
        if self._syncing:
            return
        self._syncing = True
        self.url.setText(A.with_query(self.url.text(), self.params.rows()))
        self._syncing = False
        self._mark()

    def format_body(self):
        try:
            self.body.setPlainText(A.format_json(self.body.toPlainText()))
        except ValueError as e:
            QMessageBox.warning(self, "Format JSON", str(e))

    def leave_ok(self):
        """Before dropping what is in the editor: True to go on (saved, or the person let it go)."""
        if not self.dirty() or self.from_history and not self.current:
            return True if not (self.dirty() and self.from_history) else self._ask_unsaved("this request")
        return self._ask_unsaved(self.current["name"] if self.current else "the new request")

    def _ask_unsaved(self, what):
        box = QMessageBox(QMessageBox.Icon.Question, "Unsaved changes", f"Save the changes to '{what}' first?", parent=self)
        save = box.addButton("Save", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Don't save", QMessageBox.ButtonRole.DestructiveRole)
        cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() == cancel:
            return False
        if box.clickedButton() == save:
            return self.save_current()
        return True

    def new_request(self, ask=True):
        if ask and not self.leave_ok():
            return
        self.load(A.blank())
        self.tree.blockSignals(True)
        self.tree.clearSelection()
        self.tree.setCurrentItem(None)
        self.tree.blockSignals(False)
        self.url.setFocus()

    def save_current(self):
        """Save in place, or (a new request, one from history, or a Shared one seen from an organization) ask where."""
        s = self.state()
        secret = self.secret_text()
        own = self.current and self.current.get("org") == db.target()
        if not own:
            base = {**s, "id": None, "org": db.target(), "shared": 0, "created": None, "updated": None}
            if self.current and self.current.get("org") == db.GLOBAL and db.target() != db.GLOBAL and (base["auth"].get("profile_id") or 0) > 0:
                base["auth"] = {**base["auth"], "profile_id": -base["auth"]["profile_id"]}       # Global's profile, as this organization refers to it
            dlg = SaveDialog(base, self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return False
            base.update(dlg.values())
            s = base
        try:
            rid = A.save(s, secret if s["auth"]["type"] in ("bearer", "basic", "apikey") else "")
        except ValueError as e:
            QMessageBox.warning(self, "Save request", str(e))
            return False
        self.load(A.get(rid, s.get("org")), secret)          # as saved: a copy made from a Shared request now refers to its organization's own ids
        self.refresh_tree(select=(s.get("org"), rid))
        return True

    # ---------------------------------------------------------------- sending
    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def send_now(self):
        if self.running():
            return
        s = self.state()
        try:
            prepared = A.build(s, self.secret_text(), A.variable_values())
        except ValueError as e:
            self._say(str(e), "FAIL")
            return
        self._say("Sending...", None)
        self.send_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self._sent = (s, prepared)
        self.worker = SendWorker(prepared)
        self.worker.done.connect(self._done)
        self.worker.start()

    def cancel_send(self):
        if self.running():
            self.worker.cancel.set()
            self._say("Cancelling...", None)

    def _done(self, result):
        self.send_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        s, prepared = self._sent
        self._result = result
        code = int(result.get("status") or 0)
        self._say(A.status_text(result), "FAIL" if result.get("error") or code >= 400 else "WARN" if code >= 300 else "OK")
        self.resp_headers.setPlainText("\n".join(f"{k}: {v}" for k, v in result.get("headers") or []))
        self._show_body()
        A.record(s, prepared, result, request_id=self.current["id"] if self.current and self.current.get("org") == db.target() else None)
        self.refresh_history()

    def _show_body(self, *_):
        r = self._result
        if not r:
            self.resp_body.setPlainText("")
            return
        text, _kind = A.pretty(r.get("body") or b"", r.get("headers") or [], self.pretty.isChecked())
        if r.get("truncated"):
            text = f"[showing the first {A.size_text(A.MAX_BODY)} of {A.size_text(r['size'])}]\n" + text
        self.resp_body.setPlainText(text)

    def _say(self, text, status):
        self.status.setText(text)
        self.status.setStyleSheet(f"color: {st.ink(status)}; font-weight: 600;" if status else "")

    # ---------------------------------------------------------------- the tree
    @staticmethod
    def _key(kind, org, ident):
        return f"{kind}:{org}:{ident}"

    def kind_of(self, item):
        """('request', id, org), ('folder', id, org), ('org', org, org) or ('', None, None)."""
        key = (item.data(0, ROLE) or "") if item is not None else ""
        parts = key.split(":")
        if len(parts) == 3 and parts[1].lstrip("-").isdigit() and parts[2].lstrip("-").isdigit():
            return parts[0], int(parts[2]), int(parts[1])
        return "", None, None

    def selected(self):
        """[(kind, id, org)] of what is selected in the tree."""
        return [self.kind_of(i) for i in self.tree.selectedItems() if self.kind_of(i)[0]]

    def refresh_tree(self, select=None):
        """Rebuild the tree: the organization's own folders and requests, then Global's Shared ones under a branch."""
        self._building = True
        keep = select or next(((o, i) for k, i, o in self.selected() if k == "request"), None)
        self.tree.blockSignals(True)
        self.tree.clear()
        self.payload = {}
        me = db.target()
        rows = A.list_requests()
        own = [r for r in rows if r["org"] == me]
        self._fill(None, A.list_folders(), own, me)
        shared = [r for r in rows if r["org"] != me]
        if shared:
            with db.within(db.GLOBAL):
                gfolders = A.list_folders()
            node = QTreeWidgetItem([f"Shared  ({len(shared)})", ""])
            node.setData(0, ROLE, self._key("org", db.GLOBAL, db.GLOBAL))
            node.setToolTip(0, "Requests Global shares with every organization. They are changed from Global; Save here makes your own copy.")
            node.setFlags((node.flags() | Qt.ItemFlag.ItemIsEnabled) & ~Qt.ItemFlag.ItemIsDragEnabled & ~Qt.ItemFlag.ItemIsDropEnabled & ~Qt.ItemFlag.ItemIsSelectable)
            self.tree.addTopLevelItem(node)
            self._fill(node, gfolders, shared, db.GLOBAL)
            node.setExpanded(True)
        self.tree.blockSignals(False)
        self._building = False
        self.tree_hint.setVisible(not rows)
        self.tree.resizeColumnToContents(0)
        if keep:
            for it in self._all_items():
                k, i, o = self.kind_of(it)
                if k == "request" and (o, i) == tuple(keep):
                    self.tree.blockSignals(True)
                    self.tree.setCurrentItem(it)
                    self.tree.blockSignals(False)
                    break

    def _fill(self, top, folders, found, org):
        known = {f["id"] for f in folders}
        kids, by_folder = {}, {}
        for f in folders:
            kids.setdefault(f["parent_id"] if f["parent_id"] in known else None, []).append(f)
        for x in found:
            by_folder.setdefault(x["folder_id"] if x["folder_id"] in known else None, []).append(x)
        editable = org == db.target()

        def count(fid):
            return len(by_folder.get(fid, [])) + sum(count(c["id"]) for c in kids.get(fid, []))

        def add(parent, item):
            (parent.addChild if parent else self.tree.addTopLevelItem)(item)

        def fill(parent, fid):
            for f in sorted(kids.get(fid, []), key=lambda f: f["name"].lower()):
                if not editable and not count(f["id"]):
                    continue                                      # a Shared branch shows only folders with something shared in them
                item = QTreeWidgetItem([f"{f['name']}  ({count(f['id'])})", ""])
                key = self._key("folder", org, f["id"])
                item.setData(0, ROLE, key)
                self.payload[key] = {**f, "org": org}
                font = item.font(0)
                font.setBold(True)
                item.setFont(0, font)
                flags = item.flags() | Qt.ItemFlag.ItemIsDropEnabled | Qt.ItemFlag.ItemIsDragEnabled
                item.setFlags(flags if editable else flags & ~Qt.ItemFlag.ItemIsDragEnabled & ~Qt.ItemFlag.ItemIsDropEnabled)
                add(parent, item)
                fill(item, f["id"])
                item.setExpanded((org, f["id"]) in self.expanded or not editable)
            for x in sorted(by_folder.get(fid, []), key=lambda x: x["name"].lower()):
                item = QTreeWidgetItem([x["name"] + ("  (Shared)" if x.get("shared") and editable else ""), x["method"]])
                key = self._key("request", org, x["id"])
                item.setData(0, ROLE, key)
                self.payload[key] = x
                flags = (item.flags() | Qt.ItemFlag.ItemIsDragEnabled) & ~Qt.ItemFlag.ItemIsDropEnabled
                item.setFlags(flags if editable else flags & ~Qt.ItemFlag.ItemIsDragEnabled)
                add(parent, item)

        fill(top, None)

    def _all_items(self):
        out, todo = [], [self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())]
        while todo:
            it = todo.pop()
            out.append(it)
            todo.extend(it.child(i) for i in range(it.childCount()))
        return out

    def _remember(self, item, open_):
        if self._building:
            return
        kind, ident, org = self.kind_of(item)
        if kind == "folder":
            (self.expanded.add if open_ else self.expanded.discard)((org, ident))

    def _selected(self):
        if self._building:
            return
        picked = [(k, i, o) for k, i, o in self.selected() if k == "request"]
        if len(picked) != 1:
            return
        kind, rid, org = picked[0]
        r = self.payload.get(self._key("request", org, rid))
        if not r or (self.current and self.current.get("id") == rid and self.current.get("org") == org and not self.from_history):
            return
        if not self.leave_ok():
            self.refresh_tree(select=(self.current.get("org"), self.current["id"]) if self.current else None)
            return
        self.load(r, A.request_secret(r))

    def _item_edited(self, item, column):
        """A name typed into the tree (Rename)."""
        if self._building or column != 0:
            return
        kind, ident, org = self.kind_of(item)
        text = item.text(0).strip()
        try:
            if kind == "request":
                A.rename(ident, text, org)
                if self.current and self.current.get("id") == ident and self.current.get("org") == org:
                    self.current = A.get(ident, org)
                    self._set_title()
            elif kind == "folder":
                with db.within(org):
                    A.rename_folder(ident, text)
        except ValueError as e:
            QMessageBox.warning(self, "Rename", str(e))
        self.refresh_tree()

    def rename_selected(self):
        picked = self.selected()
        if len(picked) != 1 or picked[0][2] != db.target():
            return
        item = self.tree.selectedItems()[0]
        kind, ident, org = picked[0]
        name = self.payload[item.data(0, ROLE)]["name"]
        self._building = True
        item.setText(0, name)
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEditable)
        self._building = False
        self.tree.editItem(item, 0)

    def duplicate_selected(self):
        for kind, ident, org in self.selected():
            if kind == "request" and org == db.target():
                A.duplicate(ident, org)
        self.refresh_tree()

    def delete_selected(self):
        picked = [(k, i, o) for k, i, o in self.selected() if o == db.target()]
        if not picked:
            return
        names = [self.payload[self._key(k, o, i)]["name"] for k, i, o in picked]
        if len(picked) == 1 and picked[0][0] == "folder":
            text = f"Delete the folder '{names[0]}'? The requests and folders in it move up one level."
        elif len(picked) == 1:
            text = f"Delete the request '{names[0]}'? Its stored token or password is removed from the vault too."
        else:
            text = f"Delete {len(picked)} items? Stored tokens and passwords are removed from the vault too; folders' contents move up one level."
        box = QMessageBox(QMessageBox.Icon.Question, "Delete", text, parent=self)
        yes = box.addButton("Delete", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() != yes:
            return
        for kind, ident, org in picked:
            try:
                if kind == "request":
                    A.delete(ident, org)
                    if self.current and self.current.get("id") == ident and self.current.get("org") == org:
                        self.current = None
                        self._baseline = self._signature()
                        self._set_title()
                else:
                    with db.within(org):
                        A.delete_folder(ident)
            except ValueError as e:
                QMessageBox.warning(self, "Delete", str(e))
        self.refresh_tree()

    def new_folder(self):
        parent = next((i for k, i, o in self.selected() if k == "folder" and o == db.target()), None)
        name, ok = QInputDialog.getText(self, "New folder", "Folder name:")
        if not ok or not name.strip():
            return
        try:
            fid = A.create_folder(name, parent)
        except ValueError as e:
            QMessageBox.warning(self, "New folder", str(e))
            return
        if parent is not None:
            self.expanded.add((db.target(), parent))
        self.refresh_tree()
        for it in self._all_items():
            if self.kind_of(it) == ("folder", fid, db.target()):
                self.tree.setCurrentItem(it)

    def _moved(self, moves, target_folder):
        try:
            for kind, ident in moves:
                if kind == "folder":
                    A.move_folder(ident, target_folder)
            A.move_requests([i for k, i in moves if k == "request"], target_folder)
        except ValueError as e:
            QMessageBox.warning(self, "Move", str(e))
        if target_folder is not None:
            self.expanded.add((db.target(), target_folder))
        self.refresh_tree()

    # ---------------------------------------------------------------- history
    def refresh_history(self):
        self._history = A.list_history()
        self.history.blockSignals(True)
        self.history.setRowCount(len(self._history))
        for i, h in enumerate(self._history):
            status = str(h["status"]) if h["status"] else "failed"
            vals = [h["at"], h["method"], h["url"], status, f"{h['ms']} ms" if h["status"] else ""]
            for j, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if j == 3:
                    it.setForeground(st.qink("FAIL" if not h["status"] or h["status"] >= 400 else "WARN" if h["status"] >= 300 else "OK"))
                    it.setToolTip(h["error"] or h["reason"])
                self.history.setItem(i, j, it)
        self.history.resizeColumnsToContents()
        self.history.blockSignals(False)
        self.history_hint.setVisible(not self._history)
        self.keep.blockSignals(True)
        self.keep.setValue(A.history_keep())
        self.keep.blockSignals(False)

    def _history_clicked(self):
        rows = {i.row() for i in self.history.selectedIndexes()}
        if len(rows) != 1:
            return
        h = self._history[rows.pop()]
        if not self.leave_ok():
            return
        secret, note = "", ""
        if h["auth"]["type"] in ("bearer", "basic", "apikey"):
            saved = A.get(h["request_id"]) if h.get("request_id") else None
            if saved and saved["auth"]["type"] == h["auth"]["type"]:
                secret = A.request_secret(saved)
            else:
                note = "Enter the token again: history does not keep secrets."
        self.load(h, secret, from_history=True)
        self.tree.blockSignals(True)
        self.tree.clearSelection()
        self.tree.blockSignals(False)
        self._say(note or f"Loaded from history ({h['at']}). Click Send to send it again, or Save to keep it.", None)

    def _keep_changed(self, value):
        db.set_setting("api_history_keep", int(value))
        A.prune()
        self.refresh_history()

    def clear_history(self):
        box = QMessageBox(QMessageBox.Icon.Question, "Clear history", "Clear the history of this organization? Saved requests are not affected.", parent=self)
        yes = box.addButton("Clear", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() == yes:
            A.clear_history()
            self.refresh_history()

    # ---------------------------------------------------------------- the page
    def refresh(self):
        """After the organization or the inventory changed: the tree, history, variables and profiles of the one being looked at."""
        if db.target() != self._org:
            self._org = db.target()
            self.expanded = set()
            self.load(A.blank())
            self._result = None
            self._say("Not sent yet.", None)
            self.resp_body.setPlainText("")
            self.resp_headers.setPlainText("")
        self._fill_profiles()
        self.refresh_tree()
        self.refresh_history()
        self.variables.refresh()

    def shutdown(self):
        if self.running():
            self.worker.cancel.set()
            self.worker.wait(5000)
