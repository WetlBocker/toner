"""A Windows computer's services in a window of their own: list them, search, and start, stop or restart the ones you choose."""
from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox,
                               QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout)

from core import audit, profiles, winmon, winservices
from ui import status as st
from ui import theme
from ui.widgets import filling

NAME = Qt.ItemDataRole.UserRole
FILTERS = ["All services", "Running", "Stopped", "Automatic but not running"]
_SHOWN = {"auto": "Auto", "delayed": "Auto (Delayed)", "manual": "Manual", "disabled": "Disabled"}      # what the Startup column says for each type


class _Job(QThread):
    done = Signal(object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn())
        except Exception as e:                       # shown in the window, never left to a thread's traceback
            self.done.emit(e)


class SignIn(QDialog):
    """A Windows account for this window only: a computer that reports by agent has no login of its own, and Toner keeps nothing from here."""

    def __init__(self, host, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sign in to manage services")
        self.setMinimumWidth(440)
        self.user, self.password = QLineEdit(), QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.user.setPlaceholderText("DOMAIN\\user, user@domain or .\\user")
        intro = QLabel(f"This computer reports to Toner through an agent, which only sends. To list its services live and control them, "
                       f"Toner signs in to <b>{host}</b> with PowerShell remoting (WinRM). The account needs to be an administrator there. "
                       "The user name and password are used for this window only and are not saved.")
        intro.setWordWrap(True)
        form = QFormLayout()
        form.addRow("User name", self.user)
        form.addRow("Password", self.password)
        ok, cancel = QPushButton("Sign in"), QPushButton("Cancel")
        ok.setProperty("primary", True)
        ok.clicked.connect(self._accept)
        cancel.clicked.connect(self.reject)
        bar = QHBoxLayout()
        bar.addStretch()
        bar.addWidget(cancel)
        bar.addWidget(ok)
        lay = QVBoxLayout(self)
        lay.addWidget(intro)
        lay.addLayout(form)
        lay.addLayout(bar)

    def _accept(self):
        if not self.user.text().strip() or not self.password.text():
            QMessageBox.warning(self, "Sign in", "Enter the user name and the password.")
            return
        self.accept()


class ServicesDialog(QDialog):
    def __init__(self, dev, parent=None):
        super().__init__(parent)
        self.dev = dev
        self.live = dev                              # the device as used for this window: with a typed sign-in, an agent computer becomes a WinRM one
        self.password = None                         # typed for this window only
        self.rows = []
        self.busy = False                            # a list or an action is in progress
        self._threads = []                           # workers are kept until they have really finished (never dropped from inside their own signal)
        self.setWindowTitle(f"Services - {dev['name']}")
        self.resize(900, 620)
        self.setModal(False)
        from ui.finder import SearchBox
        self.search = SearchBox("Search services", page=self)
        self.filter = QComboBox()
        self.filter.addItems(FILTERS)
        self.refresh_btn = QPushButton("Refresh")
        self.start_btn, self.stop_btn, self.restart_btn = QPushButton("Start"), QPushButton("Stop"), QPushButton("Restart")
        self.signin_btn = QPushButton("Sign in to manage...")
        for b in (self.refresh_btn, self.start_btn, self.stop_btn, self.restart_btn, self.signin_btn):
            b.setAutoDefault(False)
        self.restart_btn.setProperty("primary", True)
        self.note = QLabel("")
        self.note.setWordWrap(True)
        self.note.setProperty("muted", True)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Display name", "Name", "State", "Startup"])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        hh = self.table.horizontalHeader()
        hh.setStretchLastSection(False)
        hh.setSectionResizeMode(0, hh.ResizeMode.Stretch)
        hh.setSectionResizeMode(1, hh.ResizeMode.Interactive)
        hh.setSectionResizeMode(2, hh.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, hh.ResizeMode.ResizeToContents)
        self.table.setColumnWidth(1, 190)
        self.table.horizontalHeader().setSortIndicator(0, Qt.SortOrder.AscendingOrder)       # A to Z until another column is chosen
        self.table.setSortingEnabled(True)
        top = QHBoxLayout()
        top.addWidget(self.search, 1)
        top.addWidget(self.filter)
        top.addWidget(self.refresh_btn)
        bar = QHBoxLayout()
        bar.addWidget(self.start_btn)
        bar.addWidget(self.stop_btn)
        bar.addWidget(self.restart_btn)
        bar.addWidget(self.signin_btn)
        bar.addStretch()
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.note)
        lay.addWidget(self.table, 1)
        lay.addLayout(bar)
        lay.addWidget(self.status)
        self.search.textChanged.connect(self._apply_filter)
        self.filter.currentIndexChanged.connect(self._apply_filter)
        self.refresh_btn.clicked.connect(self.refresh)
        self.start_btn.clicked.connect(lambda: self.act("start"))
        self.stop_btn.clicked.connect(lambda: self.act("stop"))
        self.restart_btn.clicked.connect(lambda: self.act("restart"))
        self.signin_btn.clicked.connect(self.sign_in)
        self.table.itemSelectionChanged.connect(self._buttons)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self._buttons()
        self.refresh()

    def _run(self, fn, done):
        self._threads = [t for t in self._threads if not t.isFinished()]
        job = _Job(fn)
        job.done.connect(done)
        self._threads.append(job)
        self.busy = True
        job.start()

    def closeEvent(self, e):
        for t in self._threads:                      # let a started action finish talking to the computer
            t.wait(3000)
        super().closeEvent(e)

    # ---------------------------------------------------------------- what can be done
    def _agent_only(self):
        return not winservices.can_control(self.live)

    def _chosen(self):
        return [self.table.item(i.row(), 1).data(NAME) for i in self.table.selectionModel().selectedRows() if self.table.item(i.row(), 1) is not None]

    def _chosen_states(self):
        return {self.table.item(i.row(), 2).text() for i in self.table.selectionModel().selectedRows()}

    def _buttons(self):
        busy = self.busy
        can = winservices.can_control(self.live) and not busy
        states = self._chosen_states()
        self.start_btn.setEnabled(can and bool(states - {"Running"}))
        self.stop_btn.setEnabled(can and "Running" in states)
        self.restart_btn.setEnabled(can and bool(states) and states <= {"Running"})          # a service that is not running has nothing to restart
        self.refresh_btn.setEnabled(not busy)
        self.signin_btn.setVisible(self._agent_only())

    # ---------------------------------------------------------------- the list
    def refresh(self, quiet=False):
        """Read the list again. quiet: keep what the status line says (after an action, the list moves under its result)."""
        if self.busy:
            return
        pw = self.password if self.password is not None else (self.dev.get("password") or profiles.secret(self.dev, "main"))
        live = profiles.resolve(self.live)
        self._quiet = quiet
        if not quiet:
            self.status.setText("Reading the services...")
        self.refresh_btn.setEnabled(False)
        self._run(lambda: winservices.listing(live, pw), self._listed)

    def _listed(self, res):
        self.busy = False
        self._buttons()
        if isinstance(res, Exception):
            self.status.setText(f"Could not get the services: {res}")
            self.status.setStyleSheet(f"color: {st.ink('FAIL')};")
            return
        if not getattr(self, "_quiet", False):
            self.status.setStyleSheet("")
        self.rows, source = res
        agent = self._agent_only()
        self.note.setText(source + ("  Starting and stopping needs a sign-in: this computer's agent only reports." if agent else ""))
        self._fill()
        if not getattr(self, "_quiet", False):
            self.status.setText(f"{len(self.rows)} services.")

    def _fill(self):
        keep = set(self._chosen())
        self.table.setSortingEnabled(False)
        with filling(self.table):
            self.table.setRowCount(len(self.rows))
            for i, r in enumerate(self.rows):
                for j, text in enumerate((r["display"] or r["name"], r["name"], r["state"], winservices.startup_label(r))):
                    it = QTableWidgetItem(text)
                    it.setToolTip(text)
                    if j == 1:
                        it.setData(NAME, r["name"])
                    self.table.setItem(i, j, it)
                self._paint(i, r)
                if r["name"] in keep:
                    self.table.selectRow(i)
        self.table.setSortingEnabled(True)
        self._apply_filter()

    def _paint(self, row, r):
        """A service that should be running but is not stands out; a running one is quiet."""
        item = self.table.item(row, 2)
        if r["state"] == "Stopped" and r["start"] == "Auto":
            item.setForeground(st.qink("WARN"))
        elif r["state"] == "Running":
            item.setForeground(QColor((theme.current() or {}).get("text", "#888888")))
        else:
            item.setForeground(QColor((theme.current() or {}).get("muted", "#888888")))

    def _apply_filter(self, *_):
        words = self.search.text().lower().split()
        mode = self.filter.currentIndex()
        shown = 0
        for i in range(self.table.rowCount()):
            text = f"{self.table.item(i, 0).text()} {self.table.item(i, 1).text()}".lower()
            state, start = self.table.item(i, 2).text(), self.table.item(i, 3).text().split(" ")[0]
            keep = all(w in text for w in words) and (mode == 0 or (mode == 1 and state == "Running") or (mode == 2 and state == "Stopped")
                                                         or (mode == 3 and state == "Stopped" and start == "Auto"))
            self.table.setRowHidden(i, not keep)
            shown += keep
        if self.rows:
            self.note.setToolTip(f"{shown} of {len(self.rows)} shown")

    # ---------------------------------------------------------------- the right-click menu
    def _menu(self, pos):
        m = self.build_menu(pos)
        if m is not None:
            m.exec(self.table.viewport().mapToGlobal(pos))

    def build_menu(self, pos):
        """The right-click menu for the row at `pos` (the row is selected first, unless it is part of the selection already)."""
        row = self.table.rowAt(pos.y())
        if row < 0:
            return None
        if not self.table.selectionModel().isRowSelected(row):
            self.table.selectRow(row)
        names = self._chosen()
        if not names:
            return None
        by_name = {r["name"]: r for r in self.rows}
        m = QMenu(self)
        for text, act, btn in (("Start", "start", self.start_btn), ("Stop", "stop", self.stop_btn), ("Restart", "restart", self.restart_btn)):
            a = m.addAction(text, lambda act=act: self.act(act))
            a.setEnabled(btn.isEnabled())
        m.addSeparator()
        sub = m.addMenu("Startup type")
        sub.setEnabled(winservices.can_control(self.live) and not self.busy)
        now = {winservices.startup_label(by_name[n]) for n in names if n in by_name}
        for key, (label, _word) in winservices.STARTUP.items():
            a = sub.addAction(label, lambda key=key: self.set_startup(key))
            a.setCheckable(True)
            a.setChecked(len(now) == 1 and now == {_SHOWN[key]})
        m.addSeparator()
        m.addAction("Copy name" + ("s" if len(names) > 1 else ""), lambda: QApplication.clipboard().setText("\n".join(names)))
        m.addAction("Copy display name" + ("s" if len(names) > 1 else ""),
                    lambda: QApplication.clipboard().setText("\n".join(by_name[n]["display"] or n for n in names if n in by_name)))
        m.addSeparator()
        m.addAction("Refresh", self.refresh).setEnabled(not self.busy)
        return m

    # ---------------------------------------------------------------- startup type
    def set_startup(self, mode):
        names = self._chosen()
        if not names or not winservices.can_control(self.live) or self.busy:
            return
        label = winservices.STARTUP[mode][0]
        shown = {r["name"]: r["display"] or r["name"] for r in self.rows}
        lines = ", ".join(shown.get(n, n) for n in names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
        text = f"Set the startup type of {lines} on {self.dev['name']} to {label}?"
        extra = []
        if mode == "disabled":
            text += "\n\nA disabled service cannot be started, by anyone or by another service, until it is set to Manual or Automatic. " \
                    "If it is running now it keeps running until it is stopped."
            extra = [w for w in (winservices.warning("stop", n) for n in names) if w]
        elif mode in ("auto", "delayed"):
            text += "\n\nIt will start by itself whenever the computer starts. It is not started now."
        if extra:
            text += "\n\n" + "\n".join(extra[:3])
        box = QMessageBox(QMessageBox.Icon.Warning if (extra or mode == "disabled") else QMessageBox.Icon.Question, "Change startup type", text,
                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, self)
        box.setDefaultButton(QMessageBox.StandardButton.No if (extra or mode == "disabled") else QMessageBox.StandardButton.Yes)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        pw = self.password if self.password is not None else (self.dev.get("password") or profiles.secret(self.dev, "main"))
        live = profiles.resolve(self.live)
        self.status.setStyleSheet("")
        self.status.setText(f"Changing the startup type of {len(names)} service(s)...")
        for b in (self.start_btn, self.stop_btn, self.restart_btn, self.refresh_btn):
            b.setEnabled(False)

        def work():
            out = []
            for n in names:
                try:
                    out.append((n, winservices.set_startup(live, mode, n, pw), None))
                except Exception as e:
                    out.append((n, None, str(e)))
                    break
            return out
        self._run(work, lambda res: self._changed(mode, names, res))

    def _changed(self, mode, names, res):
        self.busy = False
        label = winservices.STARTUP[mode][0]
        if isinstance(res, Exception):
            self._buttons()
            self.status.setText(f"Failed: {res}")
            self.status.setStyleSheet(f"color: {st.ink('FAIL')};")
            return
        done, failed = [], []
        by_name = {r["name"]: r for r in self.rows}
        for name, ans, err in res:
            shown = (ans or {}).get("display") or by_name.get(name, {}).get("display") or name
            if ans and ans["ok"]:
                done.append(shown)
                audit.log("service startup changed", f"{self.dev['name']}: {shown} ({name}) set to {label}")
                if name in by_name:
                    by_name[name]["start"], by_name[name]["delayed"] = ans.get("start") or by_name[name]["start"], ans.get("delayed", False)
            else:
                reason = err or (ans or {}).get("error") or "it did not work"
                failed.append(f"{shown}: {reason}")
                audit.log("service change failed", f"{self.dev['name']}: startup type of {shown} ({name}) to {label}: {reason}")
        skipped = len(names) - len(res)
        bits = []
        if done:
            bits.append(f"Startup type set to {label}: {', '.join(done[:5])}" + (f" and {len(done) - 5} more" if len(done) > 5 else "") + ".")
        if failed:
            bits.append("Not done - " + "; ".join(failed[:3]) + (f" (+{len(failed) - 3} more)" if len(failed) > 3 else "") + ".")
        if skipped > 0:
            bits.append(f"{skipped} more were not tried.")
        self.status.setText("  ".join(bits))
        self.status.setStyleSheet(f"color: {st.ink('FAIL')};" if failed else "")
        self._fill()
        self._buttons()
        self.refresh(quiet=True)

    # ---------------------------------------------------------------- signing in
    def sign_in(self):
        dlg = SignIn(self.dev["host"], self)
        if dlg.exec():
            self.live = winservices.with_signin(self.dev, dlg.user.text().strip())
            self.password = dlg.password.text()
            audit.log("services sign-in", f"{self.dev['name']}: WinRM as {dlg.user.text().strip()} (for the Services window)")
            self.refresh()

    # ---------------------------------------------------------------- start, stop, restart
    def act(self, action):
        names = self._chosen()
        if not names or not winservices.can_control(self.live) or self.busy:
            return
        verb = winservices.ACTIONS[action][0]
        shown = {r["name"]: r["display"] or r["name"] for r in self.rows}
        lines = ", ".join(f"{shown.get(n, n)} ({n})" if shown.get(n, n) != n else n for n in names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
        extra = [w for w in (winservices.warning(action, n) for n in names) if w]
        text = f"{verb} {lines} on {self.dev['name']}?"
        if action in ("stop", "restart"):
            text += "\n\nServices that depend on it are stopped too."
        if extra:
            text += "\n\n" + "\n".join(extra[:3])
        box = QMessageBox(QMessageBox.Icon.Warning if extra else QMessageBox.Icon.Question, f"{verb} service", text,
                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, self)
        box.setDefaultButton(QMessageBox.StandardButton.No if extra else QMessageBox.StandardButton.Yes)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        pw = self.password if self.password is not None else (self.dev.get("password") or profiles.secret(self.dev, "main"))
        live = profiles.resolve(self.live)
        self.status.setStyleSheet("")
        self.status.setText(f"{ {'start': 'Starting', 'stop': 'Stopping', 'restart': 'Restarting'}[action] } {len(names)} service(s)...")
        for b in (self.start_btn, self.stop_btn, self.restart_btn, self.refresh_btn):
            b.setEnabled(False)

        def work():
            out = []
            for n in names:
                try:
                    out.append((n, winservices.control(live, action, n, pw), None))
                except Exception as e:
                    out.append((n, None, str(e)))
                    break                              # the computer cannot be reached or commanded: the rest would fail the same way
            return out
        self._run(work, lambda res: self._acted(action, names, res))

    def _acted(self, action, names, res):
        self.busy = False
        past = winservices.ACTIONS[action][1]
        if isinstance(res, Exception):
            self._buttons()
            self.status.setText(f"Failed: {res}")
            self.status.setStyleSheet(f"color: {st.ink('FAIL')};")
            return
        done, failed = [], []
        by_name = {r["name"]: r for r in self.rows}
        for name, ans, err in res:
            label = (ans or {}).get("display") or by_name.get(name, {}).get("display") or name
            if ans and ans["ok"]:
                done.append(label)
                audit.log(f"service {past}", f"{self.dev['name']}: {label} ({name})")
            else:
                reason = err or (ans or {}).get("error") or "it did not work"
                failed.append(f"{label}: {reason}")
                audit.log("service change failed", f"{self.dev['name']}: {action} {label} ({name}): {reason}")
            if ans and name in by_name and ans.get("state"):
                by_name[name]["state"] = ans["state"]
        skipped = len(names) - len(res)
        bits = []
        if done:
            bits.append(f"{past.capitalize()}: {', '.join(done[:5])}" + (f" and {len(done) - 5} more" if len(done) > 5 else "") + ".")
        if failed:
            bits.append("Not done - " + "; ".join(failed[:3]) + (f" (+{len(failed) - 3} more)" if len(failed) > 3 else "") + ".")
        if skipped > 0:
            bits.append(f"{skipped} more were not tried.")
        self.status.setText("  ".join(bits))
        self.status.setStyleSheet(f"color: {st.ink('FAIL')};" if failed else "")
        self._fill()
        self._buttons()
        self.refresh(quiet=True)                           # the list as the computer now has it (a service may have moved on by itself)
