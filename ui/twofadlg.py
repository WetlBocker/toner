"""Set up 2FA (Settings > Accounts > External Identities, right-click): one directory's Duo settings and nothing else. The secret
key is taken from its box at the click, goes to the OS protected store only (osstore, "duo:<id>"), and the box is cleared on Save
and on close; it is never in netcheck.keys, the audit, a log or a message. An empty box keeps the stored secret. Turning Duo off
keeps it. The list signed is the verified one handed in, with this directory's duo changed (no CA re-hash)."""
import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QDialog, QFormLayout, QLabel, QLineEdit, QVBoxLayout

from core import datakey, osstore, perms, roles
from ui.directorydlg import NO_STORE
from ui.settings_base import note
from ui.signinwindow import Job, primary, say

HOST = re.compile(r"[A-Za-z0-9.-]+")


def clean_host(text):
    """`https://api-x.duosecurity.com/` -> `api-x.duosecurity.com`; None if what is left isn't a plain host name."""
    h = re.split(r"[/?#]", re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", text.strip()), 1)[0]
    return h if HOST.fullmatch(h) else None


class TwoFactorDialog(QDialog):
    """Set up Duo for `cfg`, one of `dirs` (the verified list). exec() is truthy after a Save."""

    def __init__(self, dirs, cfg, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Set up 2FA")
        self.dirs, self.cfg = list(dirs), cfg
        self.store = self.has_secret = None             # read on a Job: a Secret Service nobody unlocks takes 3 seconds to say no
        self._closed, self._jobs = False, set()
        duo = cfg.get("duo") or {}
        form = QFormLayout()
        self.second, self.duo_note = QComboBox(), note(NO_STORE)
        self.second.addItems(["Off", "Duo"])
        self.duo_note.hide()
        self.host, self.ikey, self.skey = QLineEdit(duo.get("host") or ""), QLineEdit(duo.get("ikey") or ""), QLineEdit()
        self.skey.setEchoMode(QLineEdit.EchoMode.Password)
        for text, w, under in (("Second step", self.second, self.duo_note), ("Duo API hostname", self.host, None),
                               ("Integration key", self.ikey, None), ("Secret key", self.skey, None)):
            w.setAccessibleName(text)
            lab = QLabel(text)
            lab.setBuddy(w)
            form.addRow(lab, w)
            if under is not None:
                form.addRow(under)
        self.message = QLabel()
        self.message.setWordWrap(True)
        self.message.hide()
        self.save_btn = primary("Save")
        self.save_btn.clicked.connect(self._save)
        outer = QVBoxLayout(self)
        outer.addLayout(form)
        outer.addWidget(self.message)
        outer.addWidget(self.save_btn)
        self.second.setCurrentIndex(1 if duo.get("on") else 0)
        self.second.currentIndexChanged.connect(self._fields)
        for w in (self.host, self.ikey, self.skey):
            w.textChanged.connect(self._fields)
        self._fields()
        key = "duo:" + cfg["id"]

        def probe():
            if osstore.available():
                return True, osstore.get(key) is not None
            return False, False
        self._run(probe, self._probed)

    def _probed(self, result, error):
        self.store, self.has_secret = result if error is None else (False, False)
        self.second.model().item(1).setEnabled(self.store)
        self.duo_note.setVisible(not self.store)
        if not self.store:
            self.second.setCurrentIndex(0)
        self._fields()

    def _fields(self, *_):
        duo = self.second.currentIndex() == 1
        for w in (self.host, self.ikey, self.skey):
            w.setEnabled(duo and bool(self.store))
        ready = self.store is not None and not self._jobs
        self.save_btn.setEnabled(ready and (not duo or (clean_host(self.host.text()) is not None and bool(self.ikey.text().strip())
                                                         and (bool(self.skey.text()) or bool(self.has_secret)))))

    def _save(self):
        duo, typed = self.second.currentIndex() == 1, self.skey.text()      # the secret as it is at the click
        host, ikey = clean_host(self.host.text()), self.ikey.text().strip()
        if duo and host is None:
            return
        self.skey.setText("")
        self.message.hide()
        new = dict(self.cfg)
        new["duo"] = {"on": True, "host": host, "ikey": ikey} if duo else {**(self.cfg.get("duo") or {}), "on": False}

        def store():
            if duo and typed:
                osstore.put("duo:" + self.cfg["id"], typed.encode("utf-8"))
        self._run(store, lambda _r, e: self._saved(new, duo and bool(typed), e))

    def _saved(self, new, put, error):
        if error is not None:
            return say(self.message, NO_STORE)
        if put:
            self.has_secret = True
        try:
            roles.set_directories([new if d.get("id") == new["id"] else d for d in self.dirs], edited=None)
        except (ValueError, datakey.Locked, perms.Denied) as e:
            return say(self.message, str(e))
        self.accept()

    # ---------------------------------------------------------------- Jobs
    def _run(self, fn, landed):
        job = Job(fn)
        job.landed = landed
        self._jobs.add(job)
        self._fields()
        job.done.connect(self._landed, Qt.ConnectionType.QueuedConnection)
        job.start()

    def _landed(self, job, result, error):
        job.wait()
        landed, job.fn, job.landed = job.landed, None, None
        self._jobs.discard(job)
        if not self._closed:                            # (after Close a store write in flight still completes; only set_directories is skipped)
            landed(result, error)
            self._fields()

    def done(self, r):
        """A Job must not outlive its dialog, nor the secret its box."""
        self._closed = True
        for job in list(self._jobs):
            job.wait()
        self._jobs.clear()
        self.skey.setText("")
        super().done(r)
