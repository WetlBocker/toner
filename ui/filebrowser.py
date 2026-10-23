"""The Files panel of an SSH session: this computer on one side, the device on the other, over SFTP on the session's own login.
Drag between the two lists (either way, files and whole folders), or use Upload and Download. Everything that touches the device
or copies files runs on a worker thread, with a progress line and a Cancel button."""
import json
import os
import posixpath
import queue
import shutil
import stat
import threading
import time
from datetime import datetime

from PySide6.QtCore import QMimeData, QThread, Qt, QUrl, Signal
from PySide6.QtGui import QDrag
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMessageBox,
                               QProgressBar, QPushButton, QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)
from ui.widgets import remember_sizes

MIME = "application/x-toner-files"            # a drag from one of the two lists: {"side": "local"|"remote", "paths": [...]}
NOT_CONNECTED = "Connect the session to browse the device's files."
_last_local = {"path": ""}                     # the local folder last looked at: the next session's panel starts there


class Cancelled(Exception):
    pass


class Stop(Exception):
    """The user answered Cancel to a question (nothing more is copied)."""


def human_size(n):
    if n is None:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def when(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else ""
    except (OverflowError, OSError, ValueError):
        return ""


def plain(e):
    """The server's (or the system's) message in plain words."""
    text = str(e) or type(e).__name__
    low = text.lower()
    if isinstance(e, PermissionError) or "permission denied" in low:
        return "permission denied" if isinstance(e, PermissionError) else "the device refused: permission denied"
    if isinstance(e, FileNotFoundError) or "no such file" in low:
        return "no such file or folder"
    if isinstance(e, FileExistsError) or "already exists" in low or low == "failure":
        return "the name is already in use, or the device refused" if low == "failure" else "it already exists"
    return text


# =============================================================================== the local side's file system, and the device's
class LocalFs:
    """The same small set of operations on this computer as on the device, so transfers are written once."""
    sep = os.sep

    def start(self):
        return _last_local["path"] if _last_local["path"] and os.path.isdir(_last_local["path"]) else os.path.expanduser("~")

    def join(self, folder, name):
        return os.path.join(folder, name)

    def parent(self, path):
        up = os.path.dirname(path.rstrip("\\/")) or path
        return up if up else path

    def listing(self, path):
        out = []
        with os.scandir(path) as it:
            for d in it:
                try:
                    is_dir = d.is_dir(follow_symlinks=True)            # a link to a folder opens as a folder
                    st = d.stat(follow_symlinks=is_dir)
                    out.append({"name": d.name, "is_dir": is_dir, "size": None if is_dir else st.st_size, "mtime": st.st_mtime,
                                "is_link": d.is_symlink()})
                except OSError:
                    out.append({"name": d.name, "is_dir": False, "size": None, "mtime": 0, "is_link": False})
        return out

    def is_dir(self, path):
        return os.path.isdir(path)

    def exists(self, path):
        return os.path.lexists(path)

    def mkdir(self, path):
        os.mkdir(path)

    def delete(self, path):
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    def walk(self, path):
        """[(relative folder, [file names])] for a folder, folders first, so a tree can be copied."""
        out = []
        for root, dirs, files in os.walk(path):
            rel = os.path.relpath(root, path)
            out.append(("" if rel == "." else rel.replace(os.sep, "/"), sorted(files)))
        return out


class RemoteFs:
    sep = "/"

    def __init__(self, sftp):
        self.sftp = sftp

    def start(self):
        try:
            return self.sftp.normalize(".")
        except OSError:
            return "/"

    def join(self, folder, name):
        return posixpath.join(folder, name)

    def parent(self, path):
        up = posixpath.dirname(path.rstrip("/")) or "/"
        return up

    def listing(self, path):
        try:
            if not stat.S_ISDIR(self.sftp.stat(path).st_mode or 0):
                raise OSError("not a folder")
        except OSError as e:
            raise OSError(plain(e) if str(e) != "not a folder" else "not a folder") from None
        out = []
        for a in self.sftp.listdir_attr(path):
            mode = a.st_mode or 0
            is_link = stat.S_ISLNK(mode)
            is_dir = stat.S_ISDIR(mode)
            if is_link:
                try:
                    is_dir = stat.S_ISDIR(self.sftp.stat(posixpath.join(path, a.filename)).st_mode or 0)
                except OSError:
                    is_dir = False
            out.append({"name": a.filename, "is_dir": is_dir, "size": None if is_dir else a.st_size, "mtime": a.st_mtime or 0,
                        "is_link": is_link})
        return out

    def is_dir(self, path):
        try:
            return stat.S_ISDIR(self.sftp.stat(path).st_mode or 0)
        except OSError:
            return False

    def exists(self, path):
        try:
            self.sftp.lstat(path)
            return True
        except OSError:
            return False

    def mkdir(self, path):
        self.sftp.mkdir(path)

    def delete(self, path):
        try:
            mode = self.sftp.lstat(path).st_mode or 0
        except OSError as e:
            raise OSError(plain(e)) from None
        if stat.S_ISDIR(mode):
            for a in self.sftp.listdir_attr(path):
                self.delete(posixpath.join(path, a.filename))
            self.sftp.rmdir(path)
        else:
            self.sftp.remove(path)

    def walk(self, path):
        out = []
        todo = [""]
        while todo:
            rel = todo.pop(0)
            here = posixpath.join(path, rel) if rel else path
            files = []
            for a in self.sftp.listdir_attr(here):
                if stat.S_ISDIR(a.st_mode or 0):
                    todo.append(posixpath.join(rel, a.filename) if rel else a.filename)
                else:
                    files.append(a.filename)
            out.append((rel, sorted(files)))
        return out


# =============================================================================== the worker
class Worker(QThread):
    """Runs one job at a time against the device (and this computer's disk for copies), off the UI thread."""
    done = Signal(object, object, object)       # job id, result, error (an Exception, or None)
    progress = Signal(str, int, int)            # text, done, total (bytes of the file being copied; total 0 = unknown)
    asked = Signal(str, str)                    # "'name' already exists in folder": name, folder

    def __init__(self, session):
        super().__init__()
        self.session = session                  # the SshSession: its open_sftp() opens a channel on the same login
        self.jobs = queue.Queue()
        self.sftp = None
        self.remote = None
        self.cancel = threading.Event()
        self._answer, self._answered = None, threading.Event()
        self._quit = False

    def submit(self, job_id, fn):
        self.jobs.put((job_id, fn))

    def answer(self, what):
        self._answer = what
        self._answered.set()

    def ask(self, name, folder):
        """From a job: ask the UI whether to replace a file. Returns replace / replace_all / skip, or raises Stop."""
        self._answered.clear()
        self.asked.emit(name, folder)
        while not self._answered.wait(0.1):
            if self.cancel.is_set():
                raise Cancelled
        if self._answer == "cancel":
            raise Stop
        return self._answer

    def stop(self):
        self._quit = True
        self.cancel.set()
        self.jobs.put((None, None))

    def run(self):
        while not self._quit:
            job_id, fn = self.jobs.get()
            if fn is None:
                break
            self.cancel.clear()
            try:
                if self.remote is None:
                    started = time.time()
                    while not self.session.ready() and time.time() - started < 60:     # the login may still be under way
                        if self._quit or self.cancel.is_set() or not self.session.isRunning():
                            raise OSError("the session is not connected")
                        time.sleep(0.1)
                    self.sftp = self.session.open_sftp()
                    self.remote = RemoteFs(self.sftp)
                result, error = fn(self), None
            except Exception as e:                                   # noqa: BLE001  (every failure is reported to the panel)
                result, error = None, e
            self.done.emit(job_id, result, error)
        try:
            if self.sftp is not None:
                self.sftp.close()
        except Exception:
            pass


# =============================================================================== copying
def copy_file(worker, src_fs, src, dst_fs, dst, label, policy):
    """One file, with progress. policy: {"replace_all": bool}. Returns False when skipped."""
    if dst_fs.exists(dst) and not policy.get("replace_all"):
        what = worker.ask(posixpath.basename(dst) if dst_fs.sep == "/" else os.path.basename(dst),
                          dst_fs.parent(dst))
        if what == "skip":
            return False
        if what == "replace_all":
            policy["replace_all"] = True

    def cb(done, total):
        if worker.cancel.is_set():
            raise Cancelled
        worker.progress.emit(label, done, total)

    worker.progress.emit(label, 0, 0)
    try:
        if isinstance(src_fs, LocalFs):
            worker.sftp.put(src, dst, callback=cb)
        else:
            worker.sftp.get(src, dst, callback=cb)
    except Cancelled:
        try:
            dst_fs.delete(dst)                                       # the unfinished file is removed
        except Exception:
            pass
        raise
    return True


def copy_tree(worker, src_fs, src, dst_fs, dst, verb, policy):
    """A folder with everything in it. Returns how many files were copied."""
    name = os.path.basename(src.rstrip("\\/")) if src_fs.sep != "/" else posixpath.basename(src.rstrip("/"))
    tree = src_fs.walk(src)
    total = sum(len(files) for _, files in tree)
    n = copied = 0
    for rel, files in tree:
        target = dst_fs.join(dst, rel.replace("/", dst_fs.sep)) if rel else dst
        if not dst_fs.is_dir(target):
            dst_fs.mkdir(target)
        for f in files:
            n += 1
            label = f"{verb} {name}: file {n} of {total}, {f}"
            s = src_fs.join(src_fs.join(src, rel.replace("/", src_fs.sep)) if rel else src, f)
            if copy_file(worker, src_fs, s, dst_fs, dst_fs.join(target, f), label, policy):
                copied += 1
    return copied


def transfer(worker, src_fs, items, dst_fs, dst_folder, verb):
    """Files and folders `items` (full paths) into dst_folder. Returns (files copied, stopped early by Cancel in a question)."""
    policy, copied = {}, 0
    try:
        for path in items:
            base = os.path.basename(path.rstrip("\\/")) if src_fs.sep != "/" else posixpath.basename(path.rstrip("/"))
            dst = dst_fs.join(dst_folder, base)
            if src_fs.is_dir(path):
                copied += copy_tree(worker, src_fs, path, dst_fs, dst, verb, policy)
            elif copy_file(worker, src_fs, path, dst_fs, dst, f"{verb} {base}", policy):
                copied += 1
    except Stop:
        return copied, True
    return copied, False


# =============================================================================== one side's list
class FileList(QTreeWidget):
    """Name, Size, Modified. Rows can be dragged to the other side; drops from the other side (and, on the device side,
    files from Windows Explorer) land in the folder shown, or in the folder row they are dropped on."""
    dropped = Signal(object, object)            # payload dict, target folder name (None = the folder shown)
    entered = Signal(str)                       # a folder was double-clicked

    def __init__(self, side):
        super().__init__()
        self.side = side
        self.setHeaderLabels(["Name", "Size", "Modified"])
        self.setRootIsDecorated(False)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.header().setStretchLastSection(False)
        self.setColumnWidth(1, 80)
        self.setColumnWidth(2, 120)
        self.itemDoubleClicked.connect(self._double)

    def _double(self, item, _col):
        if item.data(0, Qt.ItemDataRole.UserRole)["is_dir"]:
            self.entered.emit(item.data(0, Qt.ItemDataRole.UserRole)["name"])

    def entries(self, selected=True):
        items = self.selectedItems() if selected else [self.topLevelItem(i) for i in range(self.topLevelItemCount())]
        return [it.data(0, Qt.ItemDataRole.UserRole) for it in items]

    def fill(self, entries):
        self.clear()
        for e in sorted(entries, key=lambda e: (not e["is_dir"], e["name"].lower())):
            it = QTreeWidgetItem([e["name"] + ("/" if e["is_dir"] else ""), "" if e["is_dir"] else human_size(e["size"]), when(e["mtime"])])
            it.setData(0, Qt.ItemDataRole.UserRole, e)
            it.setTextAlignment(1, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            if e["is_link"]:
                it.setToolTip(0, "A link" + (" to a folder" if e["is_dir"] else ""))
            self.addTopLevelItem(it)

    # ---- dragging out
    def mimeTypes(self):
        return [MIME]

    def startDrag(self, actions):
        names = [e["name"] for e in self.entries()]
        if not names:
            return
        mime = QMimeData()
        mime.setData(MIME, json.dumps({"side": self.side, "names": names}).encode())
        drag = QDrag(self)
        drag.setMimeData(mime)
        drag.exec(Qt.DropAction.CopyAction)

    # ---- dropping in
    def _payload(self, mime):
        if mime.hasFormat(MIME):
            try:
                p = json.loads(bytes(mime.data(MIME)).decode())
            except ValueError:
                return None
            return p if p.get("side") != self.side else None                 # a drop back on its own list does nothing
        if self.side == "remote" and mime.hasUrls():                           # files dragged in from Windows Explorer
            paths = [u.toLocalFile() for u in mime.urls() if u.isLocalFile()]
            return {"side": "local", "paths": paths} if paths else None
        return None

    def dragEnterEvent(self, e):
        if self._payload(e.mimeData()) is not None:
            e.acceptProposedAction()
        else:
            e.ignore()

    def dragMoveEvent(self, e):
        if self._payload(e.mimeData()) is not None:
            e.acceptProposedAction()
        else:
            e.ignore()

    def dropEvent(self, e):
        payload = self._payload(e.mimeData())
        if payload is None:
            return e.ignore()
        item = self.itemAt(e.position().toPoint())
        data = item.data(0, Qt.ItemDataRole.UserRole) if item is not None else None
        e.acceptProposedAction()
        self.dropped.emit(payload, data["name"] if data and data["is_dir"] else None)


class Side(QWidget):
    """One side: a title, the path box, the list and its buttons."""
    go = Signal(str)                            # a path typed, Enter pressed (or Up, or a folder entered)

    def __init__(self, title, side, action_text, action_tip):
        super().__init__()
        self.side = side
        self.path = ""
        self.title = QLabel(title)
        self.title.setStyleSheet("font-weight: 600;")
        self.box = QLineEdit()
        self.box.setToolTip("The folder shown. Type a path and press Enter to go there.")
        self.list = FileList(side)
        self.up_btn, self.refresh_btn = QPushButton("Up"), QPushButton("Refresh")
        self.mkdir_btn, self.delete_btn = QPushButton("New folder"), QPushButton("Delete")
        self.delete_btn.setToolTip("Delete the selected files and folders (asks first)")
        self.action_btn = QPushButton(action_text)
        self.action_btn.setToolTip(action_tip)
        self.action_btn.setProperty("primary", True)
        for b in (self.up_btn, self.refresh_btn, self.mkdir_btn, self.delete_btn, self.action_btn):
            b.setAutoDefault(False)
        row = QHBoxLayout()
        for b in (self.up_btn, self.refresh_btn, self.mkdir_btn, self.delete_btn):
            row.addWidget(b)
        row.addStretch(1)
        row.addWidget(self.action_btn)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.title)
        lay.addWidget(self.box)
        lay.addWidget(self.list, 1)
        lay.addLayout(row)
        self.box.returnPressed.connect(lambda: self.go.emit(self.box.text().strip()))
        self.list.entered.connect(lambda name: self.go.emit(self._child(name)))
        self.list.itemSelectionChanged.connect(self._buttons)
        self._buttons()

    def _child(self, name):
        return posixpath.join(self.path, name) if self.side == "remote" else os.path.join(self.path, name)

    def selected_paths(self):
        return [self._child(e["name"]) for e in self.list.entries()]

    def show_path(self, path, entries):
        self.path = path
        self.box.setText(path)
        self.list.fill(entries)
        self._buttons()

    def _buttons(self):
        any_ = bool(self.list.selectedItems())
        self.delete_btn.setEnabled(any_)
        self.action_btn.setEnabled(any_)

    def set_alive(self, on):
        for b in (self.up_btn, self.refresh_btn, self.mkdir_btn, self.box):
            b.setEnabled(on)
        if not on:
            self.list.clear()
            self.delete_btn.setEnabled(False)
            self.action_btn.setEnabled(False)


# =============================================================================== the panel
class FileBrowser(QWidget):
    def __init__(self, pane):
        super().__init__()
        self.pane = pane                         # the SessionPane: pane.session is the SshSession (None, or an old one, when not connected)
        self.worker = None
        self.local_fs = LocalFs()
        self._jobs = {}                          # job id -> what to do with the result
        self._next = 0
        self.busy = False
        self.local = Side("This computer", "local", "Upload", "Send the selected files and folders to the folder shown on the device side")
        self.remote = Side(pane.spec.get("host") or "Device", "remote", "Download",
                           "Save the selected files and folders into the folder shown on this computer")
        split = QSplitter()
        split.addWidget(self.local)
        split.addWidget(self.remote)
        split.setChildrenCollapsible(False)
        remember_sizes(split, "files_panel")
        self.note = QLabel(NOT_CONNECTED)
        self.note.setWordWrap(True)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setTextVisible(False)
        self.bar.setFixedWidth(160)
        self.bar.setVisible(False)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setAutoDefault(False)
        self.cancel_btn.setVisible(False)
        foot = QHBoxLayout()
        foot.addWidget(self.note, 1)
        foot.addWidget(self.bar)
        foot.addWidget(self.cancel_btn)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 4, 0, 0)
        lay.addWidget(split, 1)
        lay.addLayout(foot)
        # wiring
        self.local.go.connect(lambda p: self.list_local(p))
        self.local.up_btn.clicked.connect(lambda: self.list_local(self.local_fs.parent(self.local.path)))
        self.local.refresh_btn.clicked.connect(lambda: self.list_local(self.local.path))
        self.local.mkdir_btn.clicked.connect(lambda: self.new_folder("local"))
        self.local.delete_btn.clicked.connect(lambda: self.delete("local"))
        self.local.action_btn.clicked.connect(self.upload_selected)
        self.remote.go.connect(lambda p: self.list_remote(p))
        self.remote.up_btn.clicked.connect(lambda: self.list_remote(None, up=True))
        self.remote.refresh_btn.clicked.connect(lambda: self.list_remote(self.remote.path))
        self.remote.mkdir_btn.clicked.connect(lambda: self.new_folder("remote"))
        self.remote.delete_btn.clicked.connect(lambda: self.delete("remote"))
        self.remote.action_btn.clicked.connect(self.download_selected)
        self.local.list.dropped.connect(lambda payload, folder: self.dropped("local", payload, folder))
        self.remote.list.dropped.connect(lambda payload, folder: self.dropped("remote", payload, folder))
        self.cancel_btn.clicked.connect(self.cancel)
        self.list_local(self.local_fs.start())
        self.remote.set_alive(False)

    # ---- the worker, following the session
    def session_changed(self):
        """The pane connected or disconnected: a new worker on the new session, or none."""
        self._drop_worker()
        if self.pane.connected() and getattr(self.pane.session, "open_sftp", None):
            self.worker = Worker(self.pane.session)
            self.worker.done.connect(self._done)
            self.worker.progress.connect(self._progress)
            self.worker.asked.connect(self._ask)
            self.worker.start()
            self.list_remote(None)
        else:
            self.remote.set_alive(False)
            self.note.setText(NOT_CONNECTED)

    def _drop_worker(self):
        if self.worker is not None:
            w, self.worker = self.worker, None
            w.stop()
            w.wait(3000)
        self._jobs.clear()
        self._set_busy(False)

    def shutdown(self):
        self._drop_worker()

    def _run(self, fn, then=None, label=""):
        """Give the worker a job; `then(result)` runs on the UI thread when it is done."""
        if self.worker is None:
            self.note.setText(NOT_CONNECTED)
            return
        self._next += 1
        self._jobs[self._next] = (then, label)
        self._set_busy(True, label)
        self.worker.submit(self._next, fn)

    def _set_busy(self, on, label=""):
        self.busy = on
        self.bar.setVisible(on)
        self.bar.setRange(0, 0 if on else 100)
        self.cancel_btn.setVisible(on)
        for s in (self.local, self.remote):
            s.action_btn.setEnabled(not on and bool(s.list.selectedItems()))
            s.delete_btn.setEnabled(not on and bool(s.list.selectedItems()))
            s.mkdir_btn.setEnabled(not on and (s.side == "local" or self.worker is not None))
        if on and label in ("Upload", "Download"):
            self.note.setText(f"{label}ing...")

    def _done(self, job_id, result, error):
        then, label = self._jobs.pop(job_id, (None, ""))
        if not self._jobs:
            self._set_busy(False)
        if error is not None:
            self._failed(label, error)
            return
        if then:
            then(result)

    def _failed(self, label, error):
        if isinstance(error, Cancelled):
            self.note.setText(f"{label} cancelled. The unfinished file was removed." if label in ("Upload", "Download") else f"{label} cancelled.")
            self.refresh_both()
            return
        text = str(error)
        if label == "Listing" and self.worker is not None and self.worker.remote is None:
            self.remote.set_alive(False)
            self.note.setText(f"This device does not offer SFTP, so its files cannot be browsed here. The terminal still works. ({plain(error)})")
            return
        self.note.setText(f"{label} failed: {plain(error)}" if label else f"Failed: {plain(error)}")
        if label in ("Upload", "Download", "Delete"):
            self.refresh_both()

    def _progress(self, text, done, total):
        self.note.setText(text)
        if total:
            self.bar.setRange(0, 100)
            self.bar.setValue(int(done * 100 / total))
            self.note.setText(f"{text}  ·  {human_size(done)} of {human_size(total)}  ·  {int(done * 100 / total)}%")
        else:
            self.bar.setRange(0, 0)

    def cancel(self):
        if self.worker is not None:
            self.worker.cancel.set()

    # ---- questions from the worker
    def _ask(self, name, folder):
        box = QMessageBox(QMessageBox.Icon.Question, "Replace file", f"'{name}' already exists in {folder}. Replace it?", parent=self)
        buttons = {box.addButton("Replace", QMessageBox.ButtonRole.AcceptRole): "replace",
                   box.addButton("Replace all", QMessageBox.ButtonRole.AcceptRole): "replace_all",
                   box.addButton("Skip", QMessageBox.ButtonRole.RejectRole): "skip",
                   box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole): "cancel"}
        box.exec()
        self.worker.answer(buttons.get(box.clickedButton(), "cancel"))

    # ---- listing
    def list_local(self, path):
        try:
            entries = self.local_fs.listing(path)
        except OSError as e:
            self.note.setText(f"Listing failed: {plain(e)}")
            return
        _last_local["path"] = path
        self.local.show_path(path, entries)

    def list_remote(self, path, up=False):
        def job(w):
            p = w.remote.parent(self.remote.path) if up else (path or (self.remote.path or w.remote.start()))
            return p, w.remote.listing(p)

        def shown(result):
            p, entries = result
            self.remote.set_alive(True)
            self.remote.show_path(p, entries)
            if self.note.text() == NOT_CONNECTED or self.note.text().startswith("Listing failed"):
                self.note.setText("")
        self._run(job, shown, "Listing")

    def refresh_both(self):
        self.list_local(self.local.path)
        if self.worker is not None and self.remote.path:
            self.list_remote(self.remote.path)

    # ---- folders and deleting
    def new_folder(self, side):
        name, ok = QInputDialog.getText(self, "New folder", "Folder name:")
        name = name.strip()
        if not ok or not name:
            return
        if side == "local":
            try:
                self.local_fs.mkdir(self.local_fs.join(self.local.path, name))
            except OSError as e:
                self.note.setText(f"New folder failed: {plain(e)}")
                return
            self.list_local(self.local.path)
        else:
            target = posixpath.join(self.remote.path, name)
            self._run(lambda w: w.remote.mkdir(target), lambda _r: self.list_remote(self.remote.path), "New folder")

    def delete(self, side):
        s = self.local if side == "local" else self.remote
        picked = s.list.entries()
        if not picked:
            return
        if len(picked) == 1:
            e = picked[0]
            text = f"Delete the folder '{e['name']}' and everything in it?" if e["is_dir"] else f"Delete '{e['name']}'?"
        else:
            text = f"Delete these {len(picked)} items?"
        if QMessageBox.question(self, "Delete", text) != QMessageBox.StandardButton.Yes:
            return
        paths = s.selected_paths()
        if side == "local":
            try:
                for p in paths:
                    self.local_fs.delete(p)
            except OSError as e:
                self.note.setText(f"Delete failed: {plain(e)}")
            self.list_local(self.local.path)
            return

        def job(w):
            for p in paths:
                w.remote.delete(p)
        self._run(job, lambda _r: self.list_remote(self.remote.path), "Delete")

    # ---- transfers
    def upload_selected(self):
        self.upload(self.local.selected_paths(), self.remote.path)

    def download_selected(self):
        self.download(self.remote.selected_paths(), self.local.path)

    def dropped(self, onto, payload, folder):
        """Something was dropped on the `onto` list: names from the other list, or paths from Windows Explorer."""
        if onto == "remote":
            paths = payload.get("paths") or [self.local_fs.join(self.local.path, n) for n in payload.get("names", [])]
            self.upload(paths, posixpath.join(self.remote.path, folder) if folder else self.remote.path)
        else:
            paths = [posixpath.join(self.remote.path, n) for n in payload.get("names", [])]
            self.download(paths, self.local_fs.join(self.local.path, folder) if folder else self.local.path)

    def upload(self, paths, remote_folder):
        if not paths or self.busy:
            return
        local_fs = self.local_fs

        def job(w):
            return transfer(w, local_fs, paths, w.remote, remote_folder, "Uploading")
        self._run(job, lambda r: self._copied("Uploaded", r, remote_folder), "Upload")

    def download(self, paths, local_folder):
        if not paths or self.busy:
            return
        local_fs = self.local_fs

        def job(w):
            return transfer(w, w.remote, paths, local_fs, local_folder, "Downloading")
        self._run(job, lambda r: self._copied("Downloaded", r, local_folder), "Download")

    def _copied(self, verb, result, folder):
        n, stopped = result
        self.note.setText(f"{verb} {n} file(s) to {folder}." + (" Stopped at your Cancel." if stopped else ""))
        self.refresh_both()
