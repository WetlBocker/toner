"""About: what this copy of Toner is, where its data lives, and the update check (with an optional automatic update)."""
import os
import platform
import sys
import threading
from datetime import datetime
from importlib import metadata

from PySide6.QtCore import QThread, QTimer, QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QApplication, QCheckBox, QFormLayout, QFrame, QHBoxLayout, QLabel, QMessageBox,
                               QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QVBoxLayout, QWidget)
from core import audit, db, display, platforms, updates
from core.version import APP_NAME, LICENSE, TAGLINE, URL, VERSION
from ui import logo

_FILE = "AppImage" if platforms.LINUX else "installer"               # what an update arrives as here
_STARTED = "The new AppImage" if platforms.LINUX else "The installer"

LIBRARIES = [("PySide6", "Qt user interface"), ("netmiko", "SSH to network devices"), ("paramiko", "SSH and SFTP"),
             ("pysnmp", "SNMP"), ("requests", "web APIs and updates"), ("cryptography", "certificates"),
             ("keyring", "the password vault"), ("PyYAML", "inventory import"), ("PySocks", "SOCKS proxies")]


def _version_of(name):
    try:
        return metadata.version(name)
    except Exception:
        try:
            return getattr(__import__(name.replace("PyYAML", "yaml").replace("PySocks", "socks")), "__version__", "")
        except Exception:
            return ""


def _muted(text=""):
    lab = QLabel(text)
    lab.setProperty("muted", True)
    lab.setWordWrap(True)
    return lab


def _selectable(text=""):
    lab = QLabel(text)
    lab.setWordWrap(True)
    lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lab


def _card():
    f = QFrame()
    f.setProperty("card", True)
    lay = QVBoxLayout(f)
    lay.setContentsMargins(18, 14, 18, 14)
    return f, lay


class CheckWorker(QThread):
    done = Signal(str, object)                       # status ('available' | 'current' | 'none' | 'error'), Release or message

    def run(self):
        try:
            self.done.emit(*updates.check())
        except updates.UpdateError as e:
            self.done.emit("error", str(e))
        except Exception as e:
            self.done.emit("error", f"{type(e).__name__}: {e}")


class DownloadWorker(QThread):
    progress = Signal(int, int)
    done = Signal(bool, str, str)                    # ok, path or message, sha256

    def __init__(self, release):
        super().__init__()
        self.release = release
        self.cancel = threading.Event()

    def run(self):
        try:
            path, sha = updates.download(self.release, progress=self.progress.emit, cancel=self.cancel)
            self.done.emit(True, path, sha)
        except updates.UpdateError as e:
            self.done.emit(False, str(e), "")
        except Exception as e:
            self.done.emit(False, f"{type(e).__name__}: {e}", "")


class RevertWorker(QThread):
    done = Signal(bool, str)                         # ok, message

    def __init__(self, item):
        super().__init__()
        self.item = item

    def run(self):
        try:
            updates.revert(self.item)                # checks the installer (maybe asking GitHub), then starts it
            self.done.emit(True, "")
        except updates.UpdateError as e:
            self.done.emit(False, str(e))
        except Exception as e:
            self.done.emit(False, f"{_STARTED} could not be started: {type(e).__name__}: {e}")


def _system_row():
    """('Windows', 'Windows 11  (10.0.26300)'), or ('Operating system', 'Ubuntu 26.04.1 LTS  (6.6.87.2-...)') on Linux and macOS."""
    if sys.platform == "win32":
        return "Windows", f"{display.windows_name(platform.system(), platform.release())}  ({platform.version()})"
    name = ""
    try:
        name = platform.freedesktop_os_release().get("PRETTY_NAME", "")      # Linux
    except (OSError, AttributeError):
        pass
    if not name and sys.platform == "darwin":
        name = f"macOS {platform.mac_ver()[0]}"
    return "Operating system", f"{name or platform.system()}  ({platform.release()})"


class AboutTab(QWidget):
    update_available = Signal(str)                   # a newer version was found (for the badge and the tray)
    update_cleared = Signal()
    quit_requested = Signal()                        # the installer has been started: Toner must close now

    def __init__(self):
        super().__init__()
        self.release = None
        self.checker = self.downloader = None
        self._manual = True
        self.timer = QTimer(self)
        self.timer.setInterval(6 * 3600 * 1000)
        self.timer.timeout.connect(self.auto_check)

        # ---- header
        mark = QLabel()
        mark.setPixmap(logo.pixmap(72, 2.0))
        mark.setFixedSize(72, 72)
        title = QLabel(APP_NAME)
        title.setStyleSheet("font-size: 22pt; font-weight: 700;")
        self.version = QLabel(f"Version {VERSION}")
        self.version.setStyleSheet("font-size: 11pt;")
        head = QHBoxLayout()
        head.setSpacing(16)
        names = QVBoxLayout()
        names.setSpacing(2)
        names.addWidget(title)
        names.addWidget(self.version)
        names.addWidget(_muted(TAGLINE))
        head.addWidget(mark)
        head.addLayout(names, 1)

        # ---- updates
        self.status = _selectable("")
        self.notes = QPlainTextEdit()
        self.notes.setReadOnly(True)
        self.notes.setMaximumHeight(150)
        self.notes.hide()
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setMaximumHeight(8)
        self.bar.hide()
        self.check_btn = QPushButton("Check for updates")
        self.install_btn = QPushButton("Download and install")
        self.install_btn.setProperty("primary", True)
        self.page_btn = QPushButton("View release")
        self.skip_btn = QPushButton("Skip this version")
        self.cancel_btn = QPushButton("Cancel download")
        for b in (self.install_btn, self.page_btn, self.skip_btn, self.cancel_btn):
            b.hide()
        self.auto_check_box = QCheckBox("Check for updates automatically (once a day)")
        self.auto_install_box = QCheckBox("Install updates automatically")
        self.direct_box = QCheckBox("Connect directly for updates (ignore the proxy settings)")
        self.auto_note = _muted("With this on, a new version is downloaded and checked as soon as it is found, and installed "
                                "when you close Toner. You can still install it straight away from here.")
        self.last = _muted("")
        buttons = QHBoxLayout()
        for b in (self.check_btn, self.install_btn, self.page_btn, self.skip_btn, self.cancel_btn):
            buttons.addWidget(b)
        buttons.addStretch()
        upd, ul = _card()
        t = QLabel("Updates")
        t.setStyleSheet("font-weight: 600;")
        ul.addWidget(t)
        ul.addWidget(self.status)
        ul.addWidget(self.bar)
        ul.addWidget(self.notes)
        ul.addLayout(buttons)
        ul.addWidget(self.auto_check_box)
        ul.addWidget(self.auto_install_box)
        ul.addWidget(self.auto_note)
        ul.addWidget(self.direct_box)
        ul.addWidget(self.last)

        # ---- earlier versions (the installers kept in the updates folder)
        self.earlier_card, el = _card()
        t = QLabel("Earlier versions")
        t.setStyleSheet("font-weight: 600;")
        el.addWidget(t)
        self.earlier_note = _muted("")
        el.addWidget(self.earlier_note)
        self.earlier_rows = QVBoxLayout()
        el.addLayout(self.earlier_rows)
        self.earlier_status = _selectable("")
        self.earlier_status.hide()
        el.addWidget(self.earlier_status)
        self.revert_btns = {}
        self.reverter = None

        # ---- details and components
        det, dl = _card()
        t = QLabel("This copy")
        t.setStyleSheet("font-weight: 600;")
        dl.addWidget(t)
        self.form = QFormLayout()
        self.form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        dl.addLayout(self.form)
        comp, cl = _card()
        t = QLabel("Built with")
        t.setStyleSheet("font-weight: 600;")
        cl.addWidget(t)
        self.parts = QFormLayout()
        cl.addLayout(self.parts)

        tools = QHBoxLayout()
        self.copy_btn, self.data_btn, self.log_btn, self.web_btn = (QPushButton(x) for x in (
            "Copy details", "Open data folder", "Open log", "Project page"))
        for b in (self.copy_btn, self.data_btn, self.log_btn, self.web_btn):
            tools.addWidget(b)
        tools.addStretch()

        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setSpacing(14)
        bl.addLayout(head)
        bl.addWidget(upd)
        bl.addWidget(self.earlier_card)
        bl.addWidget(det)
        bl.addWidget(comp)
        bl.addLayout(tools)
        bl.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(body)
        lay = QVBoxLayout(self)
        lay.addWidget(scroll)

        self.check_btn.clicked.connect(lambda: self.check(True))
        self.install_btn.clicked.connect(self.download_and_install)
        self.page_btn.clicked.connect(self.open_release)
        self.skip_btn.clicked.connect(self.skip)
        self.cancel_btn.clicked.connect(self.cancel_download)
        self.copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.details_text()))
        self.data_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(db.db_path().parent))))
        self.log_btn.clicked.connect(self.open_log)
        self.web_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(URL)))
        self.auto_check_box.toggled.connect(self._save_options)
        self.auto_install_box.toggled.connect(self._save_options)
        self.direct_box.toggled.connect(self._save_options)
        self.load()

    # ---------------------------------------------------------------- what is shown
    def details(self):
        kind = updates.installed_kind()
        what = {"installed": "Installed with the installer", "portable": "Portable copy (its data is kept beside the program)",
                "appimage": "AppImage (it updates itself in place)",
                "unpacked": "Unpacked copy (not installed)", "source": "Running from source code"}.get(kind, kind)
        try:
            size = os.path.getsize(db.db_path())
            dbtext = f"{db.db_path()}  ({size / 1048576:.1f} MB)"
        except OSError:
            dbtext = str(db.db_path())
        try:
            from PySide6 import __version__ as pyside
        except Exception:
            pyside = ""
        return [("Version", VERSION), ("Installed as", what), ("Program folder", updates.app_dir()),
                ("Data folder", str(db.db_path().parent)), ("Database", dbtext),
                ("Log file", str(db.db_path().parent / "toner.log")),
                ("Python", f"{platform.python_version()}  ({platform.architecture()[0]})"),
                ("Qt / PySide6", pyside), _system_row(),
                ("Inventory", f"{len(db.list_devices())} device(s)"), ("License", LICENSE), ("Source code", URL)]

    def libraries(self):
        return [(n, _version_of(n), why) for n, why in LIBRARIES]

    def details_text(self):
        lines = [f"{APP_NAME} {VERSION}"] + [f"{k}: {v}" for k, v in self.details() if k != "Version"]
        lines += [""] + [f"{n} {v}".strip() for n, v, _ in self.libraries()]
        return "\n".join(lines)

    def load(self):
        for form in (self.form, self.parts):
            while form.rowCount():
                form.removeRow(0)
        for k, v in self.details():
            self.form.addRow(k, _selectable(str(v)))
        for n, v, why in self.libraries():
            self.parts.addRow(n, _selectable(f"{v}   -   {why}" if v else why))
        for box, key in ((self.auto_check_box, "update_check"), (self.auto_install_box, "update_auto_install"),
                         (self.direct_box, "update_direct")):
            box.blockSignals(True)
            box.setChecked(bool(db.get_setting(key)))
            box.blockSignals(False)
        self._can_update = updates.can_self_update()
        self.auto_install_box.setEnabled(self._can_update)
        if not self._can_update:
            self.auto_note.setText(("Automatic installing is only available when Toner runs as its AppImage. " if platforms.LINUX else
                                    "Automatic installing is only available in a copy set up with the Toner installer. ")
                                   + "This copy can still check for updates and tell you where to download them.")
        self._show_last()
        self.refresh_earlier()
        if self.status.text() == "":
            self.status.setText(f"You are using version {VERSION}.")
        pend = updates.pending()
        if pend and not self.release:
            self.status.setText(f"Version {pend['version']} has been downloaded and checked. It will be installed when you "
                                "close Toner, or you can install it now.")
            self.install_btn.setText("Install now")
            self.install_btn.show()

    def _show_last(self):
        last = db.get_setting("update_last_check")
        self.last.setText(f"Last checked: {last}" if last else "Not checked yet.")

    def _save_options(self, *_):
        db.set_setting("update_check", self.auto_check_box.isChecked())
        db.set_setting("update_auto_install", self.auto_install_box.isChecked() and self._can_update)
        db.set_setting("update_direct", self.direct_box.isChecked())
        audit.log("update options changed", f"check={self.auto_check_box.isChecked()}, "
                                            f"install={self.auto_install_box.isChecked() and self._can_update}")
        self.start_background_checks()

    # ---------------------------------------------------------------- checking
    def start_background_checks(self):
        """Called once at startup (not from tests): a first check shortly after launch, then every few hours while it
        runs, each one only if a day has passed since the last."""
        if db.get_setting("update_check"):
            QTimer.singleShot(8000, self.auto_check)
            self.timer.start()
        else:
            self.timer.stop()

    def auto_check(self):
        if db.get_setting("update_check") and updates.due(24) and not self.busy():
            self.check(False)

    def busy(self):
        return bool((self.checker and self.checker.isRunning()) or (self.downloader and self.downloader.isRunning()))

    def check(self, manual=True):
        if self.busy():
            return
        self._manual = manual
        self.check_btn.setEnabled(False)
        if manual:
            self.status.setText("Checking for updates...")
        self.checker = CheckWorker()
        self.checker.done.connect(self._checked)
        self.checker.start()

    def _checked(self, status, payload):
        self.check_btn.setEnabled(True)
        if status == "error":
            if self._manual:
                self.status.setText(f"Could not check for updates. {payload}")
            return                                        # a background check fails quietly
        updates.mark_checked()
        self._show_last()
        if status == "none":
            self.release = None
            self.status.setText(f"You are up to date: version {VERSION} is the latest.")        # nothing newer has been published
            self._hide_actions()
            self.update_cleared.emit()
        elif status == "current":
            self.release = None
            self.status.setText(f"You are up to date: version {VERSION} is the latest.")
            self._hide_actions()
            self.update_cleared.emit()
        else:
            self.release = payload
            skipped = db.get_setting("update_skip") == payload.version
            if skipped and not self._manual:
                return
            self._show_available(payload)
            self.update_available.emit(payload.version)
            if not self._manual and db.get_setting("update_auto_install") and self._can_update and payload.asset_url:
                self.download(install_after=False, quiet=True)

    def _hide_actions(self):
        for b in (self.install_btn, self.page_btn, self.skip_btn, self.cancel_btn):
            b.hide()
        self.notes.hide()
        self.bar.hide()

    def _show_available(self, r):
        self.status.setText(f"Version {r.version} is available" + (f" (released {r.published})" if r.published else "")
                            + f". You are using {VERSION}.")
        if r.notes.strip():
            self.notes.setPlainText(r.notes.strip())
            self.notes.show()
        self.page_btn.setVisible(bool(r.page_url))
        self.skip_btn.show()
        can = self._can_update and bool(r.asset_url)
        self.install_btn.setText("Download and install")
        self.install_btn.setVisible(can)
        if not can:
            self.status.setText(self.status.text() + (
                ("  This copy is not running as the AppImage" if platforms.LINUX else "  This copy was not set up with the installer")
                + ", so it cannot update itself: download the new version from the release page." if not self._can_update
                else f"  The release has no {_FILE} attached."))

    # ---------------------------------------------------------------- downloading and installing
    def download_and_install(self):
        if updates.pending() and not self.release:
            self.install_now()
            return
        self.download(install_after=True)

    def download(self, install_after, quiet=False):
        if self.busy() or not self.release:
            return
        self.bar.setValue(0)
        self.bar.show()
        self.cancel_btn.show()
        self.install_btn.setEnabled(False)
        self.check_btn.setEnabled(False)
        if not quiet:
            self.status.setText(f"Downloading version {self.release.version}...")
        self.downloader = DownloadWorker(self.release)
        self.downloader.progress.connect(lambda d, t: (self.bar.setMaximum(max(1, t)), self.bar.setValue(d)))
        self.downloader.done.connect(lambda ok, a, b, rel=self.release: self._downloaded(ok, a, b, rel, install_after))
        self.downloader.start()

    def _downloaded(self, ok, path_or_msg, sha, rel, install_after):
        self.bar.hide()
        self.cancel_btn.hide()
        self.install_btn.setEnabled(True)
        self.check_btn.setEnabled(True)
        if not ok:
            self.status.setText("The update was not installed. " + ("Download cancelled." if path_or_msg == "cancelled" else path_or_msg))
            return
        updates.set_pending(rel, path_or_msg, sha)
        audit.log("update downloaded", f"{rel.version} verified (sha256 {sha[:12]}...)")
        self.status.setText(f"Version {rel.version} was downloaded and its checksum matched.")
        if install_after:
            self.install_now()
        else:
            self.status.setText(self.status.text() + " It will be installed when you close Toner, or you can install it now.")
            self.install_btn.setText("Install now")
            self.install_btn.show()

    def install_now(self):
        pend = updates.pending()
        if not pend:
            self.status.setText("The downloaded update is no longer available. Check for updates again.")
            return
        if QMessageBox.question(self, "Install update", f"Toner will close, install version {pend['version']} and open again. "
                                "Your inventory, history and saved passwords are kept.\n\nContinue?") != QMessageBox.StandardButton.Yes:
            return
        try:
            updates.launch_installer(pend["path"], relaunch=True)
        except OSError as e:
            self.status.setText(f"{_STARTED} could not be started: {e}")
            return
        audit.log("update installing", f"{VERSION} -> {pend['version']}")
        db.set_setting("update_pending", {})                      # the installer owns the file now
        self.quit_requested.emit()

    def apply_on_exit(self):
        """Toner is closing for good: if an update was downloaded and automatic installing is on, install it now.
        Returns True if the installer was started."""
        if not (db.get_setting("update_auto_install") and updates.can_self_update()):
            return False
        pend = updates.pending()
        if not pend:
            return False
        try:
            updates.launch_installer(pend["path"], relaunch=False)
        except OSError:
            return False
        audit.log("update installing", f"{VERSION} -> {pend['version']} (on exit)")
        db.set_setting("update_pending", {})
        return True

    # ---------------------------------------------------------------- going back to an earlier version
    def refresh_earlier(self):
        while self.earlier_rows.count():
            row = self.earlier_rows.takeAt(0).layout()
            while row is not None and row.count():
                w = row.takeAt(0).widget()
                if w is not None:
                    w.deleteLater()
        self.revert_btns = {}
        if not updates.can_self_update():
            self.earlier_note.setText("Going back to an earlier version needs Toner running as its AppImage." if platforms.LINUX
                                      else "Going back to an earlier version needs a copy set up with the Toner installer.")
            return
        items = updates.earlier()
        if not items:
            self.earlier_note.setText("No earlier versions are kept yet. After the next update, the version you have now can "
                                      "be restored from here.")
            return
        self.earlier_note.setText(f"Toner keeps the {_FILE}s of the last {updates.KEEP} versions in its data folder, so you "
                                  "can go back to one if an update causes trouble.")
        for item in items:
            row = QHBoxLayout()
            row.addWidget(QLabel(f"Version {item['version']}   (downloaded {item['at']})"))
            b = QPushButton(f"Revert to {item['version']}")
            b.clicked.connect(lambda _=False, it=item: self.revert(it))
            row.addWidget(b)
            row.addStretch()
            self.revert_btns[item["version"]] = b
            self.earlier_rows.addLayout(row)

    def revert(self, item):
        if self.busy() or (self.reverter and self.reverter.isRunning()):
            return
        v = item["version"]
        if QMessageBox.question(self, f"Revert to version {v}",
                                (f"Toner will close, replace this AppImage with version {v} and open again. " if platforms.LINUX else
                                 f"Toner will close, install version {v} over this copy and open again. ") + "Your inventory, history "
                                f"and saved passwords are kept; settings and checks added after {v} are not used by it.\n\n"
                                f"Version {VERSION} will not be offered as an update again; newer versions still will.\n\n"
                                "Continue?") != QMessageBox.StandardButton.Yes:
            return
        for b in self.revert_btns.values():
            b.setEnabled(False)
        self.earlier_status.setText(f"Checking the {_FILE} for {v}...")
        self.earlier_status.show()
        self.reverter = RevertWorker(item)
        self.reverter.done.connect(lambda ok, msg, v=v: self._reverted(ok, msg, v))
        self.reverter.start()

    def _reverted(self, ok, msg, version):
        for b in self.revert_btns.values():
            b.setEnabled(True)
        if not ok:
            self.earlier_status.setText(msg)
            return
        audit.log("update reverting", f"{VERSION} -> {version}")
        self.quit_requested.emit()

    def cancel_download(self):
        if self.downloader and self.downloader.isRunning():
            self.downloader.cancel.set()

    def open_release(self):
        if self.release and self.release.page_url:
            QDesktopServices.openUrl(QUrl(self.release.page_url))

    def skip(self):
        if self.release:
            db.set_setting("update_skip", self.release.version)
            self.status.setText(f"Version {self.release.version} will not be offered again. Check for updates to see newer ones.")
            self._hide_actions()
            self.update_cleared.emit()

    def open_log(self):
        path = db.db_path().parent / "toner.log"
        if path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def refresh(self):
        pass

    def shutdown(self):
        self.timer.stop()
        for w in (self.checker, self.downloader, self.reverter):
            if w and w.isRunning():
                if hasattr(w, "cancel"):
                    w.cancel.set()
                w.wait(4000)
