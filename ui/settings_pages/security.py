"""Settings pages: Security (host keys, passwords) and Data and logs."""

import json
import keyring
import sqlite3
from datetime import datetime

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QInputDialog, QLabel, QLineEdit, QMessageBox,
                               QPushButton, QTableWidget, QTableWidgetItem, QWidget)
from core import audit, db, display, legacyssh, nettools, passvault, sessionlog, vault
from ui.settings_base import Page, compact_row, note, row_of
from ui.toast import toast
from ui.widgets import EmptyHint


# ------------------------------------------------------------------ Security
class SecurityPage(Page):
    title = "Security"

    def __init__(self):
        super().__init__()
        self.mode = QComboBox()
        self.mode.addItems(nettools.HOSTKEY_MODES)
        self.form.addRow("SSH session host keys", self.mode)
        self.form.addRow(note(
            "Trust on first use: remember each device's key the first time, and refuse the connection if it "
            "ever changes (protects against a swapped or spoofed device). Always trust: accept anything, "
            "remember nothing. Reject unknown hosts: only connect to devices already remembered. "
            "This applies to the console and jump hosts, and to monitoring, config backups, the Command Runner and Detect Vendors. "
            "Keys are saved on first contact and listed below."))
        self.legacy = QCheckBox("Allow older SSH algorithms for older devices (ssh-rsa, SHA-1 key exchange)")
        self.form.addRow("", self.legacy)
        self.form.addRow(note(
            "Many Cisco ASAs, older switches and other network gear only offer these, and without them the connection fails "
            "with \"Incompatible ssh peer (no acceptable host key)\". They are tried last, so a device that offers anything "
            "newer still uses the newer one, as OpenSSH does with +ssh-rsa."))

        self.change_master = QPushButton("Change master password...")      # the vault: these act right away
        self.change_master.clicked.connect(self._change_master)
        self.remember = QCheckBox("Remember on this computer")
        self.remember.setProperty("notSetting", True)
        self.remember.setToolTip("Toner and its scheduled service open the vault without asking.")
        self.remember.toggled.connect(self._remember)
        self.lock_now = QPushButton("Lock now")
        self.lock_now.clicked.connect(self._lock)
        self.lay.insertWidget(0, QLabel("<b>Vault</b>"))
        self.lay.insertWidget(1, compact_row(self.change_master, self.remember, self.lock_now))
        from ui.vaultsettings import VaultSection
        self.vault = VaultSection()                                        # Store passwords in: Toner's vault or a password manager
        self.lay.insertWidget(2, self.vault)

        self.keys = QTableWidget(0, 3)
        self.keys.setHorizontalHeaderLabels(["Host", "Type", "Fingerprint"])
        self.keys.horizontalHeader().setStretchLastSection(True)
        self.keys.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.keys.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.keys.setMinimumHeight(110)
        self.keys_hint = EmptyHint(self.keys, "No host keys remembered", "A device's key is saved the first time you connect to it")
        forget, forget_all = QPushButton("Forget selected key"), QPushButton("Forget all keys")
        forget.clicked.connect(self.forget_one)
        forget_all.clicked.connect(self.forget_all)
        self.lay.insertWidget(4, QLabel("<b>Remembered host keys</b>  (these actions take effect immediately)"))
        self.lay.insertWidget(5, self.keys)
        self.lay.insertWidget(6, row_of(forget, forget_all, QWidget()))

        self.creds = QTableWidget(0, 3)
        self.creds.setHorizontalHeaderLabels(["Device", "Vendor", "Stored in the vault"])
        self.creds.horizontalHeader().setStretchLastSection(True)
        self.creds.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.creds.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.creds.setMinimumHeight(110)
        self.creds_hint = EmptyHint(self.creds, "No stored passwords or tokens", "They are saved in Toner's vault when you add a device")
        clear = QPushButton("Delete stored secret for selected device")
        clear.clicked.connect(self.clear_secret)
        self.lay.insertWidget(7, QLabel("<b>Stored credentials</b>  (passwords and API tokens; "
                                        "re-enter them in Inventory > Edit)"))
        self.lay.insertWidget(8, self.creds)
        self.lay.insertWidget(9, row_of(clear, QWidget()))

    def load(self):
        self.mode.setCurrentText(db.get_setting("hostkey_mode"))
        self.legacy.setChecked(bool(db.get_setting("ssh_legacy_algorithms")))
        self.refresh()

    def show_vault(self):
        self.remember.blockSignals(True)
        self.remember.setChecked(passvault.remembered())
        self.remember.blockSignals(False)
        self.lock_now.setVisible(not passvault.remembered())

    def _change_master(self):
        from ui import vaultdlg
        if vaultdlg.change_master(self):
            toast(self, "Master password changed.")

    def _remember(self, on):
        try:
            passvault.set_remembered(on)
        except passvault.Locked:
            pass
        except passvault.NoKeyring:
            from ui.vaultdlg import NO_KEYRING_TEXT
            QMessageBox.information(self, "Remember on this computer", NO_KEYRING_TEXT)
        audit.log("vault " + ("remembered on this computer" if on else "no longer remembered on this computer"))
        self.show_vault()

    def _lock(self):
        """Lock now: close the vault and ask for the master password again (Quit closes Toner)."""
        from PySide6.QtWidgets import QApplication
        from ui import vaultdlg
        passvault.lock()
        if not vaultdlg.UnlockDialog(self).exec():
            win = self.window()
            (win.quit_for_real if hasattr(win, "quit_for_real") else QApplication.quit)()

    def refresh(self):
        self.show_vault()
        if passvault.is_open():
            self.vault.load()
        keys = nettools.list_host_keys()
        self.keys.setRowCount(len(keys))
        self.keys_hint.setVisible(not keys)
        for i, row in enumerate(keys):
            for j, v in enumerate(row):
                self.keys.setItem(i, j, QTableWidgetItem(v))
        self.keys.resizeColumnsToContents()
        devs = db.list_devices()
        self.creds.setRowCount(len(devs))
        self.creds_hint.setVisible(not devs)
        for i, d in enumerate(devs):
            try:
                with db.within(d.get("org")):
                    has = bool(keyring.get_password(db.SERVICE, db.secret_name(d["name"])))
            except Exception:
                has = False
            for j, v in enumerate((d["name"], display.vendor_name(d["vendor"]), "yes" if has else "no")):
                self.creds.setItem(i, j, QTableWidgetItem(v))
            self.creds.item(i, 0).setData(Qt.ItemDataRole.UserRole, d.get("org"))
        self.creds.resizeColumnsToContents()

    def forget_one(self):
        r = self.keys.currentRow()
        if r >= 0 and self.keys.selectedIndexes():
            host = self.keys.item(r, 0).text()
            if QMessageBox.question(self, "Forget key", f"Forget the saved key for {host}?\n\nThe next "
                                    "connection will save whatever key the device presents.") \
                    == QMessageBox.StandardButton.Yes:
                nettools.forget_host_key(host)
                self.refresh()

    def forget_all(self):
        if self.keys.rowCount() and QMessageBox.question(
                self, "Forget all keys", "Forget every saved host key?") == QMessageBox.StandardButton.Yes:
            nettools.forget_host_key(None)
            self.refresh()

    def clear_secret(self):
        r = self.creds.currentRow()
        if r >= 0 and self.creds.selectedIndexes():
            name = self.creds.item(r, 0).text()
            if QMessageBox.question(self, "Delete secret", f"Delete the stored password/token for {name}?\n\n"
                                    "Checks on that device will fail until you enter it again.") \
                    == QMessageBox.StandardButton.Yes:
                with db.within(self.creds.item(r, 0).data(Qt.ItemDataRole.UserRole)):
                    db.delete_secret(db.secret_name(name))
                self.refresh()

    def save(self):
        db.set_setting("hostkey_mode", self.mode.currentText())
        db.set_setting("ssh_legacy_algorithms", self.legacy.isChecked())
        legacyssh.apply()


# ------------------------------------------------------------------ Data & logs
class DataPage(Page):
    title = "Data and logs"
    reset_requested = Signal()                     # Reset Toner to factory settings (the window does it: ui/factoryreset.py)

    def __init__(self, on_imported):
        super().__init__()
        self.on_imported = on_imported
        self.info = QLabel()
        self.info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.info.setWordWrap(True)
        self.lay.insertWidget(0, self.info)
        self.lay.insertWidget(1, note("The buttons on this page act immediately."))
        for text, fn in (("Open data folder", self.open_folder), ("Back up database...", self.backup),
                         ("Export settings...", self.export_settings), ("Import settings...", self.import_settings),
                         ("Export saved passwords...", self.export_passwords), ("Import saved passwords...", self.import_passwords),
                         ("Clear run history...", self.clear_history),
                         ("Delete all SSH session logs...", self.delete_logs)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            self.lay.insertWidget(self.lay.count() - 1, b, 0, Qt.AlignmentFlag.AlignLeft)
        self.reset_btn = QPushButton("Reset Toner to factory settings...")        # Global only: it takes every organization with it
        self.reset_btn.setProperty("danger", True)
        self.reset_btn.clicked.connect(self.reset_requested)
        self.lay.insertWidget(self.lay.count() - 1, self.reset_btn, 0, Qt.AlignmentFlag.AlignLeft)
        self.reset_btn.setVisible(db.home() == db.GLOBAL)

    def refresh(self):
        self.reset_btn.setVisible(db.home() == db.GLOBAL)
        path = db.db_path()
        with db.connect() as c:
            runs = c.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            rows = c.execute("SELECT COUNT(*) FROM results").fetchone()[0]
            sessions = c.execute("SELECT COUNT(*) FROM ssh_sessions").fetchone()[0]
        size = path.stat().st_size / 1_048_576 if path.exists() else 0
        self.info.setText(
            f"<b>Database</b>: {path} ({size:.1f} MB)<br>"
            f"<b>Run history</b>: {runs:,} runs, {rows:,} results<br>"
            f"<b>Session logs</b>: {sessions:,} sessions in {sessionlog.log_dir()}<br>"
            f"<b>Saved host keys</b>: {nettools.known_hosts_path()}<br>"
            f"<b>Vault</b>: {passvault.path()}")

    load = refresh

    def open_folder(self):
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(db.db_path().parent)))

    def backup(self):
        default = str(db.db_path().parent / f"toner-backup-{datetime.now():%Y-%m-%d}.db")
        path, _ = QFileDialog.getSaveFileName(self, "Back up database", default, "SQLite database (*.db)")
        if not path:
            return
        try:
            src, dst = db.connect(), sqlite3.connect(path)
            with dst:
                src.backup(dst)                          # consistent copy even while the app is using it
            src.close()
            dst.close()
            QMessageBox.information(self, "Backup", f"Saved to {path}\n\nThe backup holds devices, history and "
                                    "settings. Passwords and API tokens live in Toner's vault "
                                    f"({passvault.path().name}) and are not included.")
        except (OSError, sqlite3.Error) as e:
            QMessageBox.warning(self, "Backup failed", str(e))

    def _ask_password(self, title, label):
        text, ok = QInputDialog.getText(self, title, label, QLineEdit.EchoMode.Password)
        return text if ok else None

    def export_passwords(self):
        """Every saved password and token into one encrypted file, to move a portable copy to another computer."""
        first = self._ask_password("Export saved passwords", f"Choose a password to protect the file (at least {vault.MIN_PASSWORD} characters).\n"
                                   "You will need it to import the file, and it cannot be recovered.")
        if first is None:
            return
        if self._ask_password("Export saved passwords", "Type it again:") != first:
            QMessageBox.warning(self, "Export saved passwords", "The two passwords were not the same. Nothing was exported.")
            return
        try:
            data, count = vault.export_bytes(first)
        except ValueError as e:
            QMessageBox.warning(self, "Export saved passwords", str(e))
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export saved passwords", f"toner-passwords{vault.EXTENSION}", f"Toner password file (*{vault.EXTENSION})")
        if path:
            with open(path, "wb") as f:
                f.write(data)
            audit.log("saved passwords exported", f"{count} password(s)")
            QMessageBox.information(self, "Export saved passwords", f"{count} password(s) were saved, encrypted, to {path}.\n\nKeep the file "
                                    "and its password apart: together they open every device.")

    def import_passwords(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import saved passwords", "", f"Toner password file (*{vault.EXTENSION});;All files (*)")
        if not path:
            return
        word = self._ask_password("Import saved passwords", "Password for the file:")
        if word is None:
            return
        try:
            with open(path, "rb") as f:
                secrets = vault.read_bytes(f.read(), word)
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Import saved passwords", str(e))
            return
        replace = QMessageBox.question(self, "Import saved passwords", f"The file holds {len(secrets)} password(s).\n\nReplace passwords this "
                                       "computer already has? (No keeps the ones it has and adds only the missing.)") == QMessageBox.StandardButton.Yes
        with open(path, "rb") as f:
            stored, skipped = vault.import_bytes(f.read(), word, replace)
        audit.log("saved passwords imported", f"{stored} stored, {skipped} kept")
        toast(self, f"{stored} password(s) stored" + (f", {skipped} already here were kept." if skipped else "."))

    def export_settings(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export settings", "toner-settings.json", "JSON (*.json)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(db.export_settings(), f, indent=2)
            toast(self, "Settings exported. Devices and passwords are not included.")

    def import_settings(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import settings", "", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8-sig") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("expected a settings object")
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Import failed", f"Could not read the file:\n{e}")
            return
        applied, skipped = db.import_settings(data)
        self.on_imported()
        msg = f"Applied {len(applied)} setting(s)."
        if skipped:
            msg += f"\nIgnored (unknown or invalid): {', '.join(skipped)}"
        QMessageBox.information(self, "Import", msg)

    def clear_history(self):
        if QMessageBox.question(self, "Clear history", "Delete ALL run history and trend data?\n\n"
                                "Devices, settings and SSH logs are kept. This cannot be undone.") \
                != QMessageBox.StandardButton.Yes:
            return
        with db.connect() as c:
            c.execute("DELETE FROM runs")                # results go with them (cascade)
            c.execute("DELETE FROM numeric_checks")      # and so do the checks History offers to chart
        self.refresh()
        self.on_imported()

    def delete_logs(self):
        if QMessageBox.question(self, "Delete session logs", "Delete ALL finished SSH session logs "
                                "(files and index)?\n\nThis removes the audit trail and cannot be undone.") \
                != QMessageBox.StandardButton.Yes:
            return
        n = sessionlog.delete_closed()
        self.refresh()
        toast(self, f"Deleted {n} session log(s).")
