"""Settings > Data and logs > Reset Toner to factory settings: the dialog (type RESET), stopping what the window runs, the wipe
(core/reset.py) and the quit. Global only; the button is hidden inside an organization."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QLabel, QLineEdit, QMessageBox, QVBoxLayout

from core import agents, demarc, paths, platforms, reset

TITLE = "Reset Toner to factory settings"
WORD = "RESET"
BUSY = "A run is still going. Wait for it to finish, then reset."


def text():
    lines = ["This deletes everything Toner keeps on this computer and closes Toner:",
             "• every organization's devices, checks, results, history and config backups",
             "• saved sessions and session logs",
             "• the vault with every saved password, token and SNMP community, and the master password remembered on this computer",
             "• settings, the audit log, saved host keys, the agent certificate, downloaded updates and the Ansible playbooks in "
             "Toner's data folder"]
    if platforms.LINUX:
        lines.append("• the Start Toner when I sign in entry")
    lines.append(f"Data folder: {paths.data_dir()}")
    return ("\n".join(lines)
            + "\n\nNothing on other systems is touched. Windows agents keep their tokens and Demarc keeps this Toner enrolled, but both "
              "stop working until you enroll them again. Toner itself stays installed; the next start is like a fresh install."
              "\n\nThis cannot be undone. Back up the database and export saved passwords first if you may want them back.")


class ResetDialog(QDialog):
    """The red button stays off until RESET is typed."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(TITLE)
        self.setMinimumWidth(600)
        body = QLabel(text())
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.confirm = QLineEdit()
        self.confirm.setPlaceholderText(WORD)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.ok = self.buttons.addButton("Reset and quit", QDialogButtonBox.ButtonRole.AcceptRole)
        self.ok.setProperty("danger", True)
        self.ok.setEnabled(False)
        self.confirm.textChanged.connect(lambda t: self.ok.setEnabled(t == WORD))
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(body)
        lay.addSpacing(6)
        lay.addWidget(QLabel(f"Type {WORD} to confirm"))
        lay.addWidget(self.confirm)
        lay.addWidget(self.buttons)


def busy(main):
    """Checks, a backup or a playbook still running: they would write into what is being deleted."""
    return any(getattr(main, a).running() for a in ("results", "configs", "automation") if hasattr(main, a))


def stop_window(main):
    """What closeEvent stops when Toner quits, without the questions (the answer was RESET)."""
    for v in list(main.views.values()):
        v.close()
    main.tools.shutdown()
    main.automation.shutdown()
    main.sessions.shutdown()
    main.configs.shutdown()
    main.scheduler.shutdown()
    main.backup_scheduler.shutdown()
    main.about.shutdown()
    main.housekeeping.stop()


def resume(main):
    """Nothing was deleted (a file was in use): the window's own timers and services run again."""
    main.scheduler.apply()
    main.backup_scheduler.apply()
    main.housekeeping.start()
    agents.apply()
    demarc.apply()
    from core import extstore
    if extstore.active() != "toner":
        extstore.start()


def perform(main):
    """Ask, stop, wipe, quit. Returns True when Toner is quitting."""
    if busy(main):
        QMessageBox.warning(main, TITLE, BUSY)
        return False
    if not ResetDialog(main).exec():
        return False
    stop_window(main)
    try:
        reset.wipe()
    except reset.ResetError as e:
        QMessageBox.warning(main, TITLE, str(e))
        if not e.deleted:
            resume(main)
            return False
    main._wiped = True
    main._quitting = True
    main.tray.hide()
    main.hide()
    QApplication.instance().quit()
    return True
