"""The playbook editor (Tools > Playbook Editor): the library of playbooks, a YAML editor that checks as you type, and Ansible's own syntax check."""
import re

from PySide6.QtCore import QRegularExpression, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont, QFontDatabase, QKeySequence, QShortcut, QSyntaxHighlighter, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QVBoxLayout, QWidget)

from core import ansible as AN, audit
from ui import theme
from ui import status as st
from ui.widgets import EmptyHint, remember_sizes


class YamlHighlighter(QSyntaxHighlighter):
    """Colours keys, strings, numbers, comments and {{ templates }} in a playbook."""

    def __init__(self, doc):
        super().__init__(doc)
        self._rules = []
        self.restyle()

    def restyle(self):
        dark = bool((theme.current() or {}).get("dark"))
        muted = (theme.current() or {}).get("muted", "#777777")

        def fmt(color, bold=False, italic=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Weight.DemiBold)
            f.setFontItalic(italic)
            return f
        self._rules = [
            (QRegularExpression(r"(?<![\w\"'])-?\d+(\.\d+)?(?![\w\"'])"), fmt("#fb923c" if dark else "#c2410c")),
            (QRegularExpression(r"\b(true|false|yes|no|null|True|False|Yes|No)\b(?=\s*($|#|,|\}|\]))"), fmt("#c084fc" if dark else "#7e22ce")),
            (QRegularExpression(r"^\s*(-\s+)*[\w.\-]+(?=\s*:(\s|$))"), fmt("#7dd3fc" if dark else "#0369a1", bold=True)),
            (QRegularExpression(r"\"([^\"\\]|\\.)*\"|'[^']*'"), fmt("#86efac" if dark else "#15803d")),
            (QRegularExpression(r"\{\{.*?\}\}|\{%.*?%\}"), fmt("#f0abfc" if dark else "#a21caf")),
            (QRegularExpression(r"^(---|\.\.\.)\s*$"), fmt(muted, bold=True)),
            (QRegularExpression(r"(^|\s)#.*$"), fmt(muted, italic=True)),
        ]
        self.rehighlight()

    def highlightBlock(self, text):
        for rx, f in self._rules:
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), f)


class Editor(QPlainTextEdit):
    """A plain editor that behaves for YAML: Tab is two spaces, and Enter keeps the indent (one level deeper after a line ending in a colon)."""

    def keyPressEvent(self, e):
        if e.key() == Qt.Key.Key_Tab and not e.modifiers() & Qt.KeyboardModifier.ControlModifier:
            c = self.textCursor()
            if c.hasSelection():
                self._shift(2)
            else:
                c.insertText("  ")
            return
        if e.key() == Qt.Key.Key_Backtab:
            self._shift(-2)
            return
        if e.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and not self.isReadOnly():
            c = self.textCursor()
            line = c.block().text()[:c.positionInBlock()]
            indent = re.match(r"\s*", line).group(0)
            extra = "  " if line.rstrip().endswith(":") else ""
            c.insertText("\n" + indent + extra)
            self.setTextCursor(c)
            return
        super().keyPressEvent(e)

    def _shift(self, n):
        """Indent (n > 0) or outdent every selected line (or the current one)."""
        c = self.textCursor()
        c.beginEditBlock()
        start, end = c.selectionStart(), c.selectionEnd()
        c.setPosition(start)
        first = c.blockNumber()
        c.setPosition(end)
        last = c.blockNumber()
        if end > start and c.positionInBlock() == 0:
            last = max(first, last - 1)
        for b in range(first, last + 1):
            blk = self.document().findBlockByNumber(b)
            cur = QTextCursor(blk)
            if n > 0:
                cur.insertText(" " * n)
            else:
                lead = len(blk.text()) - len(blk.text().lstrip(" "))
                cur.movePosition(QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.KeepAnchor, min(-n, lead))
                cur.removeSelectedText()
        c.endEditBlock()


class NewPlaybookDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New playbook")
        self.name = QLineEdit()
        self.name.setPlaceholderText("backup-configs   or   site/restart-services")
        self.template = QComboBox()
        for key, (label, _text) in AN.TEMPLATES.items():
            self.template.addItem(label, key)
        self.hint = QLabel("A name with a slash puts the playbook in a folder. It is saved as a .yml file.")
        self.hint.setProperty("muted", True)
        self.hint.setWordWrap(True)
        form = QFormLayout()
        form.addRow("Name", self.name)
        form.addRow("Start from", self.template)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(self.hint)
        lay.addWidget(box)
        self.resize(460, self.sizeHint().height())

    def values(self):
        return self.name.text().strip(), self.template.currentData()


class _CheckWorker(QThread):
    line = Signal(str)
    done = Signal(object)

    def __init__(self, name):
        super().__init__()
        self.name = name

    def run(self):
        try:
            res = AN.run(AN.RunSpec(self.name, [], syntax_only=True), self.line.emit)
        except Exception as e:
            res = e
        self.done.emit(res)


class PlaybookEditorTab(QWidget):
    library_changed = Signal()                    # a playbook was made, renamed, deleted or saved
    run_requested = Signal(str)                   # the person asked to run this playbook (Automation > Ansible)
    settings_requested = Signal()                 # ... or to open Settings > Ansible

    def __init__(self):
        super().__init__()
        self.current = ""                         # the playbook in the editor ("" for none)
        self._loading = False
        self._worker = None
        self.listing = QListWidget()
        self.listing.setMaximumWidth(220)
        self.new_btn, self.rename_btn, self.delete_btn = QPushButton("New..."), QPushButton("Rename..."), QPushButton("Delete")
        self.folder_btn = QPushButton("Open folder")
        self.folder_btn.setToolTip("Show the playbook folder in Explorer (change it in Settings > Ansible)")
        self.list_hint = EmptyHint(self.listing, "No playbooks yet", "New... starts one from a template", actions=[("New...", lambda: self.new_playbook())], wrap=True)
        self.title = QLabel("")
        self.title.setStyleSheet("font-weight:600;")
        self.save_btn, self.revert_btn = QPushButton("Save"), QPushButton("Revert")
        self.save_btn.setProperty("primary", True)
        self.save_btn.setToolTip("Save the playbook  (Ctrl+S)")
        self.check_btn = QPushButton("Check with Ansible")
        self.check_btn.setToolTip("Run  ansible-playbook --syntax-check  on the saved playbook, using the backend chosen in Settings > Ansible")
        self.run_btn = QPushButton("Run...")
        self.run_btn.setToolTip("Open this playbook in Automation > Ansible, to pick devices and run it")
        self.settings_btn = QPushButton("Settings")
        self.settings_btn.setToolTip("Where Ansible runs, and the playbook folder: Settings > Ansible")
        self.editor = Editor()
        self.editor.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.editor.setTabStopDistance(self.editor.fontMetrics().horizontalAdvance(" ") * 2)
        self.highlighter = YamlHighlighter(self.editor.document())
        self.verdict = QLabel("")
        self.verdict.setWordWrap(True)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.output.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.output.setPlaceholderText("The result of Check with Ansible appears here")
        self.output.setVisible(False)
        left = QVBoxLayout()
        left.addWidget(QLabel("Playbooks"))
        left.addWidget(self.listing, 1)
        lb = QHBoxLayout()
        for b in (self.new_btn, self.rename_btn, self.delete_btn):
            lb.addWidget(b)
        left.addLayout(lb)
        left.addWidget(self.folder_btn)
        bar = QHBoxLayout()
        for b in (self.revert_btn, self.save_btn, self.check_btn, self.run_btn, self.settings_btn):
            bar.addWidget(b)
        bar.addStretch(1)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.editor)
        split.addWidget(self.output)
        split.setSizes([420, 120])
        remember_sizes(split, "playbook_editor")
        right = QVBoxLayout()
        right.addWidget(self.title)
        right.addLayout(bar)
        right.addWidget(split, 1)
        right.addWidget(self.verdict)
        lay = QHBoxLayout(self)
        lay.addLayout(left)
        lay.addLayout(right, 1)
        self.live = QTimer(self)                  # the YAML is checked a moment after typing stops
        self.live.setSingleShot(True)
        self.live.setInterval(400)
        self.live.timeout.connect(self.check_now)
        self.editor.textChanged.connect(self._edited)
        self.listing.itemClicked.connect(self._chosen)
        self.settings_btn.clicked.connect(self.settings_requested.emit)
        self.new_btn.clicked.connect(lambda: self.new_playbook())
        self.rename_btn.clicked.connect(lambda: self.rename_playbook())
        self.delete_btn.clicked.connect(self.delete_playbook)
        self.folder_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(AN.playbook_dir()))))
        self.save_btn.clicked.connect(lambda: self.save())
        self.revert_btn.clicked.connect(self.revert)
        self.check_btn.clicked.connect(self.check_with_ansible)
        self.run_btn.clicked.connect(self._run)
        QShortcut(QKeySequence("Ctrl+S"), self, activated=lambda: self.save(), context=Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.refresh()

    # ---- the list
    def refresh(self, select=None):
        """Re-read the library (a playbook may have been added outside Toner, or the folder changed in Settings)."""
        want = select if select is not None else self.current
        self.listing.blockSignals(True)
        self.listing.clear()
        for p in AN.list_playbooks():
            it = QListWidgetItem(p["name"])
            it.setData(Qt.ItemDataRole.UserRole, p["name"])
            self.listing.addItem(it)
        self.listing.blockSignals(False)
        self.list_hint.setVisible(self.listing.count() == 0)
        names = [self.listing.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.listing.count())]
        if self.current and self.current not in names and not self.dirty():
            self._show("")
        if want in names:
            self.listing.setCurrentRow(names.index(want))
        self._buttons()

    def names(self):
        return [self.listing.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.listing.count())]

    def _chosen(self, item):
        name = item.data(Qt.ItemDataRole.UserRole)
        if name != self.current:
            if not self.leave():
                self._select(self.current)
                return
            self.open_playbook(name)

    def _select(self, name):
        names = self.names()
        self.listing.blockSignals(True)
        self.listing.setCurrentRow(names.index(name) if name in names else -1)
        self.listing.blockSignals(False)

    # ---- opening, leaving
    def dirty(self):
        return bool(self.current) and self.editor.toPlainText() != self._saved_text

    _saved_text = ""

    def leave(self):
        """True when the editor can show something else: nothing unsaved, or the person saved or discarded it."""
        if not self.dirty():
            return True
        box = QMessageBox.question(self, "Unsaved changes", f"Save the changes to {self.current}?",
                                   QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel)
        if box == QMessageBox.StandardButton.Save:
            return self.save()
        return box == QMessageBox.StandardButton.Discard

    def open_playbook(self, name):
        """Show a playbook from the library. Returns False if the person kept the unsaved one."""
        if name != self.current and not self.leave():
            return False
        try:
            text = AN.read(name) if name else ""
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Playbook", f"Could not open {name}: {e}")
            return False
        self._show(name, text)
        if name:
            self.refresh(select=name)
        return True

    def _show(self, name, text=""):
        self.live.stop()                          # a YAML check still waiting was for the text being replaced (this one is checked below)
        self._loading = True
        self.current = name
        self._saved_text = text
        self.editor.setPlainText(text)
        self.editor.document().setModified(False)
        self._loading = False
        self.output.clear()
        self.output.setVisible(False)
        self.check_now()
        self._buttons()

    def _buttons(self):
        have = bool(self.current)
        dirty = self.dirty()
        self.editor.setReadOnly(not have)
        self.title.setText((self.current + ("   (not saved)" if dirty else "")) if have else "Choose a playbook, or start a new one")
        for b in (self.rename_btn, self.delete_btn, self.check_btn, self.run_btn):
            b.setEnabled(have)
        self.save_btn.setEnabled(dirty)
        self.revert_btn.setEnabled(dirty)
        self.check_btn.setEnabled(have and not self.checking())

    # ---- editing
    def _edited(self):
        if self._loading:
            return
        self._buttons()
        self.live.start()

    def check_now(self):
        """The YAML check, shown under the editor."""
        text = self.editor.toPlainText()
        if not self.current:
            self.verdict.setText("")
            return
        ok, msg, line = AN.check_yaml(text)
        self.verdict.setText(("The YAML is valid." if ok else (f"Line {line}: " if line else "") + msg))
        self.verdict.setStyleSheet(f"color:{st.ink('OK' if ok else 'FAIL')};")
        if not ok and line:
            self.verdict.setToolTip("Click Check with Ansible for Ansible's own check, once the YAML is valid")
        self.valid = ok

    def save(self):
        """Write the playbook. Returns True when it is saved."""
        if not self.current:
            return False
        text = self.editor.toPlainText()
        try:
            AN.write(self.current, text)
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Save playbook", f"Could not save {self.current}: {e}")
            return False
        self._saved_text = AN.read(self.current)
        audit.log("playbook saved", self.current)
        self._buttons()
        self.library_changed.emit()
        return True

    def revert(self):
        if self.current and self.dirty():
            self._show(self.current, self._saved_text)

    # ---- the library
    def new_playbook(self, template="", name=""):
        """Make a playbook from a template and open it. With no arguments the person is asked for both."""
        if not self.leave():
            return False
        if not name:
            dlg = NewPlaybookDialog(self)
            if template:
                dlg.template.setCurrentIndex(max(0, dlg.template.findData(template)))
            if not dlg.exec():
                return False
            name, template = dlg.values()
        try:
            path = AN.create(name, template or "blank")
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "New playbook", str(e))
            return False
        made = path.relative_to(AN.playbook_dir().resolve()).as_posix()
        audit.log("playbook created", made)
        self.refresh(select=made)
        self.open_playbook(made)
        self.library_changed.emit()
        return True

    def rename_playbook(self, new=""):
        if not self.current or not self.leave():
            return False
        if not new:
            new, ok = QInputDialog.getText(self, "Rename playbook", "New name (a slash puts it in a folder):", text=self.current)
            if not ok or not new.strip():
                return False
        try:
            AN.rename(self.current, new)
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Rename playbook", str(e))
            return False
        audit.log("playbook renamed", f"{self.current} -> {new}")
        self.current = ""
        self.refresh()
        now = AN._clean_name(new)
        self.open_playbook(now)
        self.library_changed.emit()
        return True

    def delete_playbook(self):
        if not self.current:
            return False
        if QMessageBox.question(self, "Delete playbook", f"Delete {self.current}?\n\nThe file is removed from the playbook folder.") != QMessageBox.StandardButton.Yes:
            return False
        try:
            AN.delete(self.current)
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Delete playbook", str(e))
            return False
        audit.log("playbook deleted", self.current)
        self._show("")
        self.refresh()
        self.library_changed.emit()
        return True

    # ---- Ansible
    def checking(self):
        return bool(self._worker and self._worker.isRunning())

    def check_with_ansible(self):
        if not self.current or self.checking():
            return
        if self.dirty():
            ask = QMessageBox.question(self, "Check with Ansible", "Ansible checks the saved playbook. Save your changes first?")
            if ask != QMessageBox.StandardButton.Yes or not self.save():
                return
        if self.live.isActive():                  # a YAML check still waiting goes now, so it can't replace Ansible's answer later
            self.live.stop()
            self.check_now()
        self.output.clear()
        self.output.setVisible(True)
        self.output.setPlainText("Checking...")
        self._buttons()
        self._first = True
        self._worker = _CheckWorker(self.current)
        self._worker.line.connect(self._line)
        self._worker.done.connect(self._checked)
        self._worker.start()

    def _line(self, text):
        if getattr(self, "_first", False):
            self.output.clear()
            self._first = False
        self.output.appendPlainText(text)

    def _checked(self, res):
        if isinstance(res, Exception):
            self.output.setPlainText(str(res))
            self.verdict.setText("Ansible could not check the playbook.")
            self.verdict.setStyleSheet(f"color:{st.ink('FAIL')};")
        else:
            good = res["exit_code"] == 0
            if getattr(self, "_first", False):
                self.output.clear()
            self.verdict.setText("Ansible's syntax check passed." if good else "Ansible's syntax check found a problem (see below).")
            self.verdict.setStyleSheet(f"color:{st.ink('OK' if good else 'FAIL')};")
        self._buttons()

    def _run(self):
        if self.current and (not self.dirty() or self.save()):
            self.run_requested.emit(self.current)

    def shutdown(self):
        if self._worker is not None:
            self._worker.wait(5000)
