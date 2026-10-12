"""What Save and Revert are about to do, in words: each setting that differs, with what it is now and what it will become.

snapshot(page) reads the page's controls into {setting name: shown value}. The Settings tab keeps one taken when each page was loaded or
saved; the difference between that and the page as it is now is the list shown before saving (old -> new) or reverting (edited -> stored)."""
import re

from PySide6.QtWidgets import (QAbstractItemView, QAbstractButton, QAbstractSpinBox, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                               QLabel, QLineEdit, QPlainTextEdit, QPushButton, QTextEdit, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)
from PySide6.QtCore import Qt


def _clean(text):
    """A form label as plain words: no markup, no ampersand shortcut, no trailing colon."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", str(text or "")).replace("&", "")).strip().rstrip(":").strip()


def _in_table(w):
    p = w.parentWidget()
    while p is not None:
        if isinstance(p, QAbstractItemView):
            return True
        p = p.parentWidget()
    return False


def _is_input(w):
    if isinstance(w, QLineEdit):
        return not isinstance(w.parentWidget(), (QAbstractSpinBox, QComboBox)) and not w.isReadOnly()      # the box inside a spin box is part of it
    if isinstance(w, QAbstractButton):
        return w.isCheckable()
    return isinstance(w, (QComboBox, QAbstractSpinBox, QPlainTextEdit, QTextEdit)) and not (hasattr(w, "isReadOnly") and w.isReadOnly())


def _value(w):
    """The text a person would read for this control."""
    if isinstance(w, QLineEdit):
        if w.echoMode() != QLineEdit.EchoMode.Normal:
            return "(set)" if w.text() else "(empty)"
        return w.text() or "(empty)"
    if isinstance(w, QAbstractButton):
        return "on" if w.isChecked() else "off"
    if isinstance(w, QComboBox):
        return w.currentText() or "(none)"
    if isinstance(w, QAbstractSpinBox):
        return w.text()
    text = w.toPlainText().strip()
    first = text.splitlines()[0] if text else ""
    return (first[:70] + ("..." if len(first) > 70 or "\n" in text else "")) or "(empty)"


def _inputs(w):
    if w is None:
        return []
    found = [w] if _is_input(w) else []
    return found + [c for c in w.findChildren(QWidget) if _is_input(c) and not _in_table(c)]


def snapshot(page):
    """{setting name: value} for everything a person can type or tick on a page. Names come from the form's labels."""
    out, seen = {}, set()
    if not getattr(page, "track", True):                        # a page whose boxes are not settings (the audit log's filter)
        return out

    def put(label, widgets):
        widgets = [w for w in widgets if id(w) not in seen and not _in_table(w)]
        if not widgets:
            return
        for w in widgets:
            seen.add(id(w))
        name = label
        n = 2
        while name in out:                                      # two rows with the same label stay apart
            name = f"{label} ({n})"
            n += 1
        out[name] = " / ".join(_value(w) for w in widgets)

    forms = [f for f in ([getattr(page, "form", None)] + page.findChildren(QFormLayout)) if f is not None]
    done = set()
    for form in forms:
        if id(form) in done:
            continue
        done.add(id(form))
        for r in range(form.rowCount()):
            lab = form.itemAt(r, QFormLayout.ItemRole.LabelRole)
            fld = form.itemAt(r, QFormLayout.ItemRole.FieldRole) or form.itemAt(r, QFormLayout.ItemRole.SpanningRole)
            text = _clean(lab.widget().text()) if lab is not None and isinstance(lab.widget(), QLabel) else ""
            if fld is None:
                continue
            if fld.widget() is not None:
                widgets = _inputs(fld.widget())
            else:
                widgets = [c for c in (fld.layout().itemAt(i).widget() for i in range(fld.layout().count())) if c is not None and _is_input(c)] if fld.layout() else []
            if not text and widgets:
                text = (_clean(widgets[0].text()) if isinstance(widgets[0], QAbstractButton) else "") or _clean(getattr(widgets[0], "placeholderText", lambda: "")()) \
                    or _clean(widgets[0].toolTip()) or "Setting"
            if len(widgets) > 1 and any(isinstance(w, QCheckBox) for w in widgets) and not (lab is not None and text):
                for w in widgets:                                # a row of tick boxes: each one is its own setting
                    put(_clean(w.text()) if isinstance(w, QAbstractButton) else text, [w])
            else:
                put(text, widgets)
    for w in page.findChildren(QWidget):                        # anything outside a form (a tick box under a heading)
        if _is_input(w) and id(w) not in seen and not _in_table(w):
            label = (_clean(w.text()) if isinstance(w, QAbstractButton) else "") or _clean(getattr(w, "placeholderText", lambda: "")()) or _clean(w.toolTip()) or "Setting"
            put(label, [w])
    extra = getattr(page, "describe_extra", None)
    if callable(extra):                                         # settings kept in a table or list: the page says what they are
        for label, value in extra():
            out[label] = value
    return out


def changes(old, new):
    """[(setting, was, becomes)] for what differs between two snapshots. Something added or removed says so."""
    rows = []
    for key in list(dict.fromkeys(list(old) + list(new))):
        if key not in old:
            rows.append((key, "(not set)", new[key]))
        elif key not in new:
            rows.append((key, old[key], "(removed)"))
        elif old[key] != new[key]:
            rows.append((key, old[key], new[key]))
    return rows


class ConfirmChanges(QDialog):
    """A list of settings by page, each with 'from' and 'to', and a button to go ahead."""

    def __init__(self, parent, title, intro, columns, groups, go_text, stay_text="Cancel"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 480)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["Setting", columns[0], columns[1]])
        self.tree.setRootIsDecorated(True)
        self.tree.setAlternatingRowColors(False)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.count = 0
        for page, rows in groups:
            top = QTreeWidgetItem([f"{page}  ({len(rows)})"])
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            self.tree.addTopLevelItem(top)
            for name, was, becomes in rows:
                it = QTreeWidgetItem([name, was, becomes])
                it.setToolTip(1, was)
                it.setToolTip(2, becomes)
                top.addChild(it)
                self.count += 1
            top.setExpanded(True)
        head = self.tree.header()
        head.setSectionResizeMode(0, head.ResizeMode.ResizeToContents)
        head.setSectionResizeMode(1, head.ResizeMode.Stretch)
        head.setSectionResizeMode(2, head.ResizeMode.Stretch)
        buttons = QDialogButtonBox()
        self.go = buttons.addButton(go_text, QDialogButtonBox.ButtonRole.AcceptRole)
        self.go.setProperty("primary", True)
        self.go.setDefault(True)
        stay = buttons.addButton(stay_text, QDialogButtonBox.ButtonRole.RejectRole)
        stay.setAutoDefault(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(intro.format(n=self.count, s="" if self.count == 1 else "s")))
        lay.addWidget(self.tree, 1)
        lay.addWidget(buttons)
