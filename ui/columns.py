"""Right-click a table heading to choose which columns show. The choice is remembered. Until someone chooses, columns that hold nothing
(a Site that is 'N/A' on every row, empty Details and Tags) are left out, so the table is not mostly blank space."""
from PySide6.QtCore import QObject, Qt
from PySide6.QtWidgets import QMenu

from core import db


class ColumnChooser(QObject):
    def __init__(self, view, header, setting, names, locked=(0,), auto=None, org_col=None):
        """view: the table or tree. setting: where the hidden columns are kept (None = automatic). auto: () -> set of column numbers
        to hide while the choice is automatic. org_col: the Organization column, which only exists while Global lists everything."""
        super().__init__(view)
        self.view, self.header, self.setting, self.names = view, header, setting, list(names)
        self.locked, self.auto, self.org_col = set(locked), auto, org_col
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self._menu)

    def chosen(self):
        """The hidden columns the person chose, or None while it is automatic."""
        raw = db.get_setting(self.setting)
        return None if raw is None else {int(i) for i in raw if isinstance(i, int) and 0 <= i < len(self.names)}

    def hidden(self):
        chosen = self.chosen()
        hide = (chosen if chosen is not None else (self.auto() if self.auto else set())) - self.locked
        if self.org_col is not None and not db.several():
            hide = hide | {self.org_col}
        return hide

    def apply(self):
        hide = self.hidden()
        for i in range(len(self.names)):
            self.view.setColumnHidden(i, i in hide)

    def _menu(self, pos):
        menu = QMenu(self.view)
        hide = self.hidden()
        for i, name in enumerate(self.names):
            if i == self.org_col and not db.several():
                continue
            act = menu.addAction(name or f"Column {i + 1}")
            act.setCheckable(True)
            act.setChecked(i not in hide)
            act.setEnabled(i not in self.locked)
            act.toggled.connect(lambda on, i=i: self.toggle(i, on))
        menu.addSeparator()
        menu.addAction("Hide empty columns automatically", self.reset).setEnabled(self.chosen() is not None)
        menu.exec(self.header.mapToGlobal(pos))

    def toggle(self, column, shown):
        hide = set(self.hidden())
        if self.org_col is not None and not db.several():
            hide.discard(self.org_col)                     # hidden here only because no organization column exists here
        (hide.discard if shown else hide.add)(column)
        db.set_setting(self.setting, sorted(hide))
        self.apply()

    def reset(self):
        db.set_setting(self.setting, None)
        self.apply()
