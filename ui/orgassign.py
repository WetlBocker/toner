"""Importing in Global: say which organization each imported device or session goes to.

The rows are grouped by their top-level folder. Choosing an organization for a folder's row applies to everything in it; single rows
can still be changed. A folder named like an organization starts out going there; everything else starts in Global. New Organization
makes an organization named after the folder (created when Import is pressed)."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QPushButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout)

from core import audit, db, orgs

ROLE = Qt.ItemDataRole.UserRole
NO_FOLDER = "(no folder)"
NEW = "new"                                   # the drop-down's New Organization


class OrgAssignDialog(QDialog):
    def __init__(self, rows, parent=None):
        """rows: [(name, [folder parts], what)] in import order. picks() then gives the organization for each, in the same order."""
        super().__init__(parent)
        self.setWindowTitle("Choose where each one goes")
        self.resize(640, 520)
        self.choices = [("Global", db.GLOBAL)] + [(o["name"], o["id"]) for o in orgs.list_orgs(archived=False)]
        self.by_name = {n.lower(): v for n, v in self.choices}
        self.taken = {o["name"].lower() for o in orgs.list_orgs(archived=True)} | {"global", "shared"}   # cannot be made new
        self.new_names = {}                   # lower-case name -> the name as the folder spells it, for organizations to create
        self.created = []                     # names of the organizations made by resolve()
        self.tops = []                        # each row's top folder ('' for none)
        self.org_of = []
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Organization"])
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.header().setStretchLastSection(True)
        groups = {}
        for i, (name, folder, what) in enumerate(rows):
            top = folder[0] if folder else NO_FOLDER
            org = self.by_name.get(top.lower(), db.GLOBAL) if folder else db.GLOBAL
            self.org_of.append(org)
            self.tops.append(folder[0].strip() if folder else "")
            g = groups.get(top)
            if g is None:
                g = groups[top] = QTreeWidgetItem([top, ""])
                f = g.font(0)
                f.setBold(True)
                g.setFont(0, f)
                g.setData(0, ROLE, None)
                self.tree.addTopLevelItem(g)
            child = QTreeWidgetItem(["/".join(folder[1:] + [name]) if folder else name, ""])
            child.setToolTip(0, f"{what}: {'/'.join(folder + [name])}")
            child.setData(0, ROLE, i)
            g.addChild(child)
        for g in groups.values():
            g.setText(0, f"{g.text(0)}  ({g.childCount()})")
        self.pick = QComboBox()
        for text, value in self.choices:
            self.pick.addItem(text, value)
        self.pick.addItem("New Organization", NEW)
        apply_btn = QPushButton("Apply to selected")
        apply_btn.clicked.connect(self.apply)
        self.all_new = QPushButton("Import All Folders as New Organizations")
        self.all_new.clicked.connect(self.apply_all_new)
        self.all_new.setEnabled(any(self.tops))
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Apply to selected:"))
        bar.addWidget(self.pick)
        bar.addWidget(apply_btn)
        bar.addStretch(1)
        bar.addWidget(self.all_new)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.buttons.addButton("Import", QDialogButtonBox.ButtonRole.AcceptRole)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        note = QLabel("Pick rows (a folder's row picks everything in it), choose an organization, and press Apply to selected.")
        note.setWordWrap(True)
        lay.addWidget(note)
        lay.addWidget(self.tree, 1)
        lay.addLayout(bar)
        lay.addWidget(self.buttons)
        self.show_orgs()

    def _name(self, org):
        if isinstance(org, str):
            return f"{self.new_names[org]} (new)"
        return next((n for n, v in self.choices if v == org), "Global")

    def show_orgs(self):
        for gi in range(self.tree.topLevelItemCount()):
            g = self.tree.topLevelItem(gi)
            seen = set()
            for ci in range(g.childCount()):
                c = g.child(ci)
                org = self.org_of[c.data(0, ROLE)]
                seen.add(org)
                c.setText(1, self._name(org))
            g.setText(1, self._name(seen.pop()) if len(seen) == 1 else "(several)")

    def _folder_org(self, i):
        """What New Organization means for row i: the organization named like its top folder (an existing one when there is one),
        or None when it has no folder or the name cannot be used (Global, Shared, an archived organization)."""
        top = self.tops[i]
        if not top:
            return None
        if top.lower() in self.by_name:
            return self.by_name[top.lower()]
        if top.lower() in self.taken:
            return None
        self.new_names.setdefault(top.lower(), top)
        return top.lower()

    def _set(self, i, org):
        if org == NEW:
            org = self._folder_org(i)
            if org is None:
                return
        self.org_of[i] = org

    def apply(self, org=None):
        """The organization chosen below goes to every selected row (a folder's row: everything in it)."""
        org = self.pick.currentData() if org is None or isinstance(org, bool) else org
        for item in self.tree.selectedItems():
            i = item.data(0, ROLE)
            if i is None:
                for ci in range(item.childCount()):
                    self._set(item.child(ci).data(0, ROLE), org)
            else:
                self._set(i, org)
        self.show_orgs()

    def apply_all_new(self):
        """Every top folder goes to the organization named after it (made on Import when there is none)."""
        for i in range(len(self.org_of)):
            self._set(i, NEW)
        self.show_orgs()

    def picks(self):
        return list(self.org_of)

    def resolve(self):
        """Make the new organizations the rows go to; the organization for each row, in import order."""
        made = {}
        for i, org in enumerate(self.org_of):
            if isinstance(org, str) and org not in made:
                name = self.new_names[org]
                made[org] = orgs.create(name, orgs.suggest_code(name))
                audit.log("organization created", name)
                self.created.append(name)
        return [made.get(o, o) if isinstance(o, str) else o for o in self.org_of]


def choose(rows, parent=None, created=None):
    """The organization for each row, or None when the person cancels. Asked in Global when there are organizations, or folders that
    could become organizations; otherwise everything goes to the one being written to (no question is asked). The names of the
    organizations made on the way are added to `created`."""
    if not db.everything() or not (db.several() or any(folder for _n, folder, _w in rows)):
        return [None] * len(rows)
    dlg = OrgAssignDialog(rows, parent)
    if not dlg.exec():
        return None
    picks = dlg.resolve()
    if created is not None:
        created += dlg.created
    return picks


def created_text(names):
    """'Created 3 organizations: Acme, Beta, Contoso.'"""
    return f"Created {len(names)} organization{'s' if len(names) != 1 else ''}: {', '.join(names)}."


def strip_top(folder, org):
    """A folder path without its top folder when that folder is named like the organization it goes to (it is the organization now)."""
    if folder and org and folder[0].lower() == db.org_name(org).lower():
        return folder[1:]
    return folder
