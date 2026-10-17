"""The Organization field of the dialogs that make things (devices, sessions, credential profiles, custom checks, maintenance
windows): which organization a new item belongs to, or Shared so every organization has it."""
from PySide6.QtWidgets import QComboBox

from core import db, orgs

GLOBAL_ONLY_CHOICE = "g"            # Global's own item, shown only in Global
SHARED_CHOICE = "s"                 # ...or a Shared one, which every organization sees (both live in the Global file)


def org_choices(combo, editing=None, preselect=None, others=True):
    """Fill an Organization drop-down. In Global: Global, Shared and (others=True) every organization; a new item has to be given
    one. In an organization: that organization or Shared."""
    from ui.settings_pages.orgs import swatch
    combo.clear()
    if db.home() == db.GLOBAL:                    # where the person is (not a db.within() the dialog is filling its lists in)
        if editing is None and preselect is None and others and orgs.list_orgs(archived=False):
            combo.addItem("(choose one)", None)
        combo.addItem("Global (only shown in Global)", GLOBAL_ONLY_CHOICE)
        combo.addItem("Shared (shown in every organization)", SHARED_CHOICE)
        for o in orgs.list_orgs(archived=False) if others else []:
            combo.addItem(swatch(o["colour"]), o["name"], o["id"])
    else:
        here = db.home()
        o = orgs.get(here) or {}
        combo.addItem(swatch(o.get("colour")), db.org_name(here), here)
        combo.addItem("Shared (shown in every organization)", SHARED_CHOICE)
    want = preselect
    if editing is not None:
        want = SHARED_CHOICE if editing.get("shared") else (editing.get("org") or GLOBAL_ONLY_CHOICE)
    if want is not None:
        combo.setCurrentIndex(max(0, combo.findData(want)))


def choice_file(choice):
    """The organization whose file a choice from org_choices lives in (None: not chosen yet)."""
    if choice is None:
        return None
    return db.GLOBAL if choice in (GLOBAL_ONLY_CHOICE, SHARED_CHOICE) else int(choice)


class OrgField(QComboBox):
    """The field for a Settings item (credential profile, custom check, maintenance window). An item being edited stays in its
    organization; one of Global's can still be made Shared or not."""

    def __init__(self, item=None):
        super().__init__()
        item = item or {}
        editing = item if item.get("id") else None
        org_choices(self, editing, None, others=editing is None)
        if editing is not None and item.get("org", db.target()) != db.GLOBAL:
            self.setEnabled(False)                     # an organization's own item stays its own
        self.setToolTip("Which organization this belongs to. Shared ones are used by every organization.")

    def file(self):
        return choice_file(self.currentData())

    def shared(self):
        return int(self.currentData() == SHARED_CHOICE)

    def chosen(self):
        return self.currentData() is not None


def show_row(form, field):
    """The field only matters once there are organizations."""
    form.setRowVisible(field, bool(orgs.list_orgs()))
