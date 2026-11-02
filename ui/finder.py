"""The search box and the funnel button every list uses, as on Inventory: the box on the right of the toolbar ('Search devices
(Ctrl+F)'), the funnel beside it with menus of tick boxes that stay open while ticking, a count on the funnel when something is
ticked, and Clear filter. Several words in the box must all match; several ticks in one menu mean any of them, and the menus
together mean all of them."""
from dataclasses import dataclass, field

from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import QLineEdit

from core import db, display, vendors
from ui.widgets import FunnelButton

DEVICE_TIP = "Filter by vendor, location, folder or tag"

class SearchBox(QLineEdit):
    """'<what>  (Ctrl+F)'. Ctrl+F on `page` puts the cursor here (only while the page is on screen)."""

    def __init__(self, what, tip="", page=None):
        super().__init__()
        self.setPlaceholderText(f"{what}  (Ctrl+F)")
        self.setAccessibleName(what)
        self.setClearButtonEnabled(True)
        self.setMinimumWidth(120)
        self.setMaximumWidth(280)
        if tip:
            self.setToolTip(tip)
        if page is not None:
            QShortcut(QKeySequence("Ctrl+F"), page, activated=self.focus_here)

    def focus_here(self):
        if self.isVisible():
            self.setFocus()
            self.selectAll()

    def words(self):
        return self.text().lower().split()

    def matches(self, *texts):
        words = self.words()
        if not words:
            return True
        hay = " ".join(str(t) for t in texts if t).lower()
        return all(w in hay for w in words)

@dataclass
class Section:
    key: str
    title: str
    options: list                    # [(shown text, value)]
    exclusive: bool = False          # one choice at a time (the first option is the default, meaning no filter)
    extra: dict = field(default_factory=dict)

class FilterButton(FunnelButton):
    """The funnel. `sections` is a function returning [Section]; it is called each time the menu opens, so the choices
    follow the data."""

    def __init__(self, sections, tip=DEVICE_TIP):
        self.sections = sections
        self.sel = {}                                       # section key -> set of ticked values
        self._labels = {}                                   # (key, value) -> shown text, for the tooltip
        super().__init__(tip)
        self._update()

    @property
    def menu_(self):                                        # the name callers and tests used before FunnelButton
        return self.menu

    # ---- what is chosen
    def selected(self, key):
        return set(self.sel.get(key, set()))

    def active(self):
        return any(self.sel.values())

    filtering = active

    def clear(self):
        self.sel = {}
        self._update()
        self.changed.emit()

    def set(self, key, values):
        self.sel[key] = set(values)
        self._update()
        self.changed.emit()

    # ---- the menu
    def build(self):
        m = self.menu
        m.clear()
        for s in self.sections():
            sub = m.addMenu(s.title)
            boxes = []
            for text, val in s.options:
                self._labels[(s.key, val)] = text
                checked = val in self.sel.get(s.key, set()) or (s.exclusive and not self.sel.get(s.key) and val == s.options[0][1])
                box = self.add_box(sub, text, checked, lambda on, s=s, val=val, boxes=boxes: self._toggle(s, val, on, boxes))
                boxes.append((val, box))
        self.finish_menu()

    def _toggle(self, s, val, on, boxes):
        cur = self.sel.setdefault(s.key, set())
        if s.exclusive:
            cur.clear()
            if on and val != s.options[0][1]:
                cur.add(val)
            for v, b in boxes:                              # the ticks follow: one choice, the first when there is none
                b.blockSignals(True)
                b.setChecked(v in cur or (not cur and v == s.options[0][1]))
                b.blockSignals(False)
        else:
            (cur.add if on else cur.discard)(val)
        self._update()
        self.changed.emit()

    def ticked_labels(self):
        return [self._labels.get((k, v), str(v)) for k, vals in self.sel.items() for v in sorted(vals, key=str)]

# ---------------------------------------------------------------- devices: the same choices and matching as Inventory
def org_section():
    """Global listing everything: Organization (archived ones too, so they can still be looked at here)."""
    from core import orgs
    opts = [("Global", db.GLOBAL)] + [(o["name"] + ("  (archived)" if o["archived"] else ""), o["id"]) for o in orgs.list_orgs()]
    return [Section("org", "Organization", opts)] if db.everything() and len(opts) > 1 else []

def wants_archived(fb):
    """True when the funnel's Organization menu picks an archived organization (lists then read its file too)."""
    return bool(db.everything() and fb is not None and set(fb.selected("org")) & db.archived_ids())

def listed_devices(fb=None, enabled_only=False):
    """db.list_devices for a page with this funnel: archived organizations are included only when the funnel picks one."""
    with db.including_archived(wants_archived(fb)):
        return db.list_devices(enabled_only=enabled_only)

def device_sections(devs, folders=True):
    """Organization (in Global), Vendor, Location, Folder (each folder that holds devices, and the folders above it) and Tag."""
    out = org_section() + [Section("vendor", "Vendor", sorted(((display.vendor_name(v) if v else "(no vendor)", v) for v in {vendors.family(d["vendor"]) for d in devs}),
                                              key=lambda x: x[0].lower()))]
    locs = sorted({d.get("location") for d in devs if d.get("location")}, key=str.lower)
    out.append(Section("location", "Location", [(x, x) for x in locs] + ([("(none)", "")] if any(not d.get("location") for d in devs) else [])))
    if folders:
        used = set()
        for d in devs:
            p = db.path_of(d)
            while p:
                used.add(p)
                p = p.rpartition("/")[0]
        out.append(Section("folder", "Folder", [(p, p) for p in sorted(used, key=str.lower)]))
    out.append(Section("tag", "Tag", [(t, t) for t in sorted({t for d in devs for t in db.split_tags(d.get("tags"))}, key=str.lower)]))
    return [s for s in out if s.options]

def device_text(d):
    """What the search box looks in, as on Inventory: name, address, vendor, location, details, tags, site, platform."""
    org = db.org_name(d["org"]) if db.everything() and d.get("org") is not None else ""      # Global: the organization's name too
    return " ".join(str(x) for x in (d.get("name"), d.get("host"), display.vendor_name(d.get("vendor", "")), d.get("location"),
                                     d.get("details"), d.get("tags"), d.get("site"), d.get("platform"), org) if x)

def device_ok(d, fb, paths=None):
    """Does the device pass the funnel's Vendor, Location, Folder and Tag ticks?"""
    v, loc, fol, tags = fb.selected("vendor"), fb.selected("location"), fb.selected("folder"), {t.lower() for t in fb.selected("tag")}
    org = fb.selected("org")
    if org and d.get("org", db.GLOBAL) not in org:
        return False
    if v and vendors.family(d["vendor"]) not in v:
        return False
    if loc and (d.get("location") or "") not in loc:
        return False
    if tags and not tags & {t.lower() for t in db.split_tags(d.get("tags"))}:
        return False
    if fol:
        p = db.path_of(d)
        if not any(p == f or p.startswith(f + "/") for f in fol):
            return False
    return True

def shown_devices(devs, box, fb):
    """The devices the search box and the funnel leave on screen."""
    paths = db.folder_paths()
    return [d for d in devs if device_ok(d, fb, paths) and box.matches(device_text(d))]
