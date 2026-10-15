"""The client being looked at.

For an MSP the top-level folders of the inventory are usually its clients. Choosing one in the sidebar narrows every section to that
client's devices: the Overview, Results, the Inventory, Configs, History, Reports and the runs started from them. "All clients" shows
everything. The choice is kept per computer (it is not a setting that travels with an export)."""
from core import db

SETTING = "client_scope"


def clients():
    """[(folder id, name)] of the top-level folders, by name."""
    folders = db.list_folders()
    known = {f["id"] for f in folders}
    return sorted(((f["id"], f["name"]) for f in folders if f["parent_id"] not in known), key=lambda x: x[1].lower())


def current():
    """The chosen client's folder id, or None for all clients (also when the folder has gone)."""
    fid = db.get_setting(SETTING)
    if fid is None:
        return None
    try:
        fid = int(fid)
    except (TypeError, ValueError):
        return None
    return fid if fid in {c for c, _n in clients()} else None


def set_current(fid):
    db.set_setting(SETTING, int(fid) if fid is not None else None)


def name():
    fid = current()
    return dict(clients()).get(fid, "") if fid is not None else ""


def label():
    """The group label for the chosen client ('Folder: Acme'), or None for all, for runs and reports."""
    fid = current()
    return f"Folder: {db.folder_paths().get(fid)}" if fid is not None else None


def folder_ids():
    """The chosen client's folder and every folder under it, or None for all clients."""
    fid = current()
    return db.folder_descendants(fid) if fid is not None else None


def keep(devs):
    """Only the devices of the chosen client (all of them when there is no choice)."""
    ids = folder_ids()
    return list(devs) if ids is None else [d for d in devs if d.get("folder_id") in ids]


def names():
    """The names of the chosen client's devices, or None when every device counts."""
    ids = folder_ids()
    return None if ids is None else {d["name"] for d in db.list_devices() if d.get("folder_id") in ids}


def groups(picked):
    """The groups a run should cover: what was picked, narrowed to the client (a run with nothing picked covers just the client)."""
    lab = label()
    if lab is None:
        return list(picked or [])
    return list(picked or []) or [lab]
