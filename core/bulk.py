"""Change the same thing on many inventory devices at once."""
import json

from core import audit, db


def apply(devices, ops):
    """ops may hold any of: folder_id (None = top level), location, add_tags, remove_tags, profile_id (None = detach),
    jump (device name, '' = direct), enabled (bool). A key that is absent is left alone. Returns the number of devices
    changed. Raises ValueError for a jump host that would loop."""
    changed = 0
    names = {d["name"] for d in db.list_devices()}
    if "jump" in ops and ops["jump"]:
        if ops["jump"] not in names:
            raise ValueError(f"'{ops['jump']}' is not in the inventory.")
        if any(d["name"] == ops["jump"] for d in devices):
            raise ValueError("A device cannot be its own jump host: remove it from the selection first.")
    for stale in devices:
        d = db.get_device(stale["id"])                     # always edit what is stored now, not an old snapshot
        if d is None:
            continue
        new = dict(d)
        if "folder_id" in ops:
            new["folder_id"] = ops["folder_id"]
        if "location" in ops:
            new["location"] = ops["location"]
        if ops.get("add_tags") or ops.get("remove_tags"):
            drop = {t.lower() for t in db.split_tags(ops.get("remove_tags"))}
            keep = [t for t in db.split_tags(d.get("tags")) if t.lower() not in drop]
            new["tags"] = ", ".join(keep + db.split_tags(ops.get("add_tags")))
        if "profile_id" in ops:
            new["profile_id"] = ops["profile_id"]
        if "jump" in ops:
            new["jump"] = {"device": ops["jump"]} if ops["jump"] else ""
        if "enabled" in ops:
            new["enabled"] = int(bool(ops["enabled"]))
        before = {k: d.get(k) for k in db.DEVICE_FIELDS}
        db.save_device(new)
        after = {k: db.get_device(d["id"]).get(k) for k in db.DEVICE_FIELDS}
        if before != after:
            changed += 1
    audit.log("bulk edit", f"{len(devices)} device(s): {', '.join(sorted(ops))}")
    return changed
