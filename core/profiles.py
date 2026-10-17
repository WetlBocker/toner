"""Credential profiles: a username, a secret and SNMP settings shared by many devices.

Each organization has its own; Global's can be marked Shared so every organization can use them. An organization's device refers
to a Shared profile by its id made negative (-5 is Global's profile 5), so the two files' ids never mix.

A device can use a profile and still override any part of it: its own username, secret or SNMP settings win.
Secrets live in Toner's vault under 'profile:<name>' (and ':snmp', ':snmp-auth', ':snmp-priv').
"""
import json

import keyring

from core import db

SNMP_DEFAULTS = {"version": "2c", "port": 161, "user": "", "level": "noAuthNoPriv",
                 "auth_protocol": "SHA", "priv_protocol": "AES-128"}


def _owner(name):
    return f"profile:{name}"


def _profiles_here():
    with db.connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM profiles ORDER BY name COLLATE NOCASE")]


def list_profiles():
    """The organization's credential profiles plus Global's Shared ones (each with 'org'; a Shared one seen from an organization has
    its id made negative, which is how a device there refers to it); Global's own in Global."""
    rows = db.gather_own(_profiles_here)
    me = db.target()
    for r in rows:
        if r["org"] != me:
            r["id"] = -r["id"]
    return rows


def listing():
    """For Settings > Credentials: in Global every organization's profiles (each with 'org'), in an organization its own plus
    Global's Shared ones (their ids negative, as its devices refer to them)."""
    return list_profiles() if not db.everything() else db.gather(_profiles_here)


def get(pid, org=None):
    """A profile by id (from `org`'s file); a negative id is Global's Shared profile, seen from an organization."""
    if org is not None and pid and pid > 0:
        with db.within(org):
            return get(pid)
    return _get(pid)


def _get(pid):
    if not pid:
        return None
    if pid < 0:
        with db.within(db.GLOBAL):
            p = get(-pid)
        return {**p, "id": pid, "org": db.GLOBAL} if p else None
    with db.connect() as c:
        row = c.execute("SELECT * FROM profiles WHERE id=?", (pid,)).fetchone()
    return {**dict(row), "org": db.target()} if row else None


def of(dev):
    """The device's credential profile, read from the device's own organization's file ({} when it has none)."""
    if not (dev or {}).get("profile_id"):
        return {}
    with db.within(dev.get("org")):
        return get(dev["profile_id"]) or {}


def by_name(name):
    with db.connect() as c:
        row = c.execute("SELECT * FROM profiles WHERE name=? COLLATE NOCASE", (name,)).fetchone()
    return dict(row) if row else None


def clean_name(name):
    name = (name or "").strip()
    if not name:
        raise ValueError("A profile needs a name.")
    if ":" in name:
        raise ValueError("A profile name cannot contain ':'.")
    return name


def save(profile, secrets=None):
    """Create or update, in the profile's own organization's file (profile['org']). `secrets` = {'main': .., 'snmp': ..,
    'snmp_auth': .., 'snmp_priv': ..}; a missing or empty entry leaves the stored value alone. Returns the id."""
    with db.within(profile.get("org")):
        return _save(profile, secrets)


def _save(profile, secrets):
    name = clean_name(profile.get("name"))
    shared = 1 if profile.get("shared") and db.target() == db.GLOBAL else 0
    snmp = profile.get("snmp") or ""
    if isinstance(snmp, dict):
        snmp = json.dumps(snmp) if snmp else ""
    with db.connect() as c:
        clash = c.execute("SELECT id FROM profiles WHERE name=? COLLATE NOCASE AND id IS NOT ?",
                          (name, profile.get("id"))).fetchone()
        if clash:
            raise ValueError(f"A profile named '{name}' already exists.")
        if profile.get("id"):
            old = c.execute("SELECT name FROM profiles WHERE id=?", (profile["id"],)).fetchone()
            c.execute("UPDATE profiles SET name=?, username=?, snmp=?, notes=?, shared=? WHERE id=?",
                      (name, profile.get("username", ""), snmp, profile.get("notes", ""), shared, profile["id"]))
            pid = profile["id"]
            if old and old["name"] != name:
                db.move_device_secrets(_owner(old["name"]), _owner(name))
        else:
            pid = c.execute("INSERT INTO profiles(name, username, snmp, notes, shared) VALUES(?,?,?,?,?)",
                            (name, profile.get("username", ""), snmp, profile.get("notes", ""), shared)).lastrowid
    for kind, value in (secrets or {}).items():
        if value:
            db.set_secret(db.secret_name(_owner(name), kind), value)
    return pid


def delete(pid, org=None):
    with db.within(org):
        return _delete(pid)


def _delete(pid):
    p = get(pid)
    if not p:
        return
    with db.connect() as c:
        c.execute("UPDATE devices SET profile_id=NULL WHERE profile_id=?", (pid,))
        c.execute("DELETE FROM profiles WHERE id=?", (pid,))
    if db.target() == db.GLOBAL:                       # organizations' devices that used it as a Shared profile
        for r in db.org_rows():
            with db.within(r["id"]), db.connect() as c:
                c.execute("UPDATE devices SET profile_id=NULL WHERE profile_id=?", (-pid,))
    db.delete_device_secrets(_owner(p["name"]))


def users_of(pid, org=None):
    """The devices using a profile (in Global, a Shared one's users in every organization too)."""
    if org is not None:
        with db.within(org):
            return users_of(pid)
    with db.connect() as c:
        names = [r["name"] for r in c.execute("SELECT name FROM devices WHERE profile_id=? ORDER BY name", (pid,))]
    if db.target() == db.GLOBAL and pid and pid > 0:
        for r in db.org_rows():
            with db.within(r["id"]), db.connect() as c:
                names += [f"{x['name']} ({r['name']})" for x in c.execute("SELECT name FROM devices WHERE profile_id=? ORDER BY name", (-pid,))]
    return names


def has_secret(name, kind="main", org=None):
    try:
        with db.within(org):
            return bool(keyring.get_password(db.SERVICE, db.secret_name(_owner(name), kind)))
    except Exception:
        return False


# ---------- what a device actually uses ----------
def snmp_settings(dev):
    """The device's effective SNMP settings (its own override, else its profile's, else defaults)."""
    def parse(text):
        try:
            return json.loads(text) if text else {}
        except ValueError:
            return {}
    prof = of(dev)
    own = parse(dev.get("snmp"))
    return {**SNMP_DEFAULTS, **parse(prof.get("snmp")), **own}


def snmp_configured(dev):
    prof = of(dev)
    return bool(dev.get("snmp") or prof.get("snmp"))


def secret(dev, kind="main"):
    """The stored secret for a device: one typed into an open dialog, its own, then its profile's."""
    typed = (dev.get("_secrets") or {}).get(kind)
    if typed:
        return typed
    with db.within(dev.get("org")):                   # its passwords are kept under its own organization's names
        return _stored(dev, kind)


def _stored(dev, kind):
    prof = of(dev) if dev.get("profile_id") else {}
    for owner, org in ((dev.get("name"), None), (_owner(prof.get("name", "")) if prof else None, prof.get("org"))):
        if not owner:
            continue
        try:
            with db.within(org):                       # a Shared profile's passwords are kept under Global's names
                value = keyring.get_password(db.SERVICE, db.secret_name(owner, kind))
        except Exception:
            value = None
        if value:
            return value
    return None


def username(dev):
    return dev.get("username") or of(dev).get("username", "")


def resolve(dev):
    """A copy of the device with the username filled in from its profile. Secrets are looked up on demand."""
    out = dict(dev)
    if not out.get("username"):
        out["username"] = username(dev)
    return out
