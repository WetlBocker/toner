"""Credential profiles: a username, a secret and SNMP settings shared by many devices.

A device can use a profile and still override any part of it: its own username, secret or SNMP settings win.
Secrets live in Windows Credential Manager under 'profile:<name>' (and ':snmp', ':snmp-auth', ':snmp-priv').
"""
import json

import keyring

from core import db

SNMP_DEFAULTS = {"version": "2c", "port": 161, "user": "", "level": "noAuthNoPriv",
                 "auth_protocol": "SHA", "priv_protocol": "AES-128"}


def _owner(name):
    return f"profile:{name}"


def list_profiles():
    with db.connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM profiles ORDER BY name COLLATE NOCASE")]


def get(pid):
    if not pid:
        return None
    with db.connect() as c:
        row = c.execute("SELECT * FROM profiles WHERE id=?", (pid,)).fetchone()
    return dict(row) if row else None


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
    """Create or update. `secrets` = {'main': .., 'snmp': .., 'snmp_auth': .., 'snmp_priv': ..}; a missing
    or empty entry leaves the stored value alone. Returns the id."""
    name = clean_name(profile.get("name"))
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
            c.execute("UPDATE profiles SET name=?, username=?, snmp=?, notes=? WHERE id=?",
                      (name, profile.get("username", ""), snmp, profile.get("notes", ""), profile["id"]))
            pid = profile["id"]
            if old and old["name"] != name:
                db.move_device_secrets(_owner(old["name"]), _owner(name))
        else:
            pid = c.execute("INSERT INTO profiles(name, username, snmp, notes) VALUES(?,?,?,?)",
                            (name, profile.get("username", ""), snmp, profile.get("notes", ""))).lastrowid
    for kind, value in (secrets or {}).items():
        if value:
            db.set_secret(db.secret_name(_owner(name), kind), value)
    return pid


def delete(pid):
    p = get(pid)
    if not p:
        return
    with db.connect() as c:
        c.execute("UPDATE devices SET profile_id=NULL WHERE profile_id=?", (pid,))
        c.execute("DELETE FROM profiles WHERE id=?", (pid,))
    db.delete_device_secrets(_owner(p["name"]))


def users_of(pid):
    with db.connect() as c:
        return [r["name"] for r in c.execute("SELECT name FROM devices WHERE profile_id=? ORDER BY name", (pid,))]


def has_secret(name, kind="main"):
    try:
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
    prof = get(dev.get("profile_id")) or {}
    own = parse(dev.get("snmp"))
    return {**SNMP_DEFAULTS, **parse(prof.get("snmp")), **own}


def snmp_configured(dev):
    prof = get(dev.get("profile_id")) or {}
    return bool(dev.get("snmp") or prof.get("snmp"))


def secret(dev, kind="main"):
    """The stored secret for a device: one typed into an open dialog, its own, then its profile's."""
    typed = (dev.get("_secrets") or {}).get(kind)
    if typed:
        return typed
    for owner in (dev.get("name"), _owner((get(dev.get("profile_id")) or {}).get("name", "")) if dev.get("profile_id") else None):
        if not owner:
            continue
        try:
            value = keyring.get_password(db.SERVICE, db.secret_name(owner, kind))
        except Exception:
            value = None
        if value:
            return value
    return None


def username(dev):
    return dev.get("username") or (get(dev.get("profile_id")) or {}).get("username", "")


def resolve(dev):
    """A copy of the device with the username filled in from its profile. Secrets are looked up on demand."""
    out = dict(dev)
    if not out.get("username"):
        out["username"] = username(dev)
    return out
