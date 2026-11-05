"""Roles: every account is an Admin, an Engineer or a Tech, and an Admin chooses what Engineers and Techs may do.

netcheck.keys holds the rules (each role's permissions and each account's role) signed with the rules key, whose fingerprint the
database keeps (setting rules_key), so an edit made outside Toner shows. Two role keys are wrapped to the box key of each account
that should hold them: the rules key (Ed25519, signs the rules) to Admins, the backups key (X25519, for passwords kept in config
backups) to roles allowed "unmasked". The recovery key counts as an Admin. Rules that don't check out give everyone a Tech's
permissions until someone signed in with the recovery key saves the roles again, under a new rules key.

Lock order: this module's lock, then datakey's. datakey's hook (_accounts_changed) runs under datakey's lock, so it never takes
this one and never reads the file again.
"""
import base64
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from core import audit, datakey, db, envelope, quiet, sqldb

ROLES = ("Admin", "Engineer", "Tech")
KINDS = ("rules", "backups")
LAST_ADMIN = "Toner needs at least one Admin."
_PART2 = ("roles", "rules_pub", "rules_sig", "backups_pub", "grants", "recovery_grants")

_lock = threading.RLock()
_held = {}           # kind -> the private role key this sign-in holds
_cache = None        # what the file says, verified: {"state", "roles", "accounts", "backups_pub"}
_rk = None           # the rules_key setting, read once
_audited = False     # "roles were changed outside Toner" written this sign-in
_upgrade_due = False  # an Admin signed in to a Part 1 file: make the role keys once the database can be written
_callbacks = []


# ---------------------------------------------------------------- the file
def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _unb64(s):
    return base64.b64decode(s.encode("ascii"), validate=True)


def _public(kind, private):
    key = (Ed25519PrivateKey if kind == "rules" else X25519PrivateKey).from_private_bytes(private)
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _aad(kind, name):
    return b"toner-role-key:" + kind.encode("ascii") + b":" + (name or "").encode("utf-8")


def _accounts(doc):
    return {n: a.get("role", "Admin") for n, a in doc["accounts"].items()}


def _admins(doc):
    return sum(r == "Admin" for r in _accounts(doc).values())


def _signed(doc):
    return envelope.canonical({"roles": doc.get("roles"), "accounts": _accounts(doc), "backups_pub": doc.get("backups_pub")})


def _rules_key():
    """The rules_key setting; None while it can't be read: signed out, or a first start, which signs in before the database is
    encrypted and set up."""
    global _rk
    if _rk is None and datakey.is_open():
        try:
            _rk = db.get_setting("rules_key")
        except sqldb.sqlite3.Error:
            pass
    return _rk


def _state_of(doc):
    rk = _rules_key()
    if not rk:                                          # only a Part 1 file is unsigned; anything of Part 2's without the key is not
        return "tampered" if any(k in doc for k in _PART2) else "unsigned"
    try:
        pub = _unb64(doc["rules_pub"])
        good = envelope.fingerprint(pub) == rk and envelope.verify(pub, _signed(doc), doc["rules_sig"])
    except (KeyError, TypeError, ValueError, AttributeError):    # a field missing or mangled
        good = False
    return "ok" if good else "tampered"


def _clean_roles(stored):
    """Engineer's and Tech's stored permissions, only known keys with True or False."""
    from core import perms
    stored = stored if isinstance(stored, dict) else {}
    out = {}
    for role in ("Engineer", "Tech"):
        given = stored.get(role) if isinstance(stored.get(role), dict) else {}
        out[role] = {k: v for k, v in given.items() if k in perms.DEFAULTS[role] and isinstance(v, bool)}
    return out


def _perms_in(stored, role):
    from core import perms
    if role == "Admin":
        return {k: True for k, _ in perms.PERMISSIONS}
    return {**perms.DEFAULTS[role], **_clean_roles(stored)[role]}


def _load():
    global _cache, _audited
    if not datakey.exists() and not datakey.is_open():  # (not cached: setting up sign-in makes the file. Deleted while
        return {"state": "off"}                         # signed in, it is unreadable below: "tampered")
    with _lock:
        if _cache is not None:
            return _cache
        if _upgrade_due and _rules_key() == "":         # the database is ready now
            _upgrade()
        try:
            doc = datakey.read()
            st = _state_of(doc)
        except (OSError, ValueError):                   # unreadable now: trust none of it
            doc, st = None, "tampered"
        c = {"state": st}
        if st == "ok":
            c.update(roles=doc.get("roles"), accounts=_accounts(doc), backups_pub=_unb64(doc["backups_pub"]))
        if st == "tampered" and datakey.is_open() and not _audited:
            _audited = True
            audit.log("roles were changed outside Toner", who=datakey.signed_in_name())
        if _rules_key() is not None:                    # else look again next time: the database may be ready by then
            _cache = c
        return c


def _invalidate():
    global _cache, _rk
    _cache = _rk = None


def _notify():
    for fn in list(_callbacks):
        try:
            fn()
        except Exception:
            quiet.ignored()


# ---------------------------------------------------------------- reading the rules
def state():
    """"off" (no keys file), "unsigned" (a Part 1 file no Admin has opened since), "ok" or "tampered"."""
    return _load()["state"]


def role_of(name):
    if name is None:                                    # the recovery key
        return "Admin"
    c = _load()
    if c["state"] == "tampered":
        return "Tech"
    if c["state"] != "ok":
        return "Admin"
    folded = name.casefold()
    return next((r for n, r in c["accounts"].items() if n.casefold() == folded), "Tech")    # gone meanwhile: the least


def permissions(role):
    from core import perms
    if role not in ROLES:
        raise ValueError("unknown role")
    c = _load()
    if c["state"] == "tampered" and role != "Admin":
        return dict(perms.DEFAULTS["Tech"])
    return _perms_in(c.get("roles"), role)


def holds(kind):
    return kind in _held


def backups_public():
    """The backups key to encrypt to, or None while the rules don't check out."""
    return _load().get("backups_pub")


def backups_private():
    return _held.get("backups")


def on_change(fn):
    _callbacks.append(fn)


# ---------------------------------------------------------------- grants
def _sync(doc):
    """Wrap each role key held to every box key that should have it (the recovery key's too), and drop grants that no longer
    apply. The caller holds the rules key and has checked the rules."""
    old = doc.get("grants") if isinstance(doc.get("grants"), dict) else {}
    grants = {}
    for name, rec in doc["accounts"].items():
        if "box_pub" not in rec:                        # a Part 1 account that hasn't signed in since: its first sign-in adds one
            continue
        role = rec.get("role", "Admin")
        want = {"rules": role == "Admin", "backups": _perms_in(doc.get("roles"), role)["unmasked"]}
        mine = old.get(name) if isinstance(old.get(name), dict) else {}
        g = {k: v for k, v in mine.items() if want.get(k)}
        for kind in KINDS:
            if want[kind] and kind not in g and kind in _held:
                g[kind] = envelope.wrap(_unb64(rec["box_pub"]), _held[kind], _aad(kind, name))
        if g:
            grants[name] = g
    doc["grants"] = grants
    old = doc.get("recovery_grants") if isinstance(doc.get("recovery_grants"), dict) else {}
    rg = {k: v for k, v in old.items() if k in KINDS}
    for kind in KINDS:
        if kind not in rg and kind in _held and "box_pub" in doc["recovery"]:
            rg[kind] = envelope.wrap(_unb64(doc["recovery"]["box_pub"]), _held[kind], _aad(kind, None))
    doc["recovery_grants"] = rg


def sync_grants():
    """Grant the role keys to whoever should hold them now. Does nothing unless this sign-in holds the rules key."""
    with _lock:
        if "rules" not in _held:
            return

        def go(doc):
            if _state_of(doc) == "ok":
                _sync(doc)
        datakey.edit(go)


def _accounts_changed(before, doc):
    """datakey's hook, inside its write that adds, removes or re-keys an account or the recovery key."""
    global _cache
    grants = doc.get("grants")
    if isinstance(grants, dict):                        # a wrap to a box key that's gone can't be opened again
        for n in list(grants):
            if n not in doc["accounts"] or before["accounts"].get(n, {}).get("box_pub") != doc["accounts"][n].get("box_pub"):
                del grants[n]
    if before["recovery"].get("box_pub") != doc["recovery"].get("box_pub"):
        doc.pop("recovery_grants", None)
    if _admins(before) and not _admins(doc):
        raise ValueError(LAST_ADMIN)
    if _state_of(before) == "ok":                       # never re-sign rules that didn't check out: that would hide the edit
        if _accounts(before) != _accounts(doc):
            if "rules" not in _held:
                raise datakey.Locked("Sign in first.")
            doc["rules_sig"] = envelope.sign(_held["rules"], _signed(doc))
        if "rules" in _held:
            _sync(doc)
    _cache = None


# ---------------------------------------------------------------- sign-in and sign-out
def _trim():
    """Let go of role keys the signed-in person's role no longer allows (their grants are already gone)."""
    role = role_of(datakey.signed_in_name())
    if role != "Admin":
        _held.pop("rules", None)
    if not permissions(role)["unmasked"]:
        _held.pop("backups", None)


def unlock():
    """After a sign-in: take this account's role keys. On a Part 1 file, whoever signs in first (everyone is an Admin) makes the
    role keys. A tampered file or a missing grant is not an error: this sign-in just holds less."""
    global _audited, _upgrade_due
    with _lock:
        _held.clear()
        _invalidate()
        _audited = _upgrade_due = False
        name, box = datakey.signed_in_name(), datakey.box_private()
        _rules_key()                                    # read the setting before taking datakey's lock
        doc = datakey.read()
        for kind in KINDS:
            try:
                g = doc["recovery_grants"] if name is None else doc["grants"][name]
                key = envelope.unwrap(box, g[kind], _aad(kind, name))
                if _public(kind, key) == _unb64(doc[kind + "_pub"]):     # a grant of some other key is no grant
                    _held[kind] = key
            except (KeyError, TypeError, ValueError, AttributeError, InvalidTag):
                pass                                    # no grant yet, or one that doesn't open
        st = _state_of(doc)
        if st == "unsigned" and (name is None or doc["accounts"][name].get("role", "Admin") == "Admin"):
            _upgrade_due = True                         # done by _load, now or once the database is ready
        elif st == "ok" and "rules" in _held:
            sync_grants()
        _invalidate()
        _trim()                                         # (reads the rules: upgrades when due, audits a tampered file once)


def _upgrade():
    global _upgrade_due
    _upgrade_due = False
    rules, rules_pub = envelope.new_signing_key()
    backups, backups_pub = envelope.new_box_key()
    _held.update(rules=rules, backups=backups)

    def go(doc):
        if _state_of(doc) != "unsigned":                # someone else got there first
            return False
        doc.update(roles={"Engineer": {}, "Tech": {}}, rules_pub=_b64(rules_pub), backups_pub=_b64(backups_pub))
        doc["rules_sig"] = envelope.sign(rules, _signed(doc))
        _sync(doc)
        return True
    if datakey.edit(go):
        # shortcut: a crash between the file and the setting leaves the file "tampered"; the recovery key's repair puts it right.
        db.set_setting("rules_key", envelope.fingerprint(rules_pub))
    else:
        _held.clear()
    _invalidate()


def close():
    global _audited, _upgrade_due
    with _lock:
        _held.clear()
        _invalidate()
        _audited = _upgrade_due = False


# ---------------------------------------------------------------- changing the rules
def _may_write(doc):
    """True for the repair (a recovery sign-in on a tampered file); raises unless this sign-in may change the rules."""
    from core import perms
    st = _state_of(doc)
    if st == "tampered":
        if datakey.signed_in_name() is None:
            return True
        raise perms.Denied()                            # everyone is a Tech until the recovery key puts it right
    if st != "ok" or "rules" not in _held:
        raise datakey.Locked("Sign in first.")
    return False


def _resign(doc, repair):
    """Sign the rules and sync the grants; the repair first makes a new rules key, returning its public half."""
    pub = None
    if repair:
        _held["rules"], pub = envelope.new_signing_key()
        if "backups" not in _held:                      # shortcut: no held backups key to vouch for backups_pub, so a new one
            _held["backups"] = envelope.new_box_key()[0]
        doc["rules_pub"] = _b64(pub)
        doc["backups_pub"] = _b64(_public("backups", _held["backups"]))
        doc["grants"], doc["recovery_grants"] = {}, {}  # wraps of the old rules key; _sync wraps both afresh
    doc["roles"] = _clean_roles(doc.get("roles"))
    doc["rules_sig"] = envelope.sign(_held["rules"], _signed(doc))
    _sync(doc)
    return pub


def _written(pub):
    if pub is not None:
        db.set_setting("rules_key", envelope.fingerprint(pub))
    _invalidate()


def set_role(name, role):
    if role not in ROLES:
        raise ValueError("unknown role")
    with _lock:
        def go(doc):
            repair = _may_write(doc)
            stored = datakey._stored(doc, name)
            old = doc["accounts"][stored].get("role", "Admin")
            doc["accounts"][stored]["role"] = role
            if not _admins(doc):
                raise ValueError(LAST_ADMIN)
            return stored, old, _resign(doc, repair)
        stored, old, pub = datakey.edit(go)
        _written(pub)
        if old != role:
            audit.log("role changed", f"{stored}: {old} to {role}")
        _trim()
    _notify()


def set_permissions(role, changes):
    from core import perms
    if role not in ("Engineer", "Tech"):
        raise ValueError("the Admin role's permissions are fixed")
    if any(k not in perms.DEFAULTS[role] or not isinstance(v, bool) for k, v in changes.items()):
        raise ValueError("unknown permission")
    labels = dict(perms.PERMISSIONS)
    with _lock:
        def go(doc):
            repair = _may_write(doc)
            stored = _clean_roles(doc.get("roles"))
            was = _perms_in(stored, role)
            stored[role].update(changes)
            doc["roles"] = stored
            return [k for k, v in changes.items() if was[k] != v], _resign(doc, repair)
        changed, pub = datakey.edit(go)
        _written(pub)
        for k in changed:
            audit.log("role permissions changed", f"{role}: {labels[k]} {'on' if changes[k] else 'off'}")
        _trim()
    _notify()


datakey.accounts_changed = _accounts_changed
