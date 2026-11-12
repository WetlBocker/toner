"""Roles: every account is an Admin, an Engineer or a Tech, and an Admin chooses what Engineers and Techs may do.

netcheck.keys holds the rules (each role's permissions, each account's role and the box key it is vouched to have, and the
recovery key's) signed with the rules key, whose fingerprint the database keeps (setting rules_key), so an edit made outside Toner
shows. Two role keys are wrapped to the box key of each account that should hold them: the rules key (Ed25519, signs the rules)
to Admins, the backups key (X25519, for passwords kept in config backups) to roles allowed "unmasked". The recovery key counts as
an Admin. A wrap goes only to a box key the rules vouch for ("attested"): whoever holds the rules key and made a box key (a new
account, a password reset, a new recovery key) vouches for it; a Part 1 account that adds its own box key later is vouched for
when it is first seen. Rules that don't check out give everyone a Tech's permissions until someone signed in with the recovery key
saves the roles again, under a new rules key.

Lock order: this module's lock, then datakey's. datakey's hooks (_accounts_changed, _landed) run under datakey's lock, so they
never take this one and never read the file again.
"""
import base64
import hashlib
import json
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from core import audit, datakey, db, dirpin, envelope, quiet, sqldb

ROLES = ("Admin", "Engineer", "Tech")
KINDS = ("rules", "backups")
LAST_ADMIN = "Toner needs at least one Admin."
REQUIRE_HELPER_ON = "Turn off \"Let group members sign in without approval\" first. It can't be on while security keys are required."


class NotHeld(ValueError):
    """A first approval whose started box key isn't held any more (Toner restarted since): start the account again."""
_PART2 = ("roles", "rules_pub", "rules_sig", "backups_pub", "grants", "recovery_grants", "attested", "recovery_attested",
          "directories")
# a directory's settings as stored (core/directory.py's Config): never a secret, which lives in the OS store or the vault
_DIRECTORY = {"id", "name", "kind", "servers", "port", "security", "ca_file", "base_dn", "netbios", "suffixes", "service_dn",
              "groups", "ous", "duo", "ca_sha256", "tls_pinned",
              "provider", "issuer", "client_id", "groups_claim", "id_claim", "group_names", "everyone"}
_DUO = {"on", "host", "ikey"}
_NOT_READY = ("no such table", "file is not a database")    # a first start signs in before the database is encrypted and set up

_lock = threading.RLock()
_held = {}           # kind -> the private role key this sign-in holds
_cache = None        # what the file says, verified: {"state", "roles", "accounts", "backups_pub", "doc"}
_rk = None           # the rules_key setting, read once
_sk = None           # some database keeps backup passwords under a backups key, looked at once (only while rules_key is empty)
_audited = False     # "roles were changed outside Toner" written this sign-in
_upgrade_due = False  # an Admin signed in to a Part 1 file: make the role keys once the database can be written
_own_box = False     # this sign-in's box key is the one its record shows (else it holds nothing and can't repair)
_root = False        # the recovery key, its own box key and the one last vouched for: the root of trust (repairs, re-keys)
_pending = None      # what this change signed: kept as rules_signed once the keys file has landed (datakey's `written` hook)
_was = None          # the role keys held before this change re-keyed: put back when its write fails
_callbacks = []


# ---------------------------------------------------------------- the file
def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _unb64(s):
    return base64.b64decode(s.encode("ascii"), validate=True)


def _public(kind, private):
    """The public half: Ed25519 for the rules key, X25519 for the backups key and box keys."""
    key = (Ed25519PrivateKey if kind == "rules" else X25519PrivateKey).from_private_bytes(private)
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _aad(kind, name):
    return b"toner-role-key:" + kind.encode("ascii") + b":" + (name or "").encode("utf-8")


def _directory(a):
    return a.get("kind") == "directory"


def _role(a):
    """The role whose permissions the account has: a directory account's from its current groups (not signed)."""
    if _directory(a):
        return a.get("groups_role") if a.get("groups_role") in ROLES else "Tech"
    return a.get("role", "Admin")


def _keys_role(a):
    """The role whose role keys the account is granted. A directory account's: the lower of the role an admin last approved and
    its groups' role now, so a demotion in the directory takes keys away at the next sync (None: not approved, or in no group)."""
    if not _directory(a):
        return a.get("role", "Admin")
    both = (a.get("approved_role"), a.get("groups_role"))
    return max(both, key=ROLES.index) if all(r in ROLES for r in both) else None


def _accounts(doc):
    return {n: _role(a) for n, a in doc["accounts"].items()}


def _admins(doc):
    return sum(_keys_role(a) == "Admin" for a in doc["accounts"].values())


def _attested(doc):
    """The vouched-for box keys by account name (kept in the file, made a dict here)."""
    att = doc.get("attested")
    doc["attested"] = att = att if isinstance(att, dict) else {}
    return att


def _signed(doc):
    """What the rules key signs. A directory account is in it once approved; its groups_role and online_at are not. The
    directories are in it once the file has them (so a file without any signs as Part 2 did), and so is rules_version, the count
    that rises with each signing (a file signed before it existed still verifies; the helper refuses an older file put back)."""
    att = doc.get("attested") or {}
    accounts = {}
    for n, a in doc["accounts"].items():
        if not _directory(a):
            accounts[n] = {"role": a.get("role", "Admin"), "box_pub": att.get(n)}
        elif a.get("approved_role") is not None:
            accounts[n] = {"approved_role": a["approved_role"], "box_pub": att.get(n), "directory": a.get("directory"),
                           "guid": a.get("guid")}
    body = {"roles": doc.get("roles"), "accounts": accounts, "recovery_box_pub": doc.get("recovery_attested"),
            "backups_pub": doc.get("backups_pub")}
    if "directories" in doc:
        body["directories"] = doc["directories"]
    if "rules_version" in doc:
        body["rules_version"] = doc["rules_version"]
    if "require_keys" in doc:                           # only while on: a copy that never used it signs as before
        body["require_keys"] = doc["require_keys"]
    return envelope.canonical(body)


def _sign(doc, signer=None):
    """Sign with the rules key held, or with `signer(payload) -> sig` (the helper service, which keeps the rules key) when given:
    its signature must verify under the file's rules_pub, else nothing is written."""
    global _pending
    att = _attested(doc)
    doc["attested"] = {n: att.get(n) for n in doc["accounts"]}
    doc["roles"] = _clean_roles(doc.get("roles"))
    payload, sig = _signed(doc), doc.get("rules_sig")
    pub = _public("rules", _held["rules"]) if signer is None else _unb64(doc["rules_pub"])
    # changed, a new key, or a file from before the count (its first signing since starts it, so an older file can't come back)
    if "rules_version" not in doc or not (isinstance(sig, str) and envelope.verify(pub, payload, sig)):
        v = doc.get("rules_version")
        doc["rules_version"] = (v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else 0) + 1
        payload = _signed(doc)
    if signer is None:
        doc["rules_sig"] = envelope.sign(_held["rules"], payload)
    else:
        doc["rules_sig"] = signer(payload)
        if not (isinstance(doc["rules_sig"], str) and envelope.verify(pub, payload, doc["rules_sig"])):
            raise ValueError("the rules weren't signed")
    _pending = payload.decode("utf-8")              # kept as rules_signed once the file has landed (_landed)


def _setting(key):
    """A setting; None while it can't be read: signed out, or the database not set up yet. Any other database error is raised:
    a passing lock must not make a signed file look tampered."""
    if datakey.is_open():
        try:
            return db.get_setting(key)
        except sqldb.sqlite3.Error as e:
            if not any(s in str(e) for s in _NOT_READY):
                raise
    return None


def _rules_key():
    global _rk
    if _rk is None:
        _rk = _setting("rules_key")
    return _rk


def _stored_signed():
    """The rules_signed setting as stored: the database keeps what was last signed, so a repair takes the box keys and
    backups_pub from there, not from the tampered file, and an older file put back doesn't match it. Read each time, past the
    database's short cache: another Toner (the command line, the service) may have signed since."""
    db._forget_settings()
    return _setting("rules_signed")


def _landed(ok):
    """datakey's hook after each change: once the keys file has landed, keep what it signed (when that is new); when the change
    failed, keep nothing and hold the role keys held before it. If keeping it raises, datakey puts the old file back and calls
    this again with False."""
    global _pending, _was, _cache
    _cache = None                                       # (a directory sign-in's own write may have changed a groups role)
    if not ok:
        if _was is not None:
            _held.clear()
            _held.update(_was)
    elif _pending is not None and _pending != _stored_signed():
        db.set_setting("rules_signed", _pending)
    _pending = _was = None


def _keep_held():
    """Before a change holds new role keys: note the ones held now, put back if its write fails."""
    global _was
    if _was is None:
        _was = dict(_held)


def last_signed():
    """What was last signed (parsed), as the encrypted database keeps it, or None when there is none or it can't be read."""
    rs = _stored_signed()
    try:
        last = json.loads(rs) if rs else None
        return last if isinstance(last.get("accounts"), dict) and isinstance(last.get("backups_pub"), str) else None
    except (ValueError, AttributeError):
        return None


def _secrets_kept():
    """A Part 2 database under a Part 1 keys file: its backups already went behind a backups key that file never had."""
    global _sk
    if _sk is None:
        from core import backupsplit
        _sk = backupsplit.secrets_kept()
    return _sk


def _verifies(doc, pub):
    try:
        return envelope.fingerprint(pub) == _rules_key() and envelope.verify(pub, _signed(doc), doc["rules_sig"])
    except (KeyError, TypeError, ValueError, AttributeError):    # a field missing or mangled
        return False


def _state_of(doc):
    if not _rules_key():                                # only a Part 1 file is unsigned; anything of Part 2's without the key is not
        later = any(k in doc for k in _PART2) or any(_directory(a) for a in doc["accounts"].values())
        return "tampered" if later or (_rules_key() == "" and _secrets_kept()) else "unsigned"
    try:
        pub = _unb64(doc["rules_pub"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return "tampered"
    if not _verifies(doc, pub):
        return "tampered"
    last = _stored_signed()                             # signed by the same key, but not what was signed last: an older file put back
    return "tampered" if last and last != _signed(doc).decode("utf-8") else "ok"


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
        if _upgrade_due and _rules_key() == "" and not _secrets_kept():    # the database is ready now (read before datakey's lock)
            _upgrade()
        try:
            doc = datakey.read()
            st = _state_of(doc)
        except (OSError, ValueError):                   # unreadable now: trust none of it
            doc, st = None, "tampered"
        c = {"state": st}
        if st == "ok":
            c.update(roles=doc.get("roles"), accounts=_accounts(doc), backups_pub=_unb64(doc["backups_pub"]), doc=doc)
        if st == "tampered" and datakey.is_open() and not _audited:
            _audited = audit.log("roles were changed outside Toner", who=datakey.signed_in_name())
        if _rules_key() is not None:                    # else look again next time: the database may be ready by then
            _cache = c
        return c


def _invalidate():
    global _cache, _rk, _sk
    _cache = _rk = _sk = None


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


def verified():
    """The keys doc whose rules checked out ("ok"), as it was checked; else None."""
    return _load().get("doc")


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


def stored_permissions(role):
    """What the file stores for Engineer or Tech (defaults filling the gaps), even while tampered: what a repair would sign."""
    try:
        return _perms_in(datakey.read().get("roles"), role)
    except (OSError, ValueError):
        return _perms_in(None, role)


def holds(kind):
    return kind in _held


def hold(kind, private):
    """An approval by the helper service: hold the role key it released (ValueError unless it is the one the rules are about).
    The approval's close() lets go of it."""
    with _lock:
        try:
            mine = _take(datakey.read(), kind, private)
        except (TypeError, ValueError):                 # not a key of that kind at all
            mine = False
        if not mine:
            raise ValueError("not this copy's role key")
        _held[kind] = private


def backups_public():
    """The backups key to encrypt to, or None while the rules don't check out."""
    return _load().get("backups_pub")


def backups_private():
    return _held.get("backups")


def on_change(fn):
    """`fn()` after the rules change. It may run on a worker thread (the directory check): one that touches widgets queues."""
    _callbacks.append(fn)


def off_change(fn):
    """Stop telling `fn` (a window that goes at Sign out)."""
    if fn in _callbacks:
        _callbacks.remove(fn)


def groups_changed():
    """After the directory check wrote the signed-in account's groups role: let go of role keys it no longer allows, then tell
    the listeners."""
    with _lock:
        _trim()
    _notify()


# ---------------------------------------------------------------- grants
def _sync(doc, signer=None):
    """Wrap each role key held to every vouched-for box key that should have it (the recovery key's too), drop grants that no
    longer apply, and sign. A box key nobody has vouched for yet (a Part 1 account that added its own since) is vouched for now;
    one that differs from what was vouched for gets nothing until an Admin resets that password. The caller holds the rules key
    and has checked the rules."""
    att = _attested(doc)
    old = doc.get("grants") if isinstance(doc.get("grants"), dict) else {}
    grants = {}
    for name, rec in doc["accounts"].items():
        live = rec.get("box_pub")
        if live and att.get(name) is None and not _directory(rec):    # (a directory account's is vouched for by approve alone)
            att[name] = live
        if not live or att.get(name) != live:           # a Part 1 account not upgraded yet, or a box key swapped in by hand
            continue
        role = _keys_role(rec)
        if role not in ROLES:                           # a directory account not approved yet
            continue
        want = {"rules": role == "Admin", "backups": _perms_in(doc.get("roles"), role)["unmasked"]}
        mine = old.get(name) if isinstance(old.get(name), dict) else {}
        g = {k: v for k, v in mine.items() if want.get(k)}
        for kind in KINDS:
            if want[kind] and kind not in g and kind in _held:
                g[kind] = envelope.wrap(_unb64(live), _held[kind], _aad(kind, name))
        if g:
            grants[name] = g
    doc["grants"] = grants
    live = doc["recovery"].get("box_pub")
    if live and doc.get("recovery_attested") is None:
        doc["recovery_attested"] = live
    old = doc.get("recovery_grants") if isinstance(doc.get("recovery_grants"), dict) else {}
    rg = {}
    if live and doc["recovery_attested"] == live:
        rg = {k: v for k, v in old.items() if k in KINDS}
        for kind in KINDS:
            if kind not in rg and kind in _held:
                rg[kind] = envelope.wrap(_unb64(live), _held[kind], _aad(kind, None))
    doc["recovery_grants"] = rg
    _sign(doc, signer)


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
    from core import perms
    me, holder, root = datakey.signed_in_name(), "rules" in _held, _root
    rekeyed = [n for n, a in doc["accounts"].items() if before["accounts"].get(n, {}).get("box_pub") != a.get("box_pub")]
    recovery = before["recovery"].get("box_pub") != doc["recovery"].get("box_pub")
    st = _state_of(before)
    ok = st == "ok"
    gone = [n for n in before["accounts"] if n not in doc["accounts"]]
    if st not in ("ok", "unsigned") and not root and ([n for n in rekeyed if n != me] or gone or recovery):
        raise perms.Denied()                            # rules that don't check out: only the recovery key, or your own password
    if ok and not holder and not root and ([n for n in rekeyed if n != me] or (recovery and me is not None)):
        raise perms.Denied()                            # only whoever holds the rules key may give someone else a box key
    grants = doc.get("grants")
    if isinstance(grants, dict):                        # a wrap to a box key that's gone can't be opened again
        for n in list(grants):
            if n not in doc["accounts"] or n in rekeyed:
                del grants[n]
    if recovery:
        doc.pop("recovery_grants", None)
    if _admins(before) and not _admins(doc):
        raise ValueError(LAST_ADMIN)
    done = None
    repair = root and recovery and st not in ("ok", "unsigned")     # else its new key isn't the root at its next sign-in
    if ok or repair:                                    # never re-sign rules that didn't check out: that would hide the edit
        if repair or not holder and root:               # e.g. a Part 1 recovery key resetting the only Admin's password
            pub = _rekey(doc)
            doc["recovery_attested"] = doc["recovery"].get("box_pub")
            holder, done = True, lambda: _written(pub)
        if holder:                                      # it made these box keys, so it vouches for them
            att = _attested(doc)
            for n in rekeyed:
                att[n] = doc["accounts"][n].get("box_pub")
            if recovery:
                doc["recovery_attested"] = doc["recovery"].get("box_pub")
            _sync(doc)
        elif _signed(before) != _signed(doc):
            raise datakey.Locked("Sign in first.")
    _cache = None
    return done


# ---------------------------------------------------------------- sign-in and sign-out
def _trim():
    """Let go of role keys the signed-in person's role no longer allows (their grants are already gone)."""
    role = role_of(datakey.signed_in_name())
    if role != "Admin":
        _held.pop("rules", None)
    if not permissions(role)["unmasked"]:
        _held.pop("backups", None)


def _field(doc, field):
    """A public key the file holds, or None when it is missing or mangled."""
    try:
        return _unb64(doc[field])
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def _take(doc, kind, key):
    """True when `key` is the role key the rules are about. The rules key: its fingerprint is rules_key. The backups key: with
    it as backups_pub (the file's, or put back where it was swapped) the rules verify, under whichever rules_pub (the file's, or
    the one of the rules key held) has rules_key's fingerprint."""
    pub = _public(kind, key)
    rk = _rules_key()
    if kind == "rules":
        return envelope.fingerprint(pub) == rk if rk else pub == _field(doc, "rules_pub")
    rules = [p for p in (_field(doc, "rules_pub"), "rules" in _held and _public("rules", _held["rules"])) if p]
    return any(_verifies({**doc, "backups_pub": _b64(pub)}, p) for p in rules)


def unlock():
    """After a sign-in: take this account's role keys. On a Part 1 file, whoever signs in first (everyone is an Admin) makes the
    role keys. A tampered file or a missing grant is not an error: this sign-in just holds less."""
    global _audited, _upgrade_due, _own_box, _root
    with _lock:
        _held.clear()
        _invalidate()
        _audited = _upgrade_due = False
        name, box = datakey.signed_in_name(), datakey.box_private()
        _rules_key()                                    # read the settings before taking datakey's lock
        last = last_signed()
        doc = datakey.read()
        rec = doc["recovery"] if name is None else doc["accounts"][name]
        _own_box = box is not None and rec.get("box_pub") == _b64(_public("box", box))
        st = _state_of(doc)
        # the recovery key last vouched for (none vouched for yet: a Part 1 one, trusted on first use)
        att = last.get("recovery_box_pub") if last else doc.get("recovery_attested") if st == "ok" else None
        _root = name is None and _own_box and (att is None or att == rec.get("box_pub"))
        for kind in KINDS if _own_box else ():         # rules first: the backups check may need it
            try:
                g = doc["recovery_grants"] if name is None else doc["grants"][name]
                key = envelope.unwrap(box, g[kind], _aad(kind, name))
                if _take(doc, kind, key):               # a grant of some other key is no grant
                    _held[kind] = key
            except (KeyError, TypeError, ValueError, AttributeError, InvalidTag):
                pass                                    # no grant yet, or one that doesn't open
        if st == "unsigned" and (name is None or _keys_role(rec) == "Admin"):
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
    _keep_held()
    _held.update(rules=rules, backups=backups)

    def go(doc):
        if _state_of(doc) != "unsigned":                # someone else got there first
            return False
        doc.update(roles={"Engineer": {}, "Tech": {}}, rules_pub=_b64(rules_pub), backups_pub=_b64(backups_pub),
                   attested={n: a.get("box_pub") for n, a in doc["accounts"].items()},
                   recovery_attested=doc["recovery"].get("box_pub"))
        _sync(doc)
        return True
    if datakey.edit(go):
        # shortcut: a crash between the file and the setting leaves the file "tampered"; the recovery key's repair puts it right.
        db.set_setting("rules_key", envelope.fingerprint(rules_pub))
    else:
        _held.clear()
    _invalidate()


def close():
    global _audited, _upgrade_due, _own_box, _root
    with _lock:
        _held.clear()
        _invalidate()
        _audited = _upgrade_due = _own_box = _root = False


# ---------------------------------------------------------------- changing the rules
def _may_write(doc):
    """True when this change re-keys: the recovery key (the root of trust) repairing a tampered file, or changing a good one
    while it holds no rules key (a Part 1 one). False for whoever holds the rules key on a good file; raises for anyone else."""
    from core import perms
    st = _state_of(doc)
    if (st == "tampered" or (st == "ok" and "rules" not in _held)) and _root:
        return True
    if st == "tampered":
        raise perms.Denied()                            # everyone is a Tech until the recovery key puts it right
    if st != "ok" or "rules" not in _held:
        raise datakey.Locked("Sign in first.")
    return False


def _rekey(doc):
    """The recovery key's re-key (its repair of a tampered file, or its first change while it holds no rules key): a new rules
    key, with the box keys and backups_pub taken from what was last signed, not from the file. Returns the new public half.
    The new key is held at once; a failed write puts back the keys held before (_landed)."""
    _keep_held()
    _held["rules"], pub = envelope.new_signing_key()
    doc["rules_pub"] = _b64(pub)
    grants = doc.get("grants") if isinstance(doc.get("grants"), dict) else {}
    rg = doc.get("recovery_grants") if isinstance(doc.get("recovery_grants"), dict) else {}
    last = last_signed()
    if last:                                            # the box keys and backups_pub vouched for last, not the file's
        old = last["accounts"]                          # (an account it never had: "", which first use never vouches for)
        doc["attested"] = {n: (old[n] or {}).get("box_pub") if n in old else "" for n in doc["accounts"]}
        doc["recovery_attested"] = last.get("recovery_box_pub")
        doc["backups_pub"] = last["backups_pub"]
        if "backups" in _held and _b64(_public("backups", _held["backups"])) != last["backups_pub"]:
            del _held["backups"]
    kept = [g for g in grants.values() if isinstance(g, dict) and "backups" in g] + (["backups"] if "backups" in rg else [])
    if "backups" not in _held and not kept:             # nobody holds the backups key any more: a new one loses nothing
        _held["backups"] = envelope.new_box_key()[0]
    if "backups" in _held:                              # held and vouched for (unlock): it goes back in, and it alone is wrapped
        doc["backups_pub"] = _b64(_public("backups", _held["backups"]))
        doc["grants"], doc["recovery_grants"] = {}, {}
    else:                                               # its wraps kept rather than lost (shortcut: unvouched without `last`)
        doc["grants"] = {n: {"backups": g["backups"]} for n, g in grants.items() if isinstance(g, dict) and "backups" in g}
        doc["recovery_grants"] = {"backups": rg["backups"]} if "backups" in rg else {}
    if not last:
        doc["recovery_attested"] = doc["recovery"]["box_pub"]      # the recovery key showed it is this one (unlock)
    return pub


def _resign(doc, repair):
    """Sign the rules and sync the grants; the recovery key's re-key first, returning the new rules key's public half."""
    pub = _rekey(doc) if repair else None
    _sync(doc)
    return pub


def _written(pub):
    if pub is not None:
        was = db.get_setting("rules_key")
        db.set_setting("rules_key", envelope.fingerprint(pub))
        if was != envelope.fingerprint(pub):
            _helper_follows(rekeyed=True)
    _invalidate()


def _helper_follows(rekeyed=False):
    """Best effort, after a change has landed: the helper service's spare copy pins the rules key, so a new one turns sign-in
    without approval off (state() sees the new key as rules_changed and does it); otherwise, while it is on, it is enrolled again
    so it has the Duo keys as they are now."""
    from core import helperclient
    try:
        st = helperclient.state(datakey.path())
        if st == "on" and rekeyed:                      # (the helper didn't see the new key: turn it off all the same)
            helperclient.rules_replaced()
        elif st == "on":
            helperclient.enroll()
    except Exception:                                   # no helper, or one that says no: nothing of the change is undone
        quiet.ignored()


def set_role(name, role):
    if role not in ROLES:
        raise ValueError("unknown role")
    with _lock:
        def go(doc):
            repair = _may_write(doc)
            stored = datakey._stored(doc, name)
            if _directory(doc["accounts"][stored]):
                raise ValueError("a directory account's role comes from its groups")
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


def require_keys():
    """Every local, AD and LDAP account must have a security key: from the verified rules."""
    return (verified() or {}).get("require_keys") is True


def must_add_key():
    """The signed-in account is sent to add a key before anything else opens: keys are required, it may have them (local, AD
    or LDAP; never SSO or the recovery key) and it has none."""
    from core import dirsignin                          # (dirsignin imports this module)
    name = datakey.signed_in_name()
    return name is not None and require_keys() and dirsignin.keys_allowed(name) and not datakey.my_keys()


def set_require_keys(on):
    """An Admin's switch, signed with the rules. Refused while sign-in without approval is on (the helper is a way round a key)."""
    from core import helperclient
    if on and helperclient.state(datakey.path(), ask_service=False) == "on":
        raise ValueError(REQUIRE_HELPER_ON)
    with _lock:
        def go(doc):
            repair = _may_write(doc)
            was = doc.get("require_keys") is True
            if on:
                doc["require_keys"] = True
            else:
                doc.pop("require_keys", None)
            return was, _resign(doc, repair)
        was, pub = datakey.edit(go)
        _written(pub)
        if was != bool(on):
            audit.log(f"security keys required turned {'on' if on else 'off'}", f"by {audit.actor()}")
        _trim()
    _notify()


# ---------------------------------------------------------------- directories and their accounts
def needs_approval(name):
    """"first" (no seal yet), "changed" (the groups' role may hold a role key the approved one may not: Admin, or unmasked) or
    None. Read from the file as it stands, since it is asked before the key is open."""
    doc = datakey.read()
    stored = datakey._find(doc, name)
    rec = doc["accounts"][stored] if stored else None
    if rec is not None and not _directory(rec):
        return None
    if rec is None or not rec.get("sealed"):
        return "first"
    now, was = rec.get("groups_role"), rec.get("approved_role")

    def unmasked(role):
        return role in ROLES and _perms_in(doc.get("roles"), role)["unmasked"]
    return "changed" if (now == "Admin" and was != "Admin") or (unmasked(now) and not unmasked(was)) else None


def approve(name, slot=None, approved_by=None, signer=None):
    """An Admin (who holds the rules key) or the recovery key approves a directory account: its approved role becomes its groups'
    role, and the role keys follow.
      first approval    `slot` is the one start_directory_account wrote: seals the data key and the box private held since then
                        under it, and vouches for that box key.
      new slot          (an approved account's new PIN, or another computer) `slot` is a new one: a new box key, vouched for and
                        sealed with the data key under it; the old slot is removed from this computer.
      no slot           (an approved account whose groups changed) keeps the seal.
    approved_by names the approver in the audit (default: whoever is signed in). `signer(payload) -> sig`: the rules are signed
    by it instead of a held rules key (the helper service's approval of a non-Admin), and only on rules that check out."""
    from core import perms
    with _lock:
        if signer is None and not _root and "rules" not in _held:
            raise perms.Denied()

        def go(doc):
            if signer is not None and _state_of(doc) != "ok":
                raise datakey.Locked("Sign in first.")
            repair = _may_write(doc) if signer is None else False
            stored = datakey._stored(doc, name)
            rec = doc["accounts"][stored]
            if not _directory(rec) or rec.get("groups_role") not in ROLES:
                raise ValueError("only a directory account in a Toner group can be approved")
            first, old = not rec.get("sealed"), None
            if first:
                if slot is None or slot.rec != rec.get("slot") or slot.slot_id != rec.get("slot_id"):
                    raise ValueError("that isn't the account's PIN slot")
                private = datakey._started.get(rec["slot_id"])
                if private is None or _b64(_public("box", private)) != rec.get("box_pub"):
                    raise NotHeld("start the account again: its box key isn't held")
            elif slot is not None:
                datakey._fresh_slot(doc, slot)
                old = dict(rec)
                private, public = envelope.new_box_key()
                rec.update(slot_kind=slot.rec["kind"], slot=slot.rec, slot_id=slot.slot_id, box_pub=_b64(public))
                if isinstance(doc.get("grants"), dict):
                    doc["grants"].pop(stored, None)     # wrapped to the old box key
            if slot is not None:
                rec["sealed"] = slot.seal(datakey.seal_payload(stored, private))
                rec.pop("keyed", None)                  # a new seal holds no security keys
                rec.pop("keys_n", None)
                rec.pop("slot_gone", None)              # (clear_keys' mark)
            had = _admins(doc)
            rec["approved_role"] = rec["groups_role"]
            if had and not _admins(doc):
                raise ValueError(LAST_ADMIN)
            pub = _rekey(doc) if repair else None
            if slot is not None:
                _attested(doc)[stored] = rec["box_pub"]   # the approver saw this box key made (at start, or just now)
            _sync(doc, signer)
            return stored, rec["slot_id"], old, pub
        stored, slot_id, old, pub = datakey.edit(go)
        _written(pub)
        datakey._started.pop(slot_id, None)
        datakey.drop_slot(old)
        admin = approved_by or datakey.signed_in_name() or audit.actor()
        audit.log("sign-in approved", f"{stored}, approved by {admin}", who=admin)
        _trim()
    _notify()


def set_directories(directories, edited=None):
    """Admin only. Replaces the directories, signed. Removing one removes its accounts, and their PIN slots on this computer.
    Only the directory being saved (id `edited`, or one the verified list doesn't have yet) has its CA file read and hashed; every
    other keeps the hash signed before, so a CA file swapped since stays refused until an admin saves that directory again. Any
    other directory's CA file path can't change here."""
    from core import directory
    signed = {d.get("id"): d for d in (verified() or {}).get("directories") or [] if isinstance(d, dict)}
    new = {}
    for d in directories:
        if not d.get("id") or set(d) - _DIRECTORY or set(d.get("duo") or {}) - _DUO:
            raise ValueError("unknown directory setting")
        directory.check_config(d)                       # TLS only (InsecureConfig is a ValueError)
        c = new[d["id"]] = json.loads(json.dumps(d))   # a copy, as the file will hold it (tuples as lists)
        c.pop("ca_sha256", None)
        for field in ("groups", "ous"):                 # {role: [DN, ...]}; role_for would read a bare string as its letters
            m = c.get(field, {})
            if not isinstance(m, dict) or set(m) - set(ROLES) or not all(
                    isinstance(v, list) and all(isinstance(x, str) for x in v) for v in m.values()):
                raise ValueError(f"bad {field} map")
        was = signed.get(c["id"]) if c["id"] != edited else None
        if was is not None:
            if (c.get("ca_file") or "") != (was.get("ca_file") or ""):
                raise ValueError("only the directory being saved can change its CA file")
            if was.get("ca_sha256"):
                c["ca_sha256"] = was["ca_sha256"]
        elif c.get("ca_file"):                          # signed with the list: connect refuses a CA file changed since
            try:
                with open(c["ca_file"], "rb") as f:
                    c["ca_sha256"] = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                raise ValueError("the CA file can't be read") from None
    if len(new) != len(directories):
        raise ValueError("two directories have one id")
    for field in ("netbios", "suffixes"):              # classify must find one directory for a name, never two
        seen = [str(v).casefold() for d in new.values() for v in ([d.get(field)] if field == "netbios" else d.get(field) or [])
                if v]
        if len(seen) != len(set(seen)):
            raise ValueError(f"two directories share a {field} name")
    with _lock:
        def go(doc):
            repair = _may_write(doc)
            old = {d.get("id"): d for d in doc.get("directories") or []}
            doc["directories"] = list(new.values())
            had = _admins(doc)
            gone = [n for n, a in doc["accounts"].items() if _directory(a) and a.get("directory") not in new]
            dropped = [doc["accounts"].pop(n) for n in gone]
            if had and not _admins(doc):
                raise ValueError(LAST_ADMIN)
            return old, dropped, _resign(doc, repair), doc
        old, dropped, pub, wrote = datakey.edit(go)
        _written(pub)
        if pub is None:
            _helper_follows()                           # (Set up 2FA saves through here: a new Duo key reaches the helper)
        dirpin.remember(wrote)                          # signed and landed: this computer's remembered list follows
        for i, d in new.items():
            if i not in old:
                audit.log("directory added", d.get("name", ""))
            elif old[i] != d:
                audit.log("directory changed", d.get("name", ""))
        for i, d in old.items():
            if i not in new:
                audit.log("directory removed", d.get("name", ""))
        for rec in dropped:
            datakey.drop_slot(rec)
        _trim()
    _notify()


datakey.accounts_changed = _accounts_changed
datakey.written = _landed
