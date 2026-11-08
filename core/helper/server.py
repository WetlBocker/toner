"""The helper's checks. It never takes Toner's word: it hands out the spare keys only for a ticket it issued after checking a
sign-in itself (an SSO answer with a nonce it issued, or a directory password plus Duo), against connection settings read only
from the admin-signed rules in the enrolled copy's netcheck.keys, verified with the rules key pinned at enrollment.

`peer` is the caller's SID or uid, given by the transport. Nonces, tickets, pending Duo checks and the failure counts live in
memory only. No answer carries a password, token, code or key, except release's keys. No Qt, and no database is opened."""
import base64
import json
import math
import os
import secrets
import threading
import time

import jwt

from core import directory, duo, envelope, oidc, roles
from core.helper.protocol import PROTOCOL
from core.version import VERSION

TTL = 600                                               # seconds a nonce, a ticket or a pending Duo check lives
FREE_TRIES, FIRST_WAIT, MAX_WAIT = 5, 30, 900           # as datakey's: 5 free failures, then 30 s doubling to 15 min
_KEEP = 100                                             # most nonces (tickets, pending) outstanding at once; the oldest goes
_COUNTED = {"not_owner", "other_user", "refused", "not_fresh", "bad_answer", "not_in_group"}
_FIELDS = {"status": ("keys_path",), "enroll": ("keys_path", "data_key", "rules_private"), "forget": ("keys_path",),
           "nonce": ("keys_path", "connection"), "check_sso": ("keys_path", "connection", "id_token", "access_token"),
           "check_directory": ("keys_path", "connection", "login", "password"), "duo_push": ("pending",),
           "duo_code": ("pending", "code"), "release": ("keys_path", "ticket", "name")}
_CODES = {oidc.Unreachable: "unreachable", oidc.Refused: "refused", oidc.NotFresh: "not_fresh", oidc.BadAnswer: "bad_answer",
          directory.Unreachable: "unreachable", directory.BadCredentials: "refused", directory.InsecureConfig: "refused",
          duo.Unavailable: "unreachable", duo.Denied: "refused"}


class _No(Exception):
    """The answer {"ok": False, "error": code}; `count` says whether it counts as a failure against the peer."""

    def __init__(self, code, count=None):
        super().__init__(code)
        self.code, self.count = code, code in _COUNTED if count is None else count


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _unb64(s):
    return base64.b64decode(s.encode("ascii"), validate=True)


def _path(p):
    try:
        return os.path.normcase(os.path.abspath(p))
    except ValueError:                                  # a NUL in it: matches no path
        return None


def _verified(path, rules_pub):
    """The keys doc at `path` when its rules_pub is `rules_pub` (b64) and the signed part verifies under it; else None."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        if doc["rules_pub"] == rules_pub and envelope.verify(_unb64(rules_pub), roles._signed(doc), doc["rules_sig"]):
            return doc
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):     # missing, unreadable or mangled
        pass
    return None


def _who(user, role):
    return {"name": user.name, "role": role, "guid": user.guid, "display": user.display}


class Helper:
    def __init__(self, store, now=time.time):
        self.store, self.now = store, now
        self._lock = threading.Lock()
        self._fails = {}                                # peer -> [failures, waiting until]
        self._reset()

    def _reset(self):
        self._nonces, self._tickets, self._pending = {}, {}, {}     # key -> (expires, ...)

    # ------------------------------------------------------------ the request
    def handle(self, req, peer, cancel=None):
        """The answer to one request from `peer`. `cancel` is set by the transport when the client goes (it stops a Duo push)."""
        op = req.get("op")
        need = _FIELDS.get(op)
        if need is None or not all(isinstance(req.get(k), str) for k in need) or (op != "status" and req.get("v") != PROTOCOL):
            return {"ok": False, "error": "bad_request"}
        if op == "status":
            return self._status(req, peer)
        wait = self._gate(peer)
        if wait:
            return {"ok": False, "error": "throttled", "wait": wait}
        try:
            try:
                if op == "enroll":
                    return {"ok": True, **self._enroll(req, peer)}
                rec = self._load()
                if rec is None:
                    raise _No("not_enrolled")
                if peer != rec["owner"] or (op not in ("duo_push", "duo_code") and _path(req["keys_path"]) != rec["keys_path"]):
                    raise _No("not_owner")
                return {"ok": True, **getattr(self, "_" + op)(req, rec, cancel or threading.Event())}
            except tuple(_CODES) as e:
                raise _No(next(c for t, c in _CODES.items() if isinstance(e, t))) from None
        except _No as e:
            wait = self._failed(peer) if e.count else 0
            return {"ok": False, "error": "throttled", "wait": wait} if wait else {"ok": False, "error": e.code}

    def _load(self):
        try:
            return self.store.load()
        except (OSError, ValueError, KeyError, TypeError, AttributeError):     # unreadable: as if not enrolled
            return None

    # ------------------------------------------------------------ failures, and what is kept in memory
    def _gate(self, peer):
        """Seconds the peer still waits (0: none)."""
        with self._lock:
            c = self._fails.get(peer)
            if not c:
                return 0
            now = self.now()
            c[1] = min(c[1], now + MAX_WAIT)            # a clock put back doesn't stretch a wait
            return math.ceil(c[1] - now) if c[1] > now else 0

    def _failed(self, peer):
        """Counts a failure; the wait it starts (0 while still free)."""
        with self._lock:
            c = self._fails.setdefault(peer, [0, 0])
            c[0] += 1
            over = c[0] - FREE_TRIES
            if over <= 0:
                return 0
            wait = min(FIRST_WAIT * 2 ** min(over - 1, 5), MAX_WAIT)
            c[1] = self.now() + wait
            return wait

    def _put(self, kept, *value):
        key = secrets.token_urlsafe(32)
        with self._lock:
            now = self.now()
            for k in [k for k, v in kept.items() if v[0] < now]:
                del kept[k]
            while len(kept) >= _KEEP:
                del kept[next(iter(kept))]
            kept[key] = (now + TTL, *value)
        return key

    def _take(self, kept, key, keep=False):
        """The value kept under `key` (removed unless `keep`), or None when there is none or it has expired."""
        with self._lock:
            v = kept.get(key) if keep else kept.pop(key, None)
        return v[1:] if v and self.now() <= v[0] else None

    def _ticket(self, rec, name, role):
        with self._lock:
            self._fails.pop(rec["owner"], None)        # a checked sign-in clears the count, as a password does in Toner
        return self._put(self._tickets, name, role)

    # ------------------------------------------------------------ the signed rules
    def _cfg(self, rec, connection, sso):
        """The connection's settings from the rules signed with the pinned key (rules_changed when they don't verify)."""
        doc = _verified(rec["keys_path"], rec["rules_pub"])
        if doc is None:
            raise _No("rules_changed")
        for d in doc.get("directories") or []:
            if isinstance(d, dict) and d.get("id") == connection and (d.get("kind") == "oidc") == sso:
                return d
        raise _No("bad_request")

    def _skey(self, rec, connection):
        skey = rec["duo"].get(connection)
        if skey is None:                                # Duo turned on since enrollment: Toner enrolls again
            raise _No("unreachable")
        return skey

    # ------------------------------------------------------------ the ops
    def _status(self, req, peer):
        rec = self._load()
        owner = rec is not None and peer == rec["owner"] and _path(req["keys_path"]) == rec["keys_path"]
        changed = owner and _verified(rec["keys_path"], rec["rules_pub"]) is None
        return {"ok": True, "protocol": PROTOCOL, "version": VERSION, "enrolled": rec is not None, "owner": owner,
                "rules_changed": changed}

    def _enroll(self, req, peer):
        duo_keys = req.get("duo") or {}
        if not isinstance(duo_keys, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in duo_keys.items()):
            raise _No("bad_request")
        try:
            data_key, rules_private = _unb64(req["data_key"]), _unb64(req["rules_private"])
            duo_keys = {k: _unb64(v) for k, v in duo_keys.items()}
            rules_pub = _b64(roles._public("rules", rules_private))
        except ValueError:
            raise _No("bad_request") from None
        if len(data_key) != 32:
            raise _No("bad_request")
        path = _path(req["keys_path"])
        with self._lock:                                # two peers enrolling at once: one wins, the other is other_user
            rec = self._load()
            if rec is not None and rec["owner"] != peer:
                raise _No("other_user")
            if _verified(path, rules_pub) is None:      # not this copy's rules key, or rules it didn't sign
                raise _No("refused")
            self.store.save({"owner": peer, "keys_path": path, "rules_pub": rules_pub, "spare": data_key + rules_private,
                             "duo": duo_keys, "enrolled_at": self.now()})
            self._reset()
        return {}

    def _forget(self, req, rec, cancel):
        with self._lock:
            self.store.clear()
            self._reset()
        return {}

    def _nonce(self, req, rec, cancel):
        return {"nonce": self._put(self._nonces, req["connection"])}

    def _check_sso(self, req, rec, cancel):
        cfg = self._cfg(rec, req["connection"], sso=True)
        try:
            nonce = jwt.decode(req["id_token"], options={"verify_signature": False}).get("nonce")
        except jwt.PyJWTError:
            raise _No("bad_answer") from None
        # used up here, whatever follows: a nonce this helper issued for this connection, once
        if not isinstance(nonce, str) or self._take(self._nonces, nonce) != (req["connection"],):
            raise _No("bad_answer")
        claims = oidc.verify_id_token(cfg, req["id_token"], nonce, max_age=300, now=self.now())
        try:
            user = oidc.user_from(cfg, claims, oidc.groups(cfg, claims, req["access_token"]))
        except KeyError:                                # the ID token names no one
            raise _No("bad_answer") from None
        role = directory.role_for(cfg, user.groups)
        if role is None:
            raise _No("not_in_group")
        return {**_who(user, role), "ticket": self._ticket(rec, user.name, role)}

    def _check_directory(self, req, rec, cancel):
        cfg = self._cfg(rec, req["connection"], sso=False)
        user = directory.sign_in(cfg, req["login"], req["password"])
        if not user.enabled:
            raise _No("refused")
        role = directory.role_for(cfg, user.groups, user.dn)
        if role is None:
            raise _No("not_in_group")
        who = _who(user, role)
        if not (cfg.get("duo") or {}).get("on"):
            return {**who, "ticket": self._ticket(rec, user.name, role)}
        r = duo.preauth(cfg, user.name, skey=self._skey(rec, cfg["id"]))
        if r == "allow":                                # Duo's bypass, set by its admin
            return {**who, "ticket": self._ticket(rec, user.name, role)}
        if r != "auth":
            raise _No("refused")
        return {**who, "duo": "auth", "pending": self._put(self._pending, cfg["id"], user.name, role)}

    def _duo(self, req, rec, check):
        """A pending Duo check: `check(cfg, name, skey)` passes or raises; then the pending check is used up for a ticket."""
        pending = self._take(self._pending, req["pending"], keep=True)
        if pending is None:
            raise _No("refused")
        connection, name, role = pending
        cfg = self._cfg(rec, connection, sso=False)
        check(cfg, name, self._skey(rec, connection))
        if self._take(self._pending, req["pending"]) is None:      # another request used it meanwhile
            raise _No("refused")
        return {"ticket": self._ticket(rec, name, role)}

    def _duo_push(self, req, rec, cancel):
        def push(cfg, name, skey):
            try:
                duo.push(cfg, name, cancel, skey=skey)
            except duo.Denied:
                raise _No("refused", count=not cancel.is_set()) from None     # the client went: no failure of the person's
        return self._duo(req, rec, push)

    def _duo_code(self, req, rec, cancel):
        return self._duo(req, rec, lambda cfg, name, skey: duo.passcode(cfg, name, req["code"], skey=skey))

    def _release(self, req, rec, cancel):
        if _verified(rec["keys_path"], rec["rules_pub"]) is None:
            raise _No("rules_changed")
        ticket = self._take(self._tickets, req["ticket"])
        if ticket is None or ticket[0] != req["name"]:
            raise _No("refused")
        spare = rec["spare"]                            # the data key, then the 32-byte Ed25519 rules private key
        return {"data_key": _b64(spare[:-32]), "rules_private": _b64(spare[-32:]), "role": ticket[1]}
