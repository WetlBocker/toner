"""The helper's checks. It never takes Toner's word: it hands out the spare keys only for a ticket it issued after checking a
sign-in itself (an SSO answer with a nonce it issued, or a directory password plus Duo), against connection settings read only
from the admin-signed rules in the enrolled copy's netcheck.keys, verified with the rules key pinned at enrollment.

`peer` is the caller's SID or uid, given by the transport. Nonces, tickets, pending Duo checks and the failure counts live in
memory only. No answer carries a password, token, code or key, except release's keys. No Qt, and no database is opened.
serve_channel is the connection loop that core/helper/windows.py and linux.py run on their own channel."""
import base64
import json
import logging
import math
import os
import re
import secrets
import stat
import threading
import time

import jwt

from core import directory, duo, envelope, oidc, roles
from core.helper.protocol import MAX, PROTOCOL, decode, encode
from core.version import VERSION

TTL = 600                                               # seconds a ticket or a pending Duo check lives
NONCE_TTL = 300                                         # a nonce: the sign-in it asks for must start after it was issued
MAX_KEYS = 1 << 20                                      # the most of a keys file read
FREE_TRIES, FIRST_WAIT, MAX_WAIT = 5, 30, 900           # as datakey's: 5 free failures, then 30 s doubling to 15 min
_KEEP = 100                                             # most nonces (tickets, pending) outstanding at once; the oldest goes
_COUNTED = {"not_owner", "other_user", "refused", "not_fresh", "bad_answer", "not_in_group"}
_FIELDS = {"status": ("keys_path",), "enroll": ("keys_path", "data_key", "rules_private"), "forget": ("keys_path",),
           "nonce": ("keys_path", "connection"), "check_sso": ("keys_path", "connection", "id_token", "access_token"),
           "check_directory": ("keys_path", "connection", "login", "password"), "duo_push": ("pending",),
           "duo_code": ("pending", "code"), "release": ("keys_path", "ticket", "name")}
_BAD = {"ok": False, "error": "bad_request"}
log = logging.getLogger(__name__)
_CODES = {oidc.Unreachable: "unreachable", oidc.Refused: "refused", oidc.NotFresh: "not_fresh", oidc.BadAnswer: "bad_answer",
          directory.Unreachable: "unreachable", directory.BadCredentials: "refused", directory.InsecureConfig: "refused",
          duo.Unavailable: "unreachable", duo.Denied: "refused"}


class _No(Exception):
    """The answer {"ok": False, "error": code}; `count` says whether it counts as a failure against the peer (by default: the
    codes that say no to a sign-in)."""

    def __init__(self, code, count=None):
        super().__init__(code)
        self.code, self.count = code, code in _COUNTED if count is None else count


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _unb64(s):
    return base64.b64decode(s.encode("ascii"), validate=True)


def _path(p):
    r"""The path normalised when it is an absolute local one (a drive letter on Windows); None for anything else: relative, UNC
    or device forms (a UNC share, the \\.\ and \\?\ prefixes), or a NUL in it. A device reached any other way is refused by
    _read, which takes regular files only."""
    if not (re.match(r"[A-Za-z]:[\\/]", p) if os.name == "nt" else p.startswith("/")):
        return None
    try:
        p = os.path.normcase(os.path.abspath(p))
    except ValueError:
        return None
    return p if (re.match(r"[a-z]:\\", p) if os.name == "nt" else not p.startswith("//")) else None


def _read(path):
    """The keys file's bytes. It must be a regular file (opened without blocking, so a FIFO can't hold SYSTEM up) of at most
    MAX_KEYS bytes, else bad_request. OSError when it can't be read."""
    if os.name == "nt" and not stat.S_ISREG(os.stat(path).st_mode):
        raise _No("bad_request")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _No("bad_request")
        with open(fd, "rb", closefd=False) as f:
            data = f.read(MAX_KEYS + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_KEYS:
        raise _No("bad_request")
    return data


def _version(doc):
    """The signed rules_version (0 for a file signed before there was one); None when it isn't a count."""
    v = doc.get("rules_version", 0)
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _verified(path, rules_pub, read):
    """The keys doc at `path`, read with `read`, when its rules_pub is `rules_pub` (b64) and the signed part verifies under it;
    else None. bad_request (raised) for a path that is not a regular file of at most MAX_KEYS."""
    if path is None:
        return None
    try:
        doc = json.loads(read(path).decode("utf-8"))
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
    def handle(self, req, peer, cancel=None, read=None):
        """The answer to one request from `peer`. `cancel` is set by the transport when the client goes (it stops a Duo push).
        `read(path) -> bytes` reads the keys file with the caller's rights (the transport impersonates it); _read by default."""
        read = read or _read
        op = req.get("op")
        need = _FIELDS.get(op)
        if need is None or not all(isinstance(req.get(k), str) for k in need) or (op != "status" and req.get("v") != PROTOCOL):
            return {"ok": False, "error": "bad_request"}
        if op == "status":
            return self._status(req, peer, read)
        wait = self._gate(peer)
        if wait:
            return {"ok": False, "error": "throttled", "wait": wait}
        try:
            try:
                if op == "enroll":
                    return {"ok": True, **self._enroll(req, peer, read)}
                rec = self._load()
                if rec is None:
                    raise _No("not_enrolled")
                if peer != rec["owner"] or (op not in ("duo_push", "duo_code") and _path(req["keys_path"]) != rec["keys_path"]):
                    raise _No("not_owner")
                return {"ok": True, **getattr(self, "_" + op)(req, rec, cancel or threading.Event(), read)}
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

    def _put(self, kept, ttl, *value):
        key = secrets.token_urlsafe(32)
        with self._lock:
            now = self.now()
            for k in [k for k, v in kept.items() if v[0] < now]:
                del kept[k]
            while len(kept) >= _KEEP:
                del kept[next(iter(kept))]
            kept[key] = (now + ttl, *value)
        return key

    def _take(self, kept, key, keep=False):
        """The value kept under `key` (removed unless `keep`), or None when there is none or it has expired."""
        with self._lock:
            v = kept.get(key) if keep else kept.pop(key, None)
        return v[1:] if v and self.now() <= v[0] else None

    def _ticket(self, rec, name, role):
        with self._lock:
            self._fails.pop(rec["owner"], None)        # a checked sign-in clears the count, as a password does in Toner
        return self._put(self._tickets, TTL, name, role)

    # ------------------------------------------------------------ the signed rules
    def _rules(self, rec, read):
        """The keys doc, its rules signed with the pinned key and no older than the newest seen (rules_changed otherwise: an
        edit, another rules key, or an older signed file put back). A newer rules_version is kept as the newest seen."""
        doc = _verified(rec["keys_path"], rec["rules_pub"], read)
        v = None if doc is None else _version(doc)
        if v is None or v < rec.get("rules_version", 0):
            raise _No("rules_changed")
        if v > rec.get("rules_version", 0):
            with self._lock:
                cur = self._load()
                if cur is not None and cur["owner"] == rec["owner"] and cur.get("rules_version", 0) < v:
                    self.store.save({**cur, "rules_version": v})
            rec["rules_version"] = v
        return doc

    def _cfg(self, rec, connection, sso, read):
        """The connection's settings from the verified rules."""
        for d in self._rules(rec, read).get("directories") or []:
            if isinstance(d, dict) and d.get("id") == connection and (d.get("kind") == "oidc") == sso:
                return d
        raise _No("bad_request")

    def _skey(self, rec, connection):
        skey = rec["duo"].get(connection)
        if skey is None:                                # Duo turned on since enrollment: Toner enrolls again
            raise _No("unreachable")
        return skey

    # ------------------------------------------------------------ the ops
    def _status(self, req, peer, read):
        rec = self._load()
        owner = rec is not None and peer == rec["owner"] and _path(req["keys_path"]) == rec["keys_path"]
        changed = False
        if owner:
            try:
                self._rules(rec, read)
            except _No:
                changed = True
        return {"ok": True, "protocol": PROTOCOL, "version": VERSION, "enrolled": rec is not None, "owner": owner,
                "rules_changed": changed}

    def _enroll(self, req, peer, read):
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
        if path is None:
            raise _No("bad_request")
        rec = self._load()
        if rec is not None and rec["owner"] != peer:
            raise _No("other_user")
        doc = _verified(path, rules_pub, read)          # read before the lock: a slow file holds up no one else
        if doc is None:                                 # not this copy's rules key, or rules it didn't sign
            raise _No("refused")
        if (_version(doc) or 0) < 1:                    # signed before the count: an Admin signs once more first, so no
            raise _No("rules_changed")                  # older unversioned file can pass the minimum kept below
        with self._lock:                                # two peers enrolling at once: one wins, the other is other_user
            rec = self._load()
            if rec is not None and rec["owner"] != peer:
                raise _No("other_user")
            self.store.save({"owner": peer, "keys_path": path, "rules_pub": rules_pub, "spare": data_key + rules_private,
                             "duo": duo_keys, "enrolled_at": self.now(), "rules_version": _version(doc)})
            self._reset()
        return {}

    def _forget(self, req, rec, cancel, read):
        with self._lock:
            self.store.clear()
            self._reset()
        return {}

    def _nonce(self, req, rec, cancel, read):
        return {"nonce": self._put(self._nonces, NONCE_TTL, req["connection"], self.now())}

    def _check_sso(self, req, rec, cancel, read):
        cfg = self._cfg(rec, req["connection"], True, read)
        try:
            nonce = jwt.decode(req["id_token"], options={"verify_signature": False}).get("nonce")
        except jwt.PyJWTError:
            raise _No("bad_answer") from None
        # used up here, whatever follows: a nonce this helper issued for this connection, once
        issued = self._take(self._nonces, nonce) if isinstance(nonce, str) else None
        if issued is None or issued[0] != req["connection"]:
            raise _No("bad_answer")
        claims = oidc.verify_id_token(cfg, req["id_token"], nonce, max_age=300, now=self.now())
        # a sign-in from before the nonce: a browser session reused quietly (prompt=none), not one typed for this sign-in
        if claims["auth_time"] < issued[1] - oidc.LEEWAY:
            raise _No("not_fresh")
        try:
            user = oidc.user_from(cfg, claims, oidc.groups(cfg, claims, req["access_token"]))
        except KeyError:                                # the ID token names no one
            raise _No("bad_answer") from None
        role = directory.role_for(cfg, user.groups)
        if role is None:
            raise _No("not_in_group")
        return {**_who(user, role), "ticket": self._ticket(rec, user.name, role)}

    def _check_directory(self, req, rec, cancel, read):
        cfg = self._cfg(rec, req["connection"], False, read)
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
        return {**who, "duo": "auth", "pending": self._put(self._pending, TTL, cfg["id"], user.name, role, {"pushed": False})}

    def _duo(self, req, rec, check, read, push=False):
        """A pending Duo check: `check(cfg, name, skey)` passes or raises; then the pending check is used up for a ticket. It
        allows one push, so a password can't send push after push."""
        pending = self._take(self._pending, req["pending"], keep=True)
        if pending is None:
            raise _No("refused")
        connection, name, role, state = pending
        if push:
            with self._lock:
                if state["pushed"]:
                    raise _No("refused")
                state["pushed"] = True
        cfg = self._cfg(rec, connection, False, read)
        check(cfg, name, self._skey(rec, connection))
        if self._take(self._pending, req["pending"]) is None:      # another request used it meanwhile
            raise _No("refused")
        return {"ticket": self._ticket(rec, name, role)}

    def _duo_push(self, req, rec, cancel, read):
        def push(cfg, name, skey):
            try:
                duo.push(cfg, name, cancel, skey=skey)
            except duo.Denied:                          # denied, timed out or cancelled: every push not allowed counts
                raise _No("refused") from None
            except duo.Unavailable:
                raise _No("unreachable", count=True) from None
        return self._duo(req, rec, push, read, push=True)

    def _duo_code(self, req, rec, cancel, read):
        return self._duo(req, rec, lambda cfg, name, skey: duo.passcode(cfg, name, req["code"], skey=skey), read)

    def _release(self, req, rec, cancel, read):
        self._rules(rec, read)
        ticket = self._take(self._tickets, req["ticket"])
        if ticket is None or ticket[0] != req["name"]:
            raise _No("refused")
        spare = rec["spare"]                            # the data key, then the 32-byte Ed25519 rules private key
        return {"data_key": _b64(spare[:-32]), "rules_private": _b64(spare[-32:]), "role": ticket[1]}


# ------------------------------------------------------------ the channel
def serve_channel(listener, helper, stop, identify, wake):
    """Accepts connections on `listener` until `stop` is set, a thread each. `identify(conn) -> (peer, read)` takes the
    caller's identity, and a reader with its rights, from the OS, never from a message. `wake()` connects once, so an accept
    waiting when `stop` is set returns."""
    threading.Thread(target=lambda: (stop.wait(), wake()), daemon=True).start()
    try:
        while not stop.is_set():
            try:
                conn = listener.accept()
            except Exception as e:                      # a client that came and went mid-accept
                log.warning("helper: accept failed: %s", type(e).__name__)
                stop.wait(0.1)
                continue
            if stop.is_set():
                conn.close()
                break
            threading.Thread(target=_connection, args=(helper, conn, identify), daemon=True).start()
    finally:
        listener.close()


def _connection(helper, conn, identify):
    """One client, request after request until it goes. A message over MAX closes the connection (recv_bytes does); one that
    isn't a JSON object is answered bad_request and closes it too. Nothing of a request or an answer is logged."""
    with conn:
        try:
            peer, read = identify(conn)
        except Exception as e:                          # the client process went before it could be named
            log.warning("helper: no peer: %s", type(e).__name__)
            return
        while True:
            try:
                req = decode(conn.recv_bytes(MAX))
            except ValueError:
                req = None
            except (EOFError, OSError):
                return
            ans = _BAD if req is None else _answer(helper, conn, req, peer, read)
            if ans is None:
                return
            try:
                conn.send_bytes(encode(ans))
            except (OSError, ValueError):
                return
            if req is None:
                return


def _answer(helper, conn, req, peer, read):
    """helper.handle, in a thread of its own while this one watches the client. When the client goes (or speaks out of turn)
    `cancel` is set, which stops a Duo push, and there is no answer. An unexpected error (a disk error saving the store, say)
    answers bad_request and logs the op and the error's type only: requests and answers carry passwords, tokens and keys."""
    cancel, box = threading.Event(), []

    def run():
        try:
            box.append(helper.handle(req, peer, cancel, read))
        except Exception as e:
            op = req.get("op")
            log.warning("helper: %s failed: %s", op if isinstance(op, str) and op in _FIELDS else "?", type(e).__name__)
            box.append(_BAD)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    while True:
        t.join(0.1)
        if not t.is_alive():
            return box[0]
        try:
            gone = conn.poll(0)
        except (EOFError, OSError):
            gone = True
        if gone:
            cancel.set()
            t.join()
            return None
