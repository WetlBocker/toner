"""Keeping Toner's passwords in a password manager (Bitwarden, Vaultwarden, Keeper, 1Password), with Toner's vault as the copy.

Toner always reads a password from its own vault (core/passvault.py), so a check never waits for the network and keeps working
when the manager cannot be reached. With a manager chosen (Settings > Security > Store passwords in):

  * every change Toner makes is queued (the queue is kept in the vault, so it survives a restart) and sent as soon as the manager
    can be reached; Toner tries when it starts, after each change, and every 5 minutes;
  * what changed in the manager is copied back (a change still waiting in Toner's queue wins: it is the newer edit);
  * each Toner organization has its own collection (a vault in 1Password, a shared folder in Keeper), 'Toner - Acme' unless
    another is chosen; Global's is 'Toner - Global';
  * a password can be linked to an item that already exists in the manager (Link...): Toner reads the linked item, keeps it as
    its stored copy (in its vault and as its own item), and falls back on that copy when the linked item cannot be read.

Keep a copy of each password in Toner's vault (Settings > Security, on by default) can be turned off. Then Toner's vault keeps
only Toner's own login for the manager: the passwords are read from the manager when Toner starts and kept in memory while it
runs (_mem), changes wait in memory until they are sent (_mem_pending), and nothing is available while the manager can't be
reached.

The vault entries this module keeps for itself start with '~ext/', which no Toner password name can. Entries that start with
'~toner/' stay in Toner's vault only and never go to the manager either.
"""
import json
import threading
import time

from core import db, extvault, passvault

INTERNAL = "~ext/"
LOCAL = "~toner/"                      # kept only in Toner's vault, never sent to the manager (Demarc's token)
PENDING = INTERNAL + "pending"
INTERVAL = 300                         # seconds between tries
_lock = threading.RLock()
_round = threading.Lock()              # one round with the manager at a time (the background one, Settings' own)
_kick = threading.Event()
_thread = None
_status = {"kind": "toner", "connected": False, "error": "", "sent": 0, "found": 0, "problems": [], "at": 0}
_failed_links = set()                  # names whose linked item could not be read the last time
_mem = {}                              # copies off: name -> password, in memory only
_mem_pending = {}                      # copies off: name -> 'put' / 'delete', waiting to be sent
_loaded = False                        # copies off: the passwords have been read from the manager since Toner started


class CannotSwitch(Exception):
    """A change of store (or of Keep a copy) that would lose passwords; the message says why, in the agreed words."""


# ---------------------------------------------------------------- settings
def active():
    """The chosen store: 'toner' (Toner's vault only) or a manager's kind."""
    kind = db.get_setting("vault_provider") or "toner"
    return kind if kind in extvault.CONNECTORS else "toner"


def keep_copies():
    """Settings > Security > Keep a copy of each password in Toner's vault (always, with Toner's vault itself)."""
    return active() == "toner" or db.get_setting("vault_keep_copies") is not False


def memory_only():
    """True when the passwords live only in the password manager (and in memory while Toner runs)."""
    return not keep_copies()


def config(kind):
    return dict((db.get_setting("vault_config") or {}).get(kind) or {})


def set_config(kind, cfg):
    allc = dict(db.get_setting("vault_config") or {})
    allc[kind] = cfg
    db.set_setting("vault_config", allc)


def secret(kind, name):
    return passvault.get(f"{INTERNAL}{kind}/{name}") if passvault.is_open() else None


def set_secret(kind, name, value):
    if value:
        passvault.put(f"{INTERNAL}{kind}/{name}", value)
    else:
        passvault.remove(f"{INTERNAL}{kind}/{name}")


def secrets(kind):
    return {f: secret(kind, f) for f in extvault.SECRET_FIELDS.get(kind, ())}


def container_name(kind, org):
    """The collection (vault, shared folder) a Toner organization's passwords go to."""
    chosen = (config(kind).get("containers") or {}).get(str(org or 0))
    return (chosen or "").strip() or f"Toner - {db.org_name(org) if org else 'Global'}"


def connector(kind=None):
    kind = kind or active()
    return extvault.make(kind, config(kind), secrets(kind))


def keep_new_secrets(kind, conn):
    """Keeper hands back its configuration after the one-time token: keep it (and forget the token)."""
    for name, value in (conn.new_secrets or {}).items():
        set_secret(kind, name, value)
    conn.new_secrets = None


# ---------------------------------------------------------------- names
def is_internal(name):
    return name.startswith((INTERNAL, LOCAL))


def local_names():
    if memory_only():
        with _lock:
            return list(_mem)
    return [n for n in passvault.names() if not is_internal(n)]


def _value(name):
    if memory_only():
        with _lock:
            return _mem.get(name)
    return passvault.get(name)


def _store(name, value):
    """A password read from the manager: into Toner's vault, or into memory (never queued: it came from there)."""
    if memory_only():
        with _lock:
            _mem[name] = value
    else:
        passvault.put(name, value)


# ---- what keyring reads and writes while the passwords are only in the manager (core/passvault.py asks memory_only() first)
def mem_get(name):
    with _lock:
        return _mem.get(name)


def mem_put(name, value):
    with _lock:
        _mem[name] = value
        _mem_pending[name] = "put"
    _kick.set()


def mem_remove(name):
    """True when there was one."""
    with _lock:
        had = name in _mem
        _mem.pop(name, None)
        _mem_pending[name] = "delete"
    _kick.set()
    return had


def org_of(name):
    """'org3/edge-fw' -> 3; a plain name is Global's (0)."""
    if name.startswith("org") and "/" in name:
        head = name.split("/", 1)[0][3:]
        if head.isdigit():
            return int(head)
    return db.GLOBAL


def _plain(name):
    return name.split("/", 1)[1] if org_of(name) else name


KIND_WORDS = {":snmp": "SNMP community", ":snmp-auth": "SNMPv3 authentication key", ":snmp-priv": "SNMPv3 privacy key",
              ":proxy": "Proxy password", ":agent": "Agent token", ":ssh": "SSH password", ":proxy-otp": "Proxy authenticator key"}
SERVICE_WORDS = {"service:proxy": "Toner proxy password", "service:proxy-otp": "Toner proxy authenticator key",
                 "service:ssh-tunnel": "Toner SSH tunnel password", "service:ssh-tunnel-otp": "Toner SSH tunnel authenticator key",
                 "service:sftp-server": "Toner SFTP server password", "service:ftp-server": "Toner FTP server password", "service:agent-enroll": "Toner agent sign-up key",
                 "service:ansible-server": "Toner Ansible control node password",
                 "firmware-source": "Toner Firmware Transfer image server password"}


def describe(name):
    """(title, user name) for Toner's item: 'edge-fw (Acme) – SSH password', the device's user name."""
    org, plain = org_of(name), _plain(name)
    where = f" ({db.org_name(org)})" if org else ""
    try:
        with db.within(org):
            if plain in SERVICE_WORDS:
                return SERVICE_WORDS[plain] + where, ""
            if plain.startswith("session:"):
                from core import sessions
                s = sessions.get(int(plain.split(":")[1]))
                return (f"Session {s['name']}{where}", s.get("username") or "") if s else (f"Session {plain[8:]}{where}", "")
            if plain.startswith("notify:"):
                from core import notify
                cid, key = plain.split(":")[1:3]
                ch = next((c for c in notify.channels() if c.get("id") == cid), None)
                return f"Notification channel {ch['name'] if ch else cid}{where} – {key}", ""
            base, word = plain, "Password"
            for suffix, label in sorted(KIND_WORDS.items(), key=lambda kv: -len(kv[0])):
                if plain.endswith(suffix):
                    base, word = plain[:-len(suffix)], label
                    break
            if base.startswith("profile:"):
                from core import profiles
                pname = base[8:]
                p = next((x for x in profiles._profiles_here() if x["name"] == pname), None)
                return f"Profile {pname}{where} – {word}", (p or {}).get("username") or ""
            dev = next((d for d in db.list_devices() if d["name"] == base and d.get("org", org) == org), None)
            return f"{base}{where} – {word}", (dev or {}).get("username") or ""
    except Exception:
        return f"{plain}{where}", ""


# ---------------------------------------------------------------- links
def link_of(name):
    raw = passvault.get(INTERNAL + "link/" + name) if passvault.is_open() else None
    return json.loads(raw) if raw else None


def set_link(name, item):
    """Link Toner's password `name` to an item in the manager ({'ref', 'title'}), or unlink (item None)."""
    if item:
        passvault.put(INTERNAL + "link/" + name, json.dumps({"kind": active(), "ref": item["ref"], "title": item["title"]}))
        _kick.set()
    else:
        passvault.remove(INTERNAL + "link/" + name)
        _failed_links.discard(name)


def links():
    return {n[len(INTERNAL) + 5:]: json.loads(passvault.get(n)) for n in passvault.names() if n.startswith(INTERNAL + "link/")}


def move_link(old, new):
    """A renamed device keeps its link."""
    if not passvault.is_open() or old == new:
        return
    raw = passvault.get(INTERNAL + "link/" + old)
    if raw:
        passvault.put(INTERNAL + "link/" + new, raw)
        passvault.remove(INTERNAL + "link/" + old)


def link_failed(name):
    """True when the linked item could not be read the last time, so the stored copy is what Toner uses."""
    return name in _failed_links


def fallback_note(device, names):
    """'edge-fw: the linked Bitwarden item couldn't be read, so Toner used its stored copy.' when that happened, else ''."""
    if any(link_failed(n) for n in names):
        return f"{device}: the linked {extvault.LABELS.get(active(), 'password manager')} item couldn't be read, so Toner used its stored copy."
    return ""


# ---------------------------------------------------------------- the queue of changes waiting to be sent
def pending():
    if memory_only():
        with _lock:
            return dict(_mem_pending)
    if not passvault.is_open():
        return {}
    raw = passvault.get(PENDING)
    return json.loads(raw) if raw else {}


def _save_pending(p):
    if p:
        passvault.put(PENDING, json.dumps(p))
    else:
        passvault.remove(PENDING)


def queue(name, op):
    """A change to send: op 'put' (made or changed) or 'delete'. Called by the vault's keyring store on every write."""
    if is_internal(name) or active() == "toner":
        return
    with _lock:
        p = pending()
        p[name] = op
        _save_pending(p)
    _kick.set()


def _done(name, op):
    with _lock:
        if memory_only():
            if _mem_pending.get(name) == op:
                _mem_pending.pop(name)
            return
        p = pending()
        if p.get(name) == op:
            p.pop(name)
            _save_pending(p)


# ---------------------------------------------------------------- one round with the manager
def sync_once():
    """Send what is queued, copy back what changed in the manager, read linked items. Returns the status."""
    with _round:
        return _sync_once()


def _sync_once():
    kind = active()
    st = {"kind": kind, "connected": False, "error": "", "sent": 0, "found": 0, "problems": [], "at": time.time()}
    if kind == "toner" or not passvault.is_open():
        _status.update(st)
        return dict(_status)
    try:
        conn = connector(kind)
        conn.connect()
        keep_new_secrets(kind, conn)
        st["connected"] = True
        orgs = [db.GLOBAL] + [r["id"] for r in db.org_rows()]
        cids, remote = {}, {}
        for org in orgs:
            try:
                cids[org] = conn.ensure(container_name(kind, org))
            except extvault.NotAllowed as e:
                if any(org_of(n) == org for n in local_names()):
                    st["problems"].append(str(e))
                continue
            for tid, item in conn.items(cids[org]).items():
                remote[tid] = (org, cids[org], item)
        st["found"] = len(remote)
        waiting = pending()
        sent_now = set()                                              # (what was just sent is not copied back from the old values)
        for name in sorted(set(local_names()) | set(waiting)):        # send: what is queued, and anything the manager lacks
            org = org_of(name)
            if org not in cids:
                continue
            op, have = waiting.get(name), remote.get(name)
            if op == "delete":
                if have:
                    conn.delete(have[2])
                    remote.pop(name)
                _done(name, op)
                st["sent"] += 1
                continue
            value = _value(name)
            if value is None:
                _done(name, op) if op else None
                continue
            title, user = describe(name)
            if have is None or (op == "put" and (have[2].value != value or have[2].title != title)):
                conn.put(cids[org], name, title, user, value, have[2] if have else None)
                sent_now.add(name)
                st["sent"] += 1
            elif op:
                sent_now.add(name)
            if op:
                _done(name, op)
        waiting = pending()
        with passvault.batch():                                       # copy back what changed in the manager
            for tid, (_org, _cid, item) in remote.items():
                if tid not in waiting and tid not in sent_now and item.value is not None and _value(tid) != item.value:
                    _store(tid, item.value)
        for name, link in links().items():                            # linked items: read, keep as the stored copy
            try:
                value = conn.read(link["ref"])
            except extvault.ExtError:
                _failed_links.add(name)
                continue
            _failed_links.discard(name)
            if _value(name) != value:
                _store(name, value)
                org = org_of(name)
                if org in cids:
                    title, user = describe(name)
                    have = remote.get(name)
                    conn.put(cids[org], name, title, user, value, have[2] if have else None)
        if memory_only():
            global _loaded
            _loaded = True
    except extvault.ExtError as e:
        st["connected"] = False
        st["error"] = str(e)
    st["waiting"] = len(pending())
    _status.update(st)
    return dict(_status)


def status():
    s = dict(_status)
    s["waiting"] = len(pending()) if passvault.is_open() else 0
    return s


def status_text(s=None):
    """The status line under Store passwords in."""
    s = s or status()
    name = extvault.LABELS.get(s.get("kind") or active(), "")
    if (s.get("kind") or active()) == "toner":
        return ""
    if not s.get("at"):
        return f"Connecting to {name}..."
    if not s.get("connected"):
        if memory_only():
            n = s.get("waiting", 0)
            return (f"Can't reach {name}. Without copies, saved passwords are unavailable until it can; "
                    f"{n} change{'s' if n != 1 else ''} will be sent when it can.")
        return f"Can't reach {name}. Toner is using its saved copies; {s.get('waiting', 0)} changes will be sent when it can."
    text = f"Connected to {name}. {s.get('sent', 0)} changes sent."
    if s.get("problems"):
        text += " " + " ".join(s["problems"])
    return text


# ---------------------------------------------------------------- in the background
_stop = threading.Event()


def _loop():
    while not _stop.is_set():
        _kick.wait(INTERVAL)
        _kick.clear()
        if _stop.is_set():
            return
        try:
            sync_once()
        except Exception:
            import logging
            logging.getLogger("toner").exception("password manager sync failed")


def start():
    """Keep the chosen password manager in step from now on (Toner's window; the first round happens right away)."""
    global _thread
    if _thread is None:
        _thread = threading.Thread(target=_loop, name="password-manager", daemon=True)
        _thread.start()
    _kick.set()


def kick():
    _kick.set()


def stop():
    """End the background rounds (a factory reset: nothing may be written after it). start() runs them again."""
    global _thread
    _stop.set()
    _kick.set()
    if _thread is not None:
        _thread.join(5)
    _thread = None
    _stop.clear()


# ---------------------------------------------------------------- choosing another store
def test(kind, cfg, secrets_):
    """Settings' Test connection: (ok, text) - 'Connected to Bitwarden. 2,412 Toner items found.' or 'Couldn't connect to ...'."""
    conn = extvault.make(kind, cfg, secrets_)
    label = extvault.LABELS[kind]
    try:
        conn.connect()
        found = 0
        have = conn.containers()
        for org in [db.GLOBAL] + [r["id"] for r in db.org_rows()]:
            name = ((cfg.get("containers") or {}).get(str(org)) or "").strip() or f"Toner - {db.org_name(org) if org else 'Global'}"
            cid = next((c for n, c in have.items() if n.lower() == name.lower()), None)
            if cid:
                found += len(conn.items(cid))
    except extvault.ExtError as e:
        return False, f"Couldn't connect to {label}: {e}", conn
    return True, f"Connected to {label}. {found:,} Toner items found.", conn


def unsent():
    """Changes made while the passwords are only in the manager that have not reached it yet (lost if Toner closes)."""
    with _lock:
        return len(_mem_pending) if memory_only() else 0


def set_keep_copies(on):
    """Turn Keep a copy on (write what is in memory into Toner's vault) or off (remove Toner's copies: only once every password
    is in the manager). Raises CannotSwitch."""
    global _mem, _mem_pending, _loaded
    if on == keep_copies():
        return
    name = extvault.LABELS[active()]
    if on:
        with _lock:
            mem, waiting = dict(_mem), dict(_mem_pending)
        with passvault.batch():
            for n, value in mem.items():
                passvault.put(n, value)
        db.set_setting("vault_keep_copies", True)
        with _lock:
            _save_pending(waiting)
            _mem, _mem_pending = {}, {}
        _kick.set()
        return
    s = status()
    if not (s.get("at") and s.get("connected") and s.get("kind") == active()) or pending():
        raise CannotSwitch(f"Toner can't remove its copies until every password is in {name}. Connect to {name} and wait for the "
                           "waiting changes to be sent, then try again.")
    names = local_names()
    with _lock:
        _mem = {n: passvault.get(n) for n in names}
        _mem_pending = {}
        _loaded = True
    db.set_setting("vault_keep_copies", False)
    with passvault.batch():
        for n in names:
            passvault.remove(n)
        passvault.remove(PENDING)


def use(kind):
    """Make `kind` the store. Toner's vault keeps its copy of every password; a manager is sent everything it lacks. When the
    passwords are only in the current manager, they are copied back into Toner's vault first (copies come back on: a new
    store starts with them). Raises CannotSwitch when that can't be done."""
    if memory_only() and kind != active():
        was = extvault.LABELS[active()]
        if not _loaded:
            raise CannotSwitch(f"Toner can't switch back to its own vault while {was} can't be reached: the passwords are only in {was}."
                               if kind == "toner" else
                               f"Toner can't switch away from {was} while it can't be reached: the passwords are only in {was}.")
        set_keep_copies(True)
    db.set_setting("vault_provider", kind)
    _failed_links.clear()
    with _lock:
        _save_pending({})                  # what waited for the old store: the new one is sent whatever it lacks anyway
    _status.update({"kind": kind, "connected": False, "error": "", "sent": 0, "found": 0, "problems": [], "at": 0})
    if kind != "toner":
        start()
