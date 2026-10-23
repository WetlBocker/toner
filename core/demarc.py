"""Sending Toner's data to Demarc, a separate server that shows every organization in one browser view (Demarc's /ingest/v1).

Toner always makes the connection, over HTTPS. Settings > Connections > Demarc connects it: Toner fetches Demarc's certificate,
shows its SHA-256 fingerprint, and only after the person confirms it sends the one-time enrollment code, pinned to that
certificate. A certificate this computer already trusts (a real one, or one from a reverse proxy) is checked the normal way
instead. Demarc answers with a token, kept in Toner's own vault (never in a password manager).

What is sent (an allowlist: only the fields in BODIES, which are exactly the ones Demarc accepts):
  * org             each organization, and Global, by its permanent ID (org_uid)
  * device          name, address, platform (the vendor), folder, groups (its location), tags, notes (the Details text)
  * device_removed  a device that was removed or renamed
  * result          every check result, with the time of its run, and its value to graph (to Demarc 0.0.3 or newer)
  * backup          each config backup version, always masked on the way out (to Demarc 0.0.8 or newer)
  * backup_log      how each config backup went (to Demarc 0.0.8 or newer)
Passwords, user names, SNMP and proxy settings, custom fields and everything else in the vault are never sent. A config backup
goes through backup.clean(mask=True) before it is queued, even when Toner keeps unmasked copies itself (Backup mask off).

The one exception, and only when Demarc asks for it: while an organization's Receive unmasked configs toggle is on in Demarc
(its replies say unmasked_configs), each config backup Toner takes is also posted unmasked to /ingest/v1/unmasked, straight
from what the device returned (offer_unmasked). It goes from memory, by whichever Toner process took the backup, and is never
written to Toner's database or the queue; one that fails is not tried again. Demarc stores it encrypted.

How it is sent:
  * every few seconds the sender compares the organizations and devices with what it last queued, and picks up new results;
  * changes wait in a queue on disk (demarc-queue.db next to Toner's database), unnumbered. They are given sequence numbers
    when they are sent, so an organization that is Live goes at once while another waits for its interval;
  * the first time (and whenever the queue had to be dropped) Toner sends a full copy instead: a snapshot, in parts;
  * Demarc's reply says what it stored (acked_seq) and how each organization wants its data (Live, or every N minutes);
  * a queue older than 7 days or bigger than 500 MB is dropped, and a full copy is sent when Demarc is back;
  * config backups are history, not state, so they are not in a full copy: they follow it, from a cursor per organization.
    Where there is no cursor yet (a first contact, a dropped queue, a Demarc just upgraded to 0.0.8) the Config history
    setting decides: every version Toner holds, or only each device's newest.
Times are sent in UTC (Toner stores local times).

Toner's window and its service may both run: only the one holding the lock file beside the queue sends.
"""
import gzip
import hashlib
import json
import logging
import math
import secrets
import socket
import sqlite3
import ssl
import threading
import time
import warnings
import zlib
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlsplit

from core import db, platforms, quiet
from core.version import VERSION

log = logging.getLogger("toner")

DEFAULT_PORT = 8760
SETTING = "demarc"                       # {'address', 'pin', 'trusted', 'enabled'} in the Global file
TOKEN_SECRET = "~toner/demarc-token"     # in Toner's vault only (core/extstore.py never sends '~toner/' entries to a manager)
MAX_ITEMS = 5000                         # Demarc takes at most this many items per request...
MAX_PART_BYTES = 40 * 1024 * 1024        # ...and at most 100 MB once unpacked; this leaves room
QUEUE_DAYS = 7
QUEUE_BYTES = 500 * 1024 * 1024
COLLECT_SECONDS = 5                      # how often changes are looked for (Live organizations are sent this quickly)
RETRY_FIRST, RETRY_MOST = 15, 300        # after a failed send: 15 s, then twice as long each time, up to 5 minutes
STATUSES = {"OK", "WARN", "FAIL", "ERROR", "N/A"}
NUMERIC_FROM = (0, 0, 3)                 # the first Demarc that takes a result's value; older ones refuse the field
BACKUPS_FROM = (0, 0, 8)                 # the first Demarc that takes config backups and the backup log
UNMASKED_PATH = "/ingest/v1/unmasked"   # an unmasked config, posted on its own (offer_unmasked)
BACKUPS_PER_ROUND = 100                  # versions (and log entries) queued per organization each round, so a long history goes
                                         # out in steps instead of filling the queue at once
HISTORY_ALL, HISTORY_LATEST = "all", "latest"   # the Config history setting

# The allowlist: each kind of item, its fields, and the longest text Demarc keeps for each (core of Demarc's ingest.py).
BODIES = {
    "org": {"name": 255, "code": 50, "colour": 20, "archived": None},
    "device": {"name": 255, "address": 255, "platform": 100, "folder": 1000, "groups": 100, "tags": 100, "notes": 10000},
    "device_removed": {"name": 255},
    "result": {"device": 255, "check": 255, "status": None, "value": 1000, "message": 4000, "ran_at": None, "numeric": None},
    "backup": {"device": 255, "taken_at": None, "sha": None, "size": None, "lines": None, "added": None, "removed": None,
               "masked": 5_000_000},
    "backup_log": {"device": 255, "at": None, "status": None, "message": 4000},
}
BACKUP_STATUSES = {"new", "changed", "unchanged", "error"}

# ---------------------------------------------------------------- wording (approved)
T_NOT_CONNECTED = "Not connected."
T_CONNECTED = "Connected to Demarc {version} at {address}. Last contact {when}."
T_WAITING = "{n} changes waiting to send."
T_WAITING_ONE = "1 change waiting to send."
T_SNAPSHOT = "Sending a full copy: part {p} of {n}."
T_OFF = "Sending is off. Nothing is kept while it's off. Toner sends a full copy when it's turned back on."
T_UNREACHABLE_SINCE = "Can't reach Demarc since {when}: {reason}. Changes wait here for up to 7 days or 500 MB."
T_DROPPED = "Changes waited longer than 7 days or passed 500 MB, so Toner dropped them. It will send a full copy when Demarc is back."
T_TOKEN = "Demarc refused Toner's token. It may have been revoked. Connect again with a new enrollment code."
T_CERT = ("Demarc's certificate has changed, so Toner stopped sending. If you expected this, connect again with a new "
          "enrollment code.")
T_SKIPPED = "Demarc skipped {n} items it couldn't read."
T_BAD_CODE = "Demarc didn't accept that enrollment code. Check it, or create a new one in Demarc under Toners."
T_EXPIRED = "That enrollment code has expired. Create a new one in Demarc under Toners."
T_TOO_MANY = "Too many tries. Wait a few minutes, then try again."
T_UNREACHABLE = "Can't reach Demarc at {address}: {reason}."
T_NOT_DEMARC = "{address} answered, but not as Demarc. Check the address and port."
T_HTTPS = "Demarc only works over HTTPS."
T_NEED = "Enter Demarc's address and the enrollment code."
T_AUDIT_CONNECTED = "Demarc connected: {address}"
T_AUDIT_DISCONNECTED = "Demarc disconnected"


class DemarcError(Exception):
    """Something the person is told, in the words above."""


class Unreachable(Exception):
    """No answer from Demarc; the message is the reason, in a few words."""


class CertChanged(Exception):
    """Demarc answered with a certificate other than the one pinned when Toner connected."""


# ---------------------------------------------------------------- identity, times, the allowlist
def install_uid():
    """This install's permanent ID: made once, kept in the Global file, never exported."""
    with db.within(db.GLOBAL):
        uid = db.get_setting("install_uid")
        if not uid:
            uid = db.new_uid()
            db.set_setting("install_uid", uid)
    return uid


def global_uid():
    """Global's org_uid. Global holds devices and results too, so Demarc sees it as an organization of this install."""
    return "global:" + install_uid()


def computer_name():
    try:
        return socket.gethostname()[:255] or "Toner"
    except OSError:
        return "Toner"


def iso(dt=None):
    """An aware time (default: now) as Demarc wants it: UTC, ISO 8601."""
    return (dt or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_of(local_text):
    """'2026-10-18 14:05:00', a local time as Toner stores it, in UTC ISO 8601. Unreadable: now."""
    try:
        return iso(datetime.strptime(str(local_text)[:19], "%Y-%m-%d %H:%M:%S").astimezone())
    except (TypeError, ValueError, OverflowError, OSError):
        return iso()


def _cut(text, n):
    return str(text if text is not None else "")[:n]


def allowed(kind, body):
    """The body with only the allowlisted fields, each cut to the length Demarc keeps. Raises KeyError for a kind or field that
    is not on the list, so nothing else can slip out."""
    spec = BODIES[kind]
    extra = set(body) - set(spec)
    if extra:
        raise KeyError(f"not on Demarc's allowlist for {kind}: {sorted(extra)}")
    out = {}
    for key, n in spec.items():
        if key not in body:
            continue
        v = body[key]
        if isinstance(v, list):
            out[key] = [_cut(x, n) for x in v if str(x)][:200]
        elif n is None:
            out[key] = v
        else:
            out[key] = _cut(v, n)
    return out


def org_body(row):
    return allowed("org", {"name": row["name"], "code": row.get("code") or "", "colour": row.get("colour") or "",
                           "archived": bool(row.get("archived"))})


GLOBAL_BODY = {"name": "Global", "code": "", "colour": "", "archived": False}


def device_body(dev, folders):
    loc = (dev.get("location") or "").strip()
    from core import display
    return allowed("device", {"name": dev["name"], "address": dev.get("host") or "", "platform": display.vendor_name(dev.get("vendor") or ""),
                              "folder": folders.get(dev.get("folder_id")) or "", "groups": [loc] if loc else [],
                              "tags": db.split_tags(dev.get("tags")), "notes": dev.get("details") or ""})


def result_body(row):
    status = row["status"] if row["status"] in STATUSES else "N/A"
    body = {"device": row["device"], "check": row["check_name"], "status": status,
            "value": "" if row["value"] is None else row["value"], "message": row["message"] or "", "ran_at": utc_of(row["started_at"])}
    if isinstance(row["numeric"], (int, float)) and math.isfinite(row["numeric"]):
        body["numeric"] = float(row["numeric"])
    return allowed("result", body)


def backup_body(row, text):
    """A stored config version as Demarc takes it: masked here whatever Toner stored, with the sha, size and line count of
    what is sent."""
    from core import backup
    masked = backup.clean(text, mask=True)
    return allowed("backup", {"device": row["device"], "taken_at": utc_of(row["taken_at"]), "sha": backup.sha(masked),
                              "size": len(masked), "lines": masked.count("\n"), "added": int(row["added"] or 0),
                              "removed": int(row["removed"] or 0), "masked": masked})


def backup_log_body(row):
    status = row["status"] if row["status"] in BACKUP_STATUSES else "error"
    return allowed("backup_log", {"device": row["device"], "at": utc_of(row["at"]), "status": status, "message": row["message"] or ""})


def org_uid(org):
    """The org_uid Demarc knows organization `org` by (Global's too), or '' for one without a uid yet."""
    if not org:
        return global_uid()
    return next((r["uid"] for r in db.org_rows() if r["id"] == int(org) and r.get("uid")), "") or ""


def wants_unmasked(org, queue=None):
    """True when Demarc's last reply asked for organization `org`'s configs unmasked, and Toner is connected and sending to a
    Demarc that takes config backups."""
    cfg = config()
    if not (cfg["address"] and cfg["enabled"]):
        return False
    st = (queue or Queue()).state()
    if st.get("stopped") or st.get("off") or not st.get("backups"):
        return False
    settings = st.get("settings") or {}
    uid = org_uid(org)
    return bool(uid) and isinstance(settings.get(uid), dict) and bool(settings[uid].get("unmasked_configs"))


def offer_unmasked(org, device, taken_at, masked_sha, text, queue=None):
    """Post one unmasked config to Demarc, if it asked for this organization's: `taken_at` is the version's local time and
    `masked_sha` the sha of its masked text (what Demarc knows the version by). The text stays in memory: nothing is written,
    and a post that fails is only logged. Returns whether Demarc stored it."""
    try:
        if not wants_unmasked(org, queue):
            return False
        tok = token()
        if not tok:
            return False
        cfg = config()
        body = {"org_uid": org_uid(org), "device": _cut(device, 255), "taken_at": utc_of(taken_at), "sha": masked_sha,
                "text": text}
        if len(text) > BODIES["backup"]["masked"]:
            return False
        status, data = Client(cfg["address"], cfg["pin"], cfg["trusted"], tok).post(UNMASKED_PATH, body, timeout=(10, 60))
        if status != 200:
            log.info("Demarc: the unmasked config of %s was not taken (%s %s)", device, status, (data or {}).get("error", ""))
        return status == 200 and bool((data or {}).get("stored"))
    except (Unreachable, CertChanged) as e:
        log.info("Demarc: couldn't send the unmasked config of %s: %s", device, e or type(e).__name__)
    except Exception:
        log.exception("Demarc: sending the unmasked config of %s failed", device)
    return False


def _from(version, first):
    try:
        return tuple(int(x) for x in str(version or "").split(".")[:3]) >= first
    except ValueError:
        return False


def takes_numeric(version):
    """True when Demarc `version` ('0.0.3') takes a result's value. Unknown or unreadable: False, so nothing is refused."""
    return _from(version, NUMERIC_FROM)


def takes_backups(version):
    """True when Demarc `version` takes config backups and the backup log (0.0.8 or newer). Unknown: False."""
    return _from(version, BACKUPS_FROM)


def fit(items, numeric):
    """Items as this Demarc takes them: without the results' values when it is older than 0.0.3."""
    if numeric:
        return items
    return [dict(it, body={k: v for k, v in it["body"].items() if k != "numeric"}) if it["kind"] == "result" else it
            for it in items]


# ---------------------------------------------------------------- reading Toner's data
def org_list():
    """[(org number, org_uid, body)]: Global first, then every organization (archived ones too: their body says so)."""
    out = [(db.GLOBAL, global_uid(), dict(GLOBAL_BODY))]
    for r in db.org_rows():
        if r.get("uid"):
            out.append((r["id"], r["uid"], org_body(r)))
    return out


def _folder_paths(c):
    rows = {r["id"]: r for r in c.execute("SELECT id, name, parent_id FROM folders")}
    out = {}
    for fid in rows:
        parts, cur, seen = [], fid, set()
        while cur in rows and cur not in seen:
            seen.add(cur)
            parts.append(rows[cur]["name"])
            cur = rows[cur]["parent_id"]
        out[fid] = "/".join(reversed(parts))
    return out


def devices_of(org):
    """{name: device body} of the devices in one organization's own file."""
    with db.within(org):
        with db.connect() as c:
            folders = _folder_paths(c)
            return {d["name"]: device_body(dict(d), folders) for d in c.execute("SELECT * FROM devices") if d["name"]}


RESULT_SQL = ("SELECT r.id, r.device, r.check_name, r.status, r.value, r.message, r.numeric, u.started_at FROM results r "
              "JOIN runs u ON u.id = r.run_id ")


def results_after(org, after, limit=MAX_ITEMS):
    """([(row id, result body)], the highest row id) of one organization's results stored after row `after`."""
    with db.within(org):
        with db.connect() as c:
            rows = c.execute(RESULT_SQL + "WHERE r.id > ? ORDER BY r.id LIMIT ?", (after, limit)).fetchall()
    out = [(r["id"], result_body(r)) for r in rows if r["device"] and r["check_name"]]
    return out, (rows[-1]["id"] if rows else after)


def latest_results(org):
    """([result body], the highest row id): the newest result of each check on each device (what a full copy carries)."""
    with db.within(org):
        with db.connect() as c:
            top = c.execute("SELECT IFNULL(MAX(id), 0) FROM results").fetchone()[0]
            rows = c.execute(RESULT_SQL + "WHERE r.id IN (SELECT MAX(id) FROM results GROUP BY device, check_name) "
                             "ORDER BY r.id").fetchall()
    return [result_body(r) for r in rows if r["device"] and r["check_name"]], top


BACKUP_SQL = "SELECT id, device, taken_at, added, removed, body FROM config_backups "
LOG_SQL = "SELECT id, device, at, status, message FROM backup_log "


def _unpack(blob):
    return zlib.decompress(blob).decode("utf-8", "replace") if blob else ""


def backups_after(org, after, log_after, limit=None):
    """([backup body], [backup log body], the highest backup id, the highest log id) of one organization: what was stored after
    the two row ids, oldest first, up to `limit` (default BACKUPS_PER_ROUND) of each."""
    limit = limit or BACKUPS_PER_ROUND
    with db.within(org):
        with db.connect() as c:
            rows = c.execute(BACKUP_SQL + "WHERE id > ? ORDER BY id LIMIT ?", (after, limit)).fetchall()
            logs = c.execute(LOG_SQL + "WHERE id > ? ORDER BY id LIMIT ?", (log_after, limit)).fetchall()
    return ([backup_body(r, _unpack(r["body"])) for r in rows if r["device"]], [backup_log_body(r) for r in logs if r["device"]],
            rows[-1]["id"] if rows else after, logs[-1]["id"] if logs else log_after)


def backup_start(org, history):
    """Where sending config backups starts for an organization that has no cursor yet, as backups_after answers. Every
    version: the first ones from row 0, the rest in the rounds after. Only the newest: each device's newest version and log
    entry, and the cursors at the top, so only what comes after follows."""
    if history != HISTORY_LATEST:
        return backups_after(org, 0, 0)
    with db.within(org):
        with db.connect() as c:
            top = c.execute("SELECT IFNULL(MAX(id), 0) FROM config_backups").fetchone()[0]
            log_top = c.execute("SELECT IFNULL(MAX(id), 0) FROM backup_log").fetchone()[0]
            rows = c.execute(BACKUP_SQL + "WHERE id IN (SELECT MAX(id) FROM config_backups GROUP BY device) ORDER BY id").fetchall()
            logs = c.execute(LOG_SQL + "WHERE id IN (SELECT MAX(id) FROM backup_log GROUP BY device) ORDER BY id").fetchall()
    return ([backup_body(r, _unpack(r["body"])) for r in rows if r["device"]], [backup_log_body(r) for r in logs if r["device"]],
            top, log_top)


def _hash(body):
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


# ---------------------------------------------------------------- the queue on disk
def queue_path():
    return db.base_path().with_name("demarc-queue.db")


GONE = "gone"                            # in `known`: an organization removed from Toner, already sent as archived


class Queue:
    """demarc-queue.db: pending (changes not numbered yet), outbox (numbered, sent, not yet stored by Demarc), known (what was
    last queued for each organization and device, to notice changes), cursors (the last result row queued per organization),
    backup_cursors (the last config backup and backup log rows queued per organization) and state (sequence numbers, Demarc's
    settings, the last contact and any error)."""

    def __init__(self, path=None):
        self.path = path or queue_path()
        self._made = False

    def connect(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.execute("PRAGMA busy_timeout = 15000")
        if not self._made:
            try:
                c.execute("PRAGMA journal_mode = WAL")
            except sqlite3.DatabaseError:
                pass
            c.executescript("""
            CREATE TABLE IF NOT EXISTS pending (id INTEGER PRIMARY KEY, org_uid TEXT NOT NULL, kind TEXT NOT NULL,
                changed_at TEXT NOT NULL, body TEXT NOT NULL, queued_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS outbox (seq INTEGER PRIMARY KEY, org_uid TEXT NOT NULL, kind TEXT NOT NULL,
                changed_at TEXT NOT NULL, body TEXT NOT NULL, queued_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS known (org_uid TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL, hash TEXT NOT NULL,
                body TEXT DEFAULT '', PRIMARY KEY (org_uid, kind, name));
            CREATE TABLE IF NOT EXISTS cursors (org_uid TEXT PRIMARY KEY, result_id INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS backup_cursors (org_uid TEXT PRIMARY KEY, backup_id INTEGER NOT NULL, log_id INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
            """)
            self._made = True
        return c

    @contextmanager
    def tx(self):
        """A connection for one transaction: committed (or rolled back) and closed at the end."""
        c = self.connect()
        try:
            with c:
                yield c
        finally:
            c.close()

    def state(self):
        with self.tx() as c:
            return {k: json.loads(v) for k, v in c.execute("SELECT key, value FROM state")}

    def get(self, key, default=None):
        with self.tx() as c:
            row = c.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, c=None, **values):
        own = c is None
        c = c or self.connect()
        try:
            for k, v in values.items():
                if v is None:
                    c.execute("DELETE FROM state WHERE key=?", (k,))
                else:
                    c.execute("INSERT INTO state(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                              (k, json.dumps(v)))
            if own:
                c.commit()
        finally:
            if own:
                c.close()

    def waiting(self):
        with self.tx() as c:
            return c.execute("SELECT (SELECT COUNT(*) FROM pending) + (SELECT COUNT(*) FROM outbox)").fetchone()[0]

    def drop(self, **state):
        """Forget every change and what was queued: the next send is a full copy."""
        with self.tx() as c:
            for t in ("pending", "outbox", "known", "cursors", "backup_cursors"):
                c.execute(f"DELETE FROM {t}")
            self.set(c, need_snapshot=True, **state)
        try:
            c = sqlite3.connect(self.path, timeout=15)
            c.execute("VACUUM")                            # give the space back
            c.close()
        except sqlite3.Error:
            quiet.ignored()

    def reset(self):
        """A new enrollment: Demarc starts this install from sequence 0, with a full copy."""
        with self.tx() as c:
            c.execute("DELETE FROM state")
        self.drop(last_seq=0)

    def over_cap(self, now=None):
        """True when the oldest change waiting is older than 7 days, or the queue holds more than 500 MB."""
        now = now or time.time()
        with self.tx() as c:
            olds = [r[0] for r in (c.execute("SELECT queued_at FROM pending ORDER BY id LIMIT 1").fetchone(),
                                   c.execute("SELECT queued_at FROM outbox ORDER BY seq LIMIT 1").fetchone()) if r]
            used = (c.execute("PRAGMA page_count").fetchone()[0] - c.execute("PRAGMA freelist_count").fetchone()[0]) \
                * c.execute("PRAGMA page_size").fetchone()[0]
        return bool(olds and now - min(olds) > QUEUE_DAYS * 86400) or used > QUEUE_BYTES


# ---------------------------------------------------------------- talking to Demarc
def parse_address(text):
    """(base URL, host, port) from 'demarc.example.com', 'host:8760' or 'https://host:8760'."""
    text = (text or "").strip().rstrip("/")
    if not text:
        raise DemarcError(T_NEED)
    if text.lower().startswith("http://"):
        raise DemarcError(T_HTTPS)
    if "://" not in text:
        text = "https://" + text
    u = urlsplit(text)
    try:
        port = u.port or DEFAULT_PORT
    except ValueError:
        raise DemarcError(T_NOT_DEMARC.format(address=text)) from None
    if u.scheme.lower() != "https" or not u.hostname:
        raise DemarcError(T_HTTPS if u.scheme.lower() != "https" else T_NEED)
    host = u.hostname
    shown = f"[{host}]" if ":" in host else host
    return f"https://{shown}:{port}", host, port


def _reason(e):
    """A few words for why a connection failed."""
    text = str(e).lower()
    for words, said in (("refused", "the connection was refused"), ("10061", "the connection was refused"),
                        ("timed out", "no answer"), ("timeout", "no answer"), ("getaddrinfo", "the name was not found"),
                        ("name or service not known", "the name was not found"), ("nodename nor servname", "the name was not found"),
                        ("no route", "no route to it"), ("unreachable", "no route to it"), ("ssl", "the secure connection failed"),
                        ("reset", "the connection was closed"), ("proxy", "the proxy refused")):
        if words in text:
            return said
    return type(e).__name__


class Client:
    """HTTPS to one Demarc: gzipped JSON, the token, and either the pinned certificate or the normal checks."""

    def __init__(self, url, pin="", trusted=False, token=""):
        import requests
        self.url, self.pin, self.trusted, self.token = url, (pin or "").lower(), bool(trusted), token
        self.host = urlsplit(url).hostname or ""
        self.session = requests.Session()
        if self.pin and not self.trusted:
            self.session.mount("https://", _pinned_adapter(self.pin))

    def post(self, path, payload, timeout=(10, 120)):
        """(HTTP status, the reply's JSON or None)."""
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        from core import proxy
        body = gzip.compress(json.dumps(payload, separators=(",", ":")).encode(), 6)
        headers = {"Content-Type": "application/json", "Content-Encoding": "gzip", "User-Agent": f"Toner/{VERSION}"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)      # not checked against a CA, because it is pinned
                r = self.session.post(self.url + path, data=body, headers=headers, timeout=timeout, allow_redirects=False,
                                      verify=self.trusted, **proxy.web_kwargs(self.host))
        except requests.exceptions.SSLError as e:
            if "fingerprint" in str(e).lower():
                raise CertChanged() from None
            raise Unreachable(_reason(e)) from None
        except requests.RequestException as e:
            raise Unreachable(_reason(e)) from None
        try:
            data = r.json()
        except ValueError:
            data = None
        return r.status_code, data if isinstance(data, dict) else None


def _pinned_adapter(pin):
    """requests' adapter that accepts exactly the certificate whose SHA-256 is `pin`, checked before anything is sent."""
    from requests.adapters import HTTPAdapter

    class Pinned(HTTPAdapter):
        def init_poolmanager(self, *a, **kw):
            kw.update(assert_fingerprint=pin, cert_reqs="CERT_NONE")
            super().init_poolmanager(*a, **kw)

        def proxy_manager_for(self, proxy_url, **kw):
            kw.update(assert_fingerprint=pin, cert_reqs="CERT_NONE")
            return super().proxy_manager_for(proxy_url, **kw)
    return Pinned()


class Probe:
    """What Toner found at an address before it sends the enrollment code."""

    def __init__(self, url, host, port, fingerprint, trusted):
        self.url, self.host, self.port, self.fingerprint, self.trusted = url, host, port, fingerprint, trusted


def probe(address, timeout=10):
    """Reach Demarc and read its certificate, sending nothing. Raises DemarcError."""
    from core import proxy
    url, host, port = parse_address(address)
    try:
        sock = proxy.create_connection(None, (host, port), timeout=timeout)
    except OSError as e:
        raise DemarcError(T_UNREACHABLE.format(address=url, reason=_reason(e))) from None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            der = s.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as e:
        sock.close()
        raise DemarcError(T_UNREACHABLE.format(address=url, reason=_reason(e))) from None
    return Probe(url, host, port, hashlib.sha256(der).hexdigest(), _trusted(url, host, timeout))


def _trusted(url, host, timeout):
    """True when this computer already trusts the certificate (and its name matches): then it is checked the normal way."""
    import requests
    from core import proxy
    try:
        requests.get(url + "/ingest/v1/enroll", timeout=timeout, allow_redirects=False, **proxy.web_kwargs(host))
        return True
    except requests.RequestException:
        return False


def config():
    with db.within(db.GLOBAL):
        return {**db.DEFAULT_SETTINGS[SETTING], **(db.get_setting(SETTING) or {})}


def save_config(**values):
    with db.within(db.GLOBAL):
        db.set_setting(SETTING, {**config(), **values})


def token():
    try:
        import keyring
        return keyring.get_password(db.SERVICE, TOKEN_SECRET) or ""
    except Exception:
        return ""                                          # the vault is locked: nothing is sent until it opens


def connected():
    return bool(config()["address"] and token())


def enroll(found, code, queue=None):
    """Swap the enrollment code for this install's token, pinned to the certificate in `found` (a Probe the person confirmed).
    Raises DemarcError."""
    code = "".join((code or "").split())
    if not code:
        raise DemarcError(T_NEED)
    pin = "" if found.trusted else found.fingerprint
    client = Client(found.url, pin, found.trusted)
    try:
        status, data = client.post("/ingest/v1/enroll", {"code": code, "install_uid": install_uid(), "name": computer_name(),
                                                         "toner_version": VERSION}, timeout=(10, 30))
    except CertChanged:
        raise DemarcError(T_CERT) from None
    except Unreachable as e:
        raise DemarcError(T_UNREACHABLE.format(address=found.url, reason=str(e))) from None
    err = (data or {}).get("error")
    if status == 200 and str((data or {}).get("token", "")).startswith("dmt_"):
        from core import audit
        db.set_secret(TOKEN_SECRET, data["token"])
        save_config(address=found.url, pin=pin, trusted=found.trusted, enabled=True)
        q = queue or Queue()
        q.reset()
        q.set(demarc_version=str(data.get("demarc_version", ""))[:40], numeric=takes_numeric(data.get("demarc_version")),
              last_contact=_local_now())
        with db.within(db.GLOBAL):
            audit.log(T_AUDIT_CONNECTED.format(address=found.url))
        kick()
        return
    if status == 403 and err == "code_expired":
        raise DemarcError(T_EXPIRED)
    if (status == 403 and err == "bad_code") or (status == 422 and err == "invalid_item"):
        raise DemarcError(T_BAD_CODE)
    if status == 429:
        raise DemarcError(T_TOO_MANY)
    raise DemarcError(T_NOT_DEMARC.format(address=found.url))


def disconnect(queue=None):
    """Stop sending and forget the token. What Demarc already has stays there."""
    from core import audit
    db.delete_secret(TOKEN_SECRET)
    save_config(pin="", trusted=False, enabled=False)
    (queue or Queue()).reset()
    with db.within(db.GLOBAL):
        audit.log(T_AUDIT_DISCONNECTED)
    kick()


def _local_now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- the sender
class Sender:
    """One round at a time (step), run by the background thread below, or directly by the tests."""

    def __init__(self, queue=None):
        self.q = queue or Queue()
        self.limit = MAX_ITEMS                              # halved when Demarc says a request is too large

    # ---------- one round
    def step(self, now=None):
        """Look for changes, then send what is due. Returns the seconds until the next round."""
        now = now or time.time()
        cfg, tok = config(), token()
        if not (cfg["address"] and tok):
            return COLLECT_SECONDS
        if not cfg["enabled"]:
            if not self.q.get("off"):
                self.q.drop(off=True)                       # nothing is kept while sending is off
            return COLLECT_SECONDS
        st = self.q.state()
        if st.get("off"):
            self.q.set(off=None)
        if st.get("stopped"):                               # token refused or certificate changed: until connected again
            return 30
        if not st.get("need_snapshot"):
            self.collect(now)
            if self.q.over_cap(now):
                self.q.drop(dropped=True)
        if now < st.get("next_try", 0):
            return max(1, min(COLLECT_SECONDS, st["next_try"] - now))
        client = Client(cfg["address"], cfg["pin"], cfg["trusted"], tok)
        try:
            if self.q.get("need_snapshot"):
                self.send_snapshot(client, now)
            else:
                self.send_due(client, now)
        except Unreachable as e:
            self._failed("unreachable", str(e), now)
        except CertChanged:
            self.q.drop(stopped="cert")
        return COLLECT_SECONDS

    def _failed(self, code, reason, now):
        st = self.q.state()
        fails = st.get("fails", 0) + 1
        err = st.get("error") or {}
        since = err.get("since") if err.get("code") == code else _local_now()
        self.q.set(fails=fails, next_try=now + min(RETRY_MOST, RETRY_FIRST * 2 ** (fails - 1)),
                   error={"code": code, "reason": reason, "since": since})

    def _contact(self, c, data, **more):
        """A good reply: remember Demarc's settings for each organization, its version (named in replies from 0.0.3: so after
        Demarc is upgraded, or put back to an older one, Toner knows) and that it answered."""
        values = dict(fails=None, next_try=None, error=None, last_contact=_local_now(), **more)
        if isinstance(data.get("settings"), dict):
            values["settings"] = data["settings"]
        version = data.get("demarc_version")
        values["numeric"] = takes_numeric(version)
        values["backups"] = takes_backups(version)
        if version:
            values["demarc_version"] = str(version)[:40]
        self.q.set(c, **values)

    def _refused(self, status, data):
        """401 / 403: the token is no good any more. True when that was the answer."""
        if status in (401, 403):
            self.q.drop(stopped="token")
            return True
        return False

    # ---------- looking for changes
    def collect(self, now=None):
        """Queue what changed since the last look: organizations, devices (added, changed, removed) and new results."""
        now = now or time.time()
        when = iso()
        with self.q.tx() as c:
            known = {(u, k, n): (h, b) for u, k, n, h, b in c.execute("SELECT org_uid, kind, name, hash, body FROM known")}
            cursors = dict(c.execute("SELECT org_uid, result_id FROM cursors").fetchall())
            bcursors = {u: (b, lg) for u, b, lg in c.execute("SELECT org_uid, backup_id, log_id FROM backup_cursors")}
        backups, history = self.q.get("backups", False), config().get("history", HISTORY_ALL)
        by_org = {}
        for (u, k, n) in known:
            if k == "device":
                by_org.setdefault(u, set()).add(n)
        items, upserts, deletes, moved, bmoved = [], [], [], {}, {}
        here = set()
        for org, uid, body in org_list():
            here.add(uid)
            h = _hash(body)
            if known.get((uid, "org", ""), (None,))[0] != h:
                items.append((uid, "org", when, body))
                upserts.append((uid, "org", "", h, json.dumps(body)))
            devs = devices_of(org)
            for name, b in devs.items():
                hb = _hash(b)
                if known.get((uid, "device", name), (None,))[0] != hb:
                    items.append((uid, "device", when, b))
                    upserts.append((uid, "device", name, hb, ""))
            for name in sorted(by_org.get(uid, set()) - set(devs)):
                items.append((uid, "device_removed", when, {"name": name}))
                deletes.append((uid, "device", name))
            rows, top = results_after(org, cursors.get(uid, 0))
            items += [(uid, "result", b["ran_at"], b) for _rid, b in rows]
            if top != cursors.get(uid, 0):
                moved[uid] = top
            if backups:
                if uid in bcursors:
                    vers, logs, b_top, l_top = backups_after(org, *bcursors[uid])
                else:
                    vers, logs, b_top, l_top = backup_start(org, history)
                items += [(uid, "backup", b["taken_at"], b) for b in vers]
                items += [(uid, "backup_log", b["at"], b) for b in logs]
                if (b_top, l_top) != bcursors.get(uid):
                    bmoved[uid] = (b_top, l_top)
        for (u, k, n), (h, b) in known.items():                  # removed from Toner: archived in Demarc, its devices removed
            if k == "org" and u not in here and h != GONE:
                body = {**json.loads(b or "{}"), "archived": True}
                items.append((u, "org", when, allowed("org", body)))
                upserts.append((u, "org", "", GONE, json.dumps(body)))
                for name in sorted(by_org.get(u, set())):
                    items.append((u, "device_removed", when, {"name": name}))
                    deletes.append((u, "device", name))
        if not (items or upserts or deletes or moved or bmoved):
            return 0
        with self.q.tx() as c:
            c.executemany("INSERT INTO pending(org_uid, kind, changed_at, body, queued_at) VALUES(?, ?, ?, ?, ?)",
                          [(u, k, at, json.dumps(b, separators=(",", ":")), now) for u, k, at, b in items])
            c.executemany("INSERT INTO known(org_uid, kind, name, hash, body) VALUES(?, ?, ?, ?, ?) ON CONFLICT(org_uid, kind, name) "
                          "DO UPDATE SET hash=excluded.hash, body=excluded.body", upserts)
            c.executemany("DELETE FROM known WHERE org_uid=? AND kind=? AND name=?", deletes)
            c.executemany("INSERT INTO cursors(org_uid, result_id) VALUES(?, ?) ON CONFLICT(org_uid) DO UPDATE SET "
                          "result_id=excluded.result_id", list(moved.items()))
            c.executemany("INSERT INTO backup_cursors(org_uid, backup_id, log_id) VALUES(?, ?, ?) ON CONFLICT(org_uid) DO UPDATE SET "
                          "backup_id=excluded.backup_id, log_id=excluded.log_id", [(u, b, lg) for u, (b, lg) in bmoved.items()])
        return len(items)

    # ---------- batches
    @staticmethod
    def _due(settings, last, now):
        """Live (or not known to Demarc yet): now. Otherwise once every interval_minutes."""
        if not isinstance(settings, dict) or settings.get("live"):
            return True
        try:
            minutes = max(1, int(settings.get("interval_minutes") or 5))
        except (TypeError, ValueError):
            minutes = 5
        return now - last >= minutes * 60

    def number(self, now=None):
        """Give sequence numbers to the waiting changes of every organization that is due, in the order they happened."""
        now = now or time.time()
        st = self.q.state()
        settings, sent_at = st.get("settings") or {}, dict(st.get("org_sent") or {})
        with self.q.tx() as c:
            uids = [r[0] for r in c.execute("SELECT DISTINCT org_uid FROM pending")]
            due = [u for u in uids if self._due(settings.get(u), sent_at.get(u, 0), now)]
            if not due:
                return 0
            marks = ",".join("?" * len(due))
            rows = c.execute(f"SELECT id, org_uid, kind, changed_at, body, queued_at FROM pending WHERE org_uid IN ({marks}) "
                             "ORDER BY id", due).fetchall()
            last = int(st.get("last_seq", 0))
            c.executemany("INSERT INTO outbox(seq, org_uid, kind, changed_at, body, queued_at) VALUES(?, ?, ?, ?, ?, ?)",
                          [(last + i, *r[1:]) for i, r in enumerate(rows, 1)])
            c.executemany("DELETE FROM pending WHERE id=?", [(r[0],) for r in rows])
            sent_at.update({u: now for u in due})
            self.q.set(c, last_seq=last + len(rows), org_sent=sent_at)
        return len(rows)

    def _outbox(self, limit):
        with self.q.tx() as c:
            rows = c.execute("SELECT seq, org_uid, kind, changed_at, body FROM outbox ORDER BY seq LIMIT ?", (limit,)).fetchall()
        out, size = [], 0
        for seq, uid, kind, at, body in rows:
            size += len(body) + 200
            if out and size > MAX_PART_BYTES:
                break
            out.append({"seq": seq, "kind": kind, "org_uid": uid, "changed_at": at, "body": json.loads(body)})
        return out

    def send_due(self, client, now=None, rounds=50):
        """Number what is due, then send the outbox in batches until it is empty (or Demarc refuses)."""
        self.number(now)
        for _ in range(rounds):
            items = fit(self._outbox(self.limit), self.q.get("numeric", False))
            if not items:
                return True
            status, data = client.post("/ingest/v1/batch", {"sent_at": iso(), "items": items})
            data = data or {}
            if status == 200 and "acked_seq" in data:
                self._acked(int(data["acked_seq"]), data)
                self.limit = min(MAX_ITEMS, self.limit * 2)
            elif status == 409 and data.get("error") == "sequence_gap":
                if not self._acked(int(data.get("acked_seq", 0)), None):
                    return False
            elif status == 413:
                if self.limit > 1:
                    self.limit = max(1, self.limit // 2)
                else:
                    self._skip([items[0]["seq"]])
            elif status == 422 and data.get("error") == "invalid_item":
                bad = self._bad_indexes(data, len(items))
                if bad is None:
                    self.q.drop()                                # an organization Demarc doesn't know: start again from a full copy
                    return False
                self._skip([items[i]["seq"] for i in bad])
            elif self._refused(status, data):
                return False
            elif status == 422:
                self.q.drop()                                    # bad_sequence: Toner and Demarc disagree; a full copy settles it
                return False
            else:
                raise Unreachable(f"HTTP {status}" + (f" {data['error']}" if data.get("error") else ""))
        return True

    def _acked(self, acked, data):
        """Demarc holds everything up to `acked`. False when it needs changes Toner no longer has (then a full copy follows)."""
        with self.q.tx() as c:
            c.execute("DELETE FROM outbox WHERE seq <= ?", (acked,))
            first = c.execute("SELECT MIN(seq) FROM outbox").fetchone()[0]
            last = int(self.q.get("last_seq", 0))
            if data is not None:
                self._contact(c, data)
        if (first is not None and first != acked + 1) or (first is None and acked != last):
            self.q.drop()
            return False
        return True

    @staticmethod
    def _bad_indexes(data, n):
        """Which items Demarc could not read ({'errors': [{'field': 'items.3.body.name', ...}]}). None when the problem is an
        organization Demarc doesn't know, or the answer names no item."""
        bad = set()
        for e in data.get("errors") or []:
            if e.get("problem") == "unknown_org":
                return None
            parts = str(e.get("field", "")).split(".")
            if len(parts) > 1 and parts[0] == "items" and parts[1].isdigit() and int(parts[1]) < n:
                bad.add(int(parts[1]))
        return sorted(bad) or None

    def _skip(self, seqs):
        """Leave out items Demarc refused, and close the gap they leave (nothing in this batch was stored)."""
        with self.q.tx() as c:
            for seq in sorted(seqs, reverse=True):
                c.execute("DELETE FROM outbox WHERE seq=?", (seq,))
                c.execute("UPDATE outbox SET seq = -(seq - 1) WHERE seq > ?", (seq,))
                c.execute("UPDATE outbox SET seq = -seq WHERE seq < 0")
            st = self.q.state()
            self.q.set(c, last_seq=int(st.get("last_seq", 0)) - len(seqs), skipped=int(st.get("skipped", 0)) + len(seqs))

    # ---------- a full copy
    def snapshot_items(self):
        """(items, known rows, cursors): everything as it is now. Organizations first, then devices, then the newest results."""
        orgs, devices, results, known, cursors = [], [], [], [], {}
        when = iso()
        for org, uid, body in org_list():
            orgs.append({"kind": "org", "org_uid": uid, "changed_at": when, "body": body})
            known.append((uid, "org", "", _hash(body), json.dumps(body)))
            for name, b in devices_of(org).items():
                devices.append({"kind": "device", "org_uid": uid, "changed_at": when, "body": b})
                known.append((uid, "device", name, _hash(b), ""))
            rows, top = latest_results(org)
            results += [{"kind": "result", "org_uid": uid, "changed_at": b["ran_at"], "body": b} for b in rows]
            cursors[uid] = top
        for (u, h, b) in self._gone_orgs({k[0] for k in known}):
            orgs.append({"kind": "org", "org_uid": u, "changed_at": when, "body": allowed("org", json.loads(b))})
            known.append((u, "org", "", h, b))
        return orgs + devices + results, known, cursors

    def _gone_orgs(self, here):
        """Organizations removed from Toner that Demarc was told about: still sent (archived), so they stay archived there."""
        with self.q.tx() as c:
            return [(u, h, b) for u, h, b in c.execute("SELECT org_uid, hash, body FROM known WHERE kind='org' AND hash=?", (GONE,))
                    if u not in here]

    @staticmethod
    def split(items):
        parts, cur, size = [], [], 0
        for it in items:
            n = len(json.dumps(it["body"])) + 200
            if cur and (len(cur) >= MAX_ITEMS or size + n > MAX_PART_BYTES):
                parts.append(cur)
                cur, size = [], 0
            cur.append(it)
            size += n
        return parts + [cur] if cur or not parts else parts

    def send_snapshot(self, client, now=None):
        """Send everything as it is now, in parts. When Demarc has every part it replaces what it held from this Toner."""
        items, known, cursors = self.snapshot_items()
        parts = self.split(items)
        seq = int(self.q.get("last_seq", 0))
        sid, taken = secrets.token_hex(12), iso()
        with self.q.tx() as c:
            c.execute("DELETE FROM pending")
            c.execute("DELETE FROM outbox")
        numeric = self.q.get("numeric", False)
        for i, part in enumerate(parts, 1):
            part[:] = fit(part, numeric)
            self.q.set(snapshot={"part": i, "parts": len(parts)})
            for _try in range(5):
                status, data = client.post("/ingest/v1/snapshot", {"snapshot_id": sid, "part": i, "parts": len(parts), "seq": seq,
                                                                   "taken_at": taken, "sent_at": iso(), "items": part})
                data = data or {}
                if status == 422 and data.get("error") == "invalid_item":
                    bad = self._bad_indexes(data, len(part))
                    if bad:
                        part[:] = [it for j, it in enumerate(part) if j not in bad]
                        self.q.set(skipped=int(self.q.get("skipped", 0)) + len(bad))
                        continue
                break
            if self._refused(status, data):
                return False
            if status != 200:
                self.q.set(snapshot=None)
                raise Unreachable(f"HTTP {status}" + (f" {data['error']}" if data.get("error") else ""))
        if not data.get("complete"):
            self.q.set(snapshot=None)
            return False                                         # a part went missing: the next round sends a new copy
        with self.q.tx() as c:
            c.execute("DELETE FROM known")
            c.execute("DELETE FROM cursors")
            c.execute("DELETE FROM backup_cursors")              # backups follow the full copy, from the Config history setting
            c.executemany("INSERT OR REPLACE INTO known(org_uid, kind, name, hash, body) VALUES(?, ?, ?, ?, ?)", known)
            c.executemany("INSERT OR REPLACE INTO cursors(org_uid, result_id) VALUES(?, ?)", list(cursors.items()))
            self._contact(c, data, need_snapshot=None, dropped=None, snapshot=None, last_seq=seq, org_sent=None)
        return True


# ---------------------------------------------------------------- what Settings shows
def status_lines(queue=None):
    """The Status lines on Settings > Connections > Demarc, in the approved words."""
    cfg = config()
    if not (cfg["address"] and token()):
        return [T_NOT_CONNECTED]
    q = queue or Queue()
    st = q.state()
    if not cfg["enabled"]:
        return [T_OFF]
    if st.get("stopped") == "token":
        return [T_TOKEN]
    if st.get("stopped") == "cert":
        return [T_CERT]
    from core import display
    lines = [T_CONNECTED.format(version=st.get("demarc_version") or "", address=cfg["address"],
                                when=display.ago(st.get("last_contact")) if st.get("last_contact") else "-")]
    err = st.get("error") or {}
    if err.get("code") == "unreachable":
        lines.append(T_UNREACHABLE_SINCE.format(when=str(err.get("since", ""))[:16], reason=err.get("reason", "")))
    if st.get("dropped"):
        lines.append(T_DROPPED)
    snap = st.get("snapshot")
    if snap:
        lines.append(T_SNAPSHOT.format(p=snap["part"], n=snap["parts"]))
    n = q.waiting()
    if n:
        lines.append(T_WAITING_ONE if n == 1 else T_WAITING.format(n=n))
    if st.get("skipped"):
        lines.append(T_SKIPPED.format(n=st["skipped"]))
    return lines


# ---------------------------------------------------------------- the background thread
_thread = None
_stop = threading.Event()
_kick = threading.Event()


_try_lock = platforms.try_lock                      # the lock file beside the queue: one Toner process sends


def _run():
    sender, lock = Sender(), None
    path = queue_path().with_name(queue_path().name + ".lock")
    while not _stop.is_set():
        if lock is None:
            lock = _try_lock(path)
            if lock is None:
                _stop.wait(30)
                continue
        try:
            delay = sender.step()
        except Exception:
            log.exception("Demarc: sending failed")
            delay = 30
        _kick.wait(delay)
        _kick.clear()
    if lock is not None:
        lock.close()                                       # closing the file lets the lock go


def apply():
    """Start the sender (it waits quietly until Demarc is connected and sending is on)."""
    global _thread
    if _thread is None or not _thread.is_alive():
        _stop.clear()
        _thread = threading.Thread(target=_run, name="demarc", daemon=True)
        _thread.start()
    kick()


def kick():
    _kick.set()


def stop():
    global _thread
    _stop.set()
    _kick.set()
    if _thread is not None:
        _thread.join(5)
    _thread = None
