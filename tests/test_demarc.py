# Run directly (python tests/test_demarc.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Demarc: permanent organization IDs, enrollment with a pinned certificate, the queue, snapshots and batches, Live and interval,
# the 7-day / 500 MB cap, UTC times, the allowlist (no secret is ever sent) and Settings > Connections > Demarc.
# A small HTTPS server in this file stands in for Demarc and refuses anything Demarc's /ingest/v1 would refuse.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
import os, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "demarc%d.db" % int(time.time() * 1000)); os.environ["APPDATA"] = SP
for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(k, None)
os.environ["NO_PROXY"] = "127.0.0.1,localhost"
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
keyring.delete_password = lambda s, u: STORE.pop((s, u), None)

import gzip, hashlib, json, math, re, socket, sqlite3, ssl, threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from core import audit, db, demarc, extstore, orgs
from drivers.base import Result

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

def dev(name, **kw):
    return dict(dict(name=name, vendor="cisco", host="10.0.0.1", port=0, platform="", username="admin", site="default", verify_ssl=0,
                     ha_expected=0, enabled=1, location="", details="", folder_id=None), **kw)


# ---------------------------------------------------------------- a stand-in for Demarc
# Demarc's allowlist, copied from Demarc's ingest.py on purpose (not from core/demarc.py), so a drift on Toner's side is caught.
DEMARC_BODIES = {"org": {"name", "code", "colour", "archived"},
                 "device": {"name", "address", "platform", "folder", "groups", "tags", "notes"},
                 "device_removed": {"name"},
                 "result": {"device", "check", "status", "value", "message", "ran_at", "numeric"},    # numeric: from Demarc 0.0.3
                 "backup": {"device", "taken_at", "sha", "size", "lines", "added", "removed", "masked"},   # these two: from 0.0.8
                 "backup_log": {"device", "at", "status", "message"}}
LATER = {"folder", "problem_state", "schedule"}
SECRET_LIKE = re.compile(r"(?i)pass|secret|token|key|credential|community|psk|private")    # the same test Demarc runs on its side
TZ = re.compile(r"(Z|[+-]\d\d:\d\d)$")


def make_cert(folder, name):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demarc")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    cp, kp = os.path.join(folder, name + ".crt"), os.path.join(folder, name + ".key")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cp, kp, cert.fingerprint(hashes.SHA256()).hex()


class FakeDemarc:
    def __init__(self, cert="a", port=0, files=None):
        self.cp, self.kp, self.fingerprint = files or make_cert(SP, cert + str(id(self)))
        self.requests = []                  # (path, headers, payload, gzipped) of what was received (tests clear it)
        self.seen = []                      # every payload ever received (never cleared: the secret scan reads it)
        self.inject = []                    # (path, status, reply) to answer once instead of handling
        self.codes = {"GOOD-CODE-1234": "ok", "OLD-CODE": "expired"}
        self.token, self.last_seq, self.revoked = None, 0, False
        self.orgs, self.devices, self.latest, self.results = {}, {}, {}, []
        self.backups_held, self.backup_log = {}, []     # from 0.0.8: (org_uid, device) -> {(taken_at, sha): body}; log entries
        self.settings = {}                  # org_uid -> {'live', 'interval_minutes', 'unmasked_configs'}
        self.unmasked = {}                  # from 0.0.8: (org_uid, device, taken_at, sha) -> the unmasked text
        self.parts, self.not_demarc, self.stored_batches = {}, False, 0
        self.version = "0.0.1"              # from 0.0.3 Demarc names its version in every reply and takes a result's value
        self.bad = []                       # what the server refused, and why (a test fails if Toner sent anything wrong)
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(405); self.end_headers()

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if fake.not_demarc:
                    return self._send(404, b"<html>not here</html>", "text/html")
                gz = self.headers.get("Content-Encoding", "").lower() == "gzip"
                try:
                    payload = json.loads(gzip.decompress(raw) if gz else raw)
                except Exception:
                    return self._json(400, {"error": "bad_gzip"})
                fake.requests.append((self.path, dict(self.headers), payload, gz))
                if self.path != "/ingest/v1/unmasked":            # the one request meant to carry secrets: checked on its own
                    fake.seen.append(payload)
                fake.gzipped = getattr(fake, "gzipped", True) and gz
                for i, (p, status, reply) in enumerate(fake.inject):
                    if p == self.path:
                        del fake.inject[i]
                        if status is None:                                        # store it, then drop the answer
                            fake.handle(self.path, self.headers, payload)
                            self.connection.close()
                            return
                        return self._json(status, reply)
                status, reply = fake.handle(self.path, self.headers, payload)
                self._json(status, reply)

            def _json(self, status, data):
                self._send(status, json.dumps(data).encode(), "application/json")

            def _send(self, status, body, ctype):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cp, self.kp)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.url = f"https://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()

    def refuse(self, why):
        self.bad.append(why)
        return 422, {"error": "invalid_item", "errors": [{"field": why, "problem": "refused"}]}

    def _items_ok(self, items, batch):
        allowed_item = {"kind", "org_uid", "changed_at", "body"} | ({"seq"} if batch else set())
        for i, it in enumerate(items):
            if set(it) != allowed_item:
                return self.refuse(f"items.{i}: fields {sorted(set(it) ^ allowed_item)}")
            if not re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", it["org_uid"]):
                return self.refuse(f"items.{i}.org_uid")
            if not TZ.search(it["changed_at"]):
                return self.refuse(f"items.{i}.changed_at has no time zone")
            if it["kind"] in LATER:
                continue
            if it["kind"] not in DEMARC_BODIES:
                return self.refuse(f"items.{i}.kind")
            extra = set(it["body"]) - (DEMARC_BODIES[it["kind"]] - (set() if self.numeric() else {"numeric"}))
            if extra:
                return self.refuse(f"items.{i}.body: {sorted(extra)}")
            if "numeric" in it["body"] and not (isinstance(it["body"]["numeric"], (int, float)) and math.isfinite(it["body"]["numeric"])):
                return self.refuse(f"items.{i}.body.numeric")
            if it["kind"] == "result" and (it["body"]["status"] not in ("OK", "WARN", "FAIL", "ERROR", "N/A") or not TZ.search(it["body"]["ran_at"])):
                return self.refuse(f"items.{i}.body.status/ran_at")
            if it["kind"] in ("backup", "backup_log") and not self.backups():
                return self.refuse(f"items.{i}.kind {it['kind']} sent to Demarc {self.version}")
            b = it["body"]
            if it["kind"] == "backup" and (not re.fullmatch(r"[0-9a-f]{64}", b["sha"]) or not TZ.search(b["taken_at"])
                                           or not isinstance(b["masked"], str) or len(b["masked"]) > 5_000_000
                                           or not all(isinstance(b[k], int) and b[k] >= 0 for k in ("size", "lines", "added", "removed"))):
                return self.refuse(f"items.{i}.body (backup)")
            if it["kind"] == "backup_log" and (b["status"] not in ("new", "changed", "unchanged", "error") or not TZ.search(b["at"])):
                return self.refuse(f"items.{i}.body (backup_log)")
        return None

    def _apply(self, items):
        for i, it in enumerate(items):
            uid, b = it["org_uid"], it["body"]
            if it["kind"] == "org":
                self.orgs[uid] = b
                self.settings.setdefault(uid, {"live": True, "interval_minutes": 5, "unmasked_configs": False})
            elif uid not in self.orgs:
                return 422, {"error": "invalid_item", "errors": [{"field": f"items.{i}.org_uid", "problem": "unknown_org"}]}
            elif it["kind"] == "device":
                self.devices[(uid, b["name"])] = dict(b, removed=False)
            elif it["kind"] == "device_removed":
                self.devices[(uid, b["name"])] = dict(self.devices.get((uid, b["name"]), {}), removed=True)
            elif it["kind"] == "result":
                self.results.append((uid, b))
                self.latest[(uid, b["device"], b["check"])] = b
            elif it["kind"] == "backup":
                self.backups_held.setdefault((uid, b["device"]), {})[(b["taken_at"], b["sha"])] = b      # stored once, as Demarc does
            elif it["kind"] == "backup_log":
                self.backup_log.append((uid, b))
        return None

    def backups(self):
        return tuple(map(int, self.version.split("."))) >= (0, 0, 8)

    def numeric(self):
        return tuple(map(int, self.version.split("."))) >= (0, 0, 3)

    def reply(self, **more):
        named = {"demarc_version": self.version} if self.numeric() else {}
        return {"acked_seq": self.last_seq, "server_time": "2026-10-18T12:00:00Z", "settings": dict(self.settings),
                "ignored_older": 0, "skipped_kinds": {}, **named, **more}

    def handle(self, path, headers, p):
        if path == "/ingest/v1/enroll":
            if set(p) != {"code", "install_uid", "name", "toner_version"} or not re.fullmatch(r"[A-Za-z0-9-]{8,64}", p["install_uid"]):
                return self.refuse("enroll fields")
            state = self.codes.pop(p["code"], None)
            if state is None:
                return 403, {"error": "bad_code"}
            if state == "expired":
                return 403, {"error": "code_expired"}
            self.token, self.last_seq, self.revoked = "dmt_" + "x" * 40, 0, False
            self.install = p
            return 200, {"token": self.token, "demarc_version": self.version, "server_time": "2026-10-18T12:00:00Z", "acked_seq": 0}
        auth = headers.get("Authorization", "")
        if not self.token or auth != "Bearer " + self.token:
            return 401, {"error": "bad_token"}
        if self.revoked:
            return 403, {"error": "revoked"}
        if path == "/ingest/v1/unmasked":
            if set(p) != {"org_uid", "device", "taken_at", "sha", "text"} or not re.fullmatch(r"[0-9a-f]{64}", p["sha"]) \
                    or not TZ.search(p["taken_at"]) or not self.backups():
                return self.refuse("unmasked fields")
            if not (self.settings.get(p["org_uid"]) or {}).get("unmasked_configs"):
                return 403, {"error": "unmasked_off"}
            self.unmasked[(p["org_uid"], p["device"], p["taken_at"], p["sha"])] = p["text"]
            return 200, {"stored": True, "server_time": "2026-10-18T12:00:00Z", "demarc_version": self.version, "settings": dict(self.settings)}
        if not TZ.search(p.get("sent_at", "")):
            return self.refuse("sent_at")
        if path == "/ingest/v1/batch":
            if set(p) != {"sent_at", "items"} or len(p["items"]) > 5000:
                return self.refuse("batch fields")
            bad = self._items_ok(p["items"], True)
            if bad:
                return bad
            seqs = [it["seq"] for it in p["items"]]
            if any(b != a + 1 for a, b in zip(seqs, seqs[1:])):
                self.bad.append("bad_sequence")
                return 422, {"error": "bad_sequence"}
            if seqs and seqs[0] > self.last_seq + 1:
                return 409, {"error": "sequence_gap", "acked_seq": self.last_seq}
            fresh = [it for it in p["items"] if it["seq"] > self.last_seq]
            bad = self._apply(fresh)
            if bad:
                return bad
            self.last_seq = max([self.last_seq, *seqs])
            self.stored_batches += 1
            return 200, self.reply()
        if path == "/ingest/v1/snapshot":
            if set(p) != {"snapshot_id", "part", "parts", "seq", "taken_at", "sent_at", "items"} or len(p["items"]) > 5000:
                return self.refuse("snapshot fields")
            bad = self._items_ok(p["items"], False)
            if bad:
                return bad
            self.parts = {k: v for k, v in self.parts.items() if k[0] == p["snapshot_id"]}
            self.parts[(p["snapshot_id"], p["part"])] = p["items"]
            if len(self.parts) < p["parts"]:
                return 200, {"complete": False, "received_parts": len(self.parts), "parts": p["parts"], "acked_seq": self.last_seq,
                             "server_time": "2026-10-18T12:00:00Z"}
            items = [it for k in sorted(self.parts) for it in self.parts[k]]
            sent = {}
            for it in items:
                if it["kind"] == "device":
                    sent.setdefault(it["org_uid"], set()).add(it["body"]["name"])
                elif it["kind"] == "org":
                    sent.setdefault(it["org_uid"], set())
            bad = self._apply(items)
            if bad:
                return bad
            for (uid, name), d in self.devices.items():                       # left out of the snapshot: removed
                if uid in sent and name not in sent[uid]:
                    d["removed"] = True
            self.parts, self.last_seq = {}, p["seq"]
            self.snapshots = getattr(self, "snapshots", 0) + 1
            return 200, {"complete": True, **self.reply()}
        return 404, {"error": "not_found"}

    def live_devices(self, uid):
        return sorted(n for (u, n), d in self.devices.items() if u == uid and not d.get("removed"))

    def payloads(self):
        return [p for _path, _h, p, _gz in self.requests]


STATE = ("token", "last_seq", "revoked", "orgs", "devices", "latest", "results", "settings", "codes", "version", "backups_held",
         "backup_log", "unmasked")


def restart(old):
    """The same Demarc started again on its port, with its certificate and what it holds."""
    new = FakeDemarc(port=old.port, files=(old.cp, old.kp, old.fingerprint))
    for k in STATE:
        setattr(new, k, getattr(old, k))
    return new


# ================================================================ organization IDs
print("== a permanent ID for each organization")
db.init()
acme = orgs.create("Acme Charter", "ACME")
globex = orgs.create("Globex", "GLOBEX")
uids = {r["id"]: r["uid"] for r in orgs.list_orgs()}
check("each new organization gets an ID", all(re.fullmatch(r"[0-9a-f-]{36}", u or "") for u in uids.values()) and len(set(uids.values())) == 2, uids)
db.init(); db.forget_orgs()
check("the IDs stay the same when the database is opened again", {r["id"]: r["uid"] for r in orgs.list_orgs()} == uids)
orgs.update(acme, "Acme Charter Schools", "ACME", "#2f6fed")
db.forget_orgs()
check("renaming an organization keeps its ID", orgs.get(acme)["uid"] == uids[acme])
check("the database is at the newest schema version", db.schema_version() == db.SCHEMA_VERSION >= 7)

old = os.path.join(SP, "before-uids%d.db" % int(time.time() * 1000))         # a database from 1.6.1: organizations without IDs
c = sqlite3.connect(old)
c.executescript("CREATE TABLE orgs (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL COLLATE NOCASE, code TEXT UNIQUE NOT NULL COLLATE NOCASE, "
                "colour TEXT DEFAULT '', archived INTEGER DEFAULT 0, created TEXT DEFAULT '');"
                "INSERT INTO orgs(name, code) VALUES('Old One', 'OLD1'); INSERT INTO orgs(name, code) VALUES('Old Two', 'OLD2');")
c.execute("PRAGMA user_version = 6"); c.commit(); c.close()
saved_db = os.environ["NETCHECK_DB"]
os.environ["NETCHECK_DB"] = old
db._wal_set.clear(); db.forget_orgs()
db.init(); db.forget_orgs()
migrated = [r["uid"] for r in db.org_rows()]
check("upgrading gives every existing organization its own ID", len(migrated) == 2 and len(set(migrated)) == 2 and all(migrated), migrated)
db.init(); db.forget_orgs()
check("and upgrading again changes nothing", [r["uid"] for r in db.org_rows()] == migrated)
os.environ["NETCHECK_DB"] = saved_db
db._wal_set.clear(); db.forget_orgs(); db._forget_settings(); db._invalidate_folders()

print("== this install's ID")
iu = demarc.install_uid()
check("the install ID is made once and kept", iu == demarc.install_uid() and re.fullmatch(r"[A-Za-z0-9-]{8,64}", iu))
check("Global's ID comes from it", demarc.global_uid() == "global:" + iu and re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", demarc.global_uid()))
check("neither the install ID nor the Demarc settings travel in an exported settings file",
      "install_uid" not in db.export_settings() and "demarc" not in db.export_settings())
check("they are kept in the Global file even while an organization is picked", {"install_uid", "demarc"} <= db.GLOBAL_ONLY)
check("the token is kept in Toner's own vault, never sent to a password manager", extstore.is_internal(demarc.TOKEN_SECRET))

# ================================================================ times and the allowlist
print("== times are sent in UTC")
local = datetime(2026, 7, 1, 9, 30, 0)
want = local.astimezone().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
check("a stored local time is converted to UTC ISO 8601", demarc.utc_of("2026-07-01 09:30:00") == want, demarc.utc_of("2026-07-01 09:30:00"))
check("winter time too", demarc.utc_of("2026-01-15 23:10:05") == datetime(2026, 1, 15, 23, 10, 5).astimezone().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
check("now is in UTC, with a Z", demarc.iso().endswith("Z") and abs((datetime.strptime(demarc.iso(), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds()) < 5)
check("an unreadable time becomes now rather than being refused", TZ.search(demarc.utc_of("garbage")))

print("== the allowlist")
check("Toner's list of fields is exactly Demarc's", {k: set(v) for k, v in demarc.BODIES.items()} == DEMARC_BODIES)
check("no allowlisted field looks like a secret", not [f for spec in demarc.BODIES.values() for f in spec if SECRET_LIKE.search(f)])
try:
    demarc.allowed("device", {"name": "x", "password": "p"}); check("a field not on the list is refused", False)
except KeyError:
    check("a field not on the list is refused", True)
try:
    demarc.allowed("credentials", {}); check("a kind not on the list is refused", False)
except KeyError:
    check("a kind not on the list is refused", True)
long = demarc.allowed("result", {"device": "d" * 300, "check": "c", "status": "OK", "value": "v" * 2000, "message": "m" * 5000, "ran_at": "x"})
check("long text is cut to what Demarc keeps", len(long["device"]) == 255 and len(long["value"]) == 1000 and len(long["message"]) == 4000)

print("== addresses")
check("a name alone gets HTTPS and port 8760", demarc.parse_address(" demarc.example.com ")[0] == "https://demarc.example.com:8760")
check("a port and https:// are kept", demarc.parse_address("https://10.1.2.3:9443/")[:3] == ("https://10.1.2.3:9443", "10.1.2.3", 9443))
check("IPv6 works", demarc.parse_address("[fd00::5]:8760")[0] == "https://[fd00::5]:8760")
for text, said in (("http://demarc", demarc.T_HTTPS), ("", demarc.T_NEED)):
    try:
        demarc.parse_address(text); check(f"refused: {text!r}", False)
    except demarc.DemarcError as e:
        check(f"refused: {text!r}", str(e) == said, str(e))

# ================================================================ some data to send
print("== devices with passwords, SNMP communities and API keys")
SECRETS = {"Hunter2-p@ss!", "c0mmunity-S3cret", "APIKEY-abcdef0123456789", "v3-auth-Sekrit", "v3-priv-Sekrit", "proxy-P4ss"}
fid = db.create_folder("Sites")
sub = db.create_folder("North", fid)
db.save_device(dev("core-sw1", folder_id=sub, location="Main office", tags="core, Edge", details="Rack 4",
                   snmp=json.dumps({"version": "3", "user": "monitor"}), fields="Warranty: 2027-01-01"))
db.set_secret(db.secret_name("core-sw1"), "Hunter2-p@ss!")
db.set_secret(db.secret_name("core-sw1", "snmp_auth"), "v3-auth-Sekrit")
db.set_secret(db.secret_name("core-sw1", "snmp_priv"), "v3-priv-Sekrit")
db.save_device(dev("jump", shared=1, vendor="linux"))
with db.within(acme):
    db.save_device(dev("edge-fw", vendor="paloalto", host="203.0.113.5"))
    db.set_secret(db.secret_name("edge-fw"), "APIKEY-abcdef0123456789")
    db.set_secret(db.secret_name("edge-fw", "proxy"), "proxy-P4ss")
    db.save_device(dev("ap-1", vendor="unifi"))
    db.set_secret(db.secret_name("ap-1", "snmp"), "c0mmunity-S3cret")
    db.save_run([Result("edge-fw", "cpu", "OK", "12%", "fine"), Result("edge-fw", "memory", "WARN", "85%", "high")])
    db.save_run([Result("edge-fw", "cpu", "FAIL", "97%", "very busy")])
db.save_run([Result("core-sw1", "uptime", "OK", "40 days", "")])
body = demarc.devices_of(db.GLOBAL)["core-sw1"]
check("a device is sent with its folder path, location, tags and details",
      body == {"name": "core-sw1", "address": "10.0.0.1", "platform": "Cisco", "folder": "Sites/North", "groups": ["Main office"],
               "tags": ["core", "Edge"], "notes": "Rack 4"}, body)
check("its user name, SNMP settings and custom fields are not", "admin" not in json.dumps(body) and "monitor" not in json.dumps(body)
      and "Warranty" not in json.dumps(body))

# ================================================================ enrolling
print("== connecting")
server = FakeDemarc()
q = demarc.Queue()
check("before connecting the status says so", demarc.status_lines(q) == [demarc.T_NOT_CONNECTED])
found = demarc.probe(server.url.replace("https://", ""))
check("Toner reads Demarc's certificate before sending anything", found.fingerprint == server.fingerprint and not server.requests)
check("a self-signed certificate is not trusted by this computer, so it is pinned", found.trusted is False)
for code, said in (("WRONG", demarc.T_BAD_CODE), ("OLD-CODE", demarc.T_EXPIRED)):
    try:
        demarc.enroll(found, code, q); check(f"refused code {code}", False)
    except demarc.DemarcError as e:
        check(f"refused code {code}", str(e) == said, str(e))
server.inject.append(("/ingest/v1/enroll", 429, {"error": "too_many_attempts"}))
try:
    demarc.enroll(found, "GOOD-CODE-1234", q); check("too many tries", False)
except demarc.DemarcError as e:
    check("too many tries", str(e) == demarc.T_TOO_MANY, str(e))
other = FakeDemarc(cert="other")
other.not_demarc = True
try:
    demarc.enroll(demarc.probe(other.url), "GOOD-CODE-1234", q); check("something that is not Demarc", False)
except demarc.DemarcError as e:
    check("something that is not Demarc", str(e) == demarc.T_NOT_DEMARC.format(address=other.url), str(e))
s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = s.getsockname()[1]; s.close()
try:
    demarc.probe(f"127.0.0.1:{closed}"); check("nothing listening", False)
except demarc.DemarcError as e:
    check("nothing listening", str(e).startswith(f"Can't reach Demarc at https://127.0.0.1:{closed}: "), str(e))
wrong = demarc.Probe(server.url, "127.0.0.1", server.port, other.fingerprint, False)
n_before = len(server.requests)
try:
    demarc.enroll(wrong, "GOOD-CODE-1234", q); check("a certificate other than the one confirmed", False)
except demarc.DemarcError as e:
    check("a certificate other than the one confirmed is refused before the code is sent", str(e) == demarc.T_CERT and len(server.requests) == n_before, str(e))
other.close()

demarc.enroll(found, " GOOD-CODE-1234 ", q)
cfg = demarc.config()
check("connected: the token is in the vault", STORE.get((db.SERVICE, demarc.TOKEN_SECRET)) == server.token)
check("the address, the pinned fingerprint and sending on are kept", cfg["address"] == server.url and cfg["pin"] == server.fingerprint
      and cfg["enabled"] and not cfg["trusted"])
check("Demarc was told this install's ID, name and Toner version", server.install["install_uid"] == iu and server.install["name"]
      and server.install["toner_version"])
with db.within(db.GLOBAL):
    check("the audit log says so", any(r["action"] == f"Demarc connected: {server.url}" for r in audit.recent()))
check("the status says connected", demarc.status_lines(q)[0].startswith("Connected to Demarc 0.0.1 at " + server.url))

# ================================================================ the first full copy
print("== the first contact is a full copy")
snd = demarc.Sender(q)
snd.step()
snaps = [p for path, _h, p, _g in server.requests if path == "/ingest/v1/snapshot"]
check("a snapshot was sent and Demarc has all of it", snaps and getattr(server, "snapshots", 0) == 1 and not q.get("need_snapshot"))
items = [it for p in snaps for it in p["items"]]
kinds = [it["kind"] for it in items]
check("organizations come first, then devices, then results", kinds == sorted(kinds, key=["org", "device", "result"].index), kinds)
check("Global and both organizations are there", set(server.orgs) == {demarc.global_uid(), uids[acme], uids[globex]}
      and server.orgs[demarc.global_uid()]["name"] == "Global" and server.orgs[uids[acme]]["name"] == "Acme Charter Schools")
check("every device is in its own organization (a Shared one under Global)", server.live_devices(demarc.global_uid()) == ["core-sw1", "jump"]
      and server.live_devices(uids[acme]) == ["ap-1", "edge-fw"] and server.live_devices(uids[globex]) == [])
cpu = server.latest[(uids[acme], "edge-fw", "cpu")]
check("only the newest result of each check is in the copy", cpu["status"] == "FAIL" and cpu["value"] == "97%"
      and len([r for r in server.results if r[1]["device"] == "edge-fw" and r[1]["check"] == "cpu"]) == 1)
check("the copy restarts the sequence from 0", server.last_seq == 0 and q.get("last_seq") == 0)
check("Demarc's settings for each organization are kept", set(q.get("settings")) == set(server.orgs))
check("each part is gzipped", all(g for _p, _h, _x, g in server.requests))

print("== a big copy goes in parts")
saved_max = demarc.MAX_ITEMS
demarc.MAX_ITEMS = 2
parts = demarc.Sender.split(items)
check("parts of at most MAX_ITEMS items, nothing lost", [len(p) for p in parts][:-1] == [2] * (len(parts) - 1) and sum(map(len, parts)) == len(items))
demarc.MAX_ITEMS = saved_max
check("an empty copy is still one part", demarc.Sender.split([]) == [[]])

# ================================================================ batches of changes
print("== changes are sent as batches")
server.requests.clear()
db.save_device(dev("core-sw2", host="10.0.0.2"))
with db.within(acme):
    d = next(x for x in db.list_devices() if x["name"] == "ap-1")
    db.save_device({**d, "host": "10.9.9.9"})
    db.save_run([Result("edge-fw", "cpu", "OK", "20%", "")])
snd.step()
batches = [p for path, _h, p, _g in server.requests if path == "/ingest/v1/batch"]
seqs = [it["seq"] for p in batches for it in p["items"]]
check("one batch, numbered from 1", len(batches) == 1 and seqs == list(range(1, len(seqs) + 1)), seqs)
check("the new device, the changed one and the new result arrived", "core-sw2" in server.live_devices(demarc.global_uid())
      and server.devices[(uids[acme], "ap-1")]["address"] == "10.9.9.9" and server.latest[(uids[acme], "edge-fw", "cpu")]["value"] == "20%")
check("nothing unchanged was sent again", {it["body"].get("name") for p in batches for it in p["items"] if it["kind"] == "device"} == {"core-sw2", "ap-1"})
check("Demarc stored them and Toner's outbox is empty", server.last_seq == seqs[-1] and q.waiting() == 0)
n = len(server.requests)
snd.step()
check("a round with no changes sends nothing", len(server.requests) == n)

print("== removing and renaming")
server.requests.clear()
d = next(x for x in db.list_devices() if x["name"] == "core-sw2" and x["org"] == db.GLOBAL)
db.save_device({**d, "name": "core-sw2-new"})
with db.within(acme):
    d = next(x for x in db.list_devices() if x["name"] == "ap-1")
    db.delete_device(d["id"])
snd.step()
check("a renamed device: the old name removed, the new one added", "core-sw2" not in server.live_devices(demarc.global_uid())
      and "core-sw2-new" in server.live_devices(demarc.global_uid()))
check("a removed device is removed in Demarc", server.live_devices(uids[acme]) == ["edge-fw"])
with db.within(globex):
    db.save_device(dev("gx-sw"))
snd.step()
orgs.remove(globex)
db.forget_orgs()
snd.step()
check("a removed organization is archived in Demarc, its devices removed", server.orgs[uids[globex]]["archived"] is True
      and server.live_devices(uids[globex]) == [])
n = len(server.requests)
snd.step()
check("...and only once", len(server.requests) == n)
orgs.set_archived(acme, True); db.forget_orgs()
snd.step()
check("archiving an organization is sent", server.orgs[uids[acme]]["archived"] is True)
orgs.set_archived(acme, False); db.forget_orgs()
snd.step()

print("== Live and interval, per organization")
server.settings[uids[acme]] = {"live": False, "interval_minutes": 10, "unmasked_configs": False}
db.save_device(dev("core-sw3"))
snd.step()                                                    # Demarc's reply carries the new settings
t0 = time.time()
q.set(org_sent={uids[acme]: t0})
with db.within(acme):
    db.save_run([Result("edge-fw", "memory", "OK", "40%", "")])
db.save_device(dev("core-sw4"))
server.requests.clear()
snd.step(t0 + 1)
sent_uids = {it["org_uid"] for p in server.payloads() for it in p.get("items", [])}
check("a Live organization is sent at once", "core-sw4" in server.live_devices(demarc.global_uid()))
check("one that is not waits for its interval", uids[acme] not in sent_uids and q.waiting() == 1, (sent_uids, q.waiting()))
check("the status says how many changes wait", demarc.T_WAITING_ONE in demarc.status_lines(q))
snd.step(t0 + 9 * 60)
check("...still waiting after 9 minutes", q.waiting() == 1)
snd.step(t0 + 10 * 60 + 1)
check("...and sent after 10", q.waiting() == 0 and server.latest[(uids[acme], "edge-fw", "memory")]["value"] == "40%")
seqs = [it["seq"] for p in server.payloads() for it in p.get("items", [])]
check("sequence numbers stay contiguous across organizations", seqs == list(range(seqs[0], seqs[0] + len(seqs))), seqs)
server.settings[uids[acme]]["live"] = True

# ================================================================ when things go wrong
print("== a reply that never arrived")
db.save_device(dev("core-sw5"))
server.inject.append(("/ingest/v1/batch", None, None))        # Demarc stores it, then the connection drops
before = server.last_seq
snd.step()
check("Toner keeps the changes and tries again later", q.waiting() == 1 and q.get("error", {}).get("code") == "unreachable")
check("...after 15 seconds", 14 <= q.get("next_try") - time.time() <= 16)
q.set(next_try=None)
snd.step()
check("the resend is stored once, and acknowledged", q.waiting() == 0 and server.last_seq == before + 1 and q.get("error") is None)

print("== Demarc lost track (409 sequence_gap)")
db.save_device(dev("core-sw6")); db.save_device(dev("core-sw7")); db.save_device(dev("core-sw8"))
snd.collect(); snd.number()
first = q.get("last_seq") - 2
server.inject.append(("/ingest/v1/batch", 409, {"error": "sequence_gap", "acked_seq": first}))
server.last_seq = first                                        # Demarc already holds the first one
server.requests.clear()
snd.step()
b = [p for path, _h, p, _g in server.requests if path == "/ingest/v1/batch"]
check("Toner resends from the one after acked_seq", len(b) == 2 and b[1]["items"][0]["seq"] == first + 1 and q.waiting() == 0,
      [[i["seq"] for i in x["items"]] for x in b])
db.save_device(dev("core-sw9"))
server.last_seq = 0                                            # Demarc was restored from an older backup
server.requests.clear()
snd.step()
check("when Demarc needs changes Toner no longer has, a full copy follows", q.get("need_snapshot") is True)
snd.step()
check("...and is sent", not q.get("need_snapshot") and server.last_seq == q.get("last_seq") and "core-sw9" in server.live_devices(demarc.global_uid()))

print("== too large (413)")
for i in range(6):
    db.save_device(dev(f"bulk-{i}"))
server.inject.append(("/ingest/v1/batch", 413, {"error": "too_large"}))
server.requests.clear()
snd.limit = 4
snd.step()
b = [len(p["items"]) for path, _h, p, _g in server.requests if path == "/ingest/v1/batch"]
check("the batch is halved, then grows again once Demarc takes it", b == [4, 2, 4] and q.waiting() == 0
      and "bulk-5" in server.live_devices(demarc.global_uid()), b)
snd.limit = demarc.MAX_ITEMS

print("== items Demarc can't read (422)")
db.save_device(dev("odd-1")); db.save_device(dev("odd-2")); db.save_device(dev("odd-3"))
server.inject.append(("/ingest/v1/batch", 422, {"error": "invalid_item", "errors": [{"field": "items.1.body.name", "problem": "string_too_long"}]}))
server.requests.clear()
snd.step()
b = [p for path, _h, p, _g in server.requests if path == "/ingest/v1/batch"]
check("the item is left out and the rest go, still contiguous", len(b) == 2 and len(b[1]["items"]) == 2
      and [i["seq"] for i in b[1]["items"]] == [b[0]["items"][0]["seq"], b[0]["items"][0]["seq"] + 1] and q.waiting() == 0)
check("the status says so", demarc.T_SKIPPED.format(n=1) in demarc.status_lines(q))

print("== can't reach Demarc")
port = server.port
server.close()
db.save_device(dev("while-down"))
snd.step()
st = q.state()
check("the change waits, and the status says why", q.waiting() == 1 and st["error"]["code"] == "unreachable")
check("the status line uses the agreed words", any(l.startswith("Can't reach Demarc since ") and l.endswith("Changes wait here for up to 7 days or 500 MB.")
                                                   for l in demarc.status_lines(q)), demarc.status_lines(q))
q.set(next_try=None)
snd.step()
check("the wait doubles after another failure", 25 <= q.get("next_try") - time.time() <= 31, q.get("next_try") - time.time())
db.save_device(dev("while-down-2"))
snd.step()
check("changes are still collected while it waits", q.waiting() == 2)

print("== the 7-day and 500 MB cap")
with q.tx() as c:
    c.execute("UPDATE pending SET queued_at = ?", (time.time() - 8 * 86400,))
snd.step()
check("changes older than 7 days are dropped, and a full copy is due", q.waiting() == 0 and q.get("need_snapshot") and q.get("dropped"))
check("the status says so", demarc.T_DROPPED in demarc.status_lines(q))
db.save_device(dev("after-drop"))
snd.step()
check("nothing more is queued while a full copy is due", q.waiting() == 0)
saved = demarc.QUEUE_BYTES
demarc.QUEUE_BYTES = 1
with q.tx() as c:
    c.execute("INSERT INTO pending(org_uid, kind, changed_at, body, queued_at) VALUES('x', 'org', 'now', '{}', ?)", (time.time(),))
check("a queue bigger than the cap counts as over it", q.over_cap())
demarc.QUEUE_BYTES = saved
check("the real cap is 7 days or 500 MB", demarc.QUEUE_DAYS == 7 and demarc.QUEUE_BYTES == 500 * 1024 * 1024)

SEEN, SEEN_GZ = server.seen, getattr(server, 'gzipped', True)
server = restart(server)                                       # Demarc is back: same address, certificate, token and data
q.set(next_try=None)
snd.step()
check("when Demarc is back the full copy goes, with the changes made meanwhile", not q.get("need_snapshot") and not q.get("dropped")
      and {"while-down", "while-down-2", "after-drop"} <= set(server.live_devices(demarc.global_uid())))
check("the status is clear again", demarc.status_lines(q)[0].startswith("Connected to Demarc") and demarc.T_DROPPED not in demarc.status_lines(q)
      and not any(l.startswith("Can't reach") for l in demarc.status_lines(q)))

print("== turning sending off and on")
demarc.save_config(enabled=False)
db.save_device(dev("while-off"))
snd.step()
check("off: nothing is kept", q.waiting() == 0 and demarc.status_lines(q) == [demarc.T_OFF])
server.requests.clear()
snd.step()
check("...and nothing is sent", not server.requests)
demarc.save_config(enabled=True)
snd.step()
check("on again: a full copy, with what changed while it was off", any(p == "/ingest/v1/snapshot" for p, *_ in server.requests)
      and "while-off" in server.live_devices(demarc.global_uid()))

print("== the token is refused")
server.revoked = True
db.save_device(dev("after-revoke"))
snd.step()
check("revoked: Toner stops and says so", q.get("stopped") == "token" and demarc.status_lines(q) == [demarc.T_TOKEN])
n = len(server.requests)
snd.step()
check("...and doesn't keep trying", len(server.requests) == n)
server.revoked = False
server.codes["NEW-CODE-5678"] = "ok"
demarc.enroll(demarc.probe(server.url), "NEW-CODE-5678", q)
snd.step()
check("connecting again with a new code starts over with a full copy", not q.get("stopped") and "after-revoke" in server.live_devices(demarc.global_uid()))

print("== the certificate changes")
demarc.save_config(pin="00" * 32)
db.save_device(dev("after-cert"))
n = len(server.requests)
snd.step()
check("a different certificate: Toner stops before sending anything", q.get("stopped") == "cert" and len(server.requests) == n
      and demarc.status_lines(q) == [demarc.T_CERT])
demarc.save_config(pin=server.fingerprint)
q.reset()
snd.step()

# ================================================================ nothing secret ever left
print("== nothing secret was sent")
everything = SEEN + server.seen
def keys(o):
    if isinstance(o, dict):
        for k, v in o.items():
            yield k
            yield from keys(v)
    elif isinstance(o, list):
        for v in o:
            yield from keys(v)
allkeys = set(k for p in everything for k in keys(p))
check("no field name that looks like a secret was ever sent", not [k for k in allkeys if SECRET_LIKE.search(k)], [k for k in allkeys if SECRET_LIKE.search(k)])
text = json.dumps(everything)
check("no vault secret was ever sent", not [s for s in SECRETS if s in text])
check("no user name was ever sent", '"admin"' not in text)
check("Demarc refused nothing Toner sent", not server.bad, server.bad)
times = [it["changed_at"] for p in everything for it in p.get("items", [])] + [p["sent_at"] for p in everything if "sent_at" in p] \
    + [it["body"]["ran_at"] for p in everything for it in p.get("items", []) if it["kind"] == "result"]
check("every time sent has a time zone (UTC)", times and all(t.endswith("Z") for t in times))
check("every request was gzipped and carried the token", SEEN_GZ and getattr(server, "gzipped", True)
      and all(h.get("Authorization") == "Bearer " + server.token for p, h, _x, _g in server.requests if p != "/ingest/v1/enroll"))

# ================================================================ values to graph
print("== a result's value, for Demarc 0.0.3 and newer")
def results_sent():
    return [it["body"] for p in server.payloads() for it in p.get("items", []) if it["kind"] == "result"]
check("Demarc 0.0.1 doesn't take them, so none was ever sent to it", "numeric" not in allkeys)
server.version = "0.0.3"                                     # Demarc upgraded where it is: Toner isn't told
server.requests.clear()
with db.within(acme):
    db.save_run([Result("edge-fw", "cpu", "OK", "33%", "", 33.0)])
snd.step()
check("the first batch after the upgrade goes without values", [b.get("numeric", "none") for b in results_sent()] == ["none"])
check("its reply names the new version, so Toner knows", q.get("numeric") is True and q.get("demarc_version") == "0.0.3"
      and demarc.status_lines(q)[0].startswith("Connected to Demarc 0.0.3 at"), demarc.status_lines(q))
server.requests.clear()
with db.within(acme):
    db.save_run([Result("edge-fw", "cpu", "WARN", "91%", "busy", 91.0), Result("edge-fw", "uptime", "OK", "3 days", ""),
                 Result("edge-fw", "temp", "OK", "?", "", float("inf"))])
snd.step()
sent = {b["check"]: b for b in results_sent()}
check("from then on each result carries its value", sent["cpu"].get("numeric") == 91.0, sent)
check("a result without a value carries none", "numeric" not in sent["uptime"])
check("nor one whose value isn't a finite number", "numeric" not in sent["temp"])
check("and Demarc took them", server.latest[(uids[acme], "edge-fw", "cpu")].get("numeric") == 91.0 and not server.bad, server.bad)
q.drop()
server.requests.clear()
snd.step()
snap = [it["body"] for p, _h, x, _g in server.requests if p == "/ingest/v1/snapshot" for it in x["items"] if it["kind"] == "result"]
check("a full copy carries them too", any(b.get("numeric") == 91.0 for b in snap) and not server.bad, server.bad)
server.version = "0.0.2"                                     # put back to an older Demarc, which names no version
db.save_device(dev("after-downgrade"))
snd.step()
check("a reply that names no version stops the values", q.get("numeric") is False)
server.requests.clear()
with db.within(acme):
    db.save_run([Result("edge-fw", "cpu", "OK", "20%", "", 20.0)])
snd.step()
check("so the older Demarc takes the next results", results_sent() and all("numeric" not in b for b in results_sent())
      and not server.bad, server.bad)
check("which version takes them", (demarc.takes_numeric("0.0.3"), demarc.takes_numeric("0.1.0"), demarc.takes_numeric("0.0.2"),
                                    demarc.takes_numeric(""), demarc.takes_numeric("x.y")) == (True, True, False, False, False))

# ================================================================ config backups
print("== config backups, for Demarc 0.0.8 and newer")
from core import backup as bk
CFG = ["hostname edge-fw\nset deviceconfig system ip-address 203.0.113.5\nsnmp-server community c0mmunity-S3cret RO\n"
       "username admin password Hunter2-p@ss!\n",
       "hostname edge-fw\nset deviceconfig system ip-address 203.0.113.6\nsnmp-server community c0mmunity-S3cret RO\n"
       "username admin password Hunter2-p@ss!\n"]
with db.within(acme):
    for i, t in enumerate(CFG):
        state, row, added, removed = bk.store("edge-fw", t, mask=False)     # Backup mask off: stored unmasked
        bk.log("edge-fw", state, f"+{added} / -{removed}" if state == "changed" else "", row["id"])
    bk.store("ap-1", "hostname ap-1\nwpa-psk c0mmunity-S3cret\n", mask=False)
    bk.log("ap-1", "error", "timed out")
with db.within(acme):
    held = bk.list_backups("edge-fw")
check("Toner holds the versions unmasked here (the case that must never reach Demarc as is)",
      "Hunter2-p@ss!" in bk.get_text(held[0]["id"], acme) and len(held) == 2)


def backups_sent():
    return [it for p in server.payloads() for it in p.get("items", []) if it["kind"] in ("backup", "backup_log")]


server.requests.clear()
snd.step(); snd.step()
check("Demarc 0.0.2 doesn't take them, so none is sent", not backups_sent() and not server.bad, server.bad)
server.version = "0.0.8"                                     # upgraded where it is: Toner learns it from the next reply
db.save_device(dev("before-backups"))
snd.step()
check("the reply naming 0.0.8 tells Toner", q.get("backups") is True and not backups_sent())
snd.step()
sent = backups_sent()
vers = [it["body"] for it in sent if it["kind"] == "backup"]
check("the next round sends every version Toner holds (the default Config history), oldest first, with the backup log",
      [v["device"] for v in vers] == ["edge-fw", "edge-fw", "ap-1"] and [it["body"]["status"] for it in sent if it["kind"] == "backup_log"]
      == ["new", "changed", "error"] and not server.bad, (sent, server.bad))
text = json.dumps(sent)
check("each version is masked on the way out, though Toner stored it unmasked", "<masked>" in vers[0]["masked"]
      and not [s for s in SECRETS if s in text])
check("its sha, size and line count are of the masked text that was sent", all(
    v["sha"] == hashlib.sha256(v["masked"].encode()).hexdigest() and v["size"] == len(v["masked"]) and v["lines"] == v["masked"].count("\n")
    for v in vers))
check("its time is in UTC, as the time it was taken", all(v["taken_at"].endswith("Z") for v in vers) and vers[0]["taken_at"] == demarc.utc_of(held[-1]["taken_at"]))
check("and the changes counted by Toner go with it", vers[1]["added"] == 1 and vers[1]["removed"] == 1, vers[1])
check("Demarc took them", len(server.backups_held[(uids[acme], "edge-fw")]) == 2 and not server.bad)
server.requests.clear()
snd.step()
check("nothing is sent twice", not backups_sent())
with db.within(acme):
    state, row, *_ = bk.store("edge-fw", CFG[1] + "ntp server 10.0.0.9\n", mask=False)
    bk.log("edge-fw", state, "+1 / -0", row["id"])
snd.step()
check("a new version goes in the next batch, alone", [it["kind"] for it in backups_sent()] == ["backup", "backup_log"]
      and "ntp server" in backups_sent()[0]["body"]["masked"])

print("== Config history: only each device's newest")
demarc.save_config(history=demarc.HISTORY_LATEST)
q.drop()
server.requests.clear()
server.backups_held.clear(); server.backup_log.clear()
snd.step()
check("a full copy carries no backups: they follow it", any(p == "/ingest/v1/snapshot" for p, *_ in server.requests) and not backups_sent())
snd.step()
vers = [it["body"] for it in backups_sent() if it["kind"] == "backup"]
check("then only each device's newest version is sent", sorted((v["device"], "ntp server" in v["masked"]) for v in vers)
      == [("ap-1", False), ("edge-fw", True)], vers)
check("and each device's newest backup log entry", sorted(it["body"]["device"] for it in backups_sent() if it["kind"] == "backup_log") == ["ap-1", "edge-fw"])
server.requests.clear()
with db.within(acme):
    bk.store("ap-1", "hostname ap-1\nwpa-psk c0mmunity-S3cret\nwlan staff\n", mask=False)
snd.step()
check("what comes after follows as usual", [it["body"]["device"] for it in backups_sent()] == ["ap-1"])

print("== Config history: every version, a few at a time")
demarc.save_config(history=demarc.HISTORY_ALL)
demarc.BACKUPS_PER_ROUND = 2
q.drop()
server.backups_held.clear()
snd.step()
rounds = 0
while sum(len(v) for v in server.backups_held.values()) < 5 and rounds < 10:
    snd.step(); rounds += 1
check("a long history goes out a few versions each round, until all are in", sum(len(v) for v in server.backups_held.values()) == 5
      and rounds == 3 and not server.bad, (rounds, server.bad))
demarc.BACKUPS_PER_ROUND = 100

print("== a Demarc put back to an older version")
server.version = "0.0.7"
db.save_device(dev("after-0.0.7"))
snd.step()
check("the reply naming 0.0.7 stops the backups", q.get("backups") is False)
with db.within(acme):
    bk.store("edge-fw", "hostname edge-fw\nset version 2\n", mask=False)
server.requests.clear()
snd.step()
check("so none is sent to it", not backups_sent() and not server.bad, server.bad)
server.version = "0.0.8"
db.save_device(dev("after-0.0.8"))
snd.step(); snd.step()
check("upgraded again, the one it missed follows", [it["body"]["device"] for it in backups_sent() if it["kind"] == "backup"] == ["edge-fw"]
      and "set version 2" in backups_sent()[0]["body"]["masked"])
check("which version takes them", (demarc.takes_backups("0.0.8"), demarc.takes_backups("0.1.0"), demarc.takes_backups("0.0.7"),
                                    demarc.takes_backups("")) == (True, True, False, False))
check("Demarc refused nothing Toner sent", not server.bad, server.bad)

print("== unmasked configs, only when Demarc asks")
RAW = ("Building configuration...\nhostname core-sw\nsnmp-server community c0mmunity-S3cret RO\n"
       "username admin password Hunter2-p@ss!\ninterface vlan 10\n")
real_fetch = bk.fetch
bk.fetch = lambda d, opts=None: RAW
UNMASKED = "/ingest/v1/unmasked"


def unmasked_posts():
    return [p for path, _h, p, _g in server.requests if path == UNMASKED]


def back_up():
    with db.within(acme):
        return bk.backup_device({"name": "core-sw"}, mask=True)          # Toner keeps it masked; the unmasked copy is in memory


server.settings[uids[acme]] = {"live": True, "interval_minutes": 5, "unmasked_configs": False}
db.save_device(dev("unmasked-1"))
snd.step()
server.requests.clear()
r = back_up()
check("with Receive unmasked configs off in Demarc, nothing unmasked is sent", r.status == "OK" and not unmasked_posts()
      and not demarc.wants_unmasked(acme))
server.settings[uids[acme]]["unmasked_configs"] = True
db.save_device(dev("unmasked-2"))
snd.step(); snd.step()
check("Demarc's reply turns it on for that organization only", demarc.wants_unmasked(acme) and not demarc.wants_unmasked(globex)
      and not demarc.wants_unmasked(db.GLOBAL))
server.requests.clear()
r = back_up()
posts = unmasked_posts()
check("the next backup posts its config unmasked, on its own", r.status == "OK" and len(posts) == 1
      and set(posts[0]) == {"org_uid", "device", "taken_at", "sha", "text"} and posts[0]["org_uid"] == uids[acme], posts)
check("straight from the device, with only the volatile lines taken out", posts and "Hunter2-p@ss!" in posts[0]["text"]
      and "c0mmunity-S3cret" in posts[0]["text"] and posts[0]["text"] == bk.clean(RAW, mask=False))
snd.step()
held = server.backups_held[(uids[acme], "core-sw")]
newest = max(held.values(), key=lambda b: b["taken_at"])
check("it carries the time and the sha of the masked version Demarc gets in the batch", posts
      and (posts[0]["taken_at"], posts[0]["sha"]) == (newest["taken_at"], newest["sha"]) and "<masked>" in newest["masked"], (posts, held))
with db.within(acme):
    stored = bk.get_text(bk.latest("core-sw")["id"])
qfile = demarc.queue_path()
on_disk = b"".join(p.read_bytes() for p in qfile.parent.glob(qfile.name + "*") if p.is_file())
check("the unmasked text is in neither Toner's database (masked there) nor its queue", "Hunter2-p@ss!" not in stored
      and b"Hunter2-p@ss!" not in on_disk and not [s for s in SECRETS if s in json.dumps(backups_sent())])
server.requests.clear()
r = back_up()
check("an unchanged backup sends it again, for the same version (Demarc keeps the newer copy)", r.value == "unchanged"
      and [(p["taken_at"], p["sha"]) for p in unmasked_posts()] == [(posts[0]["taken_at"], posts[0]["sha"])])
server.inject.append((UNMASKED, 403, {"error": "unmasked_off"}))
server.requests.clear()
r = back_up()
check("one Demarc refuses (turned off just now) is dropped, and the backup still succeeds", r.status == "OK" and len(unmasked_posts()) == 1
      and not server.inject)
server.inject.append((UNMASKED, None, None))
check("a dropped connection is only logged", demarc.offer_unmasked(acme, "core-sw", "2026-10-18 12:00:00",
                                                                   "0" * 64, "hostname x\n") is False)
server.inject.clear()
demarc.save_config(enabled=False)
server.requests.clear()
back_up()
check("with Send data to Demarc off, nothing is sent", not unmasked_posts() and not demarc.wants_unmasked(acme))
demarc.save_config(enabled=True)
snd.step()                                                   # what is waiting goes to 0.0.8 first
server.version = "0.0.7"
db.save_device(dev("unmasked-3"))
snd.step()
server.requests.clear()
back_up()
check("nor to a Demarc older than 0.0.8", not unmasked_posts())
server.version = "0.0.8"
db.save_device(dev("unmasked-4"))
snd.step(); snd.step()
check("the posts were all as Demarc takes them", not server.bad, server.bad)
bk.fetch = real_fetch

# ================================================================ one sender at a time
print("== one Toner process sends at a time")
lock_path = os.path.join(SP, "lock%d" % int(time.time() * 1000))
a = demarc._try_lock(lock_path)
check("the first one gets the lock", a is not None)
check("a second one does not", demarc._try_lock(lock_path) is None)
a.close()
b2 = demarc._try_lock(lock_path)
check("once it lets go, another can", b2 is not None)
b2.close()

# ================================================================ Settings > Connections > Demarc
print("== Settings > Connections > Demarc")
from PySide6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])
from ui.settings_pages.demarc import DemarcPage, INTRO
from ui import settings as S
check("the page is listed under Connections", "Demarc" in dict(S.GROUPS)["Connections"])
check("it is managed by Global", "Demarc" in S.GLOBAL_PAGES)
started = []
demarc.apply = lambda: started.append(1)                       # the page starts the real sender; here the test sends instead
demarc.disconnect(q)
check("disconnecting forgets the token and stops", not STORE.get((db.SERVICE, demarc.TOKEN_SECRET)) and demarc.status_lines(q) == [demarc.T_NOT_CONNECTED])
with db.within(db.GLOBAL):
    check("the audit log says so", any(r["action"] == demarc.T_AUDIT_DISCONNECTED for r in audit.recent()))
page = DemarcPage()
page.load()
asked, told = [], []
page.ask = lambda title, text, yes: (asked.append((title, text, yes)), True)[1]
page.tell = lambda text: told.append(text)
check("not connected: Disconnect and Send are greyed out", not page.disconnect_btn.isEnabled() and not page.enabled.isEnabled())
page.address.setText(server.url)
page._connect()
check("Connect without a code asks for both", told == [demarc.T_NEED])
server.codes["UI-CODE-0001"] = "ok"
page.code.setText("UI-CODE-0001")
page._connect()
check("Connect shows the fingerprint and waits for the person to confirm it", asked and asked[-1][0] == "Check Demarc's certificate"
      and server.fingerprint in asked[-1][1] and asked[-1][2] == "They match, connect")
check("connected from the page", demarc.connected() and page.disconnect_btn.isEnabled() and page.cert.text() == server.fingerprint
      and page.status.text().startswith("Connected to Demarc"))
check("the code box is emptied", page.code.text() == "")
check("connecting starts the sender", started)
server.codes["UI-CODE-0002"] = "ok"
page.code.setText("UI-CODE-0002")
page.ask = lambda title, text, yes: False
n = len(server.requests)
page._connect()
check("answering Cancel sends nothing", len(server.requests) == n and server.codes.get("UI-CODE-0002") == "ok")
page.enabled.setChecked(False)
page.save()
check("Send data to Demarc is saved with Save changes", demarc.config()["enabled"] is False and page.status.text() == demarc.T_OFF)
page.enabled.setChecked(True)
page.save()
from ui.settings_pages.demarc import HISTORY, HISTORY_NOTE
check("Config history offers every version (the default) or each device's newest, in the proposed words",
      [page.history.itemText(i) for i in range(page.history.count())] == [label for _k, label in HISTORY]
      and page.history.currentData() == demarc.HISTORY_ALL and "0.0.8" in HISTORY_NOTE)
page.history.setCurrentIndex(page.history.findData(demarc.HISTORY_LATEST))
page.save()
check("it is saved with Save changes", demarc.config()["history"] == demarc.HISTORY_LATEST)
page.load()
check("and shown again when the page loads", page.history.currentData() == demarc.HISTORY_LATEST)
page.history.setCurrentIndex(page.history.findData(demarc.HISTORY_ALL))
page.save()
asked.clear()
page.ask = lambda title, text, yes: (asked.append((title, text, yes)), True)[1]
page._disconnect()
check("Disconnect asks first, in the agreed words", asked == [("Disconnect from Demarc?", "Toner stops sending and forgets its token. Changes not "
      "sent yet are dropped. Demarc keeps what it already has.", "Disconnect")])
check("...then disconnects", not demarc.connected() and page.status.text() == demarc.T_NOT_CONNECTED)
check("the page explains what Demarc is and that secrets are never sent", "never sent" in INTRO and "enrollment code" in INTRO)
check("the address and code boxes are not settings (Connect uses them)", page.address.property("notSetting") and page.code.property("notSetting"))

print("== in the Settings tab")
from ui.settings import signature
tab = S.SettingsTab()
i = next(n for n, p in enumerate(tab.pages) if p.title == "Demarc")
dp = tab.pages[i]
dp.ask = lambda title, text, yes: True
dp.tell = lambda text: told.append(text)
server.codes["UI-CODE-0003"] = "ok"
dp.address.setText(server.url)
dp.code.setText("UI-CODE-0003")
dp._connect()
check("connecting from the tab is not counted as an unsaved edit", demarc.connected() and dp.enabled.isChecked()
      and signature(dp) == tab.baseline[i])
dp.history.setCurrentIndex(dp.history.findData(demarc.HISTORY_LATEST))
check("changing Config history is an unsaved edit", signature(dp) != tab.baseline[i])
dp.history.setCurrentIndex(dp.history.findData(demarc.HISTORY_ALL))
dp.enabled.setChecked(False)
check("turning sending off is", signature(dp) != tab.baseline[i])
tab.save()
check("...and Save changes stores it", demarc.config()["enabled"] is False)
dp._disconnect()
check("disconnecting is not an unsaved edit either", signature(dp) == tab.baseline[i] and not demarc.connected())

server.close()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
