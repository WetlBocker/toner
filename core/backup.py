"""Configuration backups: fetch each device's configuration, keep the versions that differ, show what changed.

Stored text is cleaned first: volatile lines (timestamps, byte counts) are dropped so only real changes count, and
(by default) passwords, keys and SNMP communities are masked, because the database file is not encrypted.
"""
from core import proxy
import difflib
import hashlib
import re
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from core import db
from drivers.base import Result, OK, WARN, ERROR
from core import quiet

CHECK_NAME = "config backup"

# platform / vendor -> command run over SSH to print the whole configuration
SSH_COMMANDS = {
    "cisco_ios": "show running-config", "cisco_xe": "show running-config", "cisco_nxos": "show running-config",
    "cisco_asa": "show running-config", "juniper_junos": "show configuration | no-more",
    "arista_eos": "show running-config", "aruba_aoscx": "show running-config",
    "aruba_osswitch": "show running-config", "mikrotik_routeros": "/export",
}
API_VENDORS = ("fortinet", "paloalto")

# lines that change on every read without the configuration changing
VOLATILE = [re.compile(p, re.I) for p in (
    r"^!?\s*Last configuration change.*$", r"^!?\s*NVRAM config last updated.*$", r"^Building configuration.*$",
    r"^Current configuration\s*:.*$", r"^!?\s*No configuration change since last restart.*$",
    r"^ntp clock-period \d+.*$", r"^##\s*Last (commit|changed).*$", r"^#\s*\S.*by RouterOS.*$",
    r"^!\s*Time:.*$", r"^!Time:.*$", r"^\s*!\s*Startup config saved at.*$", r"^! Last configuration.*$",
    r"^\s*uptime is .*$", r"^#\s*\w{3}/\d+/\d{4}.*$", r"^#\s+software id.*$",
)]

MASKS = [
    # Cisco / Arista / HPE / generic CLI: the word, an optional type digit, then the secret
    (re.compile(r"(?im)^(\s*(?:enable\s+(?:secret|password)|username\s+\S+\s+(?:\S+\s+){0,3}?(?:secret|password)|"
                r"snmp-server\s+community|snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+\S+|"
                r"(?:tacacs|radius)(?:-server)?\s+(?:host\s+\S+\s+)?key|ntp\s+authentication-key\s+\d+\s+\S+|"
                r"(?:crypto\s+)?(?:isakmp|ikev2)\s+key|pre-shared-key|password|secret|key-string|"
                r"authentication-key|encrypted-password|wpa-psk|auth-password|priv-password))\s+(?:\d\s+)?\S.*?(;?)\s*$"),
     r"\1 <masked>\2"),
    # Junos
    (re.compile(r'(?i)\b(encrypted-password|secret|authentication-key|pre-shared-key\s+(?:ascii-text|hexadecimal)|'
                r'community)\s+"[^"]*"'), r'\1 "<masked>"'),
    # FortiOS
    (re.compile(r"(?im)^(\s*set\s+(?:password|passwd|psksecret|secret|key|community-name|auth-pwd|priv-pwd|"
                r"private-key|passphrase))\s+.*$"), r"\1 <masked>"),
    # PAN-OS XML
    (re.compile(r"<(phash|password|key|secret|community-name|passphrase|private-key)>[^<]*</\1>"),
     r"<\1><masked></\1>"),
    # RouterOS
    (re.compile(r"(?i)\b(password|secret|passphrase|private-key|wpa-pre-shared-key|wpa2-pre-shared-key)=(\"[^\"]*\"|\S+)"),
     r"\1=<masked>"),
]


class BackupError(Exception):
    pass


def supported(dev):
    from core import vendors
    v = dev.get("vendor")
    if v in API_VENDORS:
        return True
    if vendors.get(v).get("kind") != "ssh":
        return False
    return (dev.get("platform") or vendors.default_platform(v)) in SSH_COMMANDS


def why_unsupported(dev):
    v = dev.get("vendor")
    if v in ("meraki", "unifi", "unifi_network", "unifi_protect", "unifi_cloud"):
        return "cloud/controller-managed: there is no per-device configuration to read"
    if v == "snmp":
        return "generic SNMP devices have no readable configuration"
    return "no configuration command known for this platform"


# ---------------------------------------------------------------- cleaning
def clean(text, mask=True):
    out = []
    for line in (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.rstrip()
        if any(p.match(line.strip()) for p in VOLATILE):
            continue
        out.append(line)
    body = "\n".join(out).strip("\n")
    if mask:
        for rx, repl in MASKS:
            body = rx.sub(repl, body)
    return body + "\n"


def sha(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------- fetching
def fetch(dev, opts=None):
    """The device's raw configuration text. Raises BackupError with a readable reason."""
    from core import profiles
    opts = opts or db.runtime_options()
    dev = profiles.resolve(dev)
    vendor = dev["vendor"]
    if not supported(dev):
        raise BackupError(why_unsupported(dev))
    if vendor == "fortinet":
        import requests, urllib3
        if not dev.get("verify_ssl"):
            urllib3.disable_warnings()
        r = requests.get(f"https://{dev['host']}:{dev.get('port') or 443}/api/v2/monitor/system/config/backup",
                         params={"scope": "global"}, headers={"Authorization": f"Bearer {profiles.secret(dev) or ''}"},
                         verify=bool(dev.get("verify_ssl")), timeout=max(opts["http_timeout"], 60), **proxy.requests_kwargs(dev))
        r.raise_for_status()
        return r.text
    if vendor == "paloalto":
        import requests, urllib3
        if not dev.get("verify_ssl"):
            urllib3.disable_warnings()
        r = requests.get(f"https://{dev['host']}:{dev.get('port') or 443}/api/", params={"type": "export", "category": "configuration"},
                         headers={"X-PAN-KEY": profiles.secret(dev) or ""}, verify=bool(dev.get("verify_ssl")),
                         timeout=max(opts["http_timeout"], 60), **proxy.requests_kwargs(dev))
        r.raise_for_status()
        return r.text
    from drivers import DRIVERS
    drv = DRIVERS[vendor](dev, {}, opts)
    drv.plat = dev.get("platform") or drv.DEFAULT_PLATFORM
    cmd = SSH_COMMANDS[drv.plat]
    with drv.connect() as c:
        try:
            c.enable()
        except Exception:
            quiet.ignored()
        return c.send_command(cmd, read_timeout=max(120, opts["ssh_timeout"] * 4))


# ---------------------------------------------------------------- storing
def _pack(text):
    return zlib.compress(text.encode("utf-8", "replace"), 6)


def get_text(backup_id):
    with db.connect() as c:
        row = c.execute("SELECT body FROM config_backups WHERE id=?", (backup_id,)).fetchone()
    return zlib.decompress(row["body"]).decode("utf-8", "replace") if row else ""


def list_backups(device, limit=200):
    with db.connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT id, device, taken_at, sha, size, lines, added, removed FROM config_backups WHERE device=? "
            "ORDER BY id DESC LIMIT ?", (device, limit))]


def latest(device):
    rows = list_backups(device, 1)
    return rows[0] if rows else None


def summary():
    """{device: {'versions': n, 'last': time, 'changed': time of the last change}} for the device list."""
    out = {}
    with db.connect() as c:
        for r in c.execute("SELECT device, COUNT(*) n, MAX(taken_at) last FROM config_backups GROUP BY device"):
            out[r["device"]] = {"versions": r["n"], "changed": r["last"], "last": r["last"]}
        for r in c.execute("SELECT device, at, status FROM backup_log WHERE id IN "
                           "(SELECT MAX(id) FROM backup_log GROUP BY device)"):
            out.setdefault(r["device"], {"versions": 0, "changed": ""})["last"] = r["at"]
            out[r["device"]]["status"] = r["status"]
    return out


def recent_changes(hours=24):
    from datetime import timedelta
    cutoff = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    with db.connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT device, taken_at, added, removed FROM config_backups WHERE taken_at >= ? AND "
            "id NOT IN (SELECT MIN(id) FROM config_backups GROUP BY device) ORDER BY id DESC", (cutoff,))]


def diff_lines(old, new, old_label="before", new_label="after", context=3):
    """Unified diff as a list of lines, and (added, removed) counts."""
    a, b = (old or "").splitlines(), (new or "").splitlines()
    lines = list(difflib.unified_diff(a, b, old_label, new_label, lineterm="", n=context))
    added = sum(1 for l in lines if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))
    return lines, added, removed


def store(device, text, mask=True, keep=None):
    """Save `text` if it differs from the newest version. Returns (state, backup row or None, added, removed)
    where state is 'new' (first backup), 'changed' or 'unchanged'."""
    body = clean(text, mask)
    digest = sha(body)
    prev = latest(device)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if prev and prev["sha"] == digest:
        return "unchanged", prev, 0, 0
    added = removed = 0
    if prev:
        _, added, removed = diff_lines(get_text(prev["id"]), body)
    with db.connect() as c:
        bid = c.execute("INSERT INTO config_backups(device, taken_at, sha, size, lines, body, added, removed) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (device, now, digest, len(body), body.count("\n"), _pack(body), added, removed)).lastrowid
        keep = int(db.get_setting("backup_keep")) if keep is None else keep
        if keep > 0:
            c.execute("DELETE FROM config_backups WHERE device=? AND id NOT IN "
                      "(SELECT id FROM config_backups WHERE device=? ORDER BY id DESC LIMIT ?)", (device, device, keep))
    return ("changed" if prev else "new"), {"id": bid, "taken_at": now}, added, removed


def log(device, status, message="", backup_id=None):
    with db.connect() as c:
        c.execute("INSERT INTO backup_log(device, at, status, message, backup_id) VALUES(?,?,?,?,?)",
                  (device, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), status, message, backup_id))
        c.execute("DELETE FROM backup_log WHERE id NOT IN (SELECT id FROM backup_log ORDER BY id DESC LIMIT 5000)")


def backup_device(dev, opts=None, mask=None):
    """Back one device up. Returns a Result for the 'config backup' check."""
    name = dev["name"]
    mask = bool(db.get_setting("backup_mask")) if mask is None else mask
    try:
        text = fetch(dev, opts)
        if not text or len(text.strip()) < 20:
            raise BackupError("the device returned an empty configuration")
        low = text.lower()[:300]
        if "invalid input" in low or "% " in low[:3] or "unknown command" in low:
            raise BackupError("the device rejected the configuration command: " + " ".join(text.split())[:100])
        state, row, added, removed = store(name, text, mask)
    except BackupError as e:
        log(name, "error", str(e))
        return Result(name, CHECK_NAME, ERROR, "", str(e))
    except Exception as e:
        log(name, "error", f"{type(e).__name__}: {e}")
        return Result(name, CHECK_NAME, ERROR, "", f"{type(e).__name__}: {str(e)[:200]}")
    log(name, state, f"+{added} / -{removed}" if state == "changed" else "", row["id"] if row else None)
    if state == "changed":
        return Result(name, CHECK_NAME, WARN, "changed", f"+{added} / -{removed} lines since the previous backup")
    return Result(name, CHECK_NAME, OK, "first copy" if state == "new" else "unchanged")


def backup_many(devices, workers=5, on_result=None, opts=None):
    """Back several devices up in parallel. Returns the Results (also passed to on_result as they finish)."""
    opts = opts or db.runtime_options()
    todo = [d for d in devices if supported(d)]
    skipped = [Result(d["name"], CHECK_NAME, OK, "n/a", why_unsupported(d)) for d in devices if not supported(d)]
    out = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = [pool.submit(backup_device, d, opts) for d in todo]
        for f in as_completed(futs):
            r = f.result()
            out.append(r)
            if on_result:
                on_result(r)
    return out + skipped


# ---------------------------------------------------------------- searching
def search(pattern, devices=None, regex=False, all_versions=False, limit=500):
    """Find lines in stored configurations. Returns [{'device','taken_at','line_no','line'}]."""
    rx = re.compile(pattern if regex else re.escape(pattern), re.I)
    out = []
    with db.connect() as c:
        if all_versions:
            rows = c.execute("SELECT id, device, taken_at, body FROM config_backups ORDER BY device, id DESC").fetchall()
        else:
            rows = c.execute("SELECT id, device, taken_at, body FROM config_backups WHERE id IN "
                             "(SELECT MAX(id) FROM config_backups GROUP BY device) ORDER BY device").fetchall()
    for r in rows:
        if devices is not None and r["device"] not in devices:
            continue
        for n, line in enumerate(zlib.decompress(r["body"]).decode("utf-8", "replace").splitlines(), 1):
            if rx.search(line):
                out.append({"device": r["device"], "taken_at": r["taken_at"], "line_no": n, "line": line.strip(), "id": r["id"]})
                if len(out) >= limit:
                    return out
    return out


def delete_versions(device, keep_latest=1):
    with db.connect() as c:
        c.execute("DELETE FROM config_backups WHERE device=? AND id NOT IN "
                  "(SELECT id FROM config_backups WHERE device=? ORDER BY id DESC LIMIT ?)", (device, device, keep_latest))
