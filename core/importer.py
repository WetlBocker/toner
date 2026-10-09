"""Read device lists from YAML, JSON or CSV and turn them into validated inventory records."""
import csv
import json
from pathlib import Path

import yaml

from core import display, nettools, vendors


def db_split_tags(text):
    from core import db
    return db.split_tags(text)

VENDORS = list(display.VENDOR_NAMES)
FILE_FILTER = "Device lists (*.yaml *.yml *.json *.csv);;YAML (*.yaml *.yml);;JSON (*.json);;CSV (*.csv)"

# Column / key names people commonly use, mapped to ours.
ALIASES = {
    "hostname": "host", "ip": "host", "ip_address": "host", "address": "host", "dns": "host",
    "dns_name": "host", "fqdn": "host", "device": "name", "device_name": "name",
    "type": "vendor", "make": "vendor", "manufacturer": "vendor",
    "user": "username", "login": "username",
    "pass": "secret", "password": "secret", "token": "secret", "api_token": "secret", "secret": "secret",
    "ssl": "verify_ssl", "verify": "verify_ssl", "verify_cert": "verify_ssl",
    "ha": "ha_expected", "loc": "location", "site_name": "site",
    "notes": "details", "note": "details", "description": "details", "comment": "details",
    "folder": "folder", "folder_path": "folder", "path": "folder", "group": "folder", "directory": "folder",
    "tag": "tags", "tags": "tags", "labels": "tags", "label": "tags",
    "profile": "profile", "credential_profile": "profile", "credentials": "profile",
    "jump": "jump", "jump_host": "jump", "bastion": "jump", "proxy": "jump",
    "community": "snmp_community", "snmp_community": "snmp_community", "snmp": "snmp_community",
}
TRUE = {"1", "true", "yes", "y", "on", "x"}
FALSE = {"0", "false", "no", "n", "off", ""}


def _key(k):
    k = str(k or "").strip().lower().replace(" ", "_").replace("-", "_")
    return ALIASES.get(k, k)


def load_rows(path):
    """Return the raw device rows (list of dicts) from a .yaml/.yml/.json/.csv file."""
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        with open(path, newline="", encoding="utf-8-sig") as f:
            rows = [r for r in csv.DictReader(f) if any((v or "").strip() for v in r.values() if v)]
    elif suffix == ".json":
        with open(path, encoding="utf-8-sig") as f:
            rows = _devices_from(json.load(f))
    elif suffix in (".yaml", ".yml"):
        with open(path, encoding="utf-8-sig") as f:
            rows = _devices_from(yaml.safe_load(f))
    else:
        raise ValueError(f"Unsupported file type '{suffix}'. Use .yaml, .yml, .json or .csv.")
    if not rows:
        raise ValueError("No devices found in the file.")
    return rows


def _devices_from(data):
    if isinstance(data, dict):
        data = data.get("devices", [])
    if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
        raise ValueError("Expected a list of devices, or an object with a 'devices' list.")
    return data


def _flag(value, default):
    s = str(value if value is not None else "").strip().lower()
    if s in TRUE:
        return 1
    if s in FALSE:
        return default if s == "" else 0
    raise ValueError(f"'{value}' is not yes/no")


def label(raw, index):
    """How to refer to a row in messages: its name if it has one, else its position."""
    for k, v in raw.items():
        if _key(k) == "name" and str(v or "").strip():
            return str(v).strip()
    return f"row {index}"


def normalize(raw):
    """One raw row -> (device dict, secret or None). Raises ValueError with a readable reason."""
    row = {}
    for k, v in raw.items():
        row.setdefault(_key(k), v)
    text = lambda k: ("" if row.get(k) is None else str(row[k])).strip()

    name = text("name")
    if not name:
        raise ValueError("missing name")
    vendor = text("vendor").lower()
    if vendor not in VENDORS:
        raise ValueError(f"vendor must be one of {', '.join(VENDORS)} (got '{text('vendor')}')")
    host = nettools.check_host(text("host"))
    for part in text("folder").replace("\\", "/").split("/"):      # reject names the folder code would refuse
        if part.strip() in (".", ".."):
            raise ValueError("folder names cannot be '.' or '..'")

    platform = text("platform").lower()
    allowed = vendors.platform_keys(vendor)
    if allowed and platform:
        # accept the short form too: "ios" -> cisco_ios, "eos" -> arista_eos
        platform = next((k for k in allowed if platform in (k, k.split("_", 1)[-1], k.replace("_", "-"))), platform)
        if platform not in allowed:
            raise ValueError(f"platform for {display.vendor_name(vendor)} must be one of {', '.join(allowed)}")
    elif not allowed:
        platform = ""
    try:
        port = int(text("port") or 0)
        if not 0 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise ValueError(f"invalid port '{text('port')}'") from None

    dev = {"name": name, "vendor": vendor, "host": host, "port": port, "platform": platform,
           "username": text("username"), "site": text("site") or "default",
           "location": text("location"), "details": text("details"),
           "folder": "/".join(p.strip() for p in text("folder").replace("\\", "/").split("/") if p.strip()),
           "tags": ", ".join(db_split_tags(text("tags"))), "profile": text("profile"), "jump": text("jump"),
           "snmp_community": text("snmp_community"),
           "verify_ssl": _flag(row.get("verify_ssl"), 0), "ha_expected": _flag(row.get("ha_expected"), 0),
           "enabled": _flag(row.get("enabled"), 1)}
    return dev, text("secret") or None


def finalize(dev):
    """Resolve the names in an imported record into what the database stores: the folder path becomes an id, the
    profile name an id, the jump host a reference. Returns the SNMP community to keep as a secret (or '').
    Raises ValueError with a readable reason; nothing is created before everything checks out."""
    from core import db, profiles
    community = dev.pop("snmp_community", "")
    profile_name, jump_name = dev.pop("profile", ""), dev.pop("jump", "")
    if profile_name:
        p = profiles.by_name(profile_name)
        if not p:
            raise ValueError(f"credential profile '{profile_name}' does not exist (create it in Settings > Credentials)")
        dev["profile_id"] = p["id"]
    if jump_name:
        if not any(d["name"].lower() == jump_name.lower() for d in db.list_devices()):
            raise ValueError(f"jump host '{jump_name}' is not in the inventory yet (import it first)")
        dev["jump"] = {"device": next(d["name"] for d in db.list_devices() if d["name"].lower() == jump_name.lower())}
    if community or dev.get("vendor") == "snmp":
        dev["snmp"] = {"version": "2c", "port": 161}
    return community


EXPORT_COLUMNS = ["name", "vendor", "host", "platform", "port", "username", "site", "location", "details", "folder",
                  "tags", "profile", "jump", "enabled", "verify_ssl", "ha_expected"]


def export_rows(devices):
    """Inventory records as plain dicts for writing to a file. Secrets are never included."""
    from core import db, profiles
    paths = db.folder_paths()
    out = []
    for d in devices:
        try:
            jump = json.loads(d.get("jump") or "{}").get("device", "")
        except ValueError:
            jump = ""
        prof = (profiles.get(d.get("profile_id")) or {}).get("name", "")
        out.append({"name": d["name"], "vendor": d["vendor"], "host": d["host"], "platform": d.get("platform") or "",
                    "port": d.get("port") or "", "username": d.get("username") or "", "site": d.get("site") or "",
                    "location": d.get("location") or "", "details": d.get("details") or "",
                    "folder": paths.get(d.get("folder_id"), ""), "tags": d.get("tags") or "", "profile": prof,
                    "jump": jump, "enabled": "yes" if d.get("enabled", 1) else "no",
                    "verify_ssl": "yes" if d.get("verify_ssl") else "no", "ha_expected": "yes" if d.get("ha_expected") else "no"})
    return out


def write_rows(rows, path):
    """Write export_rows() output as .csv, .json or .yaml according to the file name."""
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=EXPORT_COLUMNS)
            w.writeheader()
            w.writerows(rows)
    elif suffix == ".json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"devices": rows}, f, indent=2)
    elif suffix in (".yaml", ".yml"):
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump({"devices": rows}, f, sort_keys=False, allow_unicode=True)
    else:
        raise ValueError(f"Unsupported file type '{suffix}'. Use .csv, .json or .yaml.")
