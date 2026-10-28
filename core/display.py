"""Display-only formatting. Stored values stay raw (history lookups depend on them)."""
import re

from core.vendors import VENDORS

VENDOR_NAMES = {k: v["name"] for k, v in VENDORS.items()}
PLATFORM_NAMES = {k: label for v in VENDORS.values() for k, label in v["platforms"]}
ACRONYMS = {"cpu": "CPU", "bgp": "BGP", "ospf": "OSPF", "eigrp": "EIGRP", "ha": "HA", "vpn": "VPN", "ipsec": "IPsec",
            "wan": "WAN", "lan": "LAN", "wlan": "WLAN", "www": "WWW", "ap": "AP", "ssl": "SSL",
            "tx": "TX", "rx": "RX", "isp": "ISP", "nvr": "NVR", "sd": "SD", "dns": "DNS", "tls": "TLS", "ip": "IP", "ssid": "SSID", "poe": "PoE"}


def read_on(stamp):
    """'26 Oct 2026 at 14:02' for a stored time such as '2026-10-26 14:02:37'. Unreadable: as it is."""
    from datetime import datetime
    try:
        return datetime.strptime(str(stamp)[:19], "%Y-%m-%d %H:%M:%S").strftime("%d %b %Y at %H:%M").lstrip("0")
    except (TypeError, ValueError):
        return stamp or ""


def software_line(sw, long=False):
    """The software a device runs, from db.software_of: the Version cell's tooltip ("17.09.04a, INSTALL mode, image
    cat9k_iosxe.17.09.04a.SPA.bin. Read 26 Oct 2026 at 14:02.") or, long, the device page's row ("17.09.04a (INSTALL mode,
    cat9k_iosxe.17.09.04a.SPA.bin), read 26 Oct 2026 at 14:02"). Mode and image only where they apply. '' when nothing was read."""
    if not sw or not sw.get("version"):
        return ""
    extra = [f"{sw['mode']} mode"] if sw.get("mode") else []
    if sw.get("image"):
        extra.append(sw["image"] if long else f"image {sw['image']}")
    when = read_on(sw.get("read_at"))
    if long:
        text = sw["version"] + (f" ({', '.join(extra)})" if extra else "")
        return text + (f", read {when}" if when else "")
    text = ", ".join([sw["version"]] + extra)
    return text + (f". Read {when}." if when else "")


def vendor_name(v):
    """What the Vendor column says. All the UniFi types are 'UniFi'; type_name() tells them apart."""
    from core import vendors
    return VENDOR_NAMES.get(vendors.family(v), (v or "").capitalize())


def type_name(v):
    """'UniFi - Network API (API key)' for one of several ways to monitor a vendor, else the vendor's name."""
    from core import vendors
    if v == "all":
        return "Every device"
    label = vendors.mode_label(v)
    return f"{vendor_name(v)} - {label}" if label else vendor_name(v)


def platform_name(p):
    return PLATFORM_NAMES.get(p, p or "N/A")


def windows_name(system, release):
    """'Windows 11', 'Windows Server 2025'. Python reports a server as '2025Server' (or 'Server2025'), which reads as one word."""
    release = str(release or "").strip()
    if "server" in release.lower():
        year = re.search(r"\d{4}", release)
        return "Windows Server" + (f" {year.group(0)}" if year else "") + (" R2" if re.search(r"r2(?!\d)", release, re.I) else "")
    return f"{system or 'Windows'} {release}".strip()


def uptime(hours=None, seconds=None):
    """Uptime as Days:Hours:Minutes:Seconds, e.g. 12:03:45:09 (twelve days, three hours, 45 minutes, 9 seconds)."""
    total = int(round(float(seconds) if seconds is not None else float(hours or 0) * 3600))
    days, rest = divmod(max(total, 0), 86400)
    hrs, rest = divmod(rest, 3600)
    mins, secs = divmod(rest, 60)
    return f"{days}:{hrs:02d}:{mins:02d}:{secs:02d}"


def said(name, message):
    """'Disk D: very high' as 'Disk D: very high' (and 'cpu' + 'high' as 'cpu: high'): a check name that already ends in a colon does not get a second one."""
    name = (name or "").rstrip()
    return (name if name.endswith(":") else name + ":") + " " + message if message else name


def check_name(name):
    """'wan links' -> 'WAN Links'; 'channel util (ng)' -> 'Channel Util (NG)'; 'tx retries (2.4 GHz)' -> 'TX Retries (2.4 GHz)'; 'sd-wan' -> 'SD-WAN'."""
    if re.match(r"^(?:cisco-sa-|CVE-\d)", name or ""):          # an advisory id (the Scanning section) is shown as published
        return name
    base, sep, rest = (name or "").partition(" (")
    word = lambda w: "-".join(ACRONYMS.get(p, p.capitalize()) for p in w.split("-"))
    out = " ".join(word(w) for w in base.split(" "))
    return out + (f" ({re.sub('GHZ', 'GHz', rest.rstrip(')').upper())})" if sep else "")


def value(v):
    """Capitalise plain-word values ('connected' -> 'Connected'); leave versions/numbers alone."""
    v = "" if v is None else str(v)
    if v == "ok":
        return "OK"
    return v[:1].upper() + v[1:] if re.fullmatch(r"[a-z][a-z ]*", v) else v


def ago(stamp, now=None):
    """'just now', '12 min ago', '3 h ago' or '4 days ago' for a stored time such as '2026-10-12 16:06:37'. Unreadable: as it is."""
    from datetime import datetime
    try:
        secs = ((now or datetime.now()) - datetime.strptime(str(stamp)[:19], "%Y-%m-%d %H:%M:%S")).total_seconds()
    except (TypeError, ValueError):
        return stamp or ""
    if secs < 90:
        return "just now"
    if secs < 5400:
        return f"{secs / 60:.0f} min ago"
    if secs < 129600:
        return f"{secs / 3600:.0f} h ago"
    return f"{secs / 86400:.0f} days ago"
