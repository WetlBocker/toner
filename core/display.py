"""Display-only formatting. Stored values stay raw (history lookups depend on them)."""
import re

from core.vendors import VENDORS

VENDOR_NAMES = {k: v["name"] for k, v in VENDORS.items()}
PLATFORM_NAMES = {k: label for v in VENDORS.values() for k, label in v["platforms"]}
ACRONYMS = {"cpu": "CPU", "bgp": "BGP", "ospf": "OSPF", "ha": "HA", "vpn": "VPN", "ipsec": "IPsec",
            "wan": "WAN", "lan": "LAN", "wlan": "WLAN", "www": "WWW", "ap": "AP", "ssl": "SSL",
            "tx": "TX", "rx": "RX", "isp": "ISP", "nvr": "NVR", "sd": "SD", "dns": "DNS", "tls": "TLS", "ip": "IP", "ssid": "SSID", "poe": "PoE"}


def vendor_name(v):
    """What the Vendor column says. All the UniFi types are 'UniFi'; type_name() tells them apart."""
    from core import vendors
    return VENDOR_NAMES.get(vendors.family(v), (v or "").capitalize())


def type_name(v):
    """'UniFi - Network API (API key)' for one of several ways to monitor a vendor, else the vendor's name."""
    from core import vendors
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


def check_name(name):
    """'wan links' -> 'WAN Links'; 'channel util (ng)' -> 'Channel Util (NG)'; 'tx retries (2.4 GHz)' -> 'TX Retries (2.4 GHz)'; 'sd-wan' -> 'SD-WAN'."""
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
