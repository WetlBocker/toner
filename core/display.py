"""Display-only formatting. Stored values stay raw (history lookups depend on them)."""
import re

from core.vendors import VENDORS

VENDOR_NAMES = {k: v["name"] for k, v in VENDORS.items()}
PLATFORM_NAMES = {k: label for v in VENDORS.values() for k, label in v["platforms"]}
ACRONYMS = {"cpu": "CPU", "bgp": "BGP", "ospf": "OSPF", "ha": "HA", "vpn": "VPN", "ipsec": "IPsec",
            "wan": "WAN", "lan": "LAN", "wlan": "WLAN", "www": "WWW", "ap": "AP", "ssl": "SSL"}


def vendor_name(v):
    return VENDOR_NAMES.get(v, (v or "").capitalize())


def platform_name(p):
    return PLATFORM_NAMES.get(p, p or "N/A")


def check_name(name):
    """'wan links' -> 'WAN Links'; 'channel util (ng)' -> 'Channel Util (NG)'."""
    base, sep, rest = (name or "").partition(" (")
    out = " ".join(ACRONYMS.get(w, w.capitalize()) for w in base.split(" "))
    return out + (f" ({rest.rstrip(')').upper()})" if sep else "")


def value(v):
    """Capitalise plain-word values ('connected' -> 'Connected'); leave versions/numbers alone."""
    v = "" if v is None else str(v)
    if v == "ok":
        return "OK"
    return v[:1].upper() + v[1:] if re.fullmatch(r"[a-z][a-z ]*", v) else v
