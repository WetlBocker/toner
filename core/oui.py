"""MAC address helpers: parsing, vendor lookup (OUI) and Wake-on-LAN."""
import os
import re
import socket
from pathlib import Path

# A short built-in list of prefixes that are certain, so lookups work offline for virtual machines and the like.
# "Update OUI database" fetches the full IEEE registry for everything else.
BUILTIN = {
    "000C29": "VMware", "005056": "VMware", "000569": "VMware", "080027": "VirtualBox (PCS Systems)",
    "00155D": "Microsoft Hyper-V", "525400": "QEMU/KVM", "001C42": "Parallels", "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading", "E45F01": "Raspberry Pi Trading", "00000C": "Cisco Systems",
    "0050F2": "Microsoft", "00005E": "IANA (VRRP and similar)", "FFFFFF": "Broadcast address",
}
_cache = None


def cache_path():
    base = Path(os.environ.get("APPDATA", Path.home())) / "NetCheck"
    base.mkdir(parents=True, exist_ok=True)
    return base / "oui.txt"


def normalize(mac):
    """'aa:bb:cc:dd:ee:ff' / 'AA-BB-CC-DD-EE-FF' / 'aabb.ccdd.eeff' -> 'AABBCCDDEEFF'. Raises ValueError."""
    hexdigits = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(hexdigits) != 12 or re.search(r"[^0-9A-Fa-f.:\-\s]", mac or ""):
        raise ValueError("A MAC address has 12 hex digits, like AA:BB:CC:DD:EE:FF.")
    return hexdigits.upper()


def pretty(mac, sep=":"):
    h = normalize(mac)
    return sep.join(h[i:i + 2] for i in range(0, 12, 2))


def _load():
    global _cache
    if _cache is None:
        _cache = dict(BUILTIN)
        p = cache_path()
        if p.exists():
            try:
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    m = re.match(r"^\s*([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                    if m:
                        _cache[m.group(1).replace("-", "").upper()] = m.group(2).strip()
            except OSError:
                pass
    return _cache


def reload():
    global _cache
    _cache = None


def lookup(mac):
    """Manufacturer for a MAC address, or '' if unknown. Notes locally administered (randomised) addresses."""
    h = normalize(mac)
    name = _load().get(h[:6], "")
    if not name and int(h[1], 16) & 2:
        return "(locally administered / randomised address)"
    return name


def update_from_ieee(timeout=30):
    """Download the IEEE OUI list (about 6 MB) into the cache. Returns the number of entries."""
    import requests
    r = requests.get("https://standards-oui.ieee.org/oui/oui.txt", timeout=timeout)
    r.raise_for_status()
    cache_path().write_text(r.text, encoding="utf-8")
    reload()
    return len(_load())


def send_wol(mac, broadcast="255.255.255.255", port=9):
    """Send a Wake-on-LAN magic packet. Returns the packet length."""
    h = normalize(mac)
    packet = b"\xff" * 6 + bytes.fromhex(h) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(packet, (broadcast, int(port)))
    return len(packet)
