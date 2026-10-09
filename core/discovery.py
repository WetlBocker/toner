"""Find devices on a network and work out what they are: open ports, SSH banner, certificate, SNMP identity."""
import ipaddress
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from core import db, nettools, snmp, vendors

MAX_TARGETS = 4096

# SSH banner / certificate / header keywords -> vendor hint
BANNERS = [("cisco", "cisco"), ("rosssh", "mikrotik"), ("mikrotik", "mikrotik"), ("junos", "juniper"),
           ("netscreen", "juniper"), ("fortigate", "fortinet"), ("forti", "fortinet"), ("comware", "hpe"),
           ("huawei", "huawei"), ("arista", "arista"), ("aruba", "hpe"), ("procurve", "hpe"), ("palo alto", "paloalto"),
           ("paloalto", "paloalto"), ("pan-os", "paloalto"), ("unifi", "unifi"), ("ubiquiti", "unifi"),
           ("meraki", "meraki"), ("dropbear", "(embedded Linux)"), ("openssh", "(Linux/BSD server or appliance)"),
           ("ubnt", "unifi"), ("netgear", "netgear"), ("dell", "dell"), ("extreme", "extreme"), ("mellanox", "nvidia")]


def targets(text):
    """'10.0.0.0/24', '10.0.0.5-40', 'host', or several separated by commas/spaces -> list of IP strings."""
    out, seen = [], set()
    for part in re.split(r"[,\s]+", (text or "").strip()):
        if not part:
            continue
        found = []
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            if net.num_addresses > MAX_TARGETS * 4:
                raise ValueError(f"{part} is too large ({net.num_addresses:,} addresses). Use a /20 or smaller.")
            found = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
        elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+-\d+", part):
            base, _, last = part.rpartition("-")
            start = int(base.rsplit(".", 1)[1])
            if not (0 <= start <= int(last) <= 255):
                raise ValueError(f"'{part}' is not a valid range.")
            found = [f"{base.rsplit('.', 1)[0]}.{i}" for i in range(start, int(last) + 1)]
        else:
            found = [nettools.resolve_host(nettools.check_host(part))]
        for ip in found:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
    if len(out) > MAX_TARGETS:
        raise ValueError(f"That is {len(out):,} addresses; scan at most {MAX_TARGETS:,} at a time.")
    if not out:
        raise ValueError("Enter an address, a range such as 10.0.0.1-50, or a CIDR such as 10.0.0.0/24.")
    return out


def _tcp_open(ip, port, timeout):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        return s
    except OSError:
        return None


def ssh_banner(ip, port=22, timeout=1.5):
    s = _tcp_open(ip, port, timeout)
    if not s:
        return ""
    try:
        s.settimeout(timeout)
        data = s.recv(255)
        return data.decode("utf-8", "replace").strip().splitlines()[0] if data else ""
    except OSError:
        return ""
    finally:
        s.close()


def tls_info(ip, port=443, timeout=2.0):
    """Subject and issuer of the certificate on a port, plus the HTTP Server header. {} when not TLS."""
    from core import custom
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                der = s.getpeercert(binary_form=True)
                server = ""
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    head = s.recv(2048).decode("latin-1", "replace")
                    m = re.search(r"(?im)^server:\s*(.+)$", head)
                    server = m.group(1).strip() if m else ""
                except OSError:
                    pass
        info = custom.cert_info(der)
        return {"subject": info["subject"], "issuer": info["issuer"], "server": server}
    except Exception:
        return {}


def hint_from_text(*texts):
    blob = " ".join(t for t in texts if t).lower()
    for key, vendor in BANNERS:
        if key in blob:
            return vendor
    return ""


def guess_platform(vendor, descr):
    d = (descr or "").lower()
    if vendor == "cisco":
        if "nx-os" in d or "nexus" in d:
            return "cisco_nxos"
        if "adaptive security" in d or "asa" in d.split():
            return "cisco_asa"
        if "ios-xe" in d or "ios xe" in d or "iosxe" in d:
            return "cisco_xe"
        return "cisco_ios"
    if vendor == "hpe":
        return "aruba_aoscx" if "aos-cx" in d or "arubaos-cx" in d else "aruba_osswitch"
    return vendors.default_platform(vendor)


def netcheck_vendor(hint, snmp_ok):
    """Map a vendor hint to a vendor Toner supports; generic SNMP if only SNMP answered; '' if unknown."""
    if hint in vendors.VENDORS:
        return hint
    return "snmp" if snmp_ok else ""


def probe(ip, communities=(), ports=(22, 443), timeout=1.0, snmp_port=161, ssh_ports=(22,), tls_ports=(443, 8443)):
    """Look at one address. Returns a dict, or None when nothing answered."""
    open_ports = []
    for p in ports:
        s = _tcp_open(ip, p, timeout)
        if s:
            s.close()
            open_ports.append(p)
    ident = {}
    community = ""
    for com in communities:
        try:
            with snmp.Client(ip, snmp_port, snmp.Credentials(version="2c", community=com), timeout=1, retries=0) as c:
                got = c.get(snmp.NAMES["sysDescr"] + ".0", snmp.NAMES["sysObjectID"] + ".0", snmp.NAMES["sysName"] + ".0")
        except Exception:
            continue
        if got:
            ident = {"descr": " ".join(snmp.text_of(got.get(snmp.NAMES["sysDescr"] + ".0", "")).split()),
                     "object_id": snmp.text_of(got.get(snmp.NAMES["sysObjectID"] + ".0", "")),
                     "sysname": snmp.text_of(got.get(snmp.NAMES["sysName"] + ".0", ""))}
            community = com
            break
    if not open_ports and not ident:
        return None
    banner = next((b for b in (ssh_banner(ip, p, timeout + 0.5) for p in ssh_ports if p in open_ports) if b), "")
    cert = next((c for c in (tls_info(ip, p, timeout + 1) for p in tls_ports if p in open_ports) if c), {})
    hint = (snmp.vendor_from_oid(ident.get("object_id", "")) or hint_from_text(ident.get("descr"))
            or hint_from_text(banner) or hint_from_text(cert.get("subject"), cert.get("issuer"), cert.get("server")))
    try:
        host = socket.gethostbyaddr(ip)[0]
    except OSError:
        host = ""
    vendor = netcheck_vendor(hint, bool(ident))
    name = (ident.get("sysname") or host.split(".")[0] or cert.get("subject", "").split(".")[0] or ip).strip()
    return {"ip": ip, "hostname": host, "name": re.sub(r"[^A-Za-z0-9_.\-]+", "-", name) or ip, "vendor": vendor,
            "hint": hint, "descr": ident.get("descr", ""), "snmp": bool(ident), "community": community,
            "ports": open_ports, "banner": banner, "cert": cert.get("subject", ""),
            "platform": guess_platform(vendor, ident.get("descr", "")) if vendor else ""}


def scan(addresses, communities=(), ports=(22, 443), workers=48, on_found=None, on_progress=None, cancel=None, timeout=1.0,
         **probe_kw):
    """Probe many addresses in parallel. Returns the list of found devices."""
    found, done = [], 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(probe, ip, communities, ports, timeout, **probe_kw): ip for ip in addresses}
        for f in as_completed(futs):
            done += 1
            if cancel is not None and cancel.is_set():
                for g in futs:
                    g.cancel()
                break
            try:
                r = f.result()
            except Exception:
                r = None
            if r:
                found.append(r)
                if on_found:
                    on_found(r)
            if on_progress:
                on_progress(done, len(addresses))
    found.sort(key=lambda r: ipaddress.ip_address(r["ip"]))
    return found


def known_hosts():
    """IP addresses already in the inventory (host fields that are IPs, or resolve to one quickly)."""
    out = set()
    for d in db.list_devices():
        try:
            ipaddress.ip_address(d["host"])
            out.add(d["host"])
        except ValueError:
            try:
                out.add(socket.gethostbyname(d["host"]))
            except OSError:
                pass
    return out


def unique_name(base, taken):
    name, n = base, 2
    while name.lower() in taken:
        name = f"{base}-{n}"
        n += 1
    return name


def add_to_inventory(rows, folder_id=None, profile_id=None, location="", tags=""):
    """Create inventory devices from discovery rows. Each row needs 'ip', 'name', 'vendor'; rows with no vendor
    are skipped. Returns (added names, skipped messages)."""
    taken = {d["name"].lower() for d in db.list_devices()}
    added, skipped = [], []
    for r in rows:
        vendor = r.get("vendor")
        if vendor not in vendors.VENDORS:
            skipped.append(f"{r['ip']}: choose a vendor first")
            continue
        name = unique_name(r.get("name") or r["ip"], taken)
        taken.add(name.lower())
        snmp_cfg = {"version": "2c", "port": 161} if r.get("snmp") else ""
        db.save_device({"name": name, "vendor": vendor, "host": r["ip"], "port": 0,
                        "platform": r.get("platform") or vendors.default_platform(vendor), "username": "",
                        "site": "default", "verify_ssl": 0, "ha_expected": 0, "enabled": 1, "location": location,
                        "details": (r.get("descr") or "")[:120], "folder_id": folder_id, "profile_id": profile_id,
                        "tags": tags, "snmp": snmp_cfg if (vendor == "snmp" or r.get("snmp")) else ""})
        if r.get("snmp") and r.get("community"):
            db.set_secret(db.secret_name(name, "snmp"), r["community"])
        added.append(name)
    return added, skipped
