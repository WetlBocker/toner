"""SNMP queries for the Tools tab (read-only: Get, Get-Next, Walk, Bulk-Walk).

Uses pysnmp (asyncio API) but is driven synchronously from a worker thread. Object names come from the
small table below instead of MIB files, so nothing has to be downloaded or compiled.
"""
import asyncio
import re
import socket
import threading
import time
from dataclasses import dataclass

from core import nettools
from core import quiet

VERSIONS = [("SNMP v2c", "2c"), ("SNMP v1", "1"), ("SNMP v3", "3")]
LEVELS = ["noAuthNoPriv", "authNoPriv", "authPriv"]
AUTH_PROTOCOLS = ["SHA", "MD5", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]
PRIV_PROTOCOLS = ["AES-128", "AES-192", "AES-256", "DES"]
OPERATIONS = [("Get", "get"), ("Get next", "getnext"), ("Walk", "walk"), ("Bulk walk (v2c/v3)", "bulkwalk"),
              ("System info", "system"), ("Interfaces", "interfaces"), ("Interface rates (5 s)", "rates"),
              ("Neighbours (LLDP / CDP)", "neighbors")]
MAX_ROWS = 100000

# name -> numeric OID. Enough to read common results and to type names instead of numbers.
NAMES = {
    "iso": "1", "org": "1.3", "dod": "1.3.6", "internet": "1.3.6.1", "mgmt": "1.3.6.1.2", "mib-2": "1.3.6.1.2.1",
    "enterprises": "1.3.6.1.4.1",
    "system": "1.3.6.1.2.1.1", "sysDescr": "1.3.6.1.2.1.1.1", "sysObjectID": "1.3.6.1.2.1.1.2",
    "sysUpTime": "1.3.6.1.2.1.1.3", "sysContact": "1.3.6.1.2.1.1.4", "sysName": "1.3.6.1.2.1.1.5",
    "sysLocation": "1.3.6.1.2.1.1.6", "sysServices": "1.3.6.1.2.1.1.7", "sysORLastChange": "1.3.6.1.2.1.1.8",
    "interfaces": "1.3.6.1.2.1.2", "ifNumber": "1.3.6.1.2.1.2.1", "ifTable": "1.3.6.1.2.1.2.2",
    "ifEntry": "1.3.6.1.2.1.2.2.1", "ifIndex": "1.3.6.1.2.1.2.2.1.1", "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifType": "1.3.6.1.2.1.2.2.1.3", "ifMtu": "1.3.6.1.2.1.2.2.1.4", "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6", "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8", "ifLastChange": "1.3.6.1.2.1.2.2.1.9",
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10", "ifInDiscards": "1.3.6.1.2.1.2.2.1.13",
    "ifInErrors": "1.3.6.1.2.1.2.2.1.14", "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
    "ifOutDiscards": "1.3.6.1.2.1.2.2.1.19", "ifOutErrors": "1.3.6.1.2.1.2.2.1.20",
    "ifXTable": "1.3.6.1.2.1.31.1.1", "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6", "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15", "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "ip": "1.3.6.1.2.1.4", "ipForwarding": "1.3.6.1.2.1.4.1", "ipAddrTable": "1.3.6.1.2.1.4.20",
    "ipAdEntAddr": "1.3.6.1.2.1.4.20.1.1", "ipRouteTable": "1.3.6.1.2.1.4.21",
    "tcp": "1.3.6.1.2.1.6", "udp": "1.3.6.1.2.1.7", "snmp": "1.3.6.1.2.1.11",
    "host": "1.3.6.1.2.1.25", "hrSystemUptime": "1.3.6.1.2.1.25.1.1", "hrMemorySize": "1.3.6.1.2.1.25.2.2",
    "hrStorageTable": "1.3.6.1.2.1.25.2.3", "hrStorageDescr": "1.3.6.1.2.1.25.2.3.1.3",
    "hrStorageAllocationUnits": "1.3.6.1.2.1.25.2.3.1.4", "hrStorageSize": "1.3.6.1.2.1.25.2.3.1.5",
    "hrStorageUsed": "1.3.6.1.2.1.25.2.3.1.6", "hrProcessorLoad": "1.3.6.1.2.1.25.3.3.1.2",
    "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2", "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
    "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
    "dot1dBridge": "1.3.6.1.2.1.17", "lldpRemTable": "1.0.8802.1.1.2.1.4.1",
    "bgpPeerTable": "1.3.6.1.2.1.15.3", "bgpPeerState": "1.3.6.1.2.1.15.3.1.2", "ospfNbrTable": "1.3.6.1.2.1.14.10",
    "cpmCPUTotal5minRev": "1.3.6.1.4.1.9.9.109.1.1.1.1.8", "ciscoMemoryPoolUsed": "1.3.6.1.4.1.9.9.48.1.1.1.5",
    "ciscoMemoryPoolFree": "1.3.6.1.4.1.9.9.48.1.1.1.6",
    "fgSysCpuUsage": "1.3.6.1.4.1.12356.101.4.1.3", "fgSysMemUsage": "1.3.6.1.4.1.12356.101.4.1.4",
    "jnxOperatingCPU": "1.3.6.1.4.1.2636.3.1.13.1.8", "jnxOperatingBuffer": "1.3.6.1.4.1.2636.3.1.13.1.11",
    "snmpTrapOID": "1.3.6.1.6.3.1.1.4.1",
}
_BY_OID = sorted(((v, k) for k, v in NAMES.items()), key=lambda kv: -len(kv[0]))
_ROOTS = {v for v in NAMES.values() if v.count(".") < 6}        # iso, internet, mib-2...: named only when exact
IF_STATUS = {"1": "up", "2": "down", "3": "testing", "4": "unknown", "5": "dormant", "6": "notPresent",
             "7": "lowerLayerDown"}

IF_COLUMNS = [("ifDescr", "Name"), ("ifAdminStatus", "Admin"), ("ifOperStatus", "Status"), ("ifSpeed", "Speed"),
              ("ifInErrors", "In errors"), ("ifOutErrors", "Out errors"), ("ifInOctets", "In octets"),
              ("ifOutOctets", "Out octets")]


@dataclass
class Credentials:
    version: str = "2c"                 # "1", "2c" or "3"
    community: str = "public"
    user: str = ""
    level: str = "noAuthNoPriv"
    auth_protocol: str = "SHA"
    auth_key: str = ""
    priv_protocol: str = "AES-128"
    priv_key: str = ""


def parse_oid(text):
    """'1.3.6.1.2.1.1.1.0', '.1.3.6...', 'sysDescr.0', 'IF-MIB::ifDescr.3' -> numeric dotted OID."""
    s = (text or "").strip()
    if "::" in s:
        s = s.split("::", 1)[1]
    if not s:
        raise ValueError("Enter an OID or a name such as sysDescr.0")
    s = s.lstrip(".") if re.match(r"^\.?\d", s) else s
    if re.fullmatch(r"\d+(\.\d+)*", s):
        return s
    m = re.fullmatch(r"([A-Za-z][\w-]*)((?:\.\d+)*)", s)
    if m and m.group(1) in NAMES:
        return NAMES[m.group(1)] + m.group(2)
    if m:
        raise ValueError(f"'{m.group(1)}' is not a name I know. Use the numeric OID (for example 1.3.6.1.2.1.1.1.0).")
    raise ValueError(f"'{text}' is not a valid OID")


def name_of(oid):
    """Numeric OID -> 'ifDescr.3' where the table knows it, else the number itself."""
    for num, name in _BY_OID:
        if oid == num:
            return name
        if oid.startswith(num + ".") and num not in _ROOTS:
            return f"{name}.{oid[len(num) + 1:]}"
    return oid


def _ticks(v):
    from core import display
    return f"{int(v)} ({display.uptime(seconds=int(v) // 100)})"      # whole seconds gone by: 53 hundredths is not yet a second


def format_value(value):
    """pysnmp value -> (type name, readable text)."""
    kind = type(value).__name__
    try:
        if kind == "OctetString":
            raw = bytes(value)
            try:
                text = raw.decode("utf-8")
                if text.isprintable() or all(c in "\r\n\t" or c.isprintable() for c in text):
                    return "OctetString", text
            except UnicodeDecodeError:
                pass
            return "OctetString (hex)", raw.hex(":") if raw else ""
        if kind == "TimeTicks":
            return "TimeTicks", _ticks(value)
        if kind in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
            return kind, ""
        return kind, value.prettyPrint()
    except Exception:
        return kind, str(value)


_HINTS = (
    ("timeout", "No response. Check the address, that UDP port {port} is reachable, the community or v3 "
                "credentials, and that the device's SNMP access list allows this computer."),
    ("wrong snmp pdu digest", "The device rejected the authentication: wrong password or protocol (SHA versus MD5)."),
    ("unknown user", "The device does not know that SNMPv3 user name."),
    ("unsupported security level", "The device does not allow that security level for this user."),
    ("unknown security name", "The device does not know that SNMPv3 user name."),
    ("decryption error", "The device could not decrypt the request: wrong privacy password or protocol."),
    ("not in time window", "The SNMPv3 time window was missed; try again."),
)


def friendly(err, port=161):
    text = str(err)
    low = text.lower()
    if "no snmp response" in low:
        low = "timeout"
    for key, hint in _HINTS:
        if key in low:
            return hint.format(port=port) + f"  [{text}]"
    return text


def _validate(creds):
    if creds.version not in ("1", "2c", "3"):
        raise ValueError("unknown SNMP version")
    if creds.version in ("1", "2c"):
        if not creds.community:
            raise ValueError("Enter the community string.")
        return
    if not creds.user:
        raise ValueError("SNMPv3 needs a user name.")
    if creds.level in ("authNoPriv", "authPriv") and len(creds.auth_key) < 8:
        raise ValueError("The authentication password must be at least 8 characters.")
    if creds.level == "authPriv" and len(creds.priv_key) < 8:
        raise ValueError("The privacy password must be at least 8 characters.")


def _auth_data(creds):
    from pysnmp.hlapi.v3arch import asyncio as h
    if creds.version in ("1", "2c"):
        return h.CommunityData(creds.community, mpModel=0 if creds.version == "1" else 1)
    auth = {"SHA": h.USM_AUTH_HMAC96_SHA, "MD5": h.USM_AUTH_HMAC96_MD5, "SHA-224": h.USM_AUTH_HMAC128_SHA224,
            "SHA-256": h.USM_AUTH_HMAC192_SHA256, "SHA-384": h.USM_AUTH_HMAC256_SHA384,
            "SHA-512": h.USM_AUTH_HMAC384_SHA512}[creds.auth_protocol]
    priv = {"AES-128": h.USM_PRIV_CFB128_AES, "AES-192": h.USM_PRIV_CFB192_AES, "AES-256": h.USM_PRIV_CFB256_AES,
            "DES": h.USM_PRIV_CBC56_DES}[creds.priv_protocol]
    if creds.level == "noAuthNoPriv":
        return h.UsmUserData(creds.user)
    if creds.level == "authNoPriv":
        return h.UsmUserData(creds.user, authKey=creds.auth_key, authProtocol=auth)
    return h.UsmUserData(creds.user, authKey=creds.auth_key, authProtocol=auth,
                         privKey=creds.priv_key, privProtocol=priv)


@dataclass
class Row:
    oid: str
    name: str
    type: str
    value: str


@dataclass
class Outcome:
    rows: list
    error: str = ""
    seconds: float = 0.0
    truncated: bool = False
    cancelled: bool = False
    columns: list = None                 # set by the operations that return a ready-made table
    table: list = None


def _resolve(host):
    """(ip, is_ipv6) for the transport; raises ValueError with a readable message."""
    host = nettools.check_host(host)
    try:
        info = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)[0]
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve '{host}': {e.strerror or e}") from None
    return info[4][0], info[0] == socket.AF_INET6


async def _query(host, port, creds, op, oids, timeout, retries, max_rows, cancel, on_rows):
    from pysnmp.hlapi.v3arch import asyncio as h
    ip, v6 = _resolve(host)
    engine = h.SnmpEngine()
    out = Outcome([])
    ctx = h.ContextData()
    try:
        cls = h.Udp6TransportTarget if v6 else h.UdpTransportTarget
        target = await cls.create((ip, port), timeout=timeout, retries=retries)
        auth = _auth_data(creds)

        def add(varbinds):
            new = []
            for vb in varbinds:
                oid = str(vb[0])
                typ, val = format_value(vb[1])
                new.append(Row(oid, name_of(oid), typ, val))
            out.rows.extend(new)
            if on_rows and new:
                on_rows(new)

        def failed(ind, status, index, varbinds):
            if ind:
                out.error = friendly(ind, port)
            elif status:
                bad = varbinds[int(index) - 1][0] if index and 0 < int(index) <= len(varbinds) else ""
                out.error = f"{status.prettyPrint()}" + (f" at {name_of(str(bad))}" if bad else "")
            return bool(ind or status)

        if op in ("get", "system"):
            ind, status, index, vbs = await h.get_cmd(engine, auth, target, ctx,
                                                      *[h.ObjectType(h.ObjectIdentity(o)) for o in oids])
            if not failed(ind, status, index, vbs):
                add(vbs)
        elif op == "getnext":
            ind, status, index, vbs = await h.next_cmd(engine, auth, target, ctx,
                                                       *[h.ObjectType(h.ObjectIdentity(o)) for o in oids])
            if not failed(ind, status, index, vbs):
                add(vbs)
        else:                                                    # walk, bulkwalk, interfaces
            if op == "bulkwalk" and creds.version == "1":
                raise ValueError("Bulk walk needs SNMP v2c or v3; use Walk for v1.")
            for root in oids:
                gen = (h.bulk_walk_cmd(engine, auth, target, ctx, 0, 25, h.ObjectType(h.ObjectIdentity(root)),
                                       lexicographicMode=False)
                       if op == "bulkwalk" or (op == "interfaces" and creds.version != "1")
                       else h.walk_cmd(engine, auth, target, ctx, h.ObjectType(h.ObjectIdentity(root)),
                                       lexicographicMode=False))
                async for ind, status, index, vbs in gen:
                    if cancel.is_set():
                        out.cancelled = True
                        break
                    if failed(ind, status, index, vbs):
                        break
                    add(vbs)
                    if len(out.rows) >= max_rows:
                        out.truncated = True
                        break
                if out.error or out.cancelled or out.truncated:
                    break
    except ValueError as e:
        out.error = str(e)
    except Exception as e:
        out.error = friendly(f"{type(e).__name__}: {e}", port)
    finally:
        try:
            engine.close_dispatcher()
        except Exception:
            quiet.ignored()
    return out


def query(host, port, creds, op, oid="", timeout=3, retries=1, max_rows=2000, cancel=None, on_rows=None):
    """Run one SNMP operation and return an Outcome. Never raises for network or device errors."""
    start = time.time()
    cancel = cancel or threading.Event()
    try:
        _validate(creds)
        if not 1 <= int(port) <= 65535:
            raise ValueError("The port must be between 1 and 65535.")
        if op in ("rates", "neighbors"):
            out = Outcome([])
            try:
                with Client(host, int(port), creds, timeout=timeout, retries=retries) as c:
                    if op == "rates":
                        data = interface_rates(c, 5)
                        out.columns = ["Interface", "Status", "Speed", "In", "Out", "Utilisation"]
                        out.table = [[d["name"], d["status"], fmt_bps(d["speed_bps"]) if d["speed_bps"] else "",
                                      fmt_bps(d["in_bps"]), fmt_bps(d["out_bps"]),
                                      f"{d['util']:.1f}%" if d["util"] is not None else ""] for d in data]
                    else:
                        data = neighbors(c)
                        out.columns = ["Protocol", "Local port", "Neighbour", "Remote port", "Address", "Description"]
                        out.table = [[d["protocol"], d["local_port"], d["remote_name"], d["remote_port"],
                                      d["remote_addr"], d["remote_desc"]] for d in data]
            except (SnmpError, ValueError) as e:
                out.error = str(e)
            out.seconds = time.time() - start
            return out
        if op == "system":
            oids = [NAMES[n] + ".0" for n in ("sysDescr", "sysObjectID", "sysUpTime", "sysContact", "sysName",
                                              "sysLocation")]
        elif op == "interfaces":
            oids = [NAMES[n] for n, _ in IF_COLUMNS]
        else:
            oids = [parse_oid(oid)]
        out = asyncio.run(_query(host, int(port), creds, op, oids, timeout, retries, min(max_rows, MAX_ROWS),
                                 cancel, on_rows))
    except ValueError as e:
        out = Outcome([], error=str(e))
    out.seconds = time.time() - start
    return out


def interface_table(rows):
    """Pivot raw ifTable rows into [{'index': '3', 'ifDescr': 'Gi0/3', ...}] ordered by index."""
    cols = {NAMES[n]: n for n, _ in IF_COLUMNS}
    table = {}
    for r in rows:
        col, _, idx = r.oid.rpartition(".")
        if col in cols:
            table.setdefault(int(idx), {})[cols[col]] = r.value
    out = []
    for idx in sorted(table):
        d = table[idx]
        for k in ("ifAdminStatus", "ifOperStatus"):
            if k in d:
                d[k] = IF_STATUS.get(d[k].split("(")[0].strip() if "(" in d[k] else d[k], d[k])
        if "ifSpeed" in d and d["ifSpeed"].isdigit():
            bps = int(d["ifSpeed"])
            d["ifSpeed"] = (f"{bps / 1e9:g} Gbps" if bps >= 1e9 else f"{bps / 1e6:g} Mbps" if bps >= 1e6
                            else f"{bps / 1e3:g} kbps" if bps >= 1e3 else f"{bps} bps")
        out.append({"index": str(idx), **d})
    return out


# ======================================================================================================
# A reusable client (for drivers and discovery): one event loop and one engine for many requests
# ======================================================================================================
NAMES.update({
    "lldpRemTable": "1.0.8802.1.1.2.1.4.1", "lldpRemEntry": "1.0.8802.1.1.2.1.4.1.1",
    "lldpLocSysName": "1.0.8802.1.1.2.1.3.3", "lldpLocPortTable": "1.0.8802.1.1.2.1.3.7",
    "cdpCacheTable": "1.3.6.1.4.1.9.9.23.1.2.1", "cdpCacheEntry": "1.3.6.1.4.1.9.9.23.1.2.1.1",
    "ucd": "1.3.6.1.4.1.2021", "memTotalReal": "1.3.6.1.4.1.2021.4.5", "memAvailReal": "1.3.6.1.4.1.2021.4.6",
    "memBuffer": "1.3.6.1.4.1.2021.4.14", "memCached": "1.3.6.1.4.1.2021.4.15", "ssCpuIdle": "1.3.6.1.4.1.2021.11.11",
    "entPhySensorType": "1.3.6.1.2.1.99.1.1.1.1", "entPhySensorValue": "1.3.6.1.2.1.99.1.1.1.4",
    "hrStorageType": "1.3.6.1.2.1.25.2.3.1.2", "ifInMulticastPkts": "1.3.6.1.2.1.31.1.1.1.2",
})
_BY_OID[:] = sorted(((v, k) for k, v in NAMES.items()), key=lambda kv: -len(kv[0]))
_ROOTS.update(v for v in NAMES.values() if v.count(".") < 6)

# first digits of an enterprise number (sysObjectID 1.3.6.1.4.1.<n>) -> vendor key used by Toner
ENTERPRISES = {9: "cisco", 2636: "juniper", 30065: "arista", 11: "hpe", 25506: "hpe", 47196: "hpe", 14988: "mikrotik",
               12356: "fortinet", 25461: "paloalto", 41112: "unifi", 674: "dell", 1916: "extreme", 2011: "huawei",
               4526: "netgear", 3955: "linksys", 2021: "net-snmp (Linux/BSD)", 8072: "net-snmp (Linux/BSD)",
               2620: "checkpoint", 6876: "vmware", 311: "windows", 232: "hpe", 1991: "foundry/brocade", 1588: "brocade",
               6486: "alcatel-lucent", 890: "zyxel", 171: "d-link", 5951: "netscaler", 3375: "f5", 19746: "f5",
               17713: "ubiquiti-airos", 10002: "ubiquiti", 7: "kyocera",
               8741: "sonicwall", 3097: "watchguard", 21067: "sophos", 2604: "sophos", 25053: "ruckus", 318: "apc", 534: "eaton", 476: "vertiv",
               3808: "cyberpower", 850: "tripp lite", 6574: "synology", 24681: "qnap", 789: "netapp", 10876: "supermicro", 19046: "lenovo",
               11863: "tp-link", 14823: "aruba", 4413: "extreme", 5624: "enterasys", 1602: "canon", 367: "ricoh", 253: "xerox", 641: "lexmark",
               2435: "brother", 1248: "epson", 236: "samsung printer", 1347: "kyocera/mita", 10734: "ricoh", 12325: "fireeye", 9148: "apple",
               4881: "ruijie", 2352: "ericsson", 2021: "net-snmp (Linux/BSD)", 3224: "netscreen", 25461: "paloalto", 3375: "f5", 2620: "checkpoint",
               388: "motorola", 2272: "passport/nortel", 45: "nortel", 1872: "alteon", 4874: "juniper (erx)", 3076: "silver peak", 12356: "fortinet",
               35265: "eltex", 33049: "sandvine", 12148: "ceragon", 22610: "a10", 14179: "cisco wlc", 14525: "trapeze", 6527: "nokia",
               2636: "juniper", 7114: "lantronix", 1991: "foundry/brocade", 674: "dell", 10892: "dell idrac", 232: "hpe", 343: "intel", 9: "cisco"}


class SnmpError(Exception):
    pass


def vendor_from_oid(sys_object_id):
    """'1.3.6.1.4.1.9.1.1745' -> 'cisco'; '' when the enterprise number is unknown."""
    m = re.match(r"\.?1\.3\.6\.1\.4\.1\.(\d+)", sys_object_id or "")
    return ENTERPRISES.get(int(m.group(1)), "") if m else ""


def credentials_for(dev):
    """(Credentials, port) for an inventory device, from its own SNMP settings or its profile's."""
    from core import profiles
    s = profiles.snmp_settings(dev)
    return Credentials(version=str(s["version"]), community=profiles.secret(dev, "snmp") or "", user=s["user"],
                       level=s["level"], auth_protocol=s["auth_protocol"],
                       auth_key=profiles.secret(dev, "snmp_auth") or "", priv_protocol=s["priv_protocol"],
                       priv_key=profiles.secret(dev, "snmp_priv") or ""), int(s["port"] or 161)


def text_of(raw):
    return '' if raw is None else format_value(raw)[1]


def number_of(raw, default=None):
    """An SNMP value as a float (Integer, Gauge, Counter, TimeTicks, or a numeric string), else `default`."""
    try:
        if type(raw).__name__ in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
            return default
        return float(int(raw))
    except (TypeError, ValueError):
        try:
            return float(str(raw).strip())
        except ValueError:
            return default


class Client:
    """Synchronous SNMP client that keeps one engine open, so SNMPv3 discovery happens once.
    Use as a context manager. Methods raise SnmpError with a readable message."""

    def __init__(self, host, port, creds, timeout=3, retries=1):
        from pysnmp.hlapi.v3arch import asyncio as h
        _validate(creds)
        self.h, self.port, self.creds = h, int(port), creds
        ip, v6 = _resolve(host)
        self.loop = asyncio.new_event_loop()
        self.engine = h.SnmpEngine()
        self.ctx = h.ContextData()
        self.auth = _auth_data(creds)
        try:
            cls = h.Udp6TransportTarget if v6 else h.UdpTransportTarget
            self.target = self.loop.run_until_complete(cls.create((ip, self.port), timeout=timeout, retries=retries))
        except Exception:
            self.close()
            raise

    def close(self):
        try:
            self.engine.close_dispatcher()
        except Exception:
            quiet.ignored()
        try:
            self.loop.close()
        except Exception:
            quiet.ignored()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def _fail(self, ind, status, index, vbs):
        if ind:
            raise SnmpError(friendly(ind, self.port))
        if status:
            bad = vbs[int(index) - 1][0] if index and 0 < int(index) <= len(vbs) else ""
            raise SnmpError(f"{status.prettyPrint()}" + (f" at {name_of(str(bad))}" if bad else ""))

    def get(self, *oids):
        """{numeric oid: raw value} for the objects that exist (missing ones are left out)."""
        h = self.h

        async def go():
            return await h.get_cmd(self.engine, self.auth, self.target, self.ctx,
                                   *[h.ObjectType(h.ObjectIdentity(o)) for o in oids])
        try:
            ind, status, index, vbs = self.loop.run_until_complete(go())
        except SnmpError:
            raise
        except Exception as e:
            raise SnmpError(friendly(f"{type(e).__name__}: {e}", self.port)) from None
        if status and not ind and len(oids) > 1:           # v1 fails the whole request for one missing object
            return self._get_each(oids)
        self._fail(ind, status, index, vbs)
        return {str(vb[0]): vb[1] for vb in vbs
                if type(vb[1]).__name__ not in ("NoSuchObject", "NoSuchInstance", "EndOfMibView")}

    def _get_each(self, oids):
        out = {}
        for o in oids:
            try:
                out.update(self.get(o))
            except SnmpError:
                pass
        return out

    def walk(self, root, max_rows=20000):
        """[(numeric oid, raw value)] under `root`. Uses bulk requests on v2c/v3."""
        h = self.h
        rows = []

        async def go():
            gen = (h.bulk_walk_cmd(self.engine, self.auth, self.target, self.ctx, 0, 25,
                                   h.ObjectType(h.ObjectIdentity(root)), lexicographicMode=False)
                   if self.creds.version != "1" else
                   h.walk_cmd(self.engine, self.auth, self.target, self.ctx,
                              h.ObjectType(h.ObjectIdentity(root)), lexicographicMode=False))
            async for ind, status, index, vbs in gen:
                self._fail(ind, status, index, vbs)
                rows.extend((str(vb[0]), vb[1]) for vb in vbs)
                if len(rows) >= max_rows:
                    break
        try:
            self.loop.run_until_complete(go())
        except SnmpError:
            raise
        except Exception as e:
            raise SnmpError(friendly(f"{type(e).__name__}: {e}", self.port)) from None
        return rows

    def column(self, root):
        """{row index (the part after root): raw value} for one table column."""
        return {oid[len(root) + 1:]: raw for oid, raw in self.walk(root) if oid.startswith(root + ".")}

    def try_get(self, *oids):
        try:
            return self.get(*oids)
        except SnmpError:
            return {}

    def try_column(self, root):
        try:
            return self.column(root)
        except SnmpError:
            return {}


def _mac_or_text(raw):
    kind, text = format_value(raw)
    return text


def neighbors(client):
    """LLDP and CDP neighbours as a list of dicts: protocol, local_port, remote_name, remote_port, remote_desc,
    remote_addr. Either protocol may be absent on a device; that is not an error."""
    out = []
    # ---- LLDP
    base = NAMES["lldpRemEntry"]
    names, ports, pdesc, sdesc = (client.try_column(f"{base}.{i}") for i in (9, 7, 8, 10))
    chassis = client.try_column(f"{base}.5")
    loc = client.try_column(NAMES["lldpLocPortTable"] + ".1.4")        # local port descriptions
    locid = client.try_column(NAMES["lldpLocPortTable"] + ".1.3")
    for idx in sorted(set(names) | set(ports) | set(chassis)):
        parts = idx.split(".")
        local_no = parts[1] if len(parts) >= 3 else ""
        rport = text_of(pdesc.get(idx)) if idx in pdesc and text_of(pdesc[idx]) else text_of(ports.get(idx, ""))
        out.append({"protocol": "LLDP",
                    "local_port": (text_of(loc[local_no]) if local_no in loc and text_of(loc[local_no])
                                   else text_of(locid.get(local_no, "")) or local_no),
                    "remote_name": text_of(names.get(idx, "")) or text_of(chassis.get(idx, "")),
                    "remote_port": rport, "remote_desc": text_of(sdesc.get(idx, ""))[:120], "remote_addr": ""})
    # ---- CDP
    cbase = NAMES["cdpCacheEntry"]
    cid, cport, cplat, caddr = (client.try_column(f"{cbase}.{i}") for i in (6, 7, 8, 4))
    ifdescr = client.try_column(NAMES["ifDescr"]) if cid else {}
    for idx in sorted(cid):
        ifidx = idx.split(".")[0]
        addr = ""
        raw = caddr.get(idx)
        if raw is not None:
            try:
                b = bytes(raw)
                addr = ".".join(str(x) for x in b) if len(b) == 4 else ""
            except Exception:
                addr = ""
        out.append({"protocol": "CDP", "local_port": text_of(ifdescr.get(ifidx, "")) or ifidx,
                    "remote_name": text_of(cid[idx]), "remote_port": text_of(cport.get(idx, "")),
                    "remote_desc": text_of(cplat.get(idx, "")), "remote_addr": addr})
    return out


def interface_rates(client, seconds=5):
    """Two samples `seconds` apart -> per-interface in/out bits per second and utilisation. Returns
    [{'index','name','status','speed_bps','in_bps','out_bps','util'}]."""
    import time as _t
    cols = {"in": NAMES["ifHCInOctets"], "out": NAMES["ifHCOutOctets"]}

    def sample():
        res = {}
        for k, root in cols.items():
            col = client.try_column(root)
            if not col:                                                   # 32-bit counters on older devices
                col = client.try_column(NAMES["ifInOctets"] if k == "in" else NAMES["ifOutOctets"])
                res[k + "_wrap"] = 2 ** 32
            res[k] = {i: number_of(v, 0.0) for i, v in col.items()}
        return res, _t.time()
    a, t0 = sample()
    _t.sleep(max(1, seconds))
    b, t1 = sample()
    dt = max(t1 - t0, 0.001)
    names = {i: text_of(v) for i, v in client.try_column(NAMES["ifDescr"]).items()}
    alias = {i: text_of(v) for i, v in client.try_column(NAMES["ifName"]).items()}
    oper = {i: text_of(v) for i, v in client.try_column(NAMES["ifOperStatus"]).items()}
    high = {i: number_of(v, 0.0) * 1e6 for i, v in client.try_column(NAMES["ifHighSpeed"]).items()}
    low = {i: number_of(v, 0.0) for i, v in client.try_column(NAMES["ifSpeed"]).items()}
    rows = []
    for i in sorted(names, key=lambda x: int(x) if x.isdigit() else 0):
        def rate(k):
            wrap = b.get(k + "_wrap", 2 ** 64)
            d = b[k].get(i, 0.0) - a[k].get(i, 0.0)
            return (d + wrap if d < 0 else d) * 8 / dt
        speed = high.get(i) or low.get(i) or 0.0
        rin, rout = rate("in"), rate("out")
        rows.append({"index": i, "name": alias.get(i) or names[i], "status": IF_STATUS.get(oper.get(i, ""), oper.get(i, "")),
                     "speed_bps": speed, "in_bps": rin, "out_bps": rout,
                     "util": max(rin, rout) / speed * 100 if speed else None})
    return rows


def fmt_bps(v):
    for unit, size in (("Gbps", 1e9), ("Mbps", 1e6), ("kbps", 1e3)):
        if v >= size:
            return f"{v / size:.1f} {unit}"
    return f"{v:.0f} bps"
