"""Neighbour discovery for the topology map: Layer 2 (LLDP / CDP over SNMP, over SSH for the SSH vendors, over the API for
Fortinet and Palo Alto) and Layer 3 (BGP, OSPF and EIGRP adjacencies read the same ways), each device's role for its tile,
two layouts (tiers and organic), endpoint grouping, the link state read beside the neighbours, and the last discovery kept
per organization so the map is there on opening and changes since the one before are marked."""
import math
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from core import db, profiles, quiet, snmp, vendors
from drivers import clichecks

# the show commands per platform; a platform not listed (ASA) reports no neighbours
CLI = {"cisco_ios": ("show cdp neighbors detail", "show lldp neighbors detail"),
       "cisco_xe": ("show cdp neighbors detail", "show lldp neighbors detail"),
       "cisco_nxos": ("show cdp neighbors detail", "show lldp neighbors detail"),
       "arista_eos": ("show lldp neighbors detail",), "juniper_junos": ("show lldp neighbors | no-more",),
       "aruba_aoscx": ("show lldp neighbor-info detail",), "aruba_osswitch": ("show lldp info remote-device detail",),
       "mikrotik_routeros": ("/ip neighbor print detail",)}
API_VENDORS = ("fortinet", "paloalto")
NOTHING = ("No devices that can report neighbours: set SNMP on a device (its SNMP tab) or a credential profile with SNMP, an SSH login "
           "on a Cisco, Arista, Juniper, HPE or MikroTik device, or the API key on a Fortinet or Palo Alto firewall.")


def devices():
    """The enabled devices that can be asked for neighbours: SNMP settings, an SSH vendor with commands, or an API firewall."""
    out = []
    for d in db.list_devices(enabled_only=True):
        v = d.get("vendor") or ""
        if profiles.snmp_configured(d) or vendors.is_snmp(v) or v in API_VENDORS:
            out.append(d)
        elif vendors.get(v).get("kind") == "ssh" and (d.get("platform") or vendors.default_platform(v)) in CLI:
            out.append(d)
    return out


def discover(dev):
    """(Layer 2 rows, Layer 3 rows) for one inventory device. A Layer 2 row: protocol, local_port, remote_name, remote_port,
    remote_desc, remote_addr, and for SNMP the local port's state (local_up, local_speed). A Layer 3 row: protocol (BGP, OSPF,
    EIGRP), neighbor (its address), state, up, interface, as, router_id. Raises snmp.SnmpError / ValueError on failure."""
    dev = profiles.resolve(dev)
    key = dev.get("key") or dev["name"]                          # Global: keyed apart from same-named devices
    v = dev.get("vendor") or ""
    if profiles.snmp_configured(dev) or vendors.is_snmp(v):
        creds, port = snmp.credentials_for(dev)
        with snmp.Client(dev["host"], port, creds, timeout=4, retries=1) as c:
            rows = snmp.neighbors(c)
            state = _port_state(c) if rows else {}
            l3 = _routing_snmp(c)
        for r in rows:
            st = state.get(short_port(r["local_port"]))
            r["local_up"], r["local_speed"] = (st[0], st[1]) if st else (None, "")
    elif v in API_VENDORS:
        rows, l3 = _api_rows(dev)
    else:
        rows, l3 = _cli_rows(dev)
    via = "SNMP" if profiles.snmp_configured(dev) or vendors.is_snmp(v) else "API" if v in API_VENDORS else "SSH"
    return ([{"device": key, "via": via, "local_up": None, "local_speed": "", **r} for r in rows],
            [{"device": key, "state": "", "up": True, "interface": "", "as": "", "router_id": "", **r} for r in l3])


def neighbours_of(dev):
    """The Layer 2 rows alone (see discover)."""
    return discover(dev)[0]


def _port_state(client):
    """{short port name: (up, 'speed')} from the interface table, for the link state beside each neighbour."""
    names = {i: snmp.text_of(x) for i, x in client.try_column(snmp.NAMES["ifDescr"]).items()}
    alias = {i: snmp.text_of(x) for i, x in client.try_column(snmp.NAMES["ifName"]).items()}
    oper = {i: snmp.text_of(x) for i, x in client.try_column(snmp.NAMES["ifOperStatus"]).items()}
    high = {i: snmp.number_of(x, 0.0) * 1e6 for i, x in client.try_column(snmp.NAMES["ifHighSpeed"]).items()}
    low = {i: snmp.number_of(x, 0.0) for i, x in client.try_column(snmp.NAMES["ifSpeed"]).items()}
    out = {}
    for i in set(names) | set(alias):
        up = {"1": True, "up": True, "2": False, "down": False}.get((oper.get(i) or "").lower())
        bps = high.get(i) or low.get(i) or 0.0
        speed = f"{bps / 1e9:g} Gbps" if bps >= 1e9 else f"{bps / 1e6:g} Mbps" if bps >= 1e6 else ""
        for n in (names.get(i), alias.get(i)):
            if n:
                out[short_port(n)] = (up, speed)
    return out


# ---------------------------------------------------------------- SSH and API sources
def _cli_rows(dev):
    from drivers import DRIVERS
    cls = DRIVERS[dev["vendor"]]
    plat = dev.get("platform") or cls.DEFAULT_PLATFORM
    cmds = CLI.get(plat, ())
    if not cmds:
        return []
    opts = db.runtime_options()
    drv = cls(dev, {}, opts)
    drv.plat = plat
    rows, l3 = [], []
    with drv.connect() as c:
        try:
            c.enable()
        except Exception:
            quiet.ignored()
        wait = max(60, int(opts.get("ssh_timeout", 20)) * 3)
        for cmd in cmds:
            rows += parse(plat, cmd, c.send_command(cmd, read_timeout=wait))
        for protocol, cmd in L3_CLI.get(plat, ()):
            try:
                l3 += parse_l3(protocol, c.send_command(cmd, read_timeout=wait))
            except Exception:                                   # a protocol the device does not run: its command errors or answers nothing
                quiet.ignored()
    return rows, l3


def _api_rows(dev):
    import requests, urllib3
    from core import proxy
    if not dev.get("verify_ssl"):
        urllib3.disable_warnings()
    opts = db.runtime_options()
    kw = dict(verify=bool(dev.get("verify_ssl")), timeout=opts["http_timeout"], **proxy.requests_kwargs(dev))
    base = f"https://{dev['host']}:{dev.get('port') or 443}"
    token = profiles.secret(dev) or ""
    if dev["vendor"] == "fortinet":
        hdr = {"Authorization": f"Bearer {token}"}
        r = requests.get(f"{base}/api/v2/monitor/network/lldp/neighbors", headers=hdr, **kw)
        r.raise_for_status()
        l3 = []
        for protocol, path in (("BGP", "router/bgp/neighbors"), ("OSPF", "router/ospf/neighbors")):
            try:
                a = requests.get(f"{base}/api/v2/monitor/{path}", headers=hdr, **kw)
                if a.status_code == 200:
                    l3 += parse_fortinet_l3(protocol, a.json())
            except Exception:
                quiet.ignored()
        return parse_fortinet(r.json()), l3
    hdr = {"X-PAN-KEY": token}
    r = requests.get(f"{base}/api/", params={"type": "op", "cmd": "<show><lldp><neighbors>all</neighbors></lldp></show>"}, headers=hdr, **kw)
    r.raise_for_status()
    l3 = []
    for protocol, cmd in (("BGP", "<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>"),
                          ("OSPF", "<show><routing><protocol><ospf><neighbor></neighbor></ospf></protocol></routing></show>")):
        try:
            a = requests.get(f"{base}/api/", params={"type": "op", "cmd": cmd}, headers=hdr, **kw)
            if a.status_code == 200:
                l3 += parse_panos_l3(protocol, a.text)
        except Exception:
            quiet.ignored()
    return parse_panos(r.text), l3


def _pick(d, *keys):
    for k in keys:
        if d.get(k) not in (None, ""):
            return str(d[k])
    return ""


def parse_fortinet(body):
    """FortiOS /api/v2/monitor/network/lldp/neighbors: one row per neighbour. shortcut: the field names are the 7.x ones
    (port / system_name / port_id); widen _pick when a FortiGate answers with others."""
    rows = []
    for n in (body.get("results") if isinstance(body, dict) else body) or []:
        if not isinstance(n, dict):
            continue
        rows.append({"protocol": "LLDP", "local_port": _pick(n, "port", "name", "local_port", "interface"),
                     "remote_name": _pick(n, "system_name", "system-name", "sysname", "hostname"), "remote_port": _pick(n, "port_id", "port-id", "portid"),
                     "remote_desc": _pick(n, "system_description", "system-description")[:120], "remote_addr": _pick(n, "mgmt_address", "management_address", "ip", "address")})
    return [r for r in rows if r["local_port"] and (r["remote_name"] or r["remote_port"])]


def parse_panos(text):
    """PAN-OS `show lldp neighbors all` as XML: an entry per local port, its neighbours under it."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    rows = []
    for port in root.iter("entry"):
        local = port.get("name") or ""
        if not local or port.find("neighbors") is None:
            continue
        for n in port.find("neighbors").findall("entry"):
            rows.append({"protocol": "LLDP", "local_port": local, "remote_name": (n.findtext("system-name") or "").strip(),
                         "remote_port": (n.findtext("port-id") or "").strip(), "remote_desc": (n.findtext("system-description") or "").strip()[:120],
                         "remote_addr": (n.findtext("management-address") or "").strip()})
    return [r for r in rows if r["remote_name"] or r["remote_port"]]


# ---------------------------------------------------------------- CLI parsers
_LOCAL = re.compile(r"^\s*(?:Local Intf|Local Interface|Local Port id|Local Port|Port)\s*:\s*(\S+)", re.I)
_CDP_IF = re.compile(r"^\s*Interface:\s*(\S+?),\s*Port ID \(outgoing port\):\s*(\S+)", re.I)
_ARISTA_IF = re.compile(r"^\s*Interface\s+(\S+)\s+detected\s+\d+\s+LLDP", re.I)
_NAME = re.compile(r"^\s*-?\s*(?:Device ID|System Name|SysName|System-Name)\s*:\s*\"?([^\"]*?)\"?\s*$", re.I)
_RPORT = re.compile(r"^\s*-?\s*(?:Port id|Port ID|PortId)(?:\s*\(type [^)]*\))?\s*:\s*\"?([^\"]*?)\"?\s*$", re.I)
_ADDR = re.compile(r"^\s*-?\s*(?:IP(?:v4)? address|IP|Management Address(?:es)?|Address)\s*:\s*(\d+\.\d+\.\d+\.\d+)", re.I)
_ARISTA_NB = re.compile(r"^\s*Neighbor\s+\S+/", re.I)          # a second neighbour on the same Arista port
_DESC = re.compile(r"^\s*-?\s*(?:Platform|System Description)\s*:\s*(.+?)\s*,?\s*$", re.I)
_JUNOS_ROW = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s+(\S+)\s*$")
_MT_PAIR = re.compile(r'(\S+?)=("[^"]*"|\S+)')


def parse(platform, command, text):
    """The neighbour rows one show command's output holds."""
    if platform == "juniper_junos":
        return parse_junos(text)
    if platform == "mikrotik_routeros":
        return parse_mikrotik(text)
    return parse_blocks(text, "CDP" if "cdp" in command else "LLDP")


def _blank(protocol):
    return {"protocol": protocol, "local_port": "", "remote_name": "", "remote_port": "", "remote_desc": "", "remote_addr": ""}


def parse_blocks(text, protocol):
    """Cisco, Arista and HPE 'detail' output: a block per neighbour with 'Key: value' lines. A block starts at the line that
    names the local port (or, CDP, at the Device ID before it) and ends at the next one or a ---- rule."""
    rows, cur = [], None

    def flush():
        if cur and cur["local_port"] and (cur["remote_name"] or cur["remote_port"]):
            rows.append(cur)

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if re.match(r"^\s*-{5,}\s*$", line):
            flush()
            cur = None
            continue
        m = _CDP_IF.match(line)
        if m:                                                   # CDP: both ports on one line, after the Device ID
            if cur is None or cur["local_port"]:
                flush()
                cur = _blank(protocol)
            cur["local_port"], cur["remote_port"] = m.group(1), m.group(2)
            continue
        m = _LOCAL.match(line) or _ARISTA_IF.match(line)
        if m:                                                   # the local port: opens a block, or completes one that began with the remote side (NX-OS)
            if cur is None or cur["local_port"]:
                flush()
                cur = _blank(protocol)
            cur["local_port"] = m.group(1)
            continue
        if _ARISTA_NB.match(line) and cur and cur["remote_name"]:
            local = cur["local_port"]
            flush()
            cur = _blank(protocol)
            cur["local_port"] = local
            continue
        m = _NAME.match(line)
        if m and cur is not None and cur["remote_name"]:       # a second Device ID / System Name: the next neighbour
            flush()
            cur = _blank(protocol)
        for rx, key in ((_NAME, "remote_name"), (_RPORT, "remote_port"), (_ADDR, "remote_addr"), (_DESC, "remote_desc")):
            m = rx.match(line)
            if m:
                if cur is None:
                    cur = _blank(protocol)
                if not cur[key]:
                    cur[key] = m.group(1).strip()[:120]
                break
    flush()
    return rows


def parse_junos(text):
    """`show lldp neighbors`: Local Interface, Parent Interface, Chassis Id, Port info, System Name."""
    rows, started = [], False
    for line in (text or "").splitlines():
        if re.match(r"^\s*Local Interface\s+", line, re.I):
            started = True
            continue
        m = _JUNOS_ROW.match(line.strip()) if started else None
        if m:
            rows.append({"protocol": "LLDP", "local_port": m.group(1), "remote_name": m.group(5), "remote_port": m.group(4).strip(),
                         "remote_desc": "", "remote_addr": ""})
    return rows


def parse_mikrotik(text):
    """`/ip neighbor print detail`: an entry per neighbour, 'key=value' pairs over one or more lines, a blank line between entries."""
    rows = []
    for chunk in re.split(r"\n\s*\n", (text or "").strip()):
        pairs = {k: v.strip('"') for k, v in _MT_PAIR.findall(chunk.replace("\n", " "))}
        if not pairs.get("interface"):
            continue
        by = pairs.get("discovered-by", "").lower()
        rows.append({"protocol": "CDP" if "cdp" in by and "lldp" not in by else "LLDP",
                     "local_port": pairs["interface"].split(",")[0], "remote_name": pairs.get("identity", ""), "remote_port": pairs.get("interface-name", ""),
                     "remote_desc": (pairs.get("platform", "") + " " + pairs.get("board", "")).strip()[:120], "remote_addr": pairs.get("address", "")})
    return [r for r in rows if r["remote_name"] or r["remote_port"]]


# ---------------------------------------------------------------- asking many
def collect(devices, workers=6, on_done=None):
    """Ask each device for its neighbours. Returns (Layer 2 rows, Layer 3 rows, errors) where errors is {device: message}."""
    rows, l3, errors = [], [], {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        def one(d):
            with db.within(d.get("org")):                  # its SNMP settings and passwords are in its own organization
                return discover(d)
        futs = {pool.submit(one, d): d.get("key") or d["name"] for d in devices}
        for f in as_completed(futs):
            name = futs[f]
            try:
                a, b = f.result()
                rows.extend(a)
                l3.extend(b)
            except Exception as e:
                errors[name] = str(e)
            if on_done:
                on_done(name)
    return rows, l3, errors


def _key(name):
    return (name or "").strip().lower().split(".")[0]


_IF_WORDS = (("tengigabitethernet", "te"), ("twentyfivegige", "twe"), ("fortygigabitethernet", "fo"),
             ("hundredgige", "hu"), ("gigabitethernet", "gi"), ("fastethernet", "fa"), ("port-channel", "po"),
             ("ethernet", "eth"), ("management", "mgmt"))


def short_port(name):
    """'GigabitEthernet1/0/1' and 'Gi1/0/1' are the same port: compare them in one short form."""
    s = (name or "").strip().lower().replace(" ", "")
    for long, short in _IF_WORDS:
        if s.startswith(long):
            return short + s[len(long):]
    return s


def build_graph(rows):
    """Turn neighbour rows into (nodes, links). A node is an inventory device or an outside neighbour; a link is
    one cable: the same cable reported from both ends is merged. nodes: {id: {'inventory': bool, 'addr': str}},
    links: [{'a','b','a_port','b_port','protocols','rows' (indexes into rows),'down','speed','change'}]."""
    inv = {_key(d["name"]): d["key"] for d in db.list_devices()}
    inv.update({_key(d["key"]): d["key"] for d in db.list_devices()})
    nodes, links = {}, []

    def node(name, addr=""):
        canon = inv.get(_key(name), name)
        n = nodes.setdefault(canon, {"inventory": canon in inv.values(), "addr": addr})
        if addr and not n["addr"]:
            n["addr"] = addr
        return canon

    def same_cable(link, a, ap, b, bp):
        ports = {link["a"]: link["a_port"], link["b"]: link["b_port"]}
        if {link["a"], link["b"]} != {a, b}:
            return False
        return all(not have or not want or short_port(have) == short_port(want)
                   for have, want in ((ports[a], ap), (ports[b], bp)))

    for i, r in enumerate(rows):
        a = node(r["device"])
        b = node(r["remote_name"] or r.get("remote_addr") or "?", r.get("remote_addr", ""))
        if a == b:
            continue
        ap, bp = r["local_port"], r["remote_port"]
        down, speed = r.get("local_up") is False, r.get("local_speed") or ""
        found = next((l for l in links if same_cable(l, a, ap, b, bp)), None)
        if found:
            found["protocols"].add(r["protocol"])
            found["rows"].append(i)
            found["down"] = found["down"] or down
            found["speed"] = found["speed"] or speed
            side = {found["a"]: "a_port", found["b"]: "b_port"}
            if not found[side[a]]:
                found[side[a]] = ap
            if not found[side[b]]:
                found[side[b]] = bp
        else:
            links.append({"a": a, "b": b, "a_port": ap, "b_port": bp, "protocols": {r["protocol"]}, "rows": [i], "down": down, "speed": speed, "change": ""})
    for l in links:
        l["both"] = len({rows[i]["device"] for i in l["rows"]}) >= 2        # seen from both ends, or from one device only
    return nodes, links


def link_key(l):
    return tuple(sorted(((l["a"], short_port(l["a_port"])), (l["b"], short_port(l["b_port"])))))


def mark_changes(nodes, links, prev_links):
    """Compare with the discovery before: a link not seen then is 'new'; one seen then and not now is added as 'gone'
    (its nodes too, when they went with it). Returns (nodes, links) with 'change' set on every link."""
    now, before = {link_key(l): l for l in links}, {link_key(l): l for l in prev_links}
    for k, l in now.items():
        l["change"] = "new" if k not in before else ""
    for k, l in before.items():
        if k not in now:
            links.append({**l, "protocols": set(), "rows": [], "down": False, "speed": "", "change": "gone", "both": False})
            for n in (l["a"], l["b"]):
                nodes.setdefault(n, {"inventory": False, "addr": ""})
    return nodes, links


# ---------------------------------------------------------------- the discovery kept per organization
def remember(rows, l3=()):
    """Keep this discovery as the latest; the one before it becomes the previous one, for change marking."""
    last_ = db.get_setting("topology_last")
    db.set_setting("topology_prev", last_ if isinstance(last_, dict) else None)
    db.set_setting("topology_last", {"at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "rows": rows, "l3": list(l3)})


def last():
    """{'rows', 'l3', 'at', 'prev_rows', 'prev_l3'} for this organization: the latest discovery and the one before it."""
    last_, prev = db.get_setting("topology_last"), db.get_setting("topology_prev")
    last_ = last_ if isinstance(last_, dict) else {}
    prev = prev if isinstance(prev, dict) else {}
    return {"rows": last_.get("rows") or [], "l3": last_.get("l3") or [], "at": last_.get("at") or "",
            "prev_rows": prev.get("rows") or [], "prev_l3": prev.get("l3") or []}


def _layer_setting(key, layer):
    p = db.get_setting(key)
    return (p.get(layer) if isinstance(p, dict) else None) or {}


def _set_layer_setting(key, layer, value):
    p = db.get_setting(key)
    p = dict(p) if isinstance(p, dict) else {}
    p[layer] = value
    db.set_setting(key, p if any(p.values()) else None)


def positions(layer="l2"):
    """{node: (x, y)} the user dragged to on this layer's map."""
    return {k: (float(v[0]), float(v[1])) for k, v in _layer_setting("topology_positions", layer).items()}


def save_positions(pos, layer="l2"):
    _set_layer_setting("topology_positions", layer, {k: [round(x, 1), round(y, 1)] for k, (x, y) in pos.items()} if pos else {})


def top_tier(layer="l2"):
    """The nodes pinned to the top tier of this layer's tiers layout."""
    return set(_layer_setting("topology_top", layer).get("names") or [])


def pin_top(names, layer="l2"):
    _set_layer_setting("topology_top", layer, {"names": sorted(names)} if names else {})


def layout(nodes, links, width=900, height=600, iterations=250, seed=7, fixed=None):
    """Fruchterman-Reingold: linked nodes attract, all nodes repel. Returns {node: (x, y)} inside the box. `fixed`
    positions (the ones the user dragged to) are kept as they are."""
    fixed = {k: v for k, v in (fixed or {}).items() if k in nodes}
    names = list(nodes)
    n = len(names)
    if n == 0:
        return {}
    if n == 1:
        return {names[0]: fixed.get(names[0], (width / 2, height / 2))}
    rnd = random.Random(seed)
    pos = {k: [width / 2 + math.cos(2 * math.pi * i / n) * width / 3 + rnd.uniform(-5, 5),
               height / 2 + math.sin(2 * math.pi * i / n) * height / 3 + rnd.uniform(-5, 5)] for i, k in enumerate(names)}
    for k, (x, y) in fixed.items():
        pos[k] = [x, y]
    k = math.sqrt(width * height / n) * 0.8
    edges = {(l["a"], l["b"]) for l in links}
    temp = width / 8
    for it in range(iterations):
        disp = {v: [0.0, 0.0] for v in names}
        for i, u in enumerate(names):
            for v in names[i + 1:]:
                dx, dy = pos[u][0] - pos[v][0], pos[u][1] - pos[v][1]
                d = math.hypot(dx, dy) or 0.01
                f = k * k / d
                disp[u][0] += dx / d * f
                disp[u][1] += dy / d * f
                disp[v][0] -= dx / d * f
                disp[v][1] -= dy / d * f
        for a, b in edges:
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            d = math.hypot(dx, dy) or 0.01
            f = d * d / k
            disp[a][0] -= dx / d * f
            disp[a][1] -= dy / d * f
            disp[b][0] += dx / d * f
            disp[b][1] += dy / d * f
        for v in names:
            if v in fixed:
                continue
            dx, dy = disp[v]
            d = math.hypot(dx, dy) or 0.01
            pos[v][0] += dx / d * min(d, temp)
            pos[v][1] += dy / d * min(d, temp)
            pos[v][0] = min(width - 40, max(40, pos[v][0]))
            pos[v][1] = min(height - 30, max(30, pos[v][1]))
        temp *= 0.97
    return {v: (p[0], p[1]) for v, p in pos.items()}


def latest_status():
    """{device: worst status in the most recent run that included it}."""
    return {k: v["status"] for k, v in db.device_health().items()}


def guess_vendor(desc):
    """The inventory vendor a neighbour's platform or description points at, or ''."""
    d = (desc or "").lower()
    for words, vendor in ((("cisco",), "cisco"), (("arista",), "arista"), (("juniper", "junos"), "juniper"), (("fortigate", "fortinet"), "fortinet"),
                          (("palo alto", "pan-os"), "paloalto"), (("mikrotik", "routeros"), "mikrotik"), (("aruba", "procurve", "hp "), "hpe")):
        if any(w in d for w in words):
            return vendor
    return ""


# ---------------------------------------------------------------- roles: what a tile is, by what the device or its neighbour said
ROLES = ("router", "l3switch", "switch", "firewall", "wlc", "ap", "phone", "server", "unknown")
ROLE_NAMES = {"router": "Router", "l3switch": "Layer 3 switch", "switch": "Switch", "firewall": "Firewall", "wlc": "Wireless controller",
              "ap": "Access point", "phone": "IP phone", "server": "Server / virtual host", "unknown": "Device"}
ROLE_COLORS = {"router": "#2F6EA5", "l3switch": "#237356", "switch": "#3B8C68", "firewall": "#B5452E", "wlc": "#6A4C99",
               "ap": "#8857AE", "phone": "#9B7428", "server": "#56616B", "unknown": "#78838A"}
ENDPOINT_ROLES = ("phone", "ap", "server")
GROUP_WORDS = {"phone": ("IP phone", "IP phones"), "ap": ("access point", "access points"), "server": ("host", "hosts")}
_TEXT_RULES = ((r"wireless controller|\bwlc\b|c9800|air-ct|-wlc\b", "wlc"),
               (r"\bair-(?:c?ap|lap|sap)|\bc91[0-9]{2}|\bc9105|aironet|access point|\bap\d|-ap\b|-ap\d|\bmr\d\d\b", "ap"),
               (r"\bsep[0-9a-f]{12}\b|ip phone|\bcp-\d{4}|\bphone\b", "phone"),
               (r"vmware|\besx|vmnic|hyper-v|proxmox|windows server|\blinux\b|\bubuntu\b|\bhost\b|\bsrv-?\d|\bvm-?\d", "server"),
               (r"\basa\b|firepower|\bftd\b|fortigate|fortinet|pan-os|palo alto|\bsrx\d|firewall|\bfw-|-fw\b|\bfw\d|opnsense|pfsense", "firewall"))
_NAME_RULES = ((r"\brtr|\brouter|-r\d|\bisr\d|\basr\d|\bwan\b|\bedge\b|\bgw\b|\bmikrotik\b|\bccr\b|\bhex\b", "router"),
               (r"\bcore|\bdist|\bagg|\bl3|\bn9k|\bnexus|\bc95|\bc93|\bc9[23]00x\b", "l3switch"),
               (r"\bsw\b|\bsw\d|\bacc|\bidf|\bmdf|catalyst|\bws-c|\bc9[23]00|\bc3[68]50|\bc2960|\bcrs\d|\bex\d{4}", "switch"))
_VENDOR_ROLES = {"fortinet": "firewall", "paloalto": "firewall", "opnsense": "firewall", "juniper": "router", "mikrotik": "router",
                 "arista": "l3switch", "hpe": "switch", "windows": "server", "proxmox": "server", "truenas": "server"}


def role_of(name="", desc="", caps="", dev=None):
    """The role a tile shows: from the neighbour's platform or description and capabilities, else the inventory device's
    vendor and platform, else the name."""
    text = f"{name} {desc}".lower()
    for rx, role in _TEXT_RULES:
        if re.search(rx, text):
            return role
    if dev:
        v, plat = dev.get("vendor") or "", dev.get("platform") or ""
        if plat == "cisco_asa":
            return "firewall"
        if plat == "cisco_nxos":
            return "l3switch"
        if v in _VENDOR_ROLES:
            return _VENDOR_ROLES[v]
    c = (caps or "").lower()
    if "router" in c and ("switch" in c or "bridge" in c):
        return "l3switch"
    if "router" in c:
        return "router"
    if "phone" in c:
        return "phone"
    if "host" in c and "switch" not in c:
        return "server"
    for rx, role in _NAME_RULES:
        if re.search(rx, text):
            return role
    if "switch" in c or "bridge" in c:
        return "switch"
    return "switch" if dev and (dev.get("vendor") or "") == "cisco" else "unknown"


def roles_for(nodes, rows=(), devices=None):
    """{node: role} for a graph's nodes: inventory devices by their record, outside neighbours by what their neighbours said."""
    devices = devices if devices is not None else {d["key"]: d for d in db.list_devices()}
    said = {}
    for r in rows:
        k = _key(r.get("remote_name") or r.get("remote_addr") or "")
        if k and k not in said:
            said[k] = (r.get("remote_desc") or "", r.get("remote_caps") or "")
    out = {}
    for name, info in nodes.items():
        dev = devices.get(name) if info.get("inventory") else None
        desc, caps = said.get(_key(name), ("", ""))
        out[name] = role_of(db.label(name) if dev else name, desc + " " + (dev.get("details") or "" if dev else ""), caps, dev)
    return out


def short_name(name, drop_domain=True):
    """A tile's caption: the inventory label, without the domain when asked."""
    label = db.label(name)
    return label.split(".")[0] if drop_domain and not re.match(r"^\d+\.\d+\.\d+\.\d+$", label) else label


# ---------------------------------------------------------------- Layer 3: routing adjacencies
L3_CLI = {"cisco_ios": (("BGP", "show ip bgp summary"), ("OSPF", "show ip ospf neighbor"), ("EIGRP", "show ip eigrp neighbors")),
          "cisco_xe": (("BGP", "show ip bgp summary"), ("OSPF", "show ip ospf neighbor"), ("EIGRP", "show ip eigrp neighbors")),
          "cisco_nxos": (("BGP", "show ip bgp summary"), ("OSPF", "show ip ospf neighbor"), ("EIGRP", "show ip eigrp neighbors")),
          "cisco_asa": (("BGP", "show bgp summary"), ("OSPF", "show ospf neighbor"), ("EIGRP", "show eigrp neighbors")),
          "arista_eos": (("BGP", "show ip bgp summary"), ("OSPF", "show ip ospf neighbor")),
          "juniper_junos": (("BGP", "show bgp summary | no-more"), ("OSPF", "show ospf neighbor | no-more"))}
L3_PROTOCOLS = ("BGP", "OSPF", "EIGRP")
L3_COLORS = {"BGP": "#7E57C2", "OSPF": "#1F9E9E", "EIGRP": "#D08A2E"}
_BGP_IOS = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+4\s+(\d+)\s+.*?\s(\S+)\s*$")
_BGP_JUNOS = re.compile(r"^\s*(\S+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+.*?\s(Establ|Active|Connect|Idle|OpenSent|OpenConfirm|\d+/\d+/\d+/\d+)\s*$")
_OSPF_IOS = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+\d+\s+([A-Z0-9]+)\s*/\s*(\S+)\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)")
_OSPF_JUNOS = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+([A-Za-z]+)\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+")


def _l3(protocol, neighbor, state="", up=True, interface="", as_="", router_id=""):
    return {"protocol": protocol, "neighbor": neighbor, "state": state, "up": bool(up), "interface": interface, "as": str(as_ or ""), "router_id": router_id}


def parse_l3(protocol, text):
    """The adjacency rows one routing show command's output holds (IOS, IOS XE, NX-OS, ASA, Arista and Junos forms)."""
    rows = []
    text = text or ""
    if protocol == "EIGRP":
        _running, nbrs = clichecks.eigrp_neighbors(text)
        return [_l3("EIGRP", a, "up", True, i) for a, i in nbrs]
    for line in text.splitlines():
        if protocol == "BGP":
            m = _BGP_IOS.match(line)
            if m and "Neighbor" not in line:
                last_ = m.group(3)
                up = last_.isdigit() or last_.lower().startswith("estab")
                rows.append(_l3("BGP", m.group(1), "Established" if up else last_, up, as_=m.group(2)))
                continue
            m = _BGP_JUNOS.match(line)
            if m:
                st = m.group(3)
                up = st == "Establ" or "/" in st
                rows.append(_l3("BGP", m.group(1), "Established" if up else st, up, as_=m.group(2)))
        elif protocol == "OSPF":
            m = _OSPF_IOS.match(line)
            if m:
                st = m.group(2).upper()
                rows.append(_l3("OSPF", m.group(4), st, st in ("FULL", "2WAY"), m.group(5), router_id=m.group(1)))
                continue
            m = _OSPF_JUNOS.match(line)
            if m:
                st = m.group(3).upper()
                rows.append(_l3("OSPF", m.group(1), st, st in ("FULL", "2WAY"), m.group(2), router_id=m.group(4)))
    return rows


def _routing_snmp(client):
    """BGP peers (BGP4-MIB) and OSPF neighbours (OSPF-MIB) over SNMP; a device without the tables gives none."""
    rows = []
    try:
        state = client.try_column("1.3.6.1.2.1.15.3.1.2")              # bgpPeerState, indexed by the peer's address; 6 = established
        remote_as = client.try_column("1.3.6.1.2.1.15.3.1.9")
        for idx, v in state.items():
            st = str(snmp.text_of(v)).strip()
            rows.append(_l3("BGP", idx, "Established" if st == "6" else {"1": "Idle", "2": "Connect", "3": "Active", "4": "OpenSent", "5": "OpenConfirm"}.get(st, st),
                            st == "6", as_=snmp.text_of(remote_as.get(idx, ""))))
    except Exception:
        quiet.ignored()
    try:
        addr = client.try_column("1.3.6.1.2.1.14.10.1.1")               # ospfNbrIpAddr, indexed by address.ifIndex
        rid = client.try_column("1.3.6.1.2.1.14.10.1.3")
        st = client.try_column("1.3.6.1.2.1.14.10.1.6")                 # 8 = full, 4 = twoWay
        names = {"1": "DOWN", "2": "ATTEMPT", "3": "INIT", "4": "2WAY", "5": "EXSTART", "6": "EXCHANGE", "7": "LOADING", "8": "FULL"}
        for idx, v in addr.items():
            s = names.get(str(snmp.text_of(st.get(idx, ""))).strip(), "")
            rows.append(_l3("OSPF", snmp.text_of(v) or idx.rsplit(".", 1)[0], s, s in ("FULL", "2WAY"), router_id=snmp.text_of(rid.get(idx, ""))))
    except Exception:
        quiet.ignored()
    return rows


def parse_fortinet_l3(protocol, body):
    """FortiOS /api/v2/monitor/router/bgp/neighbors and /router/ospf/neighbors. shortcut: the field names are the 7.x ones
    (neighbor_ip, state, remote_as, router_id); widen _pick when a FortiGate answers with others."""
    rows = []
    for n in (body.get("results") if isinstance(body, dict) else body) or []:
        if not isinstance(n, dict):
            continue
        ip = _pick(n, "neighbor_ip", "neighbor-ip", "ip", "address", "neighbor")
        st = _pick(n, "state", "status")
        if ip:
            up = st.lower() in ("established", "full", "2way", "up", "2-way")
            rows.append(_l3(protocol, ip, st, up, _pick(n, "interface"), _pick(n, "remote_as", "remote-as", "as"), _pick(n, "router_id", "neighbor_id")))
    return rows


def parse_panos_l3(protocol, text):
    """PAN-OS `show routing protocol bgp peer` / `ospf neighbor` as XML: an entry per peer."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    rows = []
    for e in root.iter("entry"):
        ip = (e.findtext("peer-address") or e.findtext("neighbor-address") or e.findtext("peer-ip") or "").split(":")[0].strip()
        st = (e.findtext("status") or e.findtext("state") or "").strip()
        if ip:
            up = st.lower() in ("established", "full", "2way", "up", "2-way")
            rows.append(_l3(protocol, ip, st, up, (e.findtext("interface") or "").strip(), (e.findtext("peer-as") or e.findtext("remote-as") or "").strip(),
                            (e.findtext("peer-router-id") or e.findtext("neighbor-router-id") or e.findtext("neighbor-id") or "").strip()))
    return rows


def build_l3(l3rows, l2nodes=None):
    """(nodes, links) for the Layer 3 map: a neighbour address is an inventory device when it is one's management address or
    an address the Layer 2 discovery learned for it, else an outside node named by the address. links: [{'a','b','protocol',
    'state','up','as','interface','rows','both','change'}]; the same adjacency seen from both ends is one link."""
    devs = db.list_devices()
    inv = {d["host"]: d["key"] for d in devs if d.get("host")}
    keys = {d["key"] for d in devs}
    learned = {info["addr"]: name for name, info in (l2nodes or {}).items() if info.get("addr")}
    nodes, links = {}, []

    def node(name, addr=""):
        n = nodes.setdefault(name, {"inventory": name in keys, "addr": addr})
        if addr and not n["addr"]:
            n["addr"] = addr
        return name

    for i, r in enumerate(l3rows):
        a = node(r["device"])
        ip = r.get("neighbor") or ""
        b = node(inv.get(ip) or learned.get(ip) or ip, ip)
        if a == b:
            continue
        found = next((l for l in links if {l["a"], l["b"]} == {a, b} and l["protocol"] == r["protocol"]), None)
        if found:
            found["rows"].append(i)
            found["up"] = found["up"] and bool(r.get("up", True))
            found["state"] = found["state"] or r.get("state", "")
            found["both"] = True
        else:
            links.append({"a": a, "b": b, "protocol": r["protocol"], "state": r.get("state", ""), "up": bool(r.get("up", True)), "as": r.get("as", ""),
                          "interface": r.get("interface", ""), "rows": [i], "both": False, "change": "", "down": not r.get("up", True), "speed": ""})
    for l in links:
        l["both"] = len({l3rows[i]["device"] for i in l["rows"]}) >= 2
        l["a_port"], l["b_port"] = l["interface"], ""
        l["protocols"] = {l["protocol"]}
    return nodes, links


def l3_key(l):
    return (frozenset((l["a"], l["b"])), l["protocol"])


def mark_l3_changes(nodes, links, prev_links):
    now, before = {l3_key(l): l for l in links}, {l3_key(l): l for l in prev_links}
    for k, l in now.items():
        l["change"] = "new" if k not in before else ""
    for k, l in before.items():
        if k not in now:
            links.append({**l, "rows": [], "both": False, "change": "gone", "down": False, "up": True})
            for n in (l["a"], l["b"]):
                nodes.setdefault(n, {"inventory": False, "addr": ""})
    return nodes, links


# ---------------------------------------------------------------- the picture: grouping, merging, tiers
def group_endpoints(nodes, links, roles, mode="group"):
    """Endpoints (phones, access points, hosts) outside the inventory: shown one by one ('each'), folded into one tile per
    switch and kind ('group': '6 IP phones'), or left out ('hide'). Returns (nodes, links) to draw."""
    if mode == "each":
        return nodes, links
    gone_ends = {n for l in links if l.get("change") == "gone" for n in (l["a"], l["b"])}       # a link that went is shown as it was
    ends = {n for n, info in nodes.items() if not info.get("inventory") and roles.get(n) in ENDPOINT_ROLES and n not in gone_ends}
    if not ends:
        return nodes, links
    out_nodes = {n: info for n, info in nodes.items() if n not in ends}
    out_links, groups = [], {}
    for l in links:
        end = l["b"] if l["b"] in ends else l["a"] if l["a"] in ends else None
        if end is None:
            out_links.append(l)
            continue
        if mode == "hide":
            continue
        parent = l["a"] if end == l["b"] else l["b"]
        g = groups.setdefault((parent, roles[end]), {"members": [], "ports": [], "links": []})
        g["members"].append(end)
        g["ports"].append(l["a_port"] if parent == l["a"] else l["b_port"])
        g["links"].append(l)
    for (parent, role), g in groups.items():
        n = len(g["members"])
        if n == 1:                                             # one of a kind stays itself: a group of one says nothing
            out_nodes[g["members"][0]] = nodes[g["members"][0]]
            out_links.extend(g["links"])
            continue
        name = f"{parent} » {n} {GROUP_WORDS[role][1]}"
        out_nodes[name] = {"inventory": False, "addr": "", "group": True, "members": g["members"], "role": role, "count": n}
        out_links.append({"a": parent, "b": name, "a_port": ", ".join(p for p in g["ports"] if p)[:60], "b_port": "", "protocols": set(), "rows": [],
                          "down": False, "speed": "", "change": "", "both": False})
    return out_nodes, out_links


def merge_parallel(links):
    """Links between the same two devices become one thicker link that lists the ports."""
    out, by = [], {}
    for l in links:
        k = (frozenset((l["a"], l["b"])), l.get("protocol", ""))
        if k in by:
            m = by[k]
            m["count"] = m.get("count", 1) + 1
            for side in ("a_port", "b_port"):
                if l[side] and l[side] not in m[side]:
                    m[side] = f"{m[side]}, {l[side]}" if m[side] else l[side]
            m["down"] = m.get("down", False) or l.get("down", False)
            m["change"] = m["change"] if m["change"] == l["change"] else (m["change"] or l["change"])
            continue
        by[k] = dict(l, count=1)
        out.append(by[k])
    return out


def degree(nodes, links):
    d = {n: 0 for n in nodes}
    for l in links:
        d[l["a"]] = d.get(l["a"], 0) + 1
        d[l["b"]] = d.get(l["b"], 0) + 1
    return d


def tiers_layout(nodes, links, roles, pinned=(), width=1000, height=600, gap_y=150):
    """Rows of tiles: the pinned nodes (else the routers and firewalls, else the best-connected node) on top, then each node
    by its distance from them, endpoints on the bottom row. Within a row, each node sits near the nodes it hangs from."""
    names = list(nodes)
    if not names:
        return {}
    top = [n for n in names if n in pinned] or [n for n in names if roles.get(n) in ("router", "firewall")]
    if not top:
        deg = degree(nodes, links)
        top = [max(names, key=lambda n: (deg.get(n, 0), n))]
    adj = {n: set() for n in names}
    for l in links:
        if l["a"] in adj and l["b"] in adj:
            adj[l["a"]].add(l["b"])
            adj[l["b"]].add(l["a"])
    tier, frontier = {n: 0 for n in top}, list(top)
    while frontier:
        nxt = []
        for n in frontier:
            for m in adj[n]:
                if m not in tier:
                    tier[m] = tier[n] + 1
                    nxt.append(m)
        frontier = nxt
    unreached = [n for n in names if n not in tier]
    deepest = max(tier.values()) if tier else 0
    for n in unreached:
        tier[n] = deepest + 1
    bottom = max(tier.values()) + (1 if any(roles.get(n) in ENDPOINT_ROLES or nodes[n].get("group") for n in names) else 0)
    for n in names:
        if roles.get(n) in ENDPOINT_ROLES or nodes[n].get("group"):
            tier[n] = max(bottom, tier[n])
    rows = {}
    for n in names:
        rows.setdefault(tier[n], []).append(n)
    pos = {}
    for t in sorted(rows):
        row = rows[t]
        if t == min(rows):
            row.sort(key=lambda n: n.lower())
        else:
            above = {n: [pos[m][0] for m in adj[n] if m in pos] for n in row}
            row.sort(key=lambda n: (sum(above[n]) / len(above[n]) if above[n] else width / 2, n.lower()))
        step = width / (len(row) + 1)
        for i, n in enumerate(row):
            pos[n] = (step * (i + 1), 60 + (t - min(rows)) * gap_y)
    return pos
