"""Neighbour discovery (LLDP / CDP over SNMP, over SSH for the SSH vendors, over the API for Fortinet and Palo Alto), a
simple force-directed layout for drawing the result, the link state read beside it, and the last discovery kept per
organization so the map is there on opening and changes since the one before are marked."""
import math
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from core import db, profiles, quiet, snmp, vendors

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


def neighbours_of(dev):
    """Neighbour rows for one inventory device: protocol, local_port, remote_name, remote_port, remote_desc, remote_addr,
    and for SNMP the local port's state (local_up, local_speed). Raises snmp.SnmpError / ValueError on failure."""
    dev = profiles.resolve(dev)
    key = dev.get("key") or dev["name"]                          # Global: keyed apart from same-named devices
    v = dev.get("vendor") or ""
    if profiles.snmp_configured(dev) or vendors.is_snmp(v):
        creds, port = snmp.credentials_for(dev)
        with snmp.Client(dev["host"], port, creds, timeout=4, retries=1) as c:
            rows = snmp.neighbors(c)
            state = _port_state(c) if rows else {}
        for r in rows:
            st = state.get(short_port(r["local_port"]))
            r["local_up"], r["local_speed"] = (st[0], st[1]) if st else (None, "")
    elif v in API_VENDORS:
        rows = _api_rows(dev)
    else:
        rows = _cli_rows(dev)
    return [{"device": key, "local_up": None, "local_speed": "", **r} for r in rows]


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
    rows = []
    with drv.connect() as c:
        try:
            c.enable()
        except Exception:
            quiet.ignored()
        for cmd in cmds:
            rows += parse(plat, cmd, c.send_command(cmd, read_timeout=max(60, int(opts.get("ssh_timeout", 20)) * 3)))
    return rows


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
        r = requests.get(f"{base}/api/v2/monitor/network/lldp/neighbors", headers={"Authorization": f"Bearer {token}"}, **kw)
        r.raise_for_status()
        return parse_fortinet(r.json())
    r = requests.get(f"{base}/api/", params={"type": "op", "cmd": "<show><lldp><neighbors>all</neighbors></lldp></show>"}, headers={"X-PAN-KEY": token}, **kw)
    r.raise_for_status()
    return parse_panos(r.text)


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
    """Ask each device for its neighbours. Returns (rows, errors) where errors is {device: message}."""
    rows, errors = [], {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        def one(d):
            with db.within(d.get("org")):                  # its SNMP settings and passwords are in its own organization
                return neighbours_of(d)
        futs = {pool.submit(one, d): d.get("key") or d["name"] for d in devices}
        for f in as_completed(futs):
            name = futs[f]
            try:
                rows.extend(f.result())
            except Exception as e:
                errors[name] = str(e)
            if on_done:
                on_done(name)
    return rows, errors


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
            links.append({**l, "protocols": set(), "rows": [], "down": False, "speed": "", "change": "gone"})
            for n in (l["a"], l["b"]):
                nodes.setdefault(n, {"inventory": False, "addr": ""})
    return nodes, links


# ---------------------------------------------------------------- the discovery kept per organization
def remember(rows):
    """Keep this discovery as the latest; the one before it becomes the previous one, for change marking."""
    last_ = db.get_setting("topology_last")
    db.set_setting("topology_prev", last_ if isinstance(last_, dict) else None)
    db.set_setting("topology_last", {"at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "rows": rows})


def last():
    """(rows, when, rows of the discovery before) for this organization, or ([], '', [])."""
    last_, prev = db.get_setting("topology_last"), db.get_setting("topology_prev")
    if not isinstance(last_, dict):
        return [], "", []
    return last_.get("rows") or [], last_.get("at") or "", (prev.get("rows") or []) if isinstance(prev, dict) else []


def positions():
    p = db.get_setting("topology_positions")
    return {k: (float(v[0]), float(v[1])) for k, v in p.items()} if isinstance(p, dict) else {}


def save_positions(pos):
    db.set_setting("topology_positions", {k: [round(x, 1), round(y, 1)] for k, (x, y) in pos.items()} if pos else None)


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
