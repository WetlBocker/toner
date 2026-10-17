"""Neighbour discovery (LLDP / CDP over SNMP) and a simple force-directed layout for drawing the result."""
import math
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

from core import db, profiles, snmp, vendors


def snmp_devices():
    return [d for d in db.list_devices(enabled_only=True)
            if profiles.snmp_configured(d) or vendors.is_snmp(d["vendor"])]


def neighbours_of(dev):
    """Neighbour rows for one inventory device. Raises snmp.SnmpError / ValueError on failure."""
    dev = profiles.resolve(dev)
    creds, port = snmp.credentials_for(dev)
    with snmp.Client(dev["host"], port, creds, timeout=4, retries=1) as c:
        rows = snmp.neighbors(c)
    return [{"device": dev.get("key") or dev["name"], **r} for r in rows]       # Global: keyed apart from same-named devices


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
    links: [{'a','b','a_port','b_port','protocols'}]."""
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

    for r in rows:
        a = node(r["device"])
        b = node(r["remote_name"] or r.get("remote_addr") or "?", r.get("remote_addr", ""))
        if a == b:
            continue
        ap, bp = r["local_port"], r["remote_port"]
        found = next((l for l in links if same_cable(l, a, ap, b, bp)), None)
        if found:
            found["protocols"].add(r["protocol"])
            side = {found["a"]: "a_port", found["b"]: "b_port"}
            if not found[side[a]]:
                found[side[a]] = ap
            if not found[side[b]]:
                found[side[b]] = bp
        else:
            links.append({"a": a, "b": b, "a_port": ap, "b_port": bp, "protocols": {r["protocol"]}})
    return nodes, links


def layout(nodes, links, width=900, height=600, iterations=250, seed=7):
    """Fruchterman-Reingold: linked nodes attract, all nodes repel. Returns {node: (x, y)} inside the box."""
    names = list(nodes)
    n = len(names)
    if n == 0:
        return {}
    if n == 1:
        return {names[0]: (width / 2, height / 2)}
    rnd = random.Random(seed)
    pos = {k: [width / 2 + math.cos(2 * math.pi * i / n) * width / 3 + rnd.uniform(-5, 5),
               height / 2 + math.sin(2 * math.pi * i / n) * height / 3 + rnd.uniform(-5, 5)] for i, k in enumerate(names)}
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
