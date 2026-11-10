"""MikroTik RouterOS hardening rules over `/export`, which prints non-default values only: a service stays on until a line says
otherwise. The parse joins backslash continuations and returns [(path, verb, args)]. `/export` leaves users out, so no rule reads them."""
import re

from drivers.base import FAIL, WARN

ROS = re.compile(r"(?m)^(# .*RouterOS|/(ip|system|interface|tool|snmp)\b)")
VERBS = r"(?:add|set|remove|disable|enable|unset)"
KV = re.compile(r'([\w-]+)=("(?:[^"\\]|\\.)*"|\S+)')


def parse(text):
    if not ROS.search(text):
        raise ValueError("not a RouterOS export")
    out, path = [], ""
    for l in re.sub(r"\\\r?\n\s*", "", text).splitlines():
        l = l.strip()
        if l.startswith("/"):                          # a path header, or a one-line `/ip service set ...`
            m = re.match(rf"(/.*?)(?: ({VERBS}\b.*))?$", l)
            path, l = " ".join(m.group(1).split()), m.group(2) or ""
        v = re.match(rf"({VERBS})\b(.*)", l)
        if v and path:
            out.append((path, v.group(1), v.group(2).strip()))
    return out


def _kv(args):
    return {k: v.strip('"') for k, v in KV.findall(args)}


def _cfg(doc, path):
    """The merged key=value settings of every `set` line under `path` (a singleton such as /ip ssh)."""
    got = {}
    for p, verb, args in doc:
        if p == path and verb == "set":
            got.update(_kv(args))
    return got


def _services(doc):
    """{service name: merged settings} for /ip service; each service is named first, or by `[ find name=x ]`."""
    out = {}
    for p, verb, args in doc:
        if p == "/ip service" and verb == "set":
            kv = _kv(args)
            names = kv.get("name") or ("" if args.startswith("[") else args.split()[0])
            for n in names.split(","):
                out.setdefault(n, {}).update(kv)
    return out


def _on(svc, name, default=True):
    """A service is on unless `disabled=yes`; www-ssl is off until `disabled=no`."""
    d = svc.get(name, {}).get("disabled")
    return d != "yes" if default else d == "no"


# ---------------------------------------------------------------- test(doc, platform, masked) -> None | reason | ("na", reason)
def telnet_http(doc, plat, masked):
    svc = _services(doc)
    on = ",".join(n for n in ("telnet", "ftp", "www") if _on(svc, n))
    return f"{on} not disabled: /ip service disable {on}" if on else None


def api(doc, plat, masked):
    return "api not disabled: /ip service disable api" if _on(_services(doc), "api") else None


def service_address(doc, plat, masked):
    svc = _services(doc)
    bad = [n for n in ("ssh", "winbox", "api-ssl", "www-ssl") if _on(svc, n, n != "www-ssl")
           and not (svc.get(n, {}).get("address") or svc.get(n, {}).get("available-from"))]
    return f"{', '.join(bad)} without a source address: set address (available-from on RouterOS 7.25 and later) under /ip service" if bad else None


def mac_server(doc, plat, masked):
    # a named list such as LAN passes; missing means the default, all
    bad = any(_cfg(doc, p).get("allowed-interface-list", "all") == "all" for p in ("/tool mac-server", "/tool mac-server mac-winbox"))
    return "allowed-interface-list all: /tool mac-server set allowed-interface-list=none and /tool mac-server mac-winbox set allowed-interface-list=none" if bad else None


def neighbor(doc, plat, masked):
    bad = _cfg(doc, "/ip neighbor discovery-settings").get("discover-interface-list", "all") == "all"
    return "discover-interface-list all: /ip neighbor discovery-settings set discover-interface-list=none" if bad else None


def bandwidth(doc, plat, masked):
    return "bandwidth-server is on: /tool bandwidth-server set enabled=no" if _cfg(doc, "/tool bandwidth-server").get("enabled") != "no" else None


def proxy(doc, plat, masked):
    on = [(n, p) for n, p in (("proxy", "/ip proxy"), ("socks", "/ip socks"), ("upnp", "/ip upnp")) if _cfg(doc, p).get("enabled") == "yes"]
    return f"{', '.join(n for n, _ in on)} on: set enabled=no under {', '.join(p for _, p in on)}" if on else None


def ssh(doc, plat, masked):
    return None if _cfg(doc, "/ip ssh").get("strong-crypto") == "yes" else "strong-crypto is off: /ip ssh set strong-crypto=yes"


def firewall(doc, plat, masked):
    ok = any(p == "/ip firewall filter" and verb == "add" and (kv := _kv(a)).get("chain") == "input" and kv.get("action") == "drop" and kv.get("disabled") != "yes"
             for p, verb, a in doc)
    return None if ok else "no drop rule in chain=input: add one under /ip firewall filter"


def _snmp(doc):
    """[settings dict] of /snmp community when SNMP is on: the built-in `public` (changed by `set [ find default=yes ]`, or removed), then each `add`."""
    if _cfg(doc, "/snmp").get("enabled") != "yes":
        return []
    comm = [{"name": "public"}]
    for p, verb, args in doc:
        if p != "/snmp community":
            continue
        kv = _kv(args)
        if verb == "add":
            comm.append(kv)
        elif kv.get("default") == "yes":
            comm[0].update(kv) if verb == "set" else comm.pop(0)
    return comm


def snmp_public(doc, plat, masked):
    bad = []
    for c in _snmp(doc):
        problems = (["name is public or private"] if c.get("name", "").lower() in ("public", "private") else []) \
            + (["write-access=yes"] if c.get("write-access") == "yes" else [])
        if problems:
            bad.append(f"community {c.get('name')}: {' and '.join(problems)}")
    return f"{'; '.join(bad)}: rename the community and set write-access=no under /snmp community" if bad else None


def snmp_addresses(doc, plat, masked):
    comm = _snmp(doc)
    bad = [c for c in comm if set(c.get("addresses", "0.0.0.0/0").split(",")) & {"0.0.0.0/0", "::/0"}]
    return f"{len(bad)} of {len(comm)} communities on 0.0.0.0/0: set addresses= under /snmp community" if bad else None


def snmp_v2c(doc, plat, masked):
    bad = [c for c in _snmp(doc) if c.get("security", "none") not in ("authorized", "private")]
    n = f"{len(bad)} {'community' if len(bad) == 1 else 'communities'}"
    return f"{n} without security=authorized or private: set security= and authentication-protocol= under /snmp community" if bad else None


def syslog(doc, plat, masked):
    ok = any(p == "/system logging action" and verb == "add" and _kv(a).get("target") == "remote" for p, verb, a in doc)
    return None if ok else "no remote logging action: add target=remote under /system logging action and use it in /system logging"


def ntp(doc, plat, masked):
    return None if _cfg(doc, "/system ntp client").get("enabled") == "yes" else "NTP client not enabled: /system ntp client set enabled=yes"


RULES = [
    ("mt telnet http", "Telnet, FTP or HTTP service on", FAIL, telnet_http),
    ("mt api", "API service on in clear", WARN, api),
    ("mt service address", "Management with no source limit", WARN, service_address),
    ("mt mac server", "MAC access on every interface", WARN, mac_server),
    ("mt neighbor", "Neighbor discovery on every interface", WARN, neighbor),
    ("mt bandwidth", "Bandwidth server on", WARN, bandwidth),
    ("mt proxy", "Proxy, SOCKS or UPnP on", WARN, proxy),
    ("mt ssh", "SSH strong crypto off", WARN, ssh),
    ("mt firewall", "No input firewall drop rule", WARN, firewall),
    ("mt snmp public", "SNMP community public, or write access", FAIL, snmp_public),
    ("mt snmp addresses", "SNMP community open to any address", WARN, snmp_addresses),
    ("mt snmp v2c", "SNMP version 1 or 2c in use", WARN, snmp_v2c),
    ("mt syslog", "No logging host", WARN, syslog),
    ("mt ntp", "NTP client off", WARN, ntp),
]
