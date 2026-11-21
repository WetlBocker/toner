from core import proxy, display, tlsverify
from core import quiet
import json
import re
import xml.etree.ElementTree as ET

import requests

from . import apichecks
from .base import AuthRejected, Driver, OK, WARN, FAIL, grade, grade_low
from .sshbase import worse

# check: (protocol, the states that are up, (neighbours, summary) on the legacy routing engine, the same on the Advanced Routing Engine of PAN-OS 10.2 and later)
ROUTING = {
    "bgp": ("BGP", ("established",),
            ("<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>", "<show><routing><protocol><bgp><summary></summary></bgp></protocol></routing></show>"),
            ("<show><advanced-routing><bgp><peer><status></status></peer></bgp></advanced-routing></show>", "<show><advanced-routing><bgp><summary></summary></bgp></advanced-routing></show>")),
    "ospf": ("OSPF", ("full", "2way", "twoway"),             # 2-Way is where two non-designated routers on a shared segment stay
             ("<show><routing><protocol><ospf><neighbor></neighbor></ospf></protocol></routing></show>", "<show><routing><protocol><ospf><summary></summary></ospf></protocol></routing></show>"),
             ("<show><advanced-routing><ospf><neighbor></neighbor></ospf></advanced-routing></show>", "<show><advanced-routing><ospf><summary></summary></ospf></advanced-routing></show>")),
}


def pan_neighbors(res):
    """[(name, state)] of the BGP peers or OSPF neighbours in a reply, from either routing engine.
    Legacy: one <entry> each with a <status>; BGP's is published (pan.dev, pan-os-upgrade-assurance get_bgp_peers: entry peer="..", <status>), OSPF's is
    INFERRED from the command's printed labels (neighbor-router-id, neighbor-address, status). Advanced Routing: JSON as text in <json>, keyed by logical
    router (published for `show advanced-routing route` only); the fields are INFERRED to be the routing daemon's own (FRRouting: bgpState, nbrState "Full/DR")."""
    if res is None:
        return []
    if res.find("json") is None:
        return [(e.get("peer") or e.findtext("neighbor-router-id") or e.findtext("neighbor-address") or "?", e.findtext("status").strip())
                for e in res.iter("entry") if e.findtext("status")]         # (the entry inside a peer's <prefix-counter> has no status)
    found = []

    def walk(node, name="?"):
        if isinstance(node, dict):
            state = next((node[k] for k in ("bgpState", "nbrState", "state") if isinstance(node.get(k), str)), None)
            if state is not None:
                found.append((name, state))                  # named by the key it sits under: the peer's name, the neighbour's router ID
            else:
                for k, v in node.items():
                    walk(v, k)
        elif isinstance(node, list):
            for v in node:
                walk(v, name)

    walk(json.loads((res.findtext("json") or "").strip() or "{}"))
    return found


def pan_routing_runs(res):
    """Whether a `bgp summary` / `ospf summary` reply (either engine) names a router ID, which is to say the protocol is configured.
    INFERRED (<router-id>, "routerId"): no summary reply is published. A wrong guess reads as 'not configured', never as a false warning."""
    return res is not None and (res.find(".//router-id") is not None or '"routerId"' in (res.findtext("json") or ""))


def cpu_memory(text):
    """(CPU percent, memory percent) from `show system resources` (top's output): 100 minus idle; (total - free - buff/cache) / total."""
    idle = re.search(r"%Cpu\(s\):.*?([\d.]+)\s*id", text)
    mem = re.search(r"Mem\s*:\s*([\d.]+)\s*total,\s*([\d.]+)\s*free,\s*([\d.]+)\s*used(?:,\s*([\d.]+)\s*buff/cache)?", text)
    if not (idle and mem):
        raise ValueError("could not read CPU and memory from 'show system resources'")
    total, free, cache = float(mem.group(1)), float(mem.group(2)), float(mem.group(4) or 0)
    return 100 - float(idle.group(1)), (total - free - cache) / total * 100


def uptime_hours(text):
    """Hours from '31 days, 5:55:14' or '5:55:14' (`show system info`)."""
    m = re.match(r"(?:(\d+)\s+days?,\s*)?(\d+):(\d+):(\d+)", text)
    if not m:
        raise ValueError(f"unrecognised uptime '{text}'")
    return int(m.group(1) or 0) * 24 + int(m.group(2)) + int(m.group(3)) / 60 + int(m.group(4)) / 3600


def cli_field(text, name):
    """The value of a `name: value` line of `show system info`, '' when there is none."""
    m = re.search(rf"^{re.escape(name)}:[ 	]*(.*?)\s*$", text, re.M)
    return m.group(1) if m else ""


class PaloAltoDriver(Driver):
    """PAN-OS firewalls through the XML API. The API key is the stored secret."""

    def _op(self, cmd):
        d = self.dev
        r = requests.get(f"https://{d['host']}:{d.get('port') or 443}/api/",
                         params={"type": "op", "cmd": cmd}, headers={"X-PAN-KEY": self.password or ""},
                         verify=tlsverify.verify(d), timeout=self.opts["http_timeout"], **proxy.requests_kwargs(d))
        if r.status_code in (401, 403):
            why = ""
            try:
                why = (ET.fromstring(r.content).findtext(".//msg") or "").strip()
            except ET.ParseError:
                pass
            raise AuthRejected("Palo Alto rejected the API key" + (f" ({why})" if why else f" (HTTP {r.status_code})") +
                               ": paste the key from a user that may use the XML API (Device > Administrators; the key itself is made with "
                               "https://<firewall>/api/?type=keygen&user=...&password=...), and check the address is the firewall's management one.")
        r.raise_for_status()
        root = ET.fromstring(r.content)
        if root.get("status") != "success":
            msg = root.findtext(".//msg") or root.findtext(".//line") or "request failed"
            e = ValueError(f"PAN-OS API: {msg.strip()}")
            e.code = root.get("code")                        # the API's error number: _neighbors tells 'no such command' by it
            raise e
        return root.find("result")

    def run(self):
        out = []
        try:
            s = self._system()                               # a rejected key is said once, not once per check
            self.found_software(s.findtext("sw-version") or "")
        except AuthRejected:
            raise
        except Exception:
            quiet.ignored("anything else: each check reports its own reason")
        for name, fn in (("resources", self.resources), ("uptime", self.uptime), ("firmware", self.firmware),
                         ("sessions", self.sessions), ("ha", self.ha), ("interfaces", self.interfaces), ("bgp", self.bgp), ("ospf", self.ospf), ("licenses", self.licenses),
                         ("content", self.content), ("disk", self.disk), ("panorama", self.panorama), ("last commit", self.last_commit)):
            if self.enabled(name):
                self.safe(out, name, fn)
        return out

    def _system(self):
        if not hasattr(self, "_sys"):
            res = self._op("<show><system><info/></system></show>")
            self._sys = res.find("system") if res is not None else None
            if self._sys is None:
                raise ValueError("no system information in the reply")
        return self._sys

    def resources(self):
        res = self._op("<show><system><resources/></system></show>")
        text = (res.text or "") if res is not None else ""
        cpu, mem = cpu_memory(text)
        return [self.level_check("cpu", cpu), self.level_check("memory", mem)]

    def uptime(self):
        text = (self._system().findtext("uptime") or "").strip()
        hours = uptime_hours(text)
        t = self.th["uptime"]
        status = grade_low(hours, t["warn"], t["fail"])
        return self.result("uptime", status, display.uptime(hours), "recent reboot" if status != OK else "", numeric=hours)

    def firmware(self):
        s = self._system()
        return self.result("firmware", OK, s.findtext("sw-version") or "?", s.findtext("model") or "")

    def licenses(self):
        res = self._op("<request><license><info/></license></request>")
        found = apichecks.pan_licenses(res.findall(".//entry") if res is not None else [])
        timed = [(f, d, x) for f, d, x in found if d is not None]
        expired = [f for f, d, x in found if x]
        if not timed and not expired:
            return []
        t = self.th["support_days"]
        feature, days, _ = min(timed, key=lambda x: x[1]) if timed else (expired[0], -1, True)
        status = FAIL if expired else grade_low(days, t["warn"], t["fail"])
        return self.result("licenses", status, "expired" if expired else f"{days} days", (f"expired: {', '.join(expired[:4])}" if expired else f"ends first: {feature}") if status != OK else "",
                           numeric=float(days))

    def content(self):
        ages = apichecks.pan_content_ages(self._system())
        if not ages:
            return []
        name, days = max(ages, key=lambda x: x[1])
        t = self.th["content_age"]
        return self.result("content", grade(days, t["warn"], t["fail"]), f"{days} days", f"oldest: {name} package" if days >= t["warn"] else "application, threat and antivirus content", numeric=float(days))

    def disk(self):
        res = self._op("<show><system><disk-space/></system></show>")
        worst = apichecks.pan_disk((res.text or "") if res is not None else "")
        if worst is None:
            return []
        return self.level_check("disk", float(worst[0]))

    def panorama(self):
        res = self._op("<show><panorama-status/></show>")
        state = apichecks.pan_panorama((res.text or "") if res is not None else "")
        if state is None:
            return []
        return self.result("panorama", OK if state else WARN, "connected" if state else "not connected", "" if state else "this firewall cannot reach Panorama")

    def last_commit(self):
        res = self._op("<show><jobs><all/></jobs></show>")
        last = apichecks.pan_last_commit(res.findall(".//job") if res is not None else [])
        if last is None:
            return []
        result, when = last
        return self.result("last commit", OK if result == "OK" else FAIL, "ok" if result == "OK" else result.lower() or "unknown", f"finished {when}" if when else "")

    def sessions(self):
        res = self._op("<show><session><info/></session></show>")
        active, mx = res.findtext("num-active"), res.findtext("num-max")
        if not (active and mx and int(mx)):
            raise ValueError("could not read the session table size")
        pct = int(active) / int(mx) * 100
        t = self.th["sessions"]
        return self.result("sessions", grade(pct, t["warn"], t["fail"]), f"{pct:.0f}%",
                           f"{int(active):,} of {int(mx):,}", numeric=pct)

    def ha(self):
        res = self._op("<show><high-availability><state/></high-availability></show>")
        expected = bool(self.dev.get("ha_expected"))
        if (res.findtext("enabled") or "no").lower() != "yes":
            return self.result("ha", FAIL if expected else OK, "not configured",
                               "HA is expected but not enabled" if expected else "")
        local = (res.findtext(".//local-info/state") or "?").lower()
        peer = (res.findtext(".//peer-info/state") or "?").lower()
        conn = (res.findtext(".//peer-info/conn-status") or "up").lower()
        sync = (res.findtext(".//running-sync") or "synchronized").lower()
        status, msgs = OK, []
        if local in ("suspended", "non-functional", "tentative", "initial"):
            status, msgs = FAIL, [f"this unit is {local}"]
        if conn != "up":
            status, msgs = FAIL, msgs + ["peer unreachable"]
        if sync != "synchronized":
            status, msgs = worse(status, WARN), msgs + [f"config {sync}"]
        return self.result("ha", status, f"{local} / peer {peer}", "; ".join(msgs))

    def _if_all(self):
        """`show interface all`, asked once per run: the interfaces check and the WAN port speeds both read it."""
        if not hasattr(self, "_ifall"):
            self._ifall = self._op("<show><interface>all</interface></show>")
        return self._ifall

    def interface_counters(self):
        """Each port's byte counters through the XML API (`show counter interface all`), with its speed from `show interface all`;
        a firewall that names none: by SNMP once it is set up (Driver.interface_counters)."""
        found = apichecks.pan_interface_bytes(self._op("<show><counter><interface>all</interface></counter></show>"), self._if_all())
        return found or super().interface_counters()

    def _if_states(self):
        hw = self._if_all().findall("hw/entry")
        if not hw:
            raise ValueError("no interfaces in the reply")
        return [(e.findtext("name") or "?", "up" if (e.findtext("state") or "").lower() == "up" else "down") for e in hw]

    def list_interfaces(self):
        return self._if_states()

    def interfaces(self):
        return self.interfaces_row(self._if_states())

    def _neighbors(self, check):
        """BGP peers or OSPF neighbours from the routing engine this firewall runs; the other one's command is tried when the first is not there."""
        protocol, up, legacy, advanced = ROUTING[check]
        on = (self._system().findtext("advanced-routing") or "").lower() == "on"     # `show system info` says which engine, from PAN-OS 10.2
        for neighbors, summary in ((advanced, legacy) if on else (legacy, advanced)):
            try:
                found = pan_neighbors(self._op(neighbors))
                running = bool(found) or pan_routing_runs(self._op(summary))
            except ValueError as e:
                if getattr(e, "code", None) not in ("1", "14", "17"):      # unknown command, not possible here, invalid command: not this engine's
                    raise
                continue
            down = [n if check == "bgp" else f"{n} ({s})" for n, s in found if re.sub(r"[^a-z0-9]", "", s.split("/")[0].lower()) not in up]
            return self.neighbors_row(check, protocol, running, len(found), down, value=f"{len(found) - len(down)}/{len(found)} established")
        return self.neighbors_row(check, protocol, False, 0, [])

    def bgp(self):
        return self._neighbors("bgp")

    def ospf(self):
        return self._neighbors("ospf")
