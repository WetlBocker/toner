import re

from core import proxy, tlsverify
from core import quiet
import requests

from . import apichecks
from .base import AuthRejected, Driver, OK, WARN, FAIL, grade_low

# The monitor paths are Fortinet's (its Ansible collection's fortios_monitor_fact lists them); the reply fields are published only on its
# developer network, so neighbor_ip, state and router_id are as seen in replies captured from FortiOS 7.0 (not confirmed in the documentation).
def bgp_neighbors(rows):
    """(how many peers, the ones not Established) from router/bgp/neighbors and neighbors6 joined."""
    peers = {str(r["neighbor_ip"]): str(r.get("state", "")) for r in (rows if isinstance(rows, list) else []) if isinstance(r, dict) and r.get("neighbor_ip")}
    return len(peers), [ip for ip, state in peers.items() if state.lower() != "established"]

def ospf_neighbors(rows):
    """(how many neighbours, the ones neither Full nor Two way) from router/ospf/neighbors; a DROTHER stays Two way with another DROTHER."""
    nbrs = [r for r in (rows if isinstance(rows, list) else []) if isinstance(r, dict) and r.get("state")]
    return len(nbrs), [f"{r.get('router_id') or r.get('neighbor_ip') or '?'} ({r['state']})" for r in nbrs
                       if re.sub(r"[^a-z0-9]", "", str(r["state"]).lower().split("/")[0]) not in ("full", "twoway", "2way")]

def _one(cfg):
    cfg = cfg[0] if isinstance(cfg, list) and cfg else cfg          # results is taken to be the one object; a list of one reads the same
    return cfg if isinstance(cfg, dict) else {}

def bgp_running(cfg):
    """From cmdb router/bgp ("config router bgp"): AS 0 switches BGP off."""
    return str(_one(cfg).get("as") or "0").strip() != "0"

def ospf_running(cfg):
    """From cmdb router/ospf ("config router ospf"): a router ID (0.0.0.0 when unset), an area or a network."""
    cfg = _one(cfg)
    return str(cfg.get("router-id") or "0.0.0.0") != "0.0.0.0" or bool(cfg.get("area") or cfg.get("network"))

class FortinetDriver(Driver):
    wan_in_run = True                    # its run reads wan usage from the interface list it already has

    def _get(self, path, whole=False, api="monitor"):
        d = self.dev
        port = d.get("port") or 443
        r = requests.get(f"https://{d['host']}:{port}/api/v2/{api}/{path}",
                         headers={"Authorization": f"Bearer {self.password}"},
                         verify=tlsverify.verify(d), timeout=self.opts["http_timeout"], **proxy.requests_kwargs(d))
        r.raise_for_status()
        return r.json() if whole else r.json()["results"]

    def _version(self):
        """FortiOS puts version, build and serial in the reply itself, beside results (not in it)."""
        reply = self._get("system/status", whole=True)
        if not isinstance(reply, dict):
            return ""
        return reply.get("version") or (reply.get("results") or {}).get("version") or ""

    def _optional(self, path, api="monitor"):
        """Some of these exist only when the feature is licensed or switched on; the firewall answers 400, 404 or 424 when it is not."""
        try:
            return self._get(path, api=api)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code in (400, 403, 404, 405, 424):
                return None
            raise

    def run(self):
        out = []
        try:
            self.found_software(self._version())             # a rejected token is said once, not once per check
        except requests.HTTPError as e:
            code = getattr(e.response, "status_code", None)
            if code == 401:
                raise AuthRejected("FortiGate rejected the API token (HTTP 401): check the token stored for this device, that it has not expired, "
                                   "and that this computer is in the API admin's trusted hosts.") from None
            if code == 403:
                raise AuthRejected("FortiGate refused the API token (HTTP 403): the REST API admin needs read access, and this computer must be in "
                                   "its trusted hosts.") from None
        except Exception:
            quiet.ignored()
        for name, fn in (("resources", self.resources), ("firmware", self.firmware),
                         ("wan links", self.wan), ("ha", self.ha), ("vpn", self.vpn), ("licenses", self.licenses), ("certificates", self.certificates),
                         ("interfaces", self.interfaces), ("ha sync", self.ha_sync), ("fortiaps", self.fortiaps), ("fortiswitches", self.fortiswitches),
                         ("log disk", self.log_disk), ("wan usage", self.wan_usage), ("bgp", self.bgp), ("ospf", self.ospf)):
            if self.enabled(name):
                self.safe(out, name, fn)
        return out

    def resources(self):
        res = self._get("system/resource/usage?scope=global")
        return [self.level_check("cpu", res["cpu"][0]["current"]),
                self.level_check("memory", res["mem"][0]["current"])]

    def firmware(self):
        return self.result("firmware", OK, self._version() or "?")

    def wan(self):
        ifs = self._get("system/interface?scope=global")
        wans = {n: i for n, i in ifs.items() if i.get("role") == "wan"}
        down = [n for n, i in wans.items() if not i.get("link")]
        return self.result("wan links", FAIL if down else OK,
                           f"{len(wans) - len(down)}/{len(wans)} up", ", ".join(down))

    def ha(self):
        peers = self._get("system/ha-peer")
        expected = bool(self.dev.get("ha_expected"))
        n = len(peers) if isinstance(peers, list) else 0
        if not expected and n == 0:
            return self.result("ha", OK, "not configured")
        # a healthy cluster shows this unit plus its peers
        status = OK if n >= 1 else FAIL
        names = ", ".join(p.get("hostname", p.get("serial_no", "?")) for p in peers)
        return self.result("ha", status, f"{n + 1 if n else 1} member(s)",
                           names if n else "no HA peer visible", numeric=float(n + 1))

    def licenses(self):
        """FortiCare support and FortiGuard subscriptions: the one that ends first."""
        found = apichecks.fortinet_licenses(self._optional("license/status"))
        if not found:
            return []
        name, days, state = min(found, key=lambda x: x[1])
        t = self.th["support_days"]
        status = grade_low(days, t["warn"], t["fail"])
        soon = [f"{n} ({d:.0f} d)" for n, d, _ in sorted(found, key=lambda x: x[1]) if d < t["warn"]]
        return self.result("licenses", status, f"{days:.0f} days" if days >= 0 else "expired", ("ends first: " + name + (f"; also {', '.join(soon[1:4])}" if len(soon) > 1 else "")) if status != OK else "",
                           numeric=float(days))

    def certificates(self):
        found = apichecks.fortinet_cert_days(self._optional("system/available-certificates"), dates=True)
        if not found:
            return []
        name, days, _when = min(found, key=lambda x: x[1])
        t = self.th["cert_days"]
        return self.result("certificates", grade_low(days, t["warn"], t["fail"]), f"{days:.0f} days" if days >= 0 else "expired", name, numeric=float(days),
                           items=[self.item(n, numeric=float(d), data={"expires": w, "where": "store"}) for n, d, w in found])

    def _physical(self):
        if not hasattr(self, "_phys"):                               # read once per run: interfaces and wan usage both use it
            ifs = self._get("system/interface?scope=global")
            self._phys = {n: i for n, i in ifs.items() if str(i.get("type", "physical")).lower() == "physical"}
        return self._phys

    @staticmethod
    def _if_state(i):
        if i.get("link"):
            return "up"
        return "down" if str(i.get("status", "up")).lower() == "up" and i.get("role") != "undefined" else "off"

    def list_interfaces(self):
        return [(n, self._if_state(i)) for n, i in self._physical().items()]

    def interfaces(self):
        phys = self._physical()
        if not phys:
            return []
        rows = self.interfaces_row([(n, self._if_state(i)) for n, i in phys.items()])
        rows = [rows] if rows else []
        errs = {n: int(i.get("rx_errors", 0) or 0) + int(i.get("tx_errors", 0) or 0) for n, i in phys.items() if i.get("link")}
        found = self.error_counter_rows("interface errors", errs) if errs else None
        if found:
            rows.append(found)
        return rows

    def interface_counters(self):
        return {n: (int(i.get("rx_bytes") or 0), int(i.get("tx_bytes") or 0), float(i.get("speed") or 0) * 1e6)
                for n, i in self._physical().items() if "rx_bytes" in i}

    def ha_sync(self):
        differ = apichecks.fortinet_ha_sync(self._optional("system/ha-checksums"))
        if differ is None:
            return []
        if not differ:
            return self.result("ha sync", OK, "in sync", "")
        return self.result("ha sync", WARN, "out of sync", "configuration differs: " + ", ".join(differ[:5]), numeric=float(len(differ)))

    def _managed(self, path, check, what):
        rows = self._optional(path)
        if not rows:
            return []
        up, down = apichecks.fortinet_status_list(rows)
        total = up + len(down)
        return self.result(check, WARN if down else OK, f"{up}/{total} online", (f"{what} not online: " + ", ".join(down[:5])) if down else "", numeric=float(up))

    def fortiaps(self):
        return self._managed("wifi/managed_ap", "fortiaps", "access points")

    def fortiswitches(self):
        return self._managed("switch-controller/managed-switch/status", "fortiswitches", "switches")

    def log_disk(self):
        pct = apichecks.fortinet_log_disk(self._optional("log/current-disk-usage"))
        if pct is None:
            return []
        return self.level_check("log disk", pct, th_key="disk")

    def vpn(self):
        tunnels = self._get("vpn/ipsec")
        if not tunnels:
            return []
        down = [t["name"] for t in tunnels
                if not t.get("proxyid") or any(p.get("status") != "up" for p in t["proxyid"])]
        up = len(tunnels) - len(down)
        return self.result("ipsec tunnels", WARN if down else OK, f"{up}/{len(tunnels)} up",
                           "down: " + ", ".join(down[:5]) if down else "", numeric=float(up))

    def _routing(self, check, protocol, paths, read, running):
        """The token's own VDOM, as the other calls here."""
        rows, missing = [], 0
        for path in paths:
            try:
                got = self._optional(path)
            except requests.HTTPError as e:
                if getattr(e.response, "status_code", None) != 500:     # shortcut: any 500 reads as an empty list (FortiOS 7.4.9 and later answer it when there are no neighbours), tell them apart if a real unit shows another cause
                    raise
                got = []
            missing += got is None
            rows += got if isinstance(got, list) else []
        total, down = read(rows)
        if total:
            return self.neighbors_row(check, protocol, True, total, down, value=f"{total - len(down)}/{total} established")
        on = running(self._optional(f"router/{check}", api="cmdb"))
        if on and missing == len(paths):
            self._get(paths[0])                                          # configured, and this FortiOS (before 7.0) has no such list: the row says the API's answer
        return self.neighbors_row(check, protocol, on, 0, [])

    def bgp(self):
        return self._routing("bgp", "BGP", ("router/bgp/neighbors", "router/bgp/neighbors6"), bgp_neighbors, bgp_running)

    def ospf(self):
        return self._routing("ospf", "OSPF", ("router/ospf/neighbors",), ospf_neighbors, ospf_running)
