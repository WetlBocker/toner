import requests
import urllib3
from .base import Driver, OK, WARN, FAIL

class FortinetDriver(Driver):
    def _get(self, path):
        d = self.dev
        if not d.get("verify_ssl"):
            urllib3.disable_warnings()
        port = d.get("port") or 443
        r = requests.get(f"https://{d['host']}:{port}/api/v2/monitor/{path}",
                         headers={"Authorization": f"Bearer {self.password}"},
                         verify=bool(d.get("verify_ssl")), timeout=self.opts["http_timeout"])
        r.raise_for_status()
        return r.json()["results"]

    def run(self):
        out = []
        for name, fn in (("resources", self.resources), ("firmware", self.firmware),
                         ("wan links", self.wan), ("ha", self.ha), ("vpn", self.vpn)):
            if self.enabled(name):
                self.safe(out, name, fn)
        return out

    def resources(self):
        res = self._get("system/resource/usage?scope=global")
        return [self.level_check("cpu", res["cpu"][0]["current"]),
                self.level_check("memory", res["mem"][0]["current"])]

    def firmware(self):
        return self.result("firmware", OK, self._get("system/status").get("version", "?"))

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

    def vpn(self):
        tunnels = self._get("vpn/ipsec")
        if not tunnels:
            return []
        down = [t["name"] for t in tunnels
                if not t.get("proxyid") or any(p.get("status") != "up" for p in t["proxyid"])]
        up = len(tunnels) - len(down)
        return self.result("ipsec tunnels", WARN if down else OK, f"{up}/{len(tunnels)} up",
                           "down: " + ", ".join(down[:5]) if down else "", numeric=float(up))
