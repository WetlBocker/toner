"""Proxmox VE (standalone or a cluster) through its API with an API token. The host is any node (port 8006 unless set); the secret is the token as
Proxmox shows it:  user@realm!tokenname=secret-uuid  (Datacenter > Permissions > API Tokens; PVEAuditor on / is enough, and 'Privilege Separation' may stay on if
the token itself has that role). Nodes, quorum, storage, and tasks that failed in the last day, backups included."""
import time

from core import display
from .base import OK, WARN, FAIL, grade, grade_low
from .restapi import RestApi

TASK_GOOD = ("OK", "WARNINGS")


class ProxmoxDriver(RestApi):
    PREFIX = "/api2/json"
    DEFAULT_PORT = 8006
    NAME = "Proxmox"

    def auth(self):
        return {"Authorization": f"PVEAPIToken={self.password or ''}"}, None

    def data(self, path, params=None, optional=False):
        got = self.get(path, params, optional)
        return None if got is None else got.get("data")

    def run(self):
        out = []
        version = self.data("/version") or {}
        self.found_software(version.get("version", ""))
        if self.enabled("reachability"):
            out.append(self.result("reachability", OK, f"Proxmox VE {version.get('version', '')}".strip(), version.get("release") and f"release {version['release']}" or ""))
        resources = self.data("/cluster/resources") or []
        for key, fn in (("cluster", self.cluster), ("nodes", self.nodes), ("storage", self.storage), ("guests", self.guests), ("tasks", self.tasks), ("backups", self.backups)):
            if self.enabled(key):
                self.safe(out, key, lambda fn=fn: fn(resources))
        return out

    def cluster(self, _resources):
        rows = self.data("/cluster/status", optional=True) or []
        cl = next((r for r in rows if r.get("type") == "cluster"), None)
        if cl is None:
            return []                                                     # a single node that is not part of a cluster
        nodes = [r for r in rows if r.get("type") == "node"]
        down = [r.get("name", "?") for r in nodes if not r.get("online")]
        if not int(cl.get("quorate") or 0):
            return self.result("cluster", FAIL, "no quorum", "the cluster has lost quorum: VMs may not start, and changes are refused")
        return self.result("cluster", WARN if down else OK, f"{len(nodes) - len(down)}/{len(nodes)} nodes online", ("offline: " + ", ".join(down)) if down else "quorate",
                           numeric=float(len(nodes) - len(down)))

    def nodes(self, resources):
        out = []
        for n in self.data("/nodes") or []:
            label = f"{self.name} / {n.get('node', '?')}"
            st = str(n.get("status") or "unknown").lower()
            rows = [self.result("node", OK if st == "online" else FAIL, st)]
            if st == "online":
                cpu = n.get("cpu")
                if cpu is not None:
                    t = self.th["cpu"]
                    rows.append(self.result("cpu", grade(float(cpu) * 100, t["warn"], t["fail"]), f"{float(cpu) * 100:.0f}%", numeric=float(cpu) * 100))
                if n.get("maxmem"):
                    t, pct = self.th["memory"], float(n.get("mem") or 0) / float(n["maxmem"]) * 100
                    rows.append(self.result("memory", grade(pct, t["warn"], t["fail"]), f"{pct:.0f}%", numeric=pct))
                if n.get("uptime") is not None:
                    hours = float(n["uptime"]) / 3600
                    t = self.th["uptime"]
                    rows.append(self.result("uptime", grade_low(hours, t["warn"], t["fail"]), display.uptime(hours), numeric=hours))
            for r in rows:
                r.device = label
            out += rows
        return out

    def storage(self, resources):
        stores = [r for r in resources if r.get("type") == "storage"]
        if not stores:
            return []
        bad = [f"{s.get('storage')} on {s.get('node')}" for s in stores if str(s.get("status", "available")).lower() not in ("available", "active")]
        pcts = [(float(s.get("disk") or 0) / float(s["maxdisk"]) * 100, s) for s in stores if s.get("maxdisk")]
        worst = max(pcts, key=lambda x: x[0]) if pcts else None
        t = self.th["disk"]
        status = FAIL if bad else (grade(worst[0], t["warn"], t["fail"]) if worst else OK)
        value = f"{worst[0]:.0f}%" if worst else "ok"
        message = ("not available: " + ", ".join(bad[:4])) if bad else (f"fullest: {worst[1].get('storage')} on {worst[1].get('node')}" if worst else "")
        return self.result("storage", status, value, message, numeric=float(worst[0]) if worst else None)

    def guests(self, resources):
        vms = [r for r in resources if r.get("type") in ("qemu", "lxc") and not r.get("template")]
        if not vms:
            return []
        running = sum(1 for v in vms if v.get("status") == "running")
        return self.result("guests", OK, f"{running} running, {len(vms) - running} stopped", f"{len(vms)} virtual machines and containers", numeric=float(running))

    def _recent_tasks(self):
        if not hasattr(self, "_tasks"):
            cutoff = time.time() - 86400
            self._tasks = [t for t in (self.data("/cluster/tasks", optional=True) or []) if float(t.get("endtime") or t.get("starttime") or 0) >= cutoff]
        return self._tasks

    def tasks(self, _resources):
        failed = [t for t in self._recent_tasks() if t.get("endtime") and not str(t.get("status", "OK")).startswith(TASK_GOOD) and t.get("type") != "vzdump"]
        if not failed:
            return self.result("tasks", OK, "none failed", "last 24 hours", numeric=0.0)
        return self.result("tasks", WARN, f"{len(failed)} failed", "; ".join(f"{t.get('type')} {t.get('id') or ''} ({t.get('status')})".replace("  ", " ") for t in failed[:3]), numeric=float(len(failed)))

    def backups(self, _resources):
        runs = [t for t in self._recent_tasks() if t.get("type") == "vzdump" and t.get("endtime")]
        if not runs:
            return []                                                         # no backup job ran today; nothing to say
        failed = [t for t in runs if not str(t.get("status", "OK")).startswith(TASK_GOOD)]
        if not failed:
            return self.result("backups", OK, f"{len(runs)} ok", "backup jobs, last 24 hours", numeric=0.0)
        return self.result("backups", FAIL, f"{len(failed)} of {len(runs)} failed", "; ".join(str(t.get("status")) for t in failed[:3]), numeric=float(len(failed)))
