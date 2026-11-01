"""Cisco ISE through its Open API on the Primary PAN (Administration > System > Settings > API Settings: turn the Open API on; an
admin user with the Open API role). The host is the PAN; the login is a user name and password. What it checks: the deployment's
nodes are all Connected, the version and patches, licensing, and the active sessions from the MnT API when that is on too."""
import re

from .base import OK, WARN, FAIL
from .webapi import WebApi


class CiscoIseDriver(WebApi):
    NAME = "Cisco ISE"

    def _auth(self):
        return (self.dev.get("username") or "", self.password or "")

    def get(self, path, optional=False, **kw):
        kw.setdefault("auth", self._auth())
        return super().get(path, optional=optional, **kw)

    def run(self):
        out = []
        try:
            self.nodes_ = self.get("/api/v1/deployment/node") or []
            if isinstance(self.nodes_, dict):
                self.nodes_ = self.nodes_.get("response") or self.nodes_.get("nodes") or []
            patch = self.get("/api/v1/patch", optional=True) or {}
            version = str(patch.get("iseVersion") or "") if isinstance(patch, dict) else ""
            self.found_software(version)
            if self.enabled("reachability"):
                out.append(self.result("reachability", OK, version or "answering", f"{len(self.nodes_)} node(s) in the deployment"))
            for key, fn in (("nodes", self.nodes), ("patches", lambda: self.patches(patch)), ("licensing", self.licensing), ("sessions", self.sessions)):
                if self.enabled(key):
                    self.safe(out, key, fn)
        finally:
            self.close()
        return out

    def nodes(self):
        rows = []
        bad = []
        for n in self.nodes_:
            name = n.get("hostname") or n.get("fqdn") or "node"
            status = str(n.get("nodeStatus") or n.get("status") or "")
            roles = ", ".join(n.get("roles") or []) or ", ".join(n.get("services") or [])
            okay = status.lower() in ("connected", "online", "ok")
            if not okay:
                bad.append(f"{name} ({status or 'unknown'})")
            r = self.result("node", OK if okay else FAIL, status.lower() or "unknown", roles)
            r.device = f"{self.name} / {name}"
            rows.append(r)
        if not self.nodes_:
            return self.result("nodes", WARN, "none listed", "the API returned no nodes")
        rows.insert(0, self.result("nodes", FAIL if bad else OK, f"{len(self.nodes_) - len(bad)}/{len(self.nodes_)} connected", "; ".join(bad[:4]), numeric=float(len(self.nodes_) - len(bad))))
        return rows

    def patches(self, patch):
        if not isinstance(patch, dict) or not patch:
            return []
        installed = patch.get("patchVersion") or patch.get("patches") or []
        nums = []
        for p in installed:
            n = p.get("patchNumber") if isinstance(p, dict) else p
            try:
                nums.append(int(n))
            except (TypeError, ValueError):
                continue
        level = max(nums) if nums else 0
        return self.result("patches", OK, f"patch {level}" if level else "none", f"{patch.get('iseVersion', '')}".strip(), numeric=float(level))

    def licensing(self):
        tiers = self.get("/api/v1/license/system/tier-state", optional=True)
        smart = self.get("/api/v1/license/system/smart-state", optional=True)
        if tiers is None and smart is None:
            return []
        problems, names = [], []
        for t in (tiers if isinstance(tiers, list) else (tiers or {}).get("response") or []):
            if not isinstance(t, dict):
                continue
            name, status = str(t.get("name") or t.get("tier") or ""), str(t.get("status") or "").upper()
            names.append(name)
            if status and status not in ("ENABLED", "COMPLIANT", "AUTHORIZED", "ACTIVE"):
                problems.append(f"{name}: {status.lower()}")
        state = ""
        if isinstance(smart, dict):
            s = smart.get("response") if isinstance(smart.get("response"), dict) else smart
            state = str(s.get("registrationState") or s.get("state") or s.get("authorizationStatus") or "")
            if state and state.upper() not in ("REGISTERED", "AUTHORIZED", "EVALUATION"):
                problems.append(f"smart licensing: {state.lower()}")
        return self.result("licensing", WARN if problems else OK, state.lower() or (f"{len(names)} tier(s)" if names else "ok"), "; ".join(problems[:4]) or ", ".join(names[:6]))

    def sessions(self):
        """Active sessions from the MnT API (an XML count): nothing when MnT is not reachable here."""
        try:
            r = self.call("GET", "/admin/API/mnt/Session/ActiveCount", optional=True, raw=True, auth=self._auth(), headers={"Accept": "application/xml"})
        except Exception:
            return []
        if r is None:
            return []
        m = re.search(r"<count>\s*(\d+)\s*</count>", getattr(r, "text", "") or "")
        if not m:
            return []
        n = int(m.group(1))
        return self.result("sessions", OK, str(n), "active sessions (MnT)", numeric=float(n))
