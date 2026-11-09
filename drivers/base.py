import time
from dataclasses import dataclass, field
from typing import Optional
from core import checks, db, profiles
from core import quiet

OK, WARN, FAIL, ERROR = "OK", "WARN", "FAIL", "ERROR"
NA = "N/A"                  # the check ran and does not apply here (BGP not configured, no sensors): never a problem, never an alert
SEVERITY = {NA: 0, OK: 0, WARN: 1, FAIL: 2, ERROR: 3}


def is_problem(status):
    """WARN, FAIL or ERROR: what needs a look (OK and N/A do not)."""
    return SEVERITY.get(status, 0) > 0

# Used when a driver is built without explicit options (the run normally passes db.runtime_options()).
DEFAULT_OPTS = {"ssh_timeout": 20, "http_timeout": 15, "retries": 0, "retry_delay": 3,
                "disabled": frozenset(), "counter_mode": "total", "firmware_severity": "WARN"}

class AuthRejected(ValueError):
    """The device's API turned the key or login away: every check would fail the same way, so the run stops and says so once."""


@dataclass
class Result:
    device: str
    check: str
    status: str
    value: str = ""
    message: str = ""
    numeric: Optional[float] = None     # stored for trend charts
    org: Optional[int] = field(default=None, compare=False, repr=False)    # the organization whose file the device lives in (None: the current one)
    kid: Optional[tuple] = field(default=None, compare=False, repr=False)  # a UniFi console's device: (its id or MAC, its model); see core/unifikids.py
    seen: Optional[list] = field(default=None, compare=False, repr=False)  # more of that console's devices, listed with no row of their own: [(label, kid)]
    items: Optional[list] = field(default=None, compare=False, repr=False)  # per-disk/certificate/interface detail: [{name, numeric, status, text, data}]

def grade(value, warn, fail):
    """Higher value = worse."""
    return FAIL if value >= fail else WARN if value >= warn else OK

def grade_low(value, warn, fail):
    """Lower value = worse (e.g. uptime). A limit of 0 switches that level off."""
    return FAIL if fail > 0 and value < fail else WARN if warn > 0 and value < warn else OK

class Driver:
    def __init__(self, dev: dict, thresholds: dict, opts: dict = None):
        self.dev = dev
        self.name = dev["name"]
        self.th = thresholds
        self.opts = {**DEFAULT_OPTS, **(opts or {})}
        self._baseline = None            # error counters from the previous run (delta mode)
        self._new_baseline = {}
        self.transcript = {}             # command -> output, kept so a failed parse can be reported with evidence
        self.custom = []
        self.facts = {}                  # what the run learned about the device besides results: {'software': {...}} (see found_software)
        self.on_check = None             # called (device name, check) as each check's row is made, for a progress line

    def found_software(self, version, image="", mode=""):
        """The software the device runs, read during this run; the runner keeps it on the device record (db.set_software).
        Nothing is kept without a version."""
        version = str(version or "").strip()
        if version and version != "?":
            self.facts["software"] = {"version": version, "image": str(image or "").strip(), "mode": str(mode or "").strip()}

    @property
    def password(self):
        """Password or API token: explicit value (used by Test), the device's own, or its profile's."""
        return self.dev.get("password") or profiles.secret(self.dev, "main")

    @property
    def enable_secret(self):
        """The enable password (the device's own, else its profile's); the login password when there is none."""
        return profiles.secret(self.dev, "enable") or self.password

    def enabled(self, check_key):
        """False if this check is switched off in Settings > Checks."""
        return checks.key(self.dev["vendor"], check_key) not in self.opts["disabled"]

    @property
    def delta_mode(self):
        return self.opts["counter_mode"] == "delta"

    def delta(self, key, value):
        """Increase of a cumulative counter since the previous run; None on the first run.
        A counter that went down was reset by a reboot, so everything since then is new."""
        if self._baseline is None:
            self._baseline = db.get_baselines(self.name)
        prev = self._baseline.get(key)
        self._new_baseline[key] = value
        if prev is None:
            return None
        return value if value < prev else value - prev

    def previous(self, key, value):
        """The value stored for `key` by the previous run (None on the first), keeping `value` for the next run."""
        if self._baseline is None:
            self._baseline = db.get_baselines(self.name)
        self._new_baseline[key] = value
        return self._baseline.get(key)

    def flush_baselines(self):
        if self._new_baseline:
            db.set_baselines(self.name, self._new_baseline)
            self._new_baseline = {}

    def interface_filter(self):
        """The interface names (lower case) this device is limited to, or None when every interface is checked."""
        if not hasattr(self, "_if_filter"):
            own = db.normalize_checkopts(self.dev.get("checkopts")).get("interfaces")
            self._if_chosen = list(own or [])
            self._if_filter = {n.lower() for n in own} if own else None
        return self._if_filter

    def wanted_interface(self, name):
        flt = self.interface_filter()
        return flt is None or str(name).lower() in flt

    def interfaces_row(self, states):
        """The 'interfaces' row from [(name, state)], state being up, down, off (switched off by an administrator) or errdisabled.
        Any interface that is down is a FAIL. With the device's own list of interfaces only those count, a listed one that is
        switched off counts as down, and a listed one the device no longer has is a WARN."""
        flt = self.interface_filter()
        known = {str(n).lower() for n, _s in states}
        chosen = [(n, s) for n, s in states if flt is None or str(n).lower() in flt]
        if flt is not None:
            chosen = [(n, "down" if s == "off" else s) for n, s in chosen]
        counted = [(n, s) for n, s in chosen if s != "off"]
        missing = [n for n in self._if_chosen if n.lower() not in known] if flt is not None else []
        if not counted and not missing:
            return []
        up = [n for n, s in counted if s == "up"]
        down = [n for n, s in counted if s == "down"]
        bad = [n for n, s in counted if s == "errdisabled"]
        parts = []
        if down:
            parts.append("down: " + ", ".join(down[:6]) + (f" (+{len(down) - 6} more)" if len(down) > 6 else ""))
        if bad:
            parts.append("err-disabled: " + ", ".join(bad[:5]))
        if missing:
            parts.append("not found on the device: " + ", ".join(missing[:5]))
        status = FAIL if down else WARN if (bad or missing) else OK
        return self.result("interfaces", status, f"{len(up)}/{len(counted)} up", "; ".join(parts), numeric=float(len(up)),
                           items=[self.item(n, status=FAIL if s == "down" else WARN if s == "errdisabled" else OK, text=s) for n, s in counted])

    def list_interfaces(self):
        """[(name, state)] of every interface on the device, for choosing which ones are checked. Drivers with interfaces implement it."""
        raise NotImplementedError("this kind of device has no list of interfaces")

    def interface_counters(self):
        """{name: (in_octets, out_octets, speed_bps)} for every interface that has byte counters. Drivers that can read them implement it."""
        raise NotImplementedError("this kind of device has no interface counters")

    def wan_usage(self):
        """The 'wan usage' row: the busier direction of each interface marked WAN, as a percent of its available bandwidth
        (the circuit speed typed for it, else its port speed). Its own delta keys, so the bandwidth check's are left alone."""
        wan = db.normalize_checkopts(self.dev.get("checkopts")).get("wan")
        if not wan:
            return []
        counters = self.interface_counters()
        mine = {n.lower(): v for n, v in wan.items()}
        found = [(n, counters[n], mine[n.lower()]) for n in counters if n.lower() in mine]
        if not found:
            return []
        elapsed = self.delta("wan:t", time.time())
        items, worst = [], None
        for name, (cin, cout, speed), mbps in found:
            din, dout = self.delta(f"wan:in:{name}", cin), self.delta(f"wan:out:{name}", cout)
            avail = mbps * 1e6 if mbps else speed
            if not (elapsed and elapsed >= 5 and avail and din is not None and dout is not None):
                continue
            bps = max(din, dout) * 8 / elapsed
            pct, t = bps / avail * 100, self.th["wan_usage"]
            items.append(self.item(name, numeric=pct, status=grade(pct, t["warn"], t["fail"]), text=f"{bps / 1e6:.1f} Mbps",
                                   data={"in_bps": din * 8 / elapsed, "out_bps": dout * 8 / elapsed, "available_bps": avail}))
            if worst is None or pct > worst[0]:
                worst = (pct, name, bps)
        if worst is None:
            return self.result("wan usage", OK, "baseline set", "rates are reported from the next run")
        t = self.th["wan_usage"]
        return self.result("wan usage", grade(worst[0], t["warn"], t["fail"]), f"{worst[0]:.0f}%",
                           f"busiest: {worst[1]} at {worst[2] / 1e6:.1f} Mbps", numeric=float(worst[0]), items=items)

    def error_counter_rows(self, check, errs):
        """Row for cumulative error counters {name: count}: lifetime total, or only what is new since last run."""
        errs = {n: e for n, e in errs.items() if self.wanted_interface(n)}
        if not errs:
            return None
        if not self.delta_mode:
            bad = [n for n, e in errs.items() if e > 0]
            return self.result(check, WARN if bad else OK, len(bad), ", ".join(bad[:5]), numeric=float(len(bad)),
                               items=[self.item(n, numeric=float(e)) for n, e in errs.items()])
        grew, first, graded = {}, False, []
        for name, e in errs.items():
            d = self.delta(f"err:{name}", e)
            graded.append(self.item(name, numeric=None if d is None else float(max(d, 0))))
            if d is None:
                first = True
            elif d > 0:
                grew[name] = d
        if first and not grew and not self._baseline:
            return self.result(check, OK, "baseline set", "counters recorded; changes are reported from the next run")
        return self.result(check, WARN if grew else OK, len(grew),
                           ", ".join(f"{n} (+{d:.0f})" for n, d in list(grew.items())[:5]), numeric=float(len(grew)), items=graded)

    @staticmethod
    def item(name, numeric=None, status=None, text="", data=None):
        """One per-component detail for a row's items: a drive, certificate, sensor or interface."""
        return {"name": str(name), "numeric": numeric, "status": status, "text": text, "data": data or {}}

    def result(self, check, status, value="", message="", numeric=None, items=None):
        if self.on_check is not None:
            try:
                self.on_check(self.name, check)
            except Exception:                                # noqa: BLE001  (a progress line must never spoil a result)
                quiet.ignored("noqa: BLE001  (a progress line must never spoil a result)")
        return Result(self.name, check, status, str(value), message, numeric, items=items)

    def not_applicable(self, check, value, message=""):
        """A row saying the check ran and does not apply to this device, so a chosen check never just goes missing."""
        return self.result(check, NA, value, message)

    def neighbors_row(self, check, protocol, running, total, down, fail=True, value=None, message=None):
        """BGP, OSPF or EIGRP: N/A when the protocol is not configured, WARN when it runs with no neighbors, else up/down."""
        if not total:
            if not running:
                return self.not_applicable(check, "not configured", f"{protocol} is not configured on this device")
            return self.result(check, WARN, "no neighbors", f"{protocol} is running but has no neighbors", numeric=0.0)
        status = (FAIL if fail else WARN) if down else OK
        return self.result(check, status, value or "", message if message is not None else ("down: " + ", ".join(down[:5]) if down else ""),
                           numeric=float(total - len(down)))

    def level_check(self, check, value, th_key=None, unit="%"):
        t = self.th[th_key or check]
        return self.result(check, grade(value, t["warn"], t["fail"]),
                           f"{value:.0f}{unit}", numeric=float(value))

    def safe(self, out, check, fn):
        """Run one check; a failure becomes an ERROR row instead of aborting the device."""
        try:
            r = fn()
            out.extend(r if isinstance(r, list) else ([r] if r else []))
        except Exception as e:
            out.append(self.result(check, ERROR, "", self.explain(e)))
            self._save_diag(check)

    @staticmethod
    def explain(e):
        """What an error looks like in a result row. An HTTP error from a device's API says the code, not the long address it was sent to."""
        resp = getattr(e, "response", None)
        code = getattr(resp, "status_code", None)
        if type(e).__name__ == "HTTPError" and code:
            hint = {401: "the login or key was not accepted", 403: "the key or login may not read this", 404: "not found on this device (version or feature)",
                    429: "too many requests; try again shortly"}.get(code, "")
            return f"the device's API answered HTTP {code}" + (f": {hint}" if hint else "")
        return f"{type(e).__name__}: {e}"

    def _save_diag(self, check):
        """Keep what the device said, so 'unexpected output' can be fixed from a real sample. Never raises."""
        if not self.transcript:
            return
        try:
            from core import backup
            body = "\n\n".join(f"$ {cmd}\n{out}" for cmd, out in self.transcript.items())
            db.save_diagnostic(self.name, check, backup.clean(body, mask=True))
        except Exception:
            quiet.ignored()

    def run(self) -> list:
        raise NotImplementedError
