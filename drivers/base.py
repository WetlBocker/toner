from dataclasses import dataclass
from typing import Optional
from core import checks, db, profiles
from core import quiet

OK, WARN, FAIL, ERROR = "OK", "WARN", "FAIL", "ERROR"
SEVERITY = {OK: 0, WARN: 1, FAIL: 2, ERROR: 3}

# Used when a driver is built without explicit options (the run normally passes db.runtime_options()).
DEFAULT_OPTS = {"ssh_timeout": 20, "http_timeout": 15, "retries": 0, "retry_delay": 3,
                "disabled": frozenset(), "counter_mode": "total", "firmware_severity": "WARN"}

@dataclass
class Result:
    device: str
    check: str
    status: str
    value: str = ""
    message: str = ""
    numeric: Optional[float] = None     # stored for trend charts

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

    @property
    def password(self):
        """Password or API token: explicit value (used by Test), the device's own, or its profile's."""
        return self.dev.get("password") or profiles.secret(self.dev, "main")

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

    def flush_baselines(self):
        if self._new_baseline:
            db.set_baselines(self.name, self._new_baseline)
            self._new_baseline = {}

    def error_counter_rows(self, check, errs):
        """Row for cumulative error counters {name: count}: lifetime total, or only what is new since last run."""
        if not self.delta_mode:
            bad = [n for n, e in errs.items() if e > 0]
            return self.result(check, WARN if bad else OK, len(bad), ", ".join(bad[:5]), numeric=float(len(bad)))
        grew, first = {}, False
        for name, e in errs.items():
            d = self.delta(f"err:{name}", e)
            if d is None:
                first = True
            elif d > 0:
                grew[name] = d
        if first and not grew and not self._baseline:
            return self.result(check, OK, "baseline set", "counters recorded; changes are reported from the next run")
        return self.result(check, WARN if grew else OK, len(grew),
                           ", ".join(f"{n} (+{d:.0f})" for n, d in list(grew.items())[:5]), numeric=float(len(grew)))

    def result(self, check, status, value="", message="", numeric=None):
        return Result(self.name, check, status, str(value), message, numeric)

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
            out.append(self.result(check, ERROR, "", f"{type(e).__name__}: {e}"))
            self._save_diag(check)

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
