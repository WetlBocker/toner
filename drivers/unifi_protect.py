"""UniFi Protect, through the Integration API of a console with an API key. The host is the console's address; the secret is the key.
It reports whether the NVR's alarm is in breach, whether each camera, light, sensor, chime and other device is connected,
sensor batteries, and recent leak, tamper or smoke alarms."""
from .base import OK, WARN, FAIL, grade_low
from .unifiapi import UnifiApi, hours_ago, stamp_text, state_status

# what to list, and what to call one of them
GROUPS = (("/cameras", "camera"), ("/lights", "light"), ("/sensors", "sensor"), ("/chimes", "chime"), ("/viewers", "viewer"),
          ("/speakers", "speaker"), ("/sirens", "siren"), ("/relays", "relay"), ("/bridges", "bridge"),
          ("/link-stations", "link station"), ("/alarm-hubs", "alarm hub"), ("/fobs", "fob"))
ALARMS = (("alarmTriggeredAt", "smoke or CO alarm"), ("leakDetectedAt", "water leak"), ("externalLeakDetectedAt", "external leak"),
          ("tamperingDetectedAt", "tampering"))
ALARM_HOURS = 24                          # an alarm older than this is history, not news


def items(data):
    """Protect returns a bare list; accept an envelope too."""
    if isinstance(data, dict):
        data = data.get("data", [])
    return [x for x in data or [] if isinstance(x, dict)]


class UnifiProtectDriver(UnifiApi):
    PREFIX = "/proxy/protect/integration"

    def run(self):
        out = []
        info = self.get("/meta/info")
        if self.enabled("reachability"):
            version = info.get("applicationVersion", "") if isinstance(info, dict) else ""
            out.append(self.result("reachability", OK, f"Protect {version}" if version else "answering", "UniFi Protect API"))
        if self.enabled("nvr"):
            self.safe(out, "nvr", self.nvr)
        wanted = self.enabled("devices") or self.enabled("battery") or self.enabled("alarms")
        for path, kind in GROUPS if wanted else ():
            found = items(self.get(path, optional=True))
            for dev in found:
                self.thing(out, kind, dev)
        return out

    def nvr(self):
        data = self.get("/nvrs")
        nvrs = items(data) if not (isinstance(data, dict) and "id" in data) else [data]
        if not nvrs:
            return []
        nvr = nvrs[0]
        arm = (nvr.get("armMode") or {}).get("status") or ""
        label = nvr.get("name") or nvr.get("type") or "NVR"
        if arm == "breach":
            return self.result("nvr", FAIL, "alarm breach", f"{label}: the alarm has been triggered")
        return self.result("nvr", OK, label, f"alarm {arm}" if arm else "")

    def thing(self, out, kind, dev):
        name = dev.get("name") or dev.get("mac") or kind
        if self.enabled("devices"):
            status, word = state_status(dev.get("state"))
            out.append(self.row(name, "state", status, word, kind if status == OK else f"{kind} is {word}"))
        if kind == "sensor":
            if self.enabled("battery"):
                self.battery(out, name, dev)
            if self.enabled("alarms"):
                self.alarms(out, name, dev)

    def battery(self, out, name, dev):
        b = dev.get("batteryStatus") or (dev.get("wirelessConnectionState") or {}).get("batteryStatus") or {}
        pct = b.get("percentage")
        if pct is None and not b.get("isLow"):
            return
        t = self.th["sensor_battery"]
        status = grade_low(float(pct), t["warn"], t["fail"]) if pct is not None else OK
        if b.get("isLow") and status == OK:
            status = WARN
        out.append(self.row(name, "battery", status, f"{float(pct):.0f}%" if pct is not None else "low", "low battery" if status != OK else "",
                            numeric=float(pct) if pct is not None else None))

    def alarms(self, out, name, dev):
        recent = [(label, dev.get(field)) for field, label in ALARMS
                  if hours_ago(dev.get(field)) is not None and hours_ago(dev.get(field)) <= ALARM_HOURS]
        if recent:
            out.append(self.row(name, "alarms", WARN, f"{len(recent)} in {ALARM_HOURS} h",
                                "; ".join(f"{label} at {stamp_text(when)}" for label, when in recent), numeric=float(len(recent))))
