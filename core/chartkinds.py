"""Which picture each check gets, chosen on purpose (spec: "The chart rules"). Two tables keyed by stored check name, plus a
(vendor, check) override where one name means two things. A check not listed falls back to chart_kind, from its rows."""

STATE_WORDS = {"up", "down", "ok", "warn", "warning", "fail", "failed", "error", "enabled", "disabled", "online", "offline", "connected",
               "disconnected", "active", "inactive", "true", "false", "yes", "no", "present", "absent", "running", "stopped"}


def chart_kind(rows):
    """How a check's rows are drawn: "line" (numbers over more than one time), "bar" (numbers at one time, one per device),
    "status" (no numbers, and every value empty or a state word such as up or enabled: how often each OK/WARN/FAIL happened) or "table" (text such
    as a version or model). Rows are dicts with numeric, value, status and, over time, t."""
    if any(r.get("numeric") is not None for r in rows):
        return "line" if len({r.get("t") for r in rows}) > 1 else "bar"
    states = all(str(r.get("value") or "").strip().lower() in STATE_WORDS | {""} for r in rows)
    return "status" if rows and states else "table"


def _names(kind, *names):
    return {n: kind for n in names}


OVER_TIME = {
    **_names("line", "cpu", "memory", "temperature", "sessions", "load", "response time", "reachability", "clock", "changes",
             "interface errors", "wan usage"),
    **_names("gauges", "disks", "disk", "storage", "flash", "log disk", "pool space", "datasets"),
    **_names("heatmap", "disk health", "pending reboot", "services", "tasks", "environment", "interfaces", "vpn", "ipsec tunnels",
             "alarms", "alerts", "incidents", "core dumps", "bgp", "ospf", "eigrp"),          # counts of problems: when, not how many
    **_names("table", "firewall", "last commit", "licenses", "panorama", "fortiaps", "fortiswitches", "antivirus", "firmware"),
    "certificates": "certs", "patches": "table", "config backup": "config", "uptime": "uptime", "ha": "ha", "resources": "hidden",
}
OVER_TIME_VENDOR = {("windows", "patches"): "wheel", ("truenas", "disks"): "heatmap"}
ACROSS = {"antivirus": "table", "certificates": "certs", "environment": "environment", "firmware": "firmware", "interfaces": "rings"}
_FALLBACK = {"line": "line", "bar": "line", "status": "heatmap", "table": "table"}
_ACROSS_FROM = {"line": "gauges", "gauges": "gauges", "heatmap": "health", "certs": "certs", "hidden": "hidden"}


def shown_name(check):
    """The name a check is listed under: every certificate check is "certificates", "ha sync" is "ha"."""
    if check == "certificate" or check.startswith("certificate :"):
        return "certificates"
    return "ha" if check == "ha sync" else check


def stored_names(shown, available):
    """The stored names in `available` that are listed as `shown` (the inverse of shown_name)."""
    return [c for c in available if shown_name(c) == shown]


def over_time_kind(check, vendor=None, rows=None):
    """"line", "heatmap", "table", "gauges", "wheel", "config", "uptime", "ha", "certs" or "hidden"."""
    name = shown_name(check)
    return OVER_TIME_VENDOR.get((vendor, name)) or OVER_TIME.get(name) or _FALLBACK[chart_kind(rows or [])]


def across_kind(check, rows=None, vendor=None):
    """"gauges", "table", "certs", "environment", "firmware", "rings", "health" or "hidden" (resources: Across devices leaves it out).
    A check not listed follows its over-time kind (for that vendor: TrueNAS disks are SMART health), so a count of problems is never
    drawn as a gauge."""
    return ACROSS.get(shown_name(check)) or _ACROSS_FROM.get(over_time_kind(check, vendor, rows), "table")


def is_measurement(check, vendor=None, rows=None):
    return over_time_kind(check, vendor, rows) in ("line", "gauges")
