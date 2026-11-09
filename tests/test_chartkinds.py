# Run directly (python tests/test_chartkinds.py) or all together (python tests/run_all.py). The chart table: each check's picture.
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import chartkinds as K
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

o, a = K.over_time_kind, K.across_kind
row = lambda **k: {"numeric": None, "value": "", "status": "OK", **k}
check("disk health", o("disk health") == "heatmap")
check("disks gauges, truenas heatmap", o("disks") == "gauges" and o("disks", vendor="truenas") == "heatmap")
check("disk names", {o(c) for c in ("disk", "storage", "flash", "log disk", "pool space", "datasets")} == {"gauges"})
check("pool space and datasets: gauges over time, and across", {K.across_kind(c) for c in ("pool space", "datasets")} == {"gauges"})
check("patches", o("patches", vendor="windows") == "wheel" and o("patches", vendor="ciscoise") == "table" and o("patches") == "table")
check("config/uptime/ha/hidden", (o("config backup"), o("uptime"), o("ha"), o("ha sync"), o("resources")) == ("config", "uptime", "ha", "ha", "hidden"))
check("certs", o("certificate :8443") == o("certificate") == o("certificates") == "certs")
check("heatmaps", {o(c) for c in ("vpn", "ipsec tunnels", "tasks", "services", "pending reboot", "environment", "interfaces")} == {"heatmap"})
problems = ("alarms", "alerts", "incidents", "core dumps", "bgp", "ospf", "eigrp")
check("counts of problems (alarms, alerts, incidents, core dumps, routing neighbors) are heatmaps, not lines",
      {o(c, rows=[row(numeric=1.0, t="a"), row(numeric=2.0, t="b")]) for c in problems} == {"heatmap"})
check("...and across devices the health table, never a gauge", {a(c, [row(numeric=3.0)]) for c in problems} == {"health"})
check("tables", {o(c) for c in ("firewall", "last commit", "licenses", "panorama", "fortiaps", "fortiswitches")} == {"table"})
check("lines", {o(c) for c in ("reachability", "clock", "changes", "interface errors", "cpu", "wan usage")} == {"line"})
check("fallback from rows", (o("zz", rows=[row(numeric=1.0, t="a"), row(numeric=2.0, t="b")]), o("zz", rows=[row(numeric=1.0)]),
      o("zz", rows=[row(value="up")]), o("zz", rows=[row(value="7.1")]), o("zz")) == ("line", "line", "heatmap", "table", "table"))
a = K.across_kind
check("across explicit", (a("cpu"), a("wan usage"), a("antivirus"), a("firmware"), a("interfaces"), a("environment"), a("certificate :8443"))
      == ("gauges", "gauges", "table", "firmware", "rings", "environment", "certs"))
check("across derived", (a("unknown", [row(value="up")]), a("vpn"), a("tasks"), a("resources"), a("firewall"), a("uptime"), a("patches"), a("config backup"))
      == ("health", "health", "health", "hidden", "table", "table", "table", "table"))
check("across by vendor: TrueNAS disks are SMART health, other disks gauges", (a("disks", vendor="truenas"), a("disks", vendor="windows"), a("disks"))
      == ("health", "gauges", "gauges"))
check("shown_name", (K.shown_name("certificate :8443"), K.shown_name("certificates"), K.shown_name("ha sync"), K.shown_name("cpu"))
      == ("certificates", "certificates", "ha", "cpu"))
check("stored_names", K.stored_names("certificates", ["cpu", "certificate", "certificate :8443", "certificates"]) == ["certificate", "certificate :8443", "certificates"]
      and K.stored_names("ha", ["ha", "ha sync", "vpn"]) == ["ha", "ha sync"])
check("is_measurement", K.is_measurement("cpu") and K.is_measurement("disks") and not K.is_measurement("disks", "truenas") and not K.is_measurement("vpn"))
print(f"{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
