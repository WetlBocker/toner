# Run directly (python tests/test_x.py) or all together (python tests/run_all.py).
# The charts as plain dictionaries (ui.chartspec), the TLS default for new devices (core.tlsverify), the shared funnel button,
# the shared sign-in dialog and the shared ping thread: what the review-fixes branch added. Nothing here needs QtWebEngine.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, time, warnings
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = os.path.join(SP, "charts%d.db" % int(time.time())); os.environ["APPDATA"] = os.path.join(SP, "roamingcharts%d" % int(time.time()))
from core import db
db.init()
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

from datetime import datetime, timedelta
from ui import chartspec as cs

print("== the palette")
p = cs.palette()
check("a palette without a window is a light one with the standard status colours", p["dark"] is False and p["status"]["FAIL"] and p["text"] != p["muted"])
dark = cs.palette({"dark": True, "text": "#eee", "muted": "#aaa", "surface": "#111", "border": "#333", "accent": "#5af"}, {"OK": "#0f0", "FAIL": "#f00"})
check("theme tokens and status inks are taken as given", dark["dark"] and dark["accent"] == "#5af" and dark["status"]["OK"] == "#0f0" and dark["status"]["WARN"])

def js(opt):
    """Every option must survive the trip to the page as JSON."""
    return json.loads(json.dumps(opt, default=str))

print("== donut")
d = js(cs.donut(p, {"OK": 12, "WARN": 3, "FAIL": 1, "N/A": 0}, title="Devices"))
check("one slice per status that has devices, worst statuses in Toner's order, coloured by status", [x["name"] for x in d["series"][0]["data"]] == ["OK", "WARN", "FAIL"]
      and d["series"][0]["data"][2]["itemStyle"]["color"] == p["status"]["FAIL"])
check("the total sits in the middle", d["graphic"][0]["style"]["text"] == "16")
check("nothing to count gives the empty note, not a chart", cs.donut(p, {"OK": 0}) == cs.empty("Nothing to show yet"))

print("== bars")
b = js(cs.bars(p, ["a", "b", "c"], [10, 75, 95], unit="%", warn=70, fail=90, limit=80, extra=["ka", "kb", "kc"]))
colours = [x["itemStyle"]["color"] for x in b["series"][0]["data"]]
check("bars take the status colour of the band their value is in", colours == [p["status"]["OK"], p["status"]["WARN"], p["status"]["FAIL"]])
check("a limit is a dashed line and every bar carries its extra for the click", b["series"][0]["markLine"]["data"][0]["yAxis"] == 80 and b["series"][0]["data"][1]["extra"] == "kb")
h = js(cs.bars(p, ["a"], [1], horizontal=True))
check("horizontal bars put the categories on the y axis, top first", h["yAxis"]["type"] == "category" and h["yAxis"]["inverse"] is True and h["xAxis"]["type"] == "value")

print("== grouped and stacked bars")
g = js(cs.grouped_bars(p, ["Cisco", "Juniper"], [("FAIL", [1, 0]), ("WARN", [2, 3]), ("Other", [1, 1])], stacked=True))
check("series named after a status take its colour, the rest the series palette, and stack", g["series"][0]["itemStyle"]["color"] == p["status"]["FAIL"]
      and g["series"][2]["itemStyle"]["color"] == p["series"][2] and all(s["stack"] == "total" for s in g["series"]))

print("== heatmap")
hm = js(cs.heatmap(p, ["00", "01"], ["Mon", "Tue"], [(0, 0, 3), (1, 1, 1)]))
check("cells are [x, y, value] and the colour scale runs to the FAIL colour", hm["series"][0]["data"] == [[0, 0, 3], [1, 1, 1]] and hm["visualMap"]["max"] == 3
      and hm["visualMap"]["inRange"]["color"][-1] == p["status"]["FAIL"])

print("== histogram")
hist = js(cs.histogram(p, [1, 3.9, 4, 7.5, 9, 10, 10], [0, 4, 7, 9, 10]))
check("values fall in their bins, the last bin keeps its top edge", [x["value"] for x in hist["series"][0]["data"]] == [2, 1, 1, 3] and hist["xAxis"]["data"][-1] == "9–10")

print("== gauge")
ga = js(cs.gauge(p, 78, warn=70, fail=90, title="CPU"))
stops = ga["series"][0]["axisLine"]["lineStyle"]["color"]
check("the ring is green to the warn limit, amber to the fail limit, red to the end", stops == [[0.7, p["status"]["OK"]], [0.9, p["status"]["WARN"]], [1, p["status"]["FAIL"]]] and ga["series"][0]["data"][0]["value"] == 78)
lo = js(cs.gauge(p, 20, warn=48, fail=24, title="Uptime", unit=" h", maximum=168, lower_is_worse=True))
check("a reading where lower is worse runs red, amber, then green", [s[1] for s in lo["series"][0]["axisLine"]["lineStyle"]["color"]] == [p["status"]["FAIL"], p["status"]["WARN"], p["status"]["OK"]])
check("no reading is the empty note", cs.gauge(p, None) == cs.empty("No reading yet"))

print("== area over time")
t0 = datetime(2026, 11, 1, 12, 0)
ar = js(cs.area(p, [t0, t0 + timedelta(minutes=5)], [("CPU", [40, 50]), ("Memory", [60, None])], unit="%", warn=70, fail=90))
check("times become milliseconds since the epoch, a missing value breaks the line", ar["series"][0]["data"][0][0] == t0.timestamp() * 1000 and ar["series"][1]["data"][1][1] is None
      and ar["series"][0]["connectNulls"] is False)
check("the limits are dashed lines labelled WARN and FAIL", [m["label"]["formatter"] for m in ar["series"][0]["markLine"]["data"]] == ["WARN", "FAIL"])
check("a sparkline has no axes to speak of", js(cs.sparkline(p, [1, 2, 3]))["xAxis"]["show"] is False)

print("== the chart widget without a window")
from ui import webchart
check("the page and the library are in assets", os.path.exists(webchart.page_path()) and os.path.exists(os.path.join(os.path.dirname(webchart.page_path()), "echarts.min.js")))
check("the page only reads its own files: no CDN, nothing fetched from the internet", "http" not in open(webchart.page_path(), encoding="utf-8").read().replace("qrc:///", "").split("<script")[0] and 'src="echarts.min.js"' in open(webchart.page_path(), encoding="utf-8").read())

print("== the TLS default for new devices")
from core import tlsverify, importer
check("Settings start with certificates checked on new devices", db.get_setting("default_verify_ssl") is True)
check("a device without the flag, imported or found, follows the setting", tlsverify.default_for_new() == 1 and importer.normalize({"name": "fw", "vendor": "fortinet", "host": "10.1.1.1"})[0]["verify_ssl"] == 1)
db.set_setting("default_verify_ssl", False)
check("turning it off turns it off for new devices too", tlsverify.default_for_new() == 0 and importer.normalize({"name": "fw", "vendor": "fortinet", "host": "10.1.1.1"})[0]["verify_ssl"] == 0)
check("an import file that says so wins either way", importer.normalize({"name": "fw", "vendor": "fortinet", "host": "10.1.1.1", "verify_ssl": "yes"})[0]["verify_ssl"] == 1)
check("a stored device keeps its own flag", tlsverify.verify({"verify_ssl": 0}) is False and tlsverify.verify({"verify_ssl": 1}) is True)
from urllib3.exceptions import InsecureRequestWarning, HTTPWarning
hushed = [f for f in warnings.filters if f[2] is InsecureRequestWarning and f[0] == "ignore"]
every = [f for f in warnings.filters if f[2] is HTTPWarning and f[0] == "ignore"]
check("turning verification off hushes only the unverified-HTTPS warning, not every urllib3 warning", hushed and not every, (len(hushed), len(every)))

print("== shared widgets")
from PySide6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])
from ui.widgets import FilterButton as DictFunnel, FunnelButton
from ui.finder import FilterButton as DataFunnel, Section
a = DictFunnel("Pick"); a.set_sections({"Status": [("FAIL", "FAIL"), ("OK", "OK")]}); a._toggle("Status", "FAIL", True)
b = DataFunnel(lambda: [Section("st", "Status", [("FAIL", "FAIL"), ("OK", "OK")])]); b.set("st", ["FAIL"])
check("both funnel buttons are one FunnelButton underneath and show their count the same way", isinstance(a, FunnelButton) and isinstance(b, FunnelButton) and a.text() == b.text() == " 1"
      and a.toolTip() == "Filter: Status: FAIL" and b.toolTip() == "Filter: FAIL" and a.accessibleName() == "Pick")
a.build(); b.build()
check("their menus end with Clear filter", a.menu.actions()[-1].text() == "Clear filter" and b.menu_.actions()[-1].text() == "Clear filter")
from ui.signin import SignInDialog
from ui import rdpprompt, serviceswindow
dlg = SignInDialog("T", "intro", username="bob")
check("the sign-in dialog starts in the password box when the user name is known, and both derived dialogs are it", dlg.username() == "bob" and dlg.focusWidget() in (dlg.password, None)
      and issubclass(rdpprompt.SignIn, SignInDialog) and issubclass(serviceswindow.SignIn, SignInDialog))
from ui.pingworker import PingWorker
from ui import pingpop, tools2
check("the live ping graph and the Ping window share one ping thread", tools2.PingWorker is PingWorker and pingpop.PingWorker is PingWorker)
w = PingWorker("127.0.0.1", count=2, interval=0, timeout_ms=200); got = []
w.sample.connect(lambda n, ms: got.append(n)); w.start(); w.wait(5000); app.processEvents()     # the samples cross to this thread through the event loop
check("a counted run sends that many samples, numbered from 1, then ends", got == [1, 2] and w.isFinished(), got)

print()
print(f"{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
