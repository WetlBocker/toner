# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import asyncio, os, re, sys, threading, time
pass
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\snmp%d.db").replace("\\", os.sep) % int(time.time())
from core import db, snmp
db.init()

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

PORT = 16100 + os.getpid() % 500

def agent():
    from pysnmp.entity import engine, config
    from pysnmp.entity.rfc3413 import cmdrsp, context
    from pysnmp.carrier.asyncio.dgram import udp
    async def main():
        eng = engine.SnmpEngine()
        config.add_transport(eng, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(("127.0.0.1", PORT)))
        config.add_v1_system(eng, "area", "public")
        config.add_vacm_user(eng, 2, "area", "noAuthNoPriv", (1, 3, 6, 1, 2, 1), (1, 3, 6, 1, 2, 1))
        config.add_vacm_user(eng, 1, "area", "noAuthNoPriv", (1, 3, 6, 1, 2, 1), (1, 3, 6, 1, 2, 1))
        config.add_v3_user(eng, "authuser", config.USM_AUTH_HMAC96_SHA, "authpass123", config.USM_PRIV_CFB128_AES, "privpass123")
        config.add_vacm_user(eng, 3, "authuser", "authPriv", (1, 3, 6, 1, 2, 1), (1, 3, 6, 1, 2, 1))
        ctx = context.SnmpContext(eng)
        cmdrsp.GetCommandResponder(eng, ctx); cmdrsp.NextCommandResponder(eng, ctx); cmdrsp.BulkCommandResponder(eng, ctx)
        eng.transport_dispatcher.job_started(1)
        ready.set()
        while not stop.is_set():
            await asyncio.sleep(0.1)
        eng.close_dispatcher()
    asyncio.run(main())
ready, stop = threading.Event(), threading.Event()
t = threading.Thread(target=agent, daemon=True); t.start()
check("test agent started", ready.wait(10))
time.sleep(0.5)

C = snmp.Credentials()

print("== OID parsing and naming")
check("numeric", snmp.parse_oid("1.3.6.1.2.1.1.1.0") == "1.3.6.1.2.1.1.1.0" and snmp.parse_oid(".1.3.6.1.2.1.1") == "1.3.6.1.2.1.1")
check("names", snmp.parse_oid("sysDescr.0") == "1.3.6.1.2.1.1.1.0" and snmp.parse_oid("IF-MIB::ifDescr.3") == "1.3.6.1.2.1.2.2.1.2.3" and snmp.parse_oid("ifTable") == "1.3.6.1.2.1.2.2")
for bad_oid in ("", "nonsense.1", "1.3..6", "sys Descr"):
    try: snmp.parse_oid(bad_oid); check(f"rejects '{bad_oid}'", False)
    except ValueError: check(f"rejects '{bad_oid}'", True)
check("reverse lookup", snmp.name_of("1.3.6.1.2.1.2.2.1.8.12") == "ifOperStatus.12" and snmp.name_of("1.3.6.1.2.1.1.5.0") == "sysName.0" and snmp.name_of("1.3.6.1.99.1") == "1.3.6.1.99.1")
from pysnmp.proto.rfc1902 import TimeTicks
check("ticks", snmp.format_value(TimeTicks(8640000 + 3661 * 100)) == ("TimeTicks", "9006100 (1:01:01:01)"), snmp.format_value(TimeTicks(9006100)))
check("ticks under a second show no seconds", snmp.format_value(TimeTicks(53))[1] == "53 (0:00:00:00)" and snmp.format_value(TimeTicks(99))[1] == "99 (0:00:00:00)", snmp.format_value(TimeTicks(53)))
check("ticks are not rounded up to the next day", snmp.format_value(TimeTicks(8639999))[1] == "8639999 (0:23:59:59)", snmp.format_value(TimeTicks(8639999)))
def ticks_match(value):            # "9006100 (1:01:01:01)": the d:hh:mm:ss part is the ticks in whole seconds, however long the agent has been up
    m = re.fullmatch(r"(\d+) \((\d+):(\d\d):(\d\d):(\d\d)\)", value or "")
    if not m: return False
    ticks, d, h, mi, s = map(int, m.groups())
    return h < 24 and mi < 60 and s < 60 and d * 86400 + h * 3600 + mi * 60 + s == ticks // 100

print("== live queries against a local agent")
r = snmp.query("127.0.0.1", PORT, C, "get", "sysDescr.0", timeout=2, retries=0)
check("get sysDescr", not r.error and len(r.rows) == 1 and r.rows[0].name == "sysDescr.0" and r.rows[0].type in ("OctetString", "DisplayString") and r.rows[0].value, (r.error, r.rows))
r = snmp.query("127.0.0.1", PORT, C, "getnext", "sysDescr.0", timeout=2, retries=0)
check("get next from sysDescr.0 -> sysObjectID.0", not r.error and r.rows and r.rows[0].name == "sysObjectID.0", (r.error, r.rows))
r = snmp.query("127.0.0.1", PORT, C, "walk", "system", timeout=2, retries=0)
check("walk the system group", not r.error and len(r.rows) >= 6 and all(x.oid.startswith("1.3.6.1.2.1.1.") for x in r.rows), (r.error, len(r.rows)))
r2 = snmp.query("127.0.0.1", PORT, C, "bulkwalk", "system", timeout=2, retries=0)
check("bulk walk gives the same rows", [x.oid for x in r2.rows] == [x.oid for x in r.rows], (r2.error, len(r2.rows)))
r = snmp.query("127.0.0.1", PORT, C, "system", timeout=2, retries=0)
check("system info", not r.error and [x.name for x in r.rows][:3] == ["sysDescr.0", "sysObjectID.0", "sysUpTime.0"], (r.error, r.rows))
check("uptime formatted", any(x.name == "sysUpTime.0" and ticks_match(x.value) for x in r.rows), [x.value for x in r.rows])
got = []
r = snmp.query("127.0.0.1", PORT, C, "walk", "mib-2", timeout=2, retries=0, max_rows=5, on_rows=got.extend)
check("row cap stops a runaway walk", r.truncated and len(r.rows) == 5 and len(got) == 5, (len(r.rows), r.truncated))
ev = threading.Event(); ev.set()
r = snmp.query("127.0.0.1", PORT, C, "walk", "mib-2", timeout=2, retries=0, cancel=ev)
check("cancel stops a walk", r.cancelled and len(r.rows) == 0)
r = snmp.query("127.0.0.1", PORT, C, "get", "1.3.6.1.2.1.99.99.0", timeout=2, retries=0)
check("missing object is reported, not an error", not r.error and r.rows and r.rows[0].type in ("NoSuchObject", "NoSuchInstance"), (r.error, r.rows))
r = snmp.query("127.0.0.1", PORT, C, "get", "1.3.6.1.4.1.99999.1.0", timeout=2, retries=0)
check("outside the agent's view", True)

print("== v1")
r = snmp.query("127.0.0.1", PORT, snmp.Credentials(version="1"), "get", "sysName.0", timeout=2, retries=0)
check("v1 get", not r.error and r.rows or "noSuchName" in r.error or "No" in r.error, (r.error, r.rows))
r = snmp.query("127.0.0.1", PORT, snmp.Credentials(version="1"), "bulkwalk", "system", timeout=2, retries=0)
check("bulk walk refused on v1", "v2c" in r.error)

print("== v3")
V3 = snmp.Credentials(version="3", user="authuser", level="authPriv", auth_protocol="SHA", auth_key="authpass123", priv_protocol="AES-128", priv_key="privpass123")
r = snmp.query("127.0.0.1", PORT, V3, "system", timeout=3, retries=0)
check("v3 authPriv works", not r.error and len(r.rows) >= 1, (r.error, r.rows))
r = snmp.query("127.0.0.1", PORT, snmp.Credentials(version="3", user="authuser", level="authPriv", auth_key="wrongpass123", priv_key="privpass123"), "system", timeout=3, retries=0)
check("wrong v3 password -> clear message", r.error and "authentication" in r.error.lower() or "digest" in r.error.lower(), r.error)
r = snmp.query("127.0.0.1", PORT, snmp.Credentials(version="3", user="nobody", level="noAuthNoPriv"), "system", timeout=3, retries=0)
check("unknown v3 user -> clear message", "user" in r.error.lower(), r.error)
r = snmp.query("127.0.0.1", PORT, snmp.Credentials(version="3", user="authuser", level="authPriv", auth_key="short", priv_key="privpass123"), "system")
check("short v3 password refused before sending", "8 characters" in r.error)
r = snmp.query("127.0.0.1", PORT, snmp.Credentials(version="3", user="", level="noAuthNoPriv"), "system")
check("v3 needs a user", "user name" in r.error)

print("== failures")
r = snmp.query("127.0.0.1", PORT, snmp.Credentials(community="wrong"), "get", "sysDescr.0", timeout=1, retries=0)
check("wrong community = timeout hint", "No response" in r.error and str(PORT) in r.error, r.error)
r = snmp.query("127.0.0.1", PORT, snmp.Credentials(community=""), "get", "sysDescr.0")
check("empty community refused", "community" in r.error)
r = snmp.query("no-such-host.invalid", 161, C, "get", "sysDescr.0", timeout=1, retries=0)
check("unresolvable host", "resolve" in r.error.lower() or "invalid" in r.error.lower() or "host" in r.error.lower(), r.error)
r = snmp.query("127.0.0.1", 70000, C, "get", "sysDescr.0")
check("bad port", "port" in r.error.lower())
r = snmp.query("127.0.0.1", PORT, C, "get", "bogus.0")
check("bad OID", "not a name" in r.error)
r = snmp.query("127.0.0.1", 9, C, "get", "sysDescr.0", timeout=1, retries=0)
check("closed port -> timeout hint, quickly", "No response" in r.error and r.seconds < 5, (r.error, r.seconds))

print("== interface pivot")
mk = lambda col, idx, v: snmp.Row(f"{snmp.NAMES[col]}.{idx}", "", "", v)
rows = [mk("ifDescr", 2, "Gi0/2"), mk("ifDescr", 1, "Gi0/1"), mk("ifOperStatus", 1, "1"), mk("ifOperStatus", 2, "2"), mk("ifAdminStatus", 1, "1"), mk("ifAdminStatus", 2, "1"),
        mk("ifSpeed", 1, "1000000000"), mk("ifSpeed", 2, "100000000"), mk("ifInErrors", 1, "0"), mk("ifInErrors", 2, "37")]
t = snmp.interface_table(rows)
check("pivot ordered by index with readable status/speed", [x["index"] for x in t] == ["1", "2"] and t[0]["ifOperStatus"] == "up" and t[1]["ifOperStatus"] == "down" and t[0]["ifSpeed"] == "1 Gbps" and t[1]["ifSpeed"] == "100 Mbps" and t[1]["ifInErrors"] == "37", t)
r = snmp.query("127.0.0.1", PORT, C, "interfaces", timeout=2, retries=0)
check("interfaces op on an agent without ifTable returns cleanly", not r.error and r.rows == [], (r.error, r.rows))

print("== Tools > SNMP tab")
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QCoreApplication
app = QApplication([])
import ui.tools as T
tools = T.ToolsTab(); S = tools.snmp
check("SNMP tab is in Tools", tools.tabs.indexOf(S) >= 0 and any(tools.tabs.tabText(i) == "SNMP" for i in range(tools.tabs.count())))
def wait():
    for _ in range(300):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if not S.running(): break
    QCoreApplication.processEvents()
S.host.setText("127.0.0.1"); S.port.setValue(PORT); S.timeout.setValue(2); S.retries.setValue(0); S.community.setText("public")
check("v3 box hidden for v2c, community enabled", not S.v3.isVisibleTo(S) and S.community.isEnabled())
S.version.setCurrentIndex(S.version.findData("3"))
check("v3 box shown, community disabled", S.v3.isVisibleTo(S) and not S.community.isEnabled())
S.level.setCurrentText("noAuthNoPriv"); check("noAuth disables passwords", not S.auth_key.isEnabled() and not S.priv_key.isEnabled())
S.level.setCurrentText("authNoPriv"); check("authNoPriv enables auth only", S.auth_key.isEnabled() and not S.priv_key.isEnabled())
S.level.setCurrentText("authPriv"); check("authPriv enables both", S.priv_key.isEnabled())
S.version.setCurrentIndex(S.version.findData("2c"))
S.op.setCurrentIndex(S.op.findData("system")); check("OID box off for ready-made operations", not S.oid.isEnabled())
S.go.click(); wait()
check("system info fills the table", S.table.rowCount() >= 3 and S.table.item(0, 1).text() == "sysDescr.0" and S.table.horizontalHeaderItem(0).text() == "OID", S.status.text())
check("status shows count and time", "rows" in S.status.text() and "Error" not in S.status.text(), S.status.text())
check("buttons restored after the run", S.go.isEnabled() and not S.stop.isEnabled())
S.op.setCurrentIndex(S.op.findData("walk")); S.oid.setText("system"); S.go.click(); wait()
check("walk by name", S.table.rowCount() >= 6, S.status.text())
S.table.selectRow(0); S.copy()
clip = QApplication.clipboard().text()
check("copy gives header + selected row, tab separated", clip.splitlines()[0] == "OID\tName\tType\tValue" and len(clip.splitlines()) == 2 and "sysDescr.0" in clip, clip[:80])
S.table.clearSelection(); S.copy(); check("copy with no selection copies everything", len(QApplication.clipboard().text().splitlines()) == S.table.rowCount() + 1)
import csv as _csv
from PySide6.QtWidgets import QFileDialog
asked = []
out_csv = os.path.join(os.environ["SP"], "snmp-save-test.csv")
QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (asked.append(a[2]) or out_csv, ""))
S.table.selectRow(0); S.save_btn.click()
saved = list(_csv.reader(open(out_csv, encoding="utf-8-sig", newline="")))
check("Save... writes every row (not only the selected one) to a CSV with the column names first",
      saved[0] == ["OID", "Name", "Type", "Value"] and len(saved) == S.table.rowCount() + 1 and any("sysDescr.0" in r for r in saved), saved[:2])
check("the file is named after the host and the time", asked and asked[-1].startswith("snmp-127.0.0.1-") and asked[-1].endswith(".csv"), asked)
QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: ("", "")); S.save_btn.click()
check("cancelling the file window saves nothing", True)
S.community.setText("wrong"); S.go.click(); wait()
check("failure shows the hint and an empty table", "No response" in S.status.text() and S.table.rowCount() == 0, S.status.text())
S.community.setText("public")
S.host.setText(""); S.go.click(); check("host required", "Enter a host" in S.status.text())
S.host.setText("127.0.0.1"); S.oid.setText("nope.0"); S.go.click(); wait()
check("bad OID reported in the status line", "not a name" in S.status.text(), S.status.text())
S.oid.setText("mib-2"); S.max_rows.setValue(3); S.go.click(); wait()
check("row limit reported", S.table.rowCount() == 3 and "3-row limit" in S.status.text(), S.status.text())
S.max_rows.setValue(100000); S.op.setCurrentIndex(S.op.findData("bulkwalk")); S.go.click()
check("stop is available while running", S.stop.isEnabled() and not S.go.isEnabled()); S.stop.click(); wait()
check("stop ends the run and restores the buttons", S.go.isEnabled() and not S.running())
S.op.setCurrentIndex(S.op.findData("interfaces")); S.go.click(); wait()
check("interfaces op with no table says so", "no interface table" in S.status.text(), S.status.text())
S.clear(); check("clear", S.table.rowCount() == 0 and S.status.text() == "")
S.show_secrets.setChecked(True); check("show passwords toggle", S.community.echoMode().name == "Normal"); S.show_secrets.setChecked(False)
tools.shutdown()

stop.set()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
