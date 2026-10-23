# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import os, socket, struct, sys, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + (r"\fu%d.db").replace("\\", os.sep) % int(time.time()); os.environ["APPDATA"] = SP
from core import audit, db
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import QCoreApplication
app = QApplication([])
import app as A
A.apply_look(app)
import ui.tools3 as T3
import ui.tools as T

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
def pump(cond, n=300):
    for _ in range(n):
        QCoreApplication.processEvents(); time.sleep(0.02)
        if cond(): break
    QCoreApplication.processEvents()
asked = []
QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2]), QMessageBox.StandardButton.Yes)[1])

share = os.path.join(SP, "ui_share%d" % int(time.time())); os.makedirs(share)
open(os.path.join(share, "fw.bin"), "wb").write(b"firmware" * 500)

print("== TFTP page")
t = T3.FileServerTab("tftp"); t.resize(1100, 700); t.show()
check("nothing runs until asked, uploads are off, replacing is greyed out", t.server is None and not t.write.isChecked() and not t.replace.isEnabled() and t.port.value() == 69)
t.folder.setText("C:\\" if os.name == "nt" else "/"); t.start()
check("a whole drive is refused", t.server is None and ("drive" in t.status.text() or "whole file system" in t.status.text()), t.status.text())
t.folder.setText(os.path.join(SP, "missing")); t.start(); check("a missing folder is refused", t.server is None)
t.folder.setText(share); t.allowed.setText("10.0.0.0/24, banana"); t.start(); check("a bad client list is explained", t.server is None and "banana" in t.status.text())
t.allowed.setText(""); t.port.setRange(0, 65535); t.port.setValue(0)
t.start()
check("starts read-only", t.server is not None and t.server.running and not t.server.allow_write and "read-only" in t.status.text() and t.go.text() == "Stop TFTP server", t.status.text())
check("the settings are locked while it runs", not t.folder.isEnabled() and not t.write.isEnabled() and not t.port.isEnabled())
port = t.server.port
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(struct.pack("!H", 1) + b"fw.bin\0octet\0", ("127.0.0.1", port)); got, block = b"", 1
while True:
    pkt, addr = s.recvfrom(1000)
    if struct.unpack("!H", pkt[:2])[0] == 3:
        got += pkt[4:]; s.sendto(struct.pack("!HH", 4, block), addr); block += 1
        if len(pkt) < 516: break
s.close()
pump(lambda: t.table.rowCount() >= 1)
check("the transfer appears in the list", got == b"firmware" * 500 and t.table.rowCount() == 1 and t.table.item(0, 3).text() == "fw.bin" and t.table.item(0, 5).text() == "ok" and t.table.item(0, 4).text() == "3.9 KB", [t.table.item(0, j).text() for j in range(7)] if t.table.rowCount() else "")
check("choices are remembered, a plain read is not in the audit log", db.get_setting("fileserver")["tftp"]["folder"] == share and any(a["action"] == "tftp server started" for a in audit.recent()) and not any(a["action"] == "tftp read ok" for a in audit.recent()))
t.toggle(); check("stop", t.server is None and t.folder.isEnabled() and t.go.text() == "Start TFTP server" and any(a["action"] == "tftp server stopped" for a in audit.recent()))
t.write.setChecked(True); check("replacing can be chosen once uploads are on", t.replace.isEnabled()); t.replace.setChecked(True); t.write.setChecked(False)
check("turning uploads off turns replacing off", not t.replace.isChecked() and not t.replace.isEnabled())
t.write.setChecked(True); asked.clear(); t.start()
check("uploads from anyone ask first, and say why", t.server is not None and asked and "no passwords" in asked[0])
t.stop(); asked.clear(); t.allowed.setText("127.0.0.1"); t.start(); check("naming the devices removes the question", t.server is not None and not asked); t.stop()
t.timer.stop(); t.minutes.setValue(1); t.start()
check("an automatic stop is armed", t.timer.isActive() and 55000 < t.timer.remainingTime() <= 61000, t.timer.remainingTime())   # (Linux timers round a little)
t.stop()
t.minutes.setValue(0); t.start(); check("'never' arms no timer", not t.timer.isActive()); t.stop()
t.clear_rows(); check("clear empties the list", t.table.rowCount() == 0)
t2 = T3.FileServerTab("tftp"); check("a new page remembers the last folder and settings", t2.folder.text() == share and t2.write.isChecked() and t2.allowed.text() == "127.0.0.1")
t.start(); t.shutdown(); check("closing the program stops the server", t.server is None)
t.port.setValue(0)
a = T3.FileServerTab("tftp"); a.folder.setText(share); a.port.setRange(0, 65535); a.port.setValue(0); a.write.setChecked(False); a.allowed.setText(""); a.start()
b = T3.FileServerTab("tftp"); b.folder.setText(share); b.port.setValue(a.server.port); b.start()
check("a port that is already used is reported", b.server is None and "Could not start" in b.status.text(), b.status.text()); a.stop()

print("== SFTP page")
sf = T3.FileServerTab("sftp"); sf.resize(1100, 700); sf.show()
check("has a user name and a password box", sf.user.text() == "toner" and sf.port.value() == 2222 and sf.password.echoMode() == sf.password.EchoMode.Password)
sf.folder.setText(share); sf.port.setRange(0, 65535); sf.port.setValue(0); sf.password.setText("short"); sf.start()
check("a short password is refused", sf.server is None and "8 characters" in sf.status.text(), sf.status.text())
sf.password.setText(""); sf.start()
check("with no password one is generated and shown", sf.server is not None and len(sf.password.text()) == 16 and sf.show_pw.isChecked())
pw = sf.password.text()
check("the password goes to Credential Manager, never the database", STORE.get(("netcheck", "service:sftp-server")) == pw and pw not in str(db.get_setting("fileserver")))
check("the fingerprint is shown", sf.fingerprint.text().startswith("Server fingerprint: SHA256:"))
import paramiko, logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("127.0.0.1", sf.server.port, "toner", pw, look_for_keys=False, allow_agent=False, timeout=10, banner_timeout=15, auth_timeout=15)
cl = c.open_sftp(); data = cl.open("fw.bin", "rb").read(); cl.close(); c.close()
pump(lambda: any(sf.table.item(i, 2).text() == "read" for i in range(sf.table.rowCount())))
check("a client can download, and login plus transfer are listed", data == b"firmware" * 500 and {sf.table.item(i, 2).text() for i in range(sf.table.rowCount())} >= {"login", "read"})
check("logins reach the audit log", any(a["action"] == "sftp login ok" for a in audit.recent()))
sf.stop(); sf2 = T3.FileServerTab("sftp"); check("the next time the saved password is filled in", sf2.password.text() == pw and sf2.fingerprint.text().startswith("Server fingerprint"))

print("== FTP page")
fp = T3.FileServerTab("ftp"); fp.resize(1100, 700); fp.show()
check("has a user name, a password box and the passive ports", fp.user.text() == "toner" and fp.port.value() == 21 and fp.password.echoMode() == fp.password.EchoMode.Password
      and fp.pasv_lo.value() == 50000 and fp.pasv_hi.value() == 50100 and fp.pasv_lo.isVisibleTo(fp) and not fp.fingerprint.isVisibleTo(fp))
check("the intro says what FTP is for and warns about clear text", "every cisco platform" in fp._intro().lower() and "clear text" in fp._intro())
fp.folder.setText(share); fp.port.setRange(0, 65535); fp.port.setValue(0); fp.pasv_lo.setValue(50300); fp.pasv_hi.setValue(50310); fp.password.setText("short"); fp.start()
check("a short password is refused", fp.server is None and "8 characters" in fp.status.text(), fp.status.text())
fp.password.setText(""); fp.start()
check("with no password one is generated and shown", fp.server is not None and len(fp.password.text()) == 16 and fp.show_pw.isChecked())
pw = fp.password.text()
check("the password goes to the vault, never the database, under its own name", STORE.get(("netcheck", "service:ftp-server")) == pw and pw not in str(db.get_setting("fileserver")))
check("the passive ports and user name are remembered", db.get_setting("fileserver")["ftp"]["pasv_lo"] == 50300 and db.get_setting("fileserver")["ftp"]["user"] == "toner")
check("the status line shows the copy command with the password left out", "ftp://toner:<password>@" in fp.status.text() and pw not in fp.status.text() and "read-only" in fp.status.text(), fp.status.text())
check("the settings are locked while it runs", not fp.pasv_lo.isEnabled() and not fp.user.isEnabled())
import ftplib, io
fc = ftplib.FTP(); fc.connect("127.0.0.1", fp.server.port, timeout=10); fc.login("toner", pw)
buf = io.BytesIO(); fc.retrbinary("RETR fw.bin", buf.write); fc.quit()
pump(lambda: any(fp.table.item(i, 2).text() == "read" for i in range(fp.table.rowCount())))
check("a client can download, and login plus transfer are listed", buf.getvalue() == b"firmware" * 500 and {fp.table.item(i, 2).text() for i in range(fp.table.rowCount())} >= {"login", "read"})
check("starting and logins reach the audit log", any(a["action"] == "ftp server started" for a in audit.recent()) and any(a["action"] == "ftp login ok" for a in audit.recent()))
fp.stop(); fp2 = T3.FileServerTab("ftp"); check("the next time the saved password and ports are filled in", fp2.password.text() == pw and fp2.pasv_hi.value() == 50310)
check("the SFTP page's intro now mentions SCP", "SCP" in sf._intro())

print("== iperf3 page")
ip = T3.IperfTab(); ip.resize(1100, 700); ip.show()
ip.exe = None; ip._where()
check("without iperf3 it says what to do, and Start explains instead of failing", "not found" in ip.where.text()
      and ("iperf.fr" if os.name == "nt" else "sudo apt install iperf3") in ip.where.text(), ip.where.text())
ip.start(); check("...nothing starts", not ip.runner.running() and "not found" in ip.out.toPlainText())
if os.name == "nt":
    fake = os.path.join(SP, "iperf3-fake.bat")
    open(fake, "w").write("@echo off\r\necho ARGS %*\r\necho [  5]   0.00-1.00   sec  11.2 MBytes  94.1 Mbits/sec    0   63.4 KBytes\r\n"
                          "echo [  5]   0.00-10.00  sec   112 MBytes  94.0 Mbits/sec   17             sender\r\n"
                          "echo [  5]   0.00-10.04  sec   112 MBytes  93.6 Mbits/sec                  receiver\r\n")
else:                                             # Linux, macOS: a shell script stands in for iperf3
    fake = os.path.join(SP, "iperf3-fake.sh")
    open(fake, "w").write('#!/bin/sh\necho ARGS "$@"\necho "[  5]   0.00-1.00   sec  11.2 MBytes  94.1 Mbits/sec    0   63.4 KBytes"\n'
                          'echo "[  5]   0.00-10.00  sec   112 MBytes  94.0 Mbits/sec   17             sender"\n'
                          'echo "[  5]   0.00-10.04  sec   112 MBytes  93.6 Mbits/sec                  receiver"\n')
    os.chmod(fake, 0o755)
ip.exe = fake; ip._where(); check("the program being used is shown", fake in ip.where.text())
ip.target.setText("10.1.2.3 -x"); ip.start(); check("a bad address is refused before anything runs", not ip.runner.running() and "Error" in ip.out.toPlainText())
ip.target.setText("10.1.2.3"); ip.seconds.setValue(5); ip.streams.setValue(2); ip.reverse.setChecked(True); ip.start()
check("busy while running", not ip.go.isEnabled() and ip.stop.isEnabled() and not ip.client_box.isEnabled())
pump(lambda: ip.go.isEnabled())
txt = ip.out.toPlainText()
check("the right command line was built", "-c 10.1.2.3" in txt and "-t 5" in txt and "-P 2" in txt and "-R" in txt and "-f m" in txt, txt[-300:])
check("the result is summarised", ip.result.text() == "Sent 94.0 Mbit/s (17 retransmits)   Received 93.6 Mbit/s", ip.result.text())
check("and the button is back", ip.go.isEnabled() and not ip.stop.isEnabled())
ip.mode.setCurrentIndex(1); check("server mode shows the server settings", ip.server_box.isVisibleTo(ip) and not ip.client_box.isVisibleTo(ip) and ip.go.text() == "Start server")
ip.server_port.setValue(5999); ip.one_off.setChecked(True); ip.start(); pump(lambda: ip.go.isEnabled())
check("server arguments", "-s -p 5999" in ip.out.toPlainText() and " -1" in ip.out.toPlainText())
check("starting and stopping a server is audited", any(a["action"] == "iperf3 server started" for a in audit.recent()) and any(a["action"] == "iperf3 server stopped" for a in audit.recent()))
ip.shutdown()

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
