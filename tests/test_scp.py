# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import logging, os, shlex, shutil, socket, subprocess, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\scp%d.db" % int(time.time()); os.environ["APPDATA"] = SP
from core import db, scp, xcopy
db.init()
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p)
keyring.get_password = lambda s, u: STORE.get((s, u))
import paramiko
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)


from _scp_server import ScpServer, recv_exact, read_line

base = os.path.join(SP, "scp%d" % int(time.time())); share = os.path.join(base, "dev"); mine = os.path.join(base, "mine")
os.makedirs(share); os.makedirs(mine)
def put(rel, data, root=share):
    p = os.path.join(root, *rel.split("/")); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "wb").write(data); return p
def read(rel, root=share): return open(os.path.join(root, *rel.split("/")), "rb").read()

srv = ScpServer(share)
def client(server=None, **kw):
    s = server or srv
    c, extra = scp.connect("127.0.0.1", s.port, "u", "pw", hostkey_mode="Trust on first use", timeout=10)
    events = []
    return c, scp.Scp(c, progress=lambda *a: events.append(a), timeout=10, **kw), events

# ================================================================ helpers
print("== helpers")
check("plain paths are sent as they are (network devices expect flash:/x)", scp.quote("flash:/image.bin") == "flash:/image.bin" and scp.quote("/etc/hosts") == "/etc/hosts" and scp.quote("dir/sub-1_a.cfg") == "dir/sub-1_a.cfg")
check("paths with spaces or shell characters are quoted", scp.quote("my file.txt") == "'my file.txt'" and scp.quote("a;rm -rf /") == "'a;rm -rf /'" and scp.quote("it's") == "'it'\\''s'" and scp.quote("$(x)") == "'$(x)'")
for bad_name in ("../x", "a/b", "a\\b", "..", ".", "", "x\ny", "C:evil", "f.txt:stream"):
    try: scp.safe_name(bad_name); check(f"unsafe name refused: {bad_name!r}", False)
    except scp.ScpError: check(f"unsafe name refused: {bad_name!r}", True)
check("ordinary names pass", scp.safe_name("running-config.cfg") == "running-config.cfg" and scp.safe_name("my file (1).txt"))

# ================================================================ upload
print("== upload")
src = put("../mine/hello.txt", b"hello world\n", share)
c, s, ev = client(); n = s.upload(os.path.join(mine, "hello.txt"), "hello.txt"); c.close()
check("a file arrives intact", read("hello.txt") == b"hello world\n" and n == (1, 12), n)
check("progress is reported: start, then bytes, ending complete", ev[0][:2] == ("file", "hello.txt") and ev[-1] == ("bytes", "hello.txt", 12, 12), ev)
big = os.urandom(2_500_000); put("../mine/big.bin", big, share)
c, s, ev = client(); n = s.upload(os.path.join(mine, "big.bin"), "big.bin"); c.close()
check("a 2.5 MB file is intact", read("big.bin") == big and n == (1, len(big)))
done = [e[2] for e in ev if e[0] == "bytes"]; check("progress only ever goes forward", done == sorted(done) and done[-1] == len(big))
os.makedirs(os.path.join(share, "into")); c, s, _ = client(); s.upload(os.path.join(mine, "hello.txt"), "into"); c.close()
check("into an existing folder on the device", read("into/hello.txt") == b"hello world\n")
c, s, _ = client(); s.upload(os.path.join(mine, "hello.txt"), "my copy.txt"); c.close()
check("a remote name with a space works", read("my copy.txt") == b"hello world\n" and any("'my copy.txt'" in x for x in srv.commands), srv.commands[-1])
os.utime(os.path.join(mine, "hello.txt"), (1_700_000_000, 1_700_000_000))
c, s, _ = client(); s.upload(os.path.join(mine, "hello.txt"), "kept.txt", preserve=True); c.close()
check("keeping times sets the file's date on the device", int(os.path.getmtime(os.path.join(share, "kept.txt"))) == 1_700_000_000)
c, s, _ = client(); s.upload(os.path.join(mine, "hello.txt"), "notkept.txt"); c.close()
check("without it the date is simply 'now'", abs(os.path.getmtime(os.path.join(share, "notkept.txt")) - time.time()) < 120)
tree = os.path.join(mine, "configs"); put("a.cfg", b"A", tree); put("sub/b.cfg", b"BB", tree); put("sub/deep/c.cfg", b"CCC", tree); os.makedirs(os.path.join(tree, "empty"))
os.makedirs(os.path.join(share, "dest")); c, s, ev = client(); n = s.upload(tree, "dest", recursive=True); c.close()
check("a folder is sent with everything in it", read("dest/configs/a.cfg") == b"A" and read("dest/configs/sub/b.cfg") == b"BB" and read("dest/configs/sub/deep/c.cfg") == b"CCC" and os.path.isdir(os.path.join(share, "dest", "configs", "empty")) and n == (3, 6), n)
check("folders are announced too", any(e[0] == "dir" for e in ev))
c, s, _ = client()
for args, kw, msg in (((tree, "dest"), {}, "sub-folders"), ((os.path.join(mine, "nope"), "x"), {}, "does not exist")):
    try: s.upload(*args, **kw); check(f"refused: {msg}", False)
    except scp.ScpError as e: check(f"refused: {msg}", msg in str(e), str(e))
c.close()

# ================================================================ download
print("== download")
put("run.cfg", b"hostname sw1\n"); put("logs/one.log", b"1"); put("logs/two/deep.log", b"22"); os.makedirs(os.path.join(share, "logs", "empty"))
dl = os.path.join(base, "dl"); os.makedirs(dl)
c, s, ev = client(); n = s.download("run.cfg", dl); c.close()
check("a file is saved into the chosen folder", open(os.path.join(dl, "run.cfg"), "rb").read() == b"hostname sw1\n" and n == (1, 13))
c, s, _ = client(); s.download("run.cfg", os.path.join(dl, "renamed.cfg")); c.close()
check("or under a name you choose", open(os.path.join(dl, "renamed.cfg"), "rb").read() == b"hostname sw1\n")
put("big.bin", big)
c, s, ev = client(); n = s.download("big.bin", dl); c.close()
check("a large file is intact, with progress", open(os.path.join(dl, "big.bin"), "rb").read() == big and ev[-1][2] == len(big))
check("no half-written file is left behind", not [f for f in os.listdir(dl) if f.endswith(".toner-part")])
c, s, _ = client(); s.download("run.cfg", os.path.join(dl, "renamed.cfg")); c.close()
open(os.path.join(dl, "renamed.cfg"), "wb").write(b"MINE")
c, s, _ = client(); s.download("run.cfg", os.path.join(dl, "renamed.cfg")); c.close()
check("...it is kept, and reported as skipped", open(os.path.join(dl, "renamed.cfg"), "rb").read() == b"MINE" and s.skipped == [os.path.join(dl, "renamed.cfg")] and s.files == 0, s.skipped)
c, s, _ = client(); s.download("run.cfg", os.path.join(dl, "renamed.cfg"), overwrite=True); c.close()
check("...and replaced when you do", open(os.path.join(dl, "renamed.cfg"), "rb").read() == b"hostname sw1\n")
os.utime(os.path.join(share, "run.cfg"), (1_600_000_000, 1_600_000_000))
c, s, _ = client(); s.download("run.cfg", os.path.join(dl, "dated.cfg"), preserve=True); c.close()
check("keeping times copies the device's file date", int(os.path.getmtime(os.path.join(dl, "dated.cfg"))) == 1_600_000_000)
c, s, _ = client(); n = s.download("logs", os.path.join(dl, "logs-copy"), recursive=True); c.close()
check("a folder comes down with everything in it", open(os.path.join(dl, "logs-copy", "logs", "one.log"), "rb").read() == b"1" and open(os.path.join(dl, "logs-copy", "logs", "two", "deep.log"), "rb").read() == b"22" and os.path.isdir(os.path.join(dl, "logs-copy", "logs", "empty")) and n == (2, 3), n)
c, s, _ = client()
try: s.download("logs", os.path.join(dl, "x")); check("a folder without 'sub-folders' is explained", False)
except scp.ScpError as e: check("a folder without 'sub-folders' is explained", "not a regular file" in str(e) or "Include sub-folders" in str(e), str(e))
try: s.download("missing.cfg", dl); check("a missing remote file gives the device's own message", False)
except scp.ScpError as e: check("a missing remote file gives the device's own message", "No such file or directory" in str(e), str(e))
c.close()

print("== a device that sends hostile names")
for evil in ("../evil.txt", "a/b.txt", "..", "C:\\evil.txt"):
    es = ScpServer(share, evil_name=evil)
    c, s, _ = client(es)
    try: s.download("run.cfg", dl); check(f"refused: {evil!r}", False)
    except scp.ScpError as e: check(f"refused: {evil!r}", "unsafe file name" in str(e), str(e))
    c.close(); es.stop()
check("nothing was written outside the chosen folder", not os.path.exists(os.path.join(base, "evil.txt")) and not os.path.exists(os.path.join(dl, "b.txt")) and not os.path.exists(os.path.join(os.path.dirname(dl), "evil.txt")))
check("and no partial files remain", not [f for f in os.listdir(dl) if f.endswith(".toner-part")])

print("== stopping, and devices without scp")
cancel = threading.Event(); c, s, ev = client(cancel=cancel)
s.progress = lambda kind, name, done, total: (cancel.set() if kind == "bytes" and done > 100000 else None)
try: s.download("big.bin", os.path.join(dl, "cancelled.bin")); check("Stop cancels a download", False)
except scp.Cancelled: check("Stop cancels a download", not os.path.exists(os.path.join(dl, "cancelled.bin")) and not [f for f in os.listdir(dl) if f.endswith(".toner-part")])
c.close()
cancel = threading.Event(); c, s, ev = client(cancel=cancel); cancel.set()
try: s.upload(os.path.join(mine, "hello.txt"), "never.txt"); check("Stop cancels an upload", False)
except scp.Cancelled: check("Stop cancels an upload", True)
c.close()
denied = ScpServer(share, deny_exec=True); c, s, _ = client(denied)
try: s.upload(os.path.join(mine, "hello.txt"), "x"); check("a device that refuses scp is explained", False)
except (scp.ScpError, paramiko.SSHException) as e: check("a device that refuses scp is explained", True, str(e))
c.close(); denied.stop()
try: scp.connect("127.0.0.1", srv.port, "u", "wrong", timeout=8); check("a wrong password is refused", False)
except paramiko.AuthenticationException: check("a wrong password is refused", True)

# ================================================================ against the real scp.exe (legacy protocol)
print("== the server side agrees with the real Windows scp.exe (so the client is tested against the real protocol)")
exe = shutil.which("scp")
if exe:
    key = paramiko.RSAKey.generate(2048); kf = os.path.join(base, "id_rsa"); key.write_private_key_file(kf)
    try:
        subprocess.run(["icacls", kf, "/inheritance:r", "/grant:r", f"{os.environ['USERNAME']}:F"], capture_output=True)
    except OSError: pass
    rs = ScpServer(share, pubkey=key)
    def real(*args):
        r = subprocess.run([exe, "-O", "-q", "-P", str(rs.port), "-i", kf, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", *args],
                           capture_output=True, text=True, timeout=60)
        return r.returncode, (r.stdout + r.stderr).strip()
    rc, out = real(os.path.join(mine, "hello.txt"), "u@127.0.0.1:real-up.txt")
    if rc == 0 and "denied" not in out.lower():
        check("real scp.exe uploads to the test server", read("real-up.txt") == b"hello world\n", out)
        rc, out = real("u@127.0.0.1:run.cfg", os.path.join(dl, "real-down.cfg")); check("real scp.exe downloads from it", rc == 0 and open(os.path.join(dl, "real-down.cfg"), "rb").read() == b"hostname sw1\n", out)
        rc, out = real("-r", "u@127.0.0.1:logs", os.path.join(dl, "real-tree")) if os.makedirs(os.path.join(dl, "real-tree"), exist_ok=True) is None else (1, "")
        check("real scp.exe downloads a folder", rc == 0 and os.path.exists(os.path.join(dl, "real-tree", "logs", "two", "deep.log")), out)
        rc, out = real("-r", tree, "u@127.0.0.1:dest"); check("real scp.exe uploads a folder", rc == 0 and read("dest/configs/sub/deep/c.cfg") == b"CCC", out)
        c2, extra = scp.connect("127.0.0.1", rs.port, "u", "pw", timeout=10); c2.close()
        check("and this app talks to the same server the real client does", True)
    else:
        print("  note  real scp.exe could not authenticate here (", out[:120], "); interoperability check skipped")
    rs.stop()
else:
    print("  note  scp.exe is not installed; interoperability check skipped")

# ================================================================ xcopy
print("== xcopy")
check("xcopy.exe is found", xcopy.find_xcopy() and xcopy.find_xcopy().lower().endswith("xcopy.exe"))
a = xcopy.build_args(os.path.join(mine, "configs"), os.path.join(base, "out"))
check("the default arguments: folder destination, no prompts, sub-folders, keep going", a[2:] == ["/I", "/Y", "/E", "/C"], a)
a = xcopy.build_args(os.path.join(mine, "configs"), os.path.join(base, "out"), subfolders=False, existing=xcopy.NEWER, hidden=True, keep_readonly=True, keep_going=False, verify=True, preview=True)
check("every option maps to its switch", a[2:] == ["/I", "/Y", "/D", "/H", "/K", "/V", "/L", "/F"], a)
check("a trailing backslash is removed (it would escape the closing quote)", xcopy.clean("C:\\TFTP\\") == "C:\\TFTP" and xcopy.clean('"D:\\x y\\"') == "D:\\x y" and xcopy.clean("C:\\") == "C:\\" and xcopy.clean("") == "")
for src_, dst_, why in (("", base, "Choose the folder"), (mine, "", "where to copy"), (os.path.join(base, "nope"), base, "does not exist"), (mine, mine, "same"), (mine, 'x"y', "not allowed"), (mine + "|x", base, "")):
    try: xcopy.check_paths(src_, dst_); check(f"refused: {why or src_[-4:]}", False)
    except ValueError as e: check(f"refused: {why or 'a bad character'}", why in str(e) or not why, str(e))
check("a wildcard source is allowed when its folder exists", xcopy.check_paths(os.path.join(mine, "*.txt"), base)[0].endswith("*.txt"))
check("the file count is read from xcopy's last line", xcopy.count_copied("a\nb\n3 File(s) copied\n") == 3 and xcopy.count_copied("2 File(s)") == 2 and xcopy.count_copied("nothing") is None)
check("exit codes are explained", "No files" in xcopy.describe_exit(1) and "disk write" in xcopy.describe_exit(5) and xcopy.describe_exit(0, "4 File(s) copied") == "Done: 4 file(s)." and "exit code 9" in xcopy.describe_exit(9))
def run_x(*args):
    r = subprocess.run([xcopy.find_xcopy(), *args], capture_output=True, text=True, timeout=60, errors="replace"); return r.returncode, r.stdout
out = os.path.join(base, "out"); rc, text = run_x(*xcopy.build_args(tree, out))
check("it copies a folder tree, empty folders included", rc == 0 and open(os.path.join(out, "sub", "deep", "c.cfg"), "rb").read() == b"CCC" and os.path.isdir(os.path.join(out, "empty")) and xcopy.count_copied(text) == 3, text[-200:])
out2 = os.path.join(base, "out2"); rc, text = run_x(*xcopy.build_args(tree, out2, preview=True))
check("a preview lists the files and copies nothing", rc == 0 and not os.path.exists(out2) and "a.cfg" in text and xcopy.count_copied(text) == 3, text[-200:])
rc, text = run_x(*xcopy.build_args(tree, out, existing=xcopy.NEWER)); check("'only if newer' copies nothing the second time", rc == 0 and xcopy.count_copied(text) == 0, text[-200:])
open(os.path.join(tree, "a.cfg"), "wb").write(b"A2"); os.utime(os.path.join(tree, "a.cfg"), (time.time() + 100, time.time() + 100))
rc, text = run_x(*xcopy.build_args(tree, out, existing=xcopy.NEWER)); check("...and copies the changed one", xcopy.count_copied(text) == 1 and open(os.path.join(out, "a.cfg"), "rb").read() == b"A2")
open(os.path.join(out, "a.cfg"), "wb").write(b"OLD"); rc, text = run_x(*xcopy.build_args(tree, out))
check("replace mode never stops to ask (/Y)", rc == 0 and open(os.path.join(out, "a.cfg"), "rb").read() == b"A2")
rc, text = run_x(*xcopy.build_args(os.path.join(tree, "sub"), os.path.join(base, "flat"), subfolders=False))
check("without sub-folders only the files at the top are copied", rc == 0 and os.path.exists(os.path.join(base, "flat", "b.cfg")) and not os.path.exists(os.path.join(base, "flat", "deep")))
spaced = os.path.join(base, "with space"); put("x y.txt", b"s", spaced); rc, text = run_x(*xcopy.build_args(spaced, os.path.join(base, "out space")))
check("paths with spaces work", rc == 0 and open(os.path.join(base, "out space", "x y.txt"), "rb").read() == b"s", text[-200:])
rc, text = run_x(*xcopy.build_args(os.path.join(tree, "*.zzz"), os.path.join(base, "o3")))
check("a pattern that matches nothing is explained, whichever exit code xcopy gives", (rc == 1 and "No files" in xcopy.describe_exit(rc, text)) or (rc == 0 and xcopy.describe_exit(rc, text) == "Nothing needed copying (0 files)."), (rc, text))
os.makedirs(os.path.join(base, "emptysrc")); rc, text = run_x(*xcopy.build_args(os.path.join(base, "emptysrc"), os.path.join(base, "o4"), subfolders=False))
check("an empty folder copies zero files, said plainly", rc == 0 and xcopy.describe_exit(rc, text) == "Nothing needed copying (0 files).", (rc, text))

srv.stop()
print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
