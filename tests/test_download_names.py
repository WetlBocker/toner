# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Nothing on this computer is touched outside
# a throw-away folder, and nothing is connected to.
# Downloads from a device in the Files panel: a name the device lists can't steer a file outside the chosen folder, and a
# download isn't planned from the size the device reports (ui/filebrowser.py RemoteFs.walk, transfer, copy_file).
import os, sys, stat, tempfile, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["APPDATA"] = tempfile.mkdtemp(prefix="netcheck_appdata_")       # never this computer's own data folder
os.environ["NETCHECK_DB"] = os.path.join(os.environ["APPDATA"], "dlnames.db")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from core.scp import ScpError
from ui import filebrowser as FB

ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)

class Attr:
    def __init__(self, filename, folder=False):
        self.filename, self.st_mode, self.st_size, self.st_mtime = filename, (stat.S_IFDIR if folder else stat.S_IFREG) | 0o644, 2, 0

class Sftp:
    """A device that lists what LISTING says and writes two bytes for any file asked for."""
    def __init__(self, listing): self.listing, self.got = listing, []
    def listdir_attr(self, path): return self.listing.get(path, [])
    def stat(self, path): return Attr(path.rsplit("/", 1)[-1], folder=path in self.listing)
    def get(self, src, dst, callback=None, prefetch=True):
        self.got.append((src, dst, prefetch))
        if os.path.realpath(dst).startswith(os.path.realpath(home) + os.sep):     # this test never writes outside its own folder
            with open(dst, "wb") as f:
                f.write(b"hi")

class Signal:
    def emit(self, *a): pass

class Worker:
    def __init__(self, sftp): self.sftp, self.cancel, self.progress = sftp, threading.Event(), Signal()
    def ask(self, *a): return "skip"

def refused(fn):
    try:
        fn()
    except ScpError as e:
        return str(e)
    except Exception as e:
        print("   (raised", type(e).__name__, e, ")")
    return None

def tree(base):
    return sorted(os.path.relpath(os.path.join(r, f), base).replace(os.sep, "/") for r, _, fs in os.walk(base) for f in fs)

home = tempfile.mkdtemp(prefix="netcheck_dl_")
chosen = os.path.join(home, "Downloads"); os.makedirs(chosen)

# ---------------------------------------------------------------- a folder whose listing holds names that climb out
for bad_name in ("../climbed.txt", "..", "/abs.txt", "a\\b.txt"):
    sftp = Sftp({"/logs": [Attr("ok.txt"), Attr(bad_name)]})
    w = Worker(sftp)
    msg = refused(lambda: FB.transfer(w, FB.RemoteFs(sftp), ["/logs"], FB.LocalFs(), chosen, "Downloading"))
    check(f"a folder that lists {bad_name!r} is refused before anything is copied", msg is not None and not sftp.got, (msg, sftp.got))
sftp = Sftp({"/logs": [Attr("sub", folder=True)], "/logs/sub": [Attr("ok.txt")], "/logs/../x": []})
sftp.listing["/logs"].append(Attr("../x", folder=True))
check("so is a listed folder name that climbs out", refused(lambda: FB.transfer(Worker(sftp), FB.RemoteFs(sftp), ["/logs"], FB.LocalFs(), chosen, "Downloading")) is not None)
sftp = Sftp({})
check("and a single file whose own name holds a backslash", refused(lambda: FB.transfer(Worker(sftp), FB.RemoteFs(sftp), ["/logs/..\\up.txt"], FB.LocalFs(), chosen, "Downloading")) is not None and not sftp.got)
check("nothing was written anywhere", tree(home) == [], tree(home))

# ---------------------------------------------------------------- an ordinary folder still downloads
sftp = Sftp({"/logs": [Attr("ok.txt"), Attr("sub", folder=True)], "/logs/sub": [Attr("inner.txt")]})
n, stopped = FB.transfer(Worker(sftp), FB.RemoteFs(sftp), ["/logs"], FB.LocalFs(), chosen, "Downloading")
check("an ordinary folder lands inside the chosen folder", n == 2 and tree(home) == ["Downloads/logs/ok.txt", "Downloads/logs/sub/inner.txt"], tree(home))
check("a download is not planned from the size the device reports (no prefetch)", sftp.got and all(p is False for _, _, p in sftp.got), sftp.got)

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
