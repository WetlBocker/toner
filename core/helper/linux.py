"""The helper on Linux: the toner-helper systemd service, running as root, on the socket /run/toner-helper/helper.sock. The
socket is 0666, so any local user can connect: who they are comes from SO_PEERCRED, never the file mode. The keys file is read
with the caller's filesystem uid and gid. The program lives in /opt/toner-helper/ and the store in /var/lib/toner-helper/
(root, 0700; the file 0600), so protect/unprotect change nothing."""
import ctypes
import logging
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
from multiprocessing import connection
from pathlib import Path

from core.helper import server, store

ADDRESS = "/run/toner-helper/helper.sock"
PROGRAM_DIR = Path("/opt/toner-helper")
DATA_DIR = Path("/var/lib/toner-helper")
STORE_PATH = DATA_DIR / "helper.json"
UNIT_PATH = Path("/etc/systemd/system/toner-helper.service")
UNIT = """[Unit]
Description=Toner helper

[Service]
ExecStart=/opt/toner-helper/toner-helper --service
User=root
RuntimeDirectory=toner-helper
RuntimeDirectoryMode=0755
StateDirectory=toner-helper
StateDirectoryMode=0700
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
log = logging.getLogger(__name__)
_on_read = None                                         # test hook: called inside the read, as the caller
_libc = ctypes.CDLL(None, use_errno=True) if sys.platform.startswith("linux") else None
if _libc:
    _libc.setfsuid.argtypes = _libc.setfsgid.argtypes = [ctypes.c_uint]


def protect(b):
    return b


unprotect = protect


# ------------------------------------------------------------ the socket
def _creds(conn):
    """(pid, uid, gid) of the process at the other end, from the kernel."""
    s = socket.fromfd(conn.fileno(), socket.AF_UNIX, socket.SOCK_STREAM)      # a duplicate, closed below
    try:
        return struct.unpack("iII", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII")))
    finally:
        s.close()


def peer_of(conn):
    """The uid of the process at the other end (SO_PEERCRED), as a string: never from a message."""
    return str(_creds(conn)[1])


def _fs_ids():
    return _libc.setfsuid(0xFFFFFFFF), _libc.setfsgid(0xFFFFFFFF)      # -1 changes nothing and answers the current one


def _reader(uid, gid):
    """read(path) as the caller: server._read (its regular-file and size checks included) with this thread's filesystem uid
    and gid switched to the caller's, so links and permissions are followed with the person's rights, not root's. setfsuid
    is per thread on Linux, so other connections keep running as root meanwhile. serve drops root's supplementary groups,
    which would otherwise still apply. A thread that can't go back to root ends the process."""
    def read(path):
        back = os.geteuid(), os.getegid()
        try:
            _libc.setfsgid(gid)
            _libc.setfsuid(uid)
            if _fs_ids() != (uid, gid):
                raise PermissionError("can't read as the caller")
            if _on_read:
                _on_read()
            return server._read(path)
        finally:
            _libc.setfsuid(back[0])
            _libc.setfsgid(back[1])
            if _fs_ids() != back:
                os._exit(1)
    return read


def _identify(conn):
    _, uid, gid = _creds(conn)
    return str(uid), _reader(uid, gid)


def _wake(address):
    try:
        connection.Client(address).close()
    except OSError:
        pass


def serve(helper, stop, address=ADDRESS):
    """The helper on the socket until `stop` is set: a thread per connection (server.serve_channel). A socket left by a
    helper that died is replaced (its folder is root's)."""
    if os.geteuid() == 0:
        os.setgroups([])                                # a read as the caller then has the caller's gid and no other group
    try:
        os.unlink(address)
    except FileNotFoundError:
        pass
    listener = connection.Listener(address, family="AF_UNIX", backlog=16)
    os.chmod(address, 0o666)
    server.serve_channel(listener, helper, stop, _identify, lambda: _wake(address))


def run_service():
    """The service under systemd, in the foreground until SIGTERM. Errors (types only) go to the journal."""
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *a: stop.set())
    serve(server.Helper(store.Store(STORE_PATH, protect, unprotect)), stop)


# ------------------------------------------------------------ install and uninstall (as root, from toner-helper)
def _elevated():
    return os.geteuid() == 0


def _inside(path, folder):
    a, b = os.path.abspath(path), os.path.abspath(folder)
    return a == b or a.startswith(b.rstrip("/") + "/")


def _homes():
    import pwd
    homes = [Path.home(), Path("/home")]
    for var in ("PKEXEC_UID", "SUDO_UID"):              # the person who asked for root
        try:
            homes.append(Path(pwd.getpwuid(int(os.environ[var])).pw_dir))
        except (KeyError, ValueError):
            pass
    return homes


def _guard():
    """PermissionError unless root; ValueError when a helper folder is in a home folder."""
    if not _elevated():
        raise PermissionError("not running as root")
    for d in (PROGRAM_DIR, DATA_DIR):
        if any(_inside(d, h) for h in _homes()):
            raise ValueError(f"{d} is in a home folder")


def install_plan(src_dir):
    """The steps of install, in order: commands, and "copy"/"write" done here."""
    return [["systemctl", "stop", "toner-helper"], ["copy", str(src_dir), str(PROGRAM_DIR)],
            ["write", str(UNIT_PATH), UNIT], ["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", "toner-helper"]]


def install(src_dir):
    """Puts the helper service in place from `src_dir` (toner-helper's own folder). Only as root."""
    _guard()
    src = Path(src_dir).resolve()
    if _inside(src, PROGRAM_DIR):
        raise ValueError("installing from the program folder itself")
    for step in install_plan(src):
        _step(step)


def uninstall():
    """Stops and removes the service, its unit, its program folder and its store. Only as root."""
    _guard()
    for step in [["systemctl", "disable", "--now", "toner-helper"], ["rm", str(UNIT_PATH)], ["systemctl", "daemon-reload"],
                 ["rmdir", str(DATA_DIR)], ["rmdir", str(PROGRAM_DIR)]]:
        _step(step)


def _step(step):
    if step[0] == "copy":
        _copy(Path(step[1]), Path(step[2]))
    elif step[0] == "write":
        fd = os.open(step[1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with open(fd, "w", encoding="utf-8") as f:
            os.fchmod(fd, 0o644)
            f.write(step[2])
    elif step[0] == "rm":
        Path(step[1]).unlink(missing_ok=True)
    elif step[0] == "rmdir":
        _remove(Path(step[1]))
    else:
        r = subprocess.run(step, capture_output=True)
        if r.returncode and step[1] not in ("stop", "disable"):     # no service to stop: nothing to do
            raise OSError(f"{step[0]} {step[1]} failed ({r.returncode})")


def _remove(path):
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _copy(src, dst):
    """A fresh copy of `src` at `dst`, links followed (files only), all root's: folders 0755, files 0755 or 0644."""
    _remove(dst)
    os.makedirs(dst.parent, exist_ok=True)
    shutil.copytree(src, dst)
    for top, dirs, files in os.walk(dst):
        os.chown(top, 0, 0)
        os.chmod(top, 0o755)
        for name in files:
            p = os.path.join(top, name)
            os.chown(p, 0, 0)
            os.chmod(p, 0o755 if os.stat(p).st_mode & 0o111 else 0o644)
