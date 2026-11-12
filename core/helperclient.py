"""Toner's side of the helper service (core/helper): asking it over its pipe or socket, putting it in place as an administrator,
and the "Let group members sign in without approval" switch's state. Nothing is sent before the other end is known to be the
helper itself: on Windows the TonerHelper service's own process (anyone can make a pipe of the same name), on Linux root
(SO_PEERCRED). enroll hands it the data key, the rules private key and the Duo secret keys over that channel only; they are never
logged, audited or shown."""
import base64
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from core import datakey, db, quiet, session, updates
from core.helper import protocol

if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    from core.helper import windows as _plat
    _TRUSTED = {"S-1-5-18"}                             # LocalSystem; tests add their own SID
else:
    from core.helper import linux as _plat
    _TRUSTED = {0}                                      # root; tests add their own uid
ADDRESS = _plat.ADDRESS
# INSTALL_FAILED's {reason} (approved wording); any other reason is the OS's own text, never an exception's class name
EXITED = "it stopped with code {code}."
TOO_LONG = "the administrator prompt wasn't answered in time."
NO_ANSWER = "it didn't start."
NO_COPY = "it couldn't copy its files."


_notice_due = False     # rules_replaced before sign-in: the Accounts page's note, set once the key opens


class NotRunning(Exception):
    """No helper answers, or what answers isn't the helper."""


class InstallFailed(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class HelperError(Exception):
    """The helper said no: its error code (protocol.ERRORS)."""


def _b64(b):
    return base64.b64encode(b).decode("ascii")


# ------------------------------------------------------------ who is at the other end
if os.name == "nt":
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _shell = ctypes.WinDLL("shell32", use_last_error=True)
    H, D = wintypes.HANDLE, wintypes.DWORD

    class _SEI(ctypes.Structure):                       # SHELLEXECUTEINFOW
        _fields_ = [("cbSize", D), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
                    ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int), ("hInstApp", H), ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
                    ("hkeyClass", H), ("dwHotKey", D), ("hIcon", H), ("hProcess", H)]

    for _dll, _name, _args, _res in [
            (_k32, "GetNamedPipeServerProcessId", [H, ctypes.POINTER(wintypes.ULONG)], wintypes.BOOL),
            (_k32, "OpenProcess", [D, wintypes.BOOL, D], H),
            (_k32, "CloseHandle", [H], wintypes.BOOL),
            (_k32, "WaitForSingleObject", [H, D], D),
            (_k32, "GetExitCodeProcess", [H, ctypes.POINTER(D)], wintypes.BOOL),
            (_adv, "OpenProcessToken", [H, D, ctypes.POINTER(H)], wintypes.BOOL),
            (_adv, "OpenSCManagerW", [wintypes.LPCWSTR, wintypes.LPCWSTR, D], H),
            (_adv, "OpenServiceW", [H, wintypes.LPCWSTR, D], H),
            (_adv, "QueryServiceStatusEx", [H, ctypes.c_int, ctypes.c_void_p, D, ctypes.POINTER(D)], wintypes.BOOL),
            (_adv, "CloseServiceHandle", [H], wintypes.BOOL),
            (_shell, "ShellExecuteExW", [ctypes.POINTER(_SEI)], wintypes.BOOL)]:
        getattr(_dll, _name).argtypes, getattr(_dll, _name).restype = _args, _res

    def _sid_of(pid):
        """The SID of the user running process `pid`; None when this user may not look (a SYSTEM process, to most users)."""
        proc = _k32.OpenProcess(0x1000, False, pid)     # PROCESS_QUERY_LIMITED_INFORMATION
        if not proc:
            return None
        try:
            token = H()
            if not _adv.OpenProcessToken(proc, 0x8, ctypes.byref(token)):     # TOKEN_QUERY
                return None
            try:
                return _plat._token_sid(token)
            finally:
                _k32.CloseHandle(token)
        finally:
            _k32.CloseHandle(proc)

    def _service_pid():
        """The process id of the running TonerHelper service, from the service manager (0: not running)."""
        scm = _adv.OpenSCManagerW(None, None, 0x1)      # SC_MANAGER_CONNECT
        if not scm:
            return 0
        try:
            svc = _adv.OpenServiceW(scm, _plat.SERVICE, 0x4)    # SERVICE_QUERY_STATUS
            if not svc:
                return 0
            try:
                st, n = (D * 9)(), D()                  # SERVICE_STATUS_PROCESS: the status, then dwProcessId, flags
                if not _adv.QueryServiceStatusEx(svc, 0, st, ctypes.sizeof(st), ctypes.byref(n)):
                    return 0
                return st[7] if st[1] == 4 else 0       # SERVICE_RUNNING
            finally:
                _adv.CloseServiceHandle(svc)
        finally:
            _adv.CloseServiceHandle(scm)

    def _server_ok(conn):
        """The pipe's server is a LocalSystem process, or (when this user can't read that, as most can't) the TonerHelper
        service's own process as the service manager names it. Only administrators can make or change that service."""
        pid = wintypes.ULONG()
        if not _k32.GetNamedPipeServerProcessId(conn.fileno(), ctypes.byref(pid)) or not pid.value:
            return False
        return _sid_of(pid.value) in _TRUSTED or pid.value == _service_pid()
else:
    def _server_ok(conn):
        return _plat._creds(conn)[1] in _TRUSTED


# ------------------------------------------------------------ asking it
def _connect():
    """A connection to the helper, its identity checked before anything is sent; NotRunning otherwise."""
    try:
        conn = _plat.client(ADDRESS)
    except OSError:
        raise NotRunning() from None
    try:
        ok = _server_ok(conn)
    except OSError:
        ok = False
    if not ok:
        conn.close()
        raise NotRunning()
    return conn


def call(req, timeout=10, cancel=None):
    """The helper's answer to `req` (an op and its fields; the protocol version is added). NotRunning when there is no helper
    to ask, no answer within `timeout` seconds, or `cancel` (an Event) is set first: the connection then closes, which stops a
    Duo push at the helper."""
    conn = _connect()
    try:
        conn.send_bytes(protocol.encode({**req, "v": protocol.PROTOCOL}))
        end = time.monotonic() + timeout
        while not conn.poll(max(0.0, min(0.5, end - time.monotonic()))):
            if time.monotonic() >= end or (cancel is not None and cancel.is_set()):
                raise NotRunning()
        return protocol.decode(conn.recv_bytes(protocol.MAX))
    except (OSError, EOFError, ValueError):             # gone mid-request, or an answer that isn't one
        raise NotRunning() from None
    finally:
        conn.close()


def _ok(ans):
    if not ans.get("ok"):
        raise HelperError(str(ans.get("error")))
    return ans


def installed():
    """The helper service is installed (running or not)."""
    cmd = ["sc.exe", "query", _plat.SERVICE] if os.name == "nt" else ["systemctl", "is-enabled", "toner-helper"]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=10,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


SYSTEMD_DIR = Path("/run/systemd/system")              # exists only while systemd is the running init (sd_booted)


def not_installed():
    """The stricter question beside installed(), for security keys (dirsignin.helper_may_be_on): True only when the service
    manager answers that no helper service exists: Windows' 1060 (no such service), or no toner-helper unit known to systemd.
    Installed but disabled or stopped, or an error or timeout while asking: False. Another OS, or Linux where systemd isn't the
    running init (WSL without it), has no helper: True."""
    if sys.platform not in ("win32", "linux"):
        return True
    nt = sys.platform == "win32"
    if not nt and not SYSTEMD_DIR.is_dir():             # systemd's own test that it is the running init (not PATH)
        return True
    cmd = ["sc.exe", "query", _plat.SERVICE] if nt else ["systemctl", "show", "--property=LoadState", "--value", "toner-helper.service"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 1060 if nt else r.returncode == 0 and r.stdout.strip() == b"not-found"


def state(keys_path, ask_service=True):
    """The switch's state for the copy whose keys file is `keys_path`: "portable", "absent", "not_running", "outdated",
    "other_user", "rules_changed", "off" or "on". On "rules_changed" the helper's spare copy pins rules this copy no longer has,
    so it is forgotten here (turned off, audited, and the Accounts page says so once). `ask_service=False`: no helper answering
    is "not_running" without asking the service manager whether it is installed."""
    if updates.installed_kind() == "portable":
        return "portable"
    try:
        st = call({"op": "status", "keys_path": str(keys_path)})
    except NotRunning:
        return "not_running" if not ask_service or installed() else "absent"
    if st.get("protocol") != protocol.PROTOCOL:
        return "outdated"
    if not st.get("owner"):
        return "other_user" if st.get("enrolled") else "off"
    if st.get("rules_changed"):
        rules_replaced(keys_path)
        return "rules_changed"
    return "on"


def rules_replaced(keys_path=None):
    """Turns it off because the rules key was replaced. Once the helper has let go of its spare copy it is audited and the
    Accounts page says so once; found before sign-in, both wait for the key to open. While the helper can't be made to let go,
    nothing is said yet: a later look that turns it off says it, so it is never said twice."""
    global _notice_due
    try:
        forget(keys_path)
    except (NotRunning, HelperError):
        quiet.ignored()
        return
    session.audit_soon("sign-in without approval turned off", "the rules key was replaced")
    _notice_due = True
    _set_notice("open" if datakey.is_open() else None)


def _set_notice(new):
    """session's listener (and rules_replaced): the Accounts page's note written once the key is open."""
    global _notice_due
    if new == "open" and _notice_due and datakey.is_open():
        try:
            db.set_setting("helper_off_notice", True)
            _notice_due = False
        except Exception:
            quiet.ignored()


session.on_change(_set_notice)


def enroll():
    """In an Admin session: gives the helper this copy's keys file, the data key, the rules private key and the Duo secret key
    of every directory with Duo on. HelperError when it refuses, NotRunning when it can't be asked."""
    from core import datakey, osstore, roles
    if not roles.holds("rules"):
        raise HelperError("not_admin")
    if ((roles.verified() or {}).get("rules_version") or 0) < 1:
        roles.sync_grants()                             # signs once: the helper refuses rules signed before the count
    duo = {}
    for d in (roles.verified() or {}).get("directories") or []:
        if isinstance(d, dict) and (d.get("duo") or {}).get("on"):
            skey = osstore.get("duo:" + d["id"])
            if skey:
                duo[d["id"]] = _b64(skey)
    _ok(call({"op": "enroll", "keys_path": str(datakey.path()), "data_key": _b64(datakey._key),
              "rules_private": _b64(roles._held["rules"]), "duo": duo}))


def forget(keys_path=None):
    """Has the helper delete its spare copy for this copy. Nothing enrolled (or someone else's) is nothing to delete."""
    from core import datakey
    ans = call({"op": "forget", "keys_path": str(keys_path or datakey.path())})
    if not ans.get("ok") and ans.get("error") not in ("not_enrolled", "not_owner"):
        raise HelperError(str(ans.get("error")))


# ------------------------------------------------------------ installing it
def _elevate(timeout):
    """Runs the helper's --install as an administrator/root and waits; its exit code."""
    if os.name == "nt":
        exe = Path(updates.app_dir()) / "TonerHelper" / "TonerHelper.exe"
        sei = _SEI(cbSize=ctypes.sizeof(_SEI), fMask=0x40 | 0x100, lpVerb="runas", lpFile=str(exe),   # NOCLOSEPROCESS, NOASYNC
                   lpParameters="--install", nShow=0)
        if not _shell.ShellExecuteExW(ctypes.byref(sei)):
            raise ctypes.WinError(ctypes.get_last_error())      # 1223: the administrator prompt was cancelled
        try:
            if _k32.WaitForSingleObject(sei.hProcess, int(timeout * 1000)) != 0:
                raise subprocess.TimeoutExpired("TonerHelper.exe", timeout)
            code = D()
            if not _k32.GetExitCodeProcess(sei.hProcess, ctypes.byref(code)):
                raise ctypes.WinError(ctypes.get_last_error())
            return code.value
        finally:
            _k32.CloseHandle(sei.hProcess)
    # root usually can't read a FUSE-mounted AppImage: copy the helper out to a folder only this user can open, then delete it
    src = Path(os.environ.get("APPDIR") or updates.app_dir()) / "usr" / "lib" / "toner-helper"
    tmp = tempfile.mkdtemp(prefix="toner-helper-")      # 0700
    try:
        copy = Path(tmp) / "toner-helper"
        try:
            shutil.copytree(src, copy)
        except OSError:                                 # (shutil.Error too)
            raise InstallFailed(NO_COPY) from None
        return subprocess.run(["pkexec", str(copy / "toner-helper"), "--install"], capture_output=True, timeout=timeout).returncode
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def install_elevated(timeout=120):
    """Installs (or updates) the helper service as an administrator, then waits up to 15 s for it to answer. InstallFailed."""
    try:
        code = _elevate(timeout)
    except subprocess.TimeoutExpired:
        raise InstallFailed(TOO_LONG) from None
    except OSError as e:
        raise InstallFailed(e.strerror or NO_ANSWER) from None
    if code:
        raise InstallFailed(NO_COPY if code == protocol.COPY_FAILED else EXITED.format(code=code))
    end = time.monotonic() + 15
    while True:
        try:
            call({"op": "status", "keys_path": ""}, timeout=5)
            return
        except NotRunning:
            if time.monotonic() > end:
                raise InstallFailed(NO_ANSWER) from None
            time.sleep(0.5)
