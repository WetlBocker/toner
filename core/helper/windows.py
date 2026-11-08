r"""The helper on Windows: the TonerHelper service, running as LocalSystem, on the named pipe \\.\pipe\TonerHelper. The caller
is the user of the pipe client's process, and the keys file is read impersonating the client. The program lives in
%ProgramFiles%\Toner Helper\ and the store in %ProgramData%\Toner Helper\: both writable by SYSTEM and Administrators only. The
store's secrets are sealed by the security chip (a machine key with no PIN), so a copy of the disk opens nothing elsewhere; DPAPI
as LocalSystem only where there is no chip. ctypes only (no pywin32)."""
import _winapi
import ctypes
import logging
import logging.handlers
import os
import secrets
import shutil
import subprocess
import threading
import time
import uuid
from ctypes import wintypes
from multiprocessing import connection
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core import passvault, tpm_windows
from core.helper import server, store

ADDRESS = r"\\.\pipe\TonerHelper"
SERVICE = "TonerHelper"
# Signed-in users may connect, network logons may not; only SYSTEM and Administrators may do more. Users get read and write
# (0x0012019b: GRGW less FILE_CREATE_PIPE_INSTANCE), so they can't add an instance of the pipe to catch the next client; its
# owner (OW: SYSTEM, which made the first instance) makes the next ones.
_PIPE_SD = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x0012019b;;;AU)"
_CLIENT_ACCESS = 0x80000000 | 0x2 | 0x100               # GENERIC_READ, FILE_WRITE_DATA, FILE_WRITE_ATTRIBUTES (message mode)
_DIR_SD = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"      # owned by Administrators; SYSTEM and Administrators only
_ADMINS = {"S-1-5-18", "S-1-5-32-544"}                 # SYSTEM, Administrators
# what lets someone change a folder or what's in it: write/append data (add file/subfolder), write EA, delete child, write
# attributes, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE
_WRITE = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
_ACL = ["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]    # SIDs: the names are translated
log = logging.getLogger(__name__)
_on_read = None                                         # test hook: called inside the read, while impersonating

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_adv = ctypes.WinDLL("advapi32", use_last_error=True)
_shell = ctypes.WinDLL("shell32", use_last_error=True)
_ole = ctypes.WinDLL("ole32")
H, P, D = wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD
for _dll, _name, _args, _res in [
        (_k32, "CreateNamedPipeW", [wintypes.LPCWSTR, D, D, D, D, D, D, P], H),
        (_k32, "CreateDirectoryW", [wintypes.LPCWSTR, P], wintypes.BOOL),
        (_k32, "GetNamedPipeClientProcessId", [H, ctypes.POINTER(wintypes.ULONG)], wintypes.BOOL),
        (_k32, "OpenProcess", [D, wintypes.BOOL, D], H),
        (_k32, "CloseHandle", [H], wintypes.BOOL),
        (_k32, "LocalFree", [P], P),
        (_adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [wintypes.LPCWSTR, D, ctypes.POINTER(P), P], wintypes.BOOL),
        (_adv, "OpenProcessToken", [H, D, ctypes.POINTER(H)], wintypes.BOOL),
        (_adv, "GetTokenInformation", [H, ctypes.c_int, P, D, ctypes.POINTER(D)], wintypes.BOOL),
        (_adv, "ConvertSidToStringSidW", [P, ctypes.POINTER(P)], wintypes.BOOL),
        (_adv, "GetNamedSecurityInfoW", [wintypes.LPCWSTR, ctypes.c_int, D] + [ctypes.POINTER(P)] * 5, D),
        (_adv, "GetAce", [P, D, ctypes.POINTER(P)], wintypes.BOOL),
        (_adv, "ImpersonateNamedPipeClient", [H], wintypes.BOOL),
        (_adv, "RevertToSelf", [], wintypes.BOOL),
        (_adv, "RegisterServiceCtrlHandlerExW", [wintypes.LPCWSTR, P, P], H),
        (_adv, "SetServiceStatus", [H, P], wintypes.BOOL),
        (_adv, "StartServiceCtrlDispatcherW", [P], wintypes.BOOL),
        (_shell, "SHGetKnownFolderPath", [P, D, H, ctypes.POINTER(P)], ctypes.c_long),
        (_shell, "IsUserAnAdmin", [], wintypes.BOOL),
        (_ole, "CoTaskMemFree", [P], None)]:
    getattr(_dll, _name).argtypes, getattr(_dll, _name).restype = _args, _res


def _check(ok):
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return ok


def _known(guid):
    """A known folder's path, from Windows itself rather than the environment (which the person can change)."""
    g = (ctypes.c_byte * 16).from_buffer_copy(uuid.UUID(guid).bytes_le)
    p = P()
    hr = _shell.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(p))
    try:
        if hr:
            raise OSError(f"no known folder {guid} ({hr & 0xFFFFFFFF:#x})")
        return Path(ctypes.wstring_at(p.value))
    finally:
        _ole.CoTaskMemFree(p)


PROGRAM_DIR = _known("905E63B6-C1BF-494E-B29C-65B732D3D21A") / "Toner Helper"      # FOLDERID_ProgramFiles
DATA_DIR = _known("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97") / "Toner Helper"         # FOLDERID_ProgramData
STORE_PATH = DATA_DIR / "helper.json"
_SYSTEM = _known("1AC14E77-02E7-4E5D-B744-2EB1AE5198B7")                           # FOLDERID_System: sc.exe, icacls.exe
_PROFILES = _known("0762D272-C50A-4BB0-A382-697DCD729B80")                         # FOLDERID_UserProfiles: C:\Users
SPARE_KEY = "Toner-Helper-Spare"                       # the security chip's machine key that seals the store's secrets
_CHIP = b"tpm1:"                                        # a blob sealed by it starts so; any other is DPAPI's (as LocalSystem)
_OAEP = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
_AAD = b"toner-helper-spare"


def protect(b):
    """`b` sealed as core/pinslot.py seals a chip slot: RSA-OAEP of a random key by the machine key (made on first use), then
    AES-GCM. With no security chip: DPAPI as LocalSystem, which only SYSTEM can open."""
    try:
        try:
            der = tpm_windows.public(SPARE_KEY, machine=True)
        except FileNotFoundError:
            der = tpm_windows.create(SPARE_KEY, None, machine=True)
    except OSError:                                     # no chip here (as tpm_windows.available() decides)
        return passvault.dpapi_protect(b)
    kek, nonce = os.urandom(32), os.urandom(12)
    wrapped = serialization.load_der_public_key(der).encrypt(kek, _OAEP)
    return _CHIP + wrapped + nonce + AESGCM(kek).encrypt(nonce, b, _AAD)


def unprotect(b):
    if not b.startswith(_CHIP):
        return passvault.dpapi_unprotect(b)
    raw = b[len(_CHIP):]
    kek = tpm_windows.decrypt(SPARE_KEY, None, raw[:256], machine=True)        # RSA-2048: 256 bytes
    return AESGCM(kek).decrypt(raw[256:268], raw[268:], _AAD)


def forget_key():
    """The machine key goes (forget and uninstall): best effort, since without the store it opens nothing."""
    try:
        tpm_windows.delete(SPARE_KEY, machine=True)
    except OSError as e:
        log.warning("helper: the chip's key wasn't deleted: %s", type(e).__name__)


class Store(store.Store):
    """The helper's store; clearing it (forget) deletes the machine key too."""

    def clear(self):
        super().clear()
        forget_key()


class _SA(ctypes.Structure):
    _fields_ = [("nLength", D), ("lpSecurityDescriptor", P), ("bInheritHandle", wintypes.BOOL)]


def _sa(sddl):
    """SECURITY_ATTRIBUTES for `sddl` (the descriptor is never freed: one per pipe listener or folder made)."""
    sd = P()
    _check(_adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None))
    return _SA(ctypes.sizeof(_SA), sd, False)


# ------------------------------------------------------------ the pipe
class _Pipes(connection.PipeListener):
    """multiprocessing's pipe listener, its pipe made with _PIPE_SD and refusing remote clients (multiprocessing's own gets the
    default DACL, which lets other users only read, and takes clients over the network). The first instance fails when the
    name is taken, so no one else's pipe can sit under the helper's name."""

    def __init__(self, address):
        self._sa = _sa(_PIPE_SD)
        super().__init__(address)

    def _new_handle(self, first=False):
        mode = _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED | (_winapi.FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0)
        pipe = (_winapi.PIPE_TYPE_MESSAGE | _winapi.PIPE_READMODE_MESSAGE | _winapi.PIPE_WAIT
                | 0x8)                                  # PIPE_REJECT_REMOTE_CLIENTS
        h = _k32.CreateNamedPipeW(self._address, mode, pipe, _winapi.PIPE_UNLIMITED_INSTANCES, 8192, 8192,
                                  _winapi.NMPWAIT_WAIT_FOREVER, ctypes.byref(self._sa))
        if h in (None, P(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        return h


def _token_sid(token):
    """The string SID of a token's user."""
    buf = ctypes.create_string_buffer(256)              # TOKEN_USER: a pointer, attributes, then the SID (at most 68 bytes)
    n = D()
    _check(_adv.GetTokenInformation(token, 1, buf, len(buf), ctypes.byref(n)))      # TokenUser
    return _sid_str(ctypes.cast(buf, ctypes.POINTER(P))[0])


def _sid_str(psid):
    s = P()
    _check(_adv.ConvertSidToStringSidW(psid, ctypes.byref(s)))
    try:
        return ctypes.wstring_at(s.value)
    finally:
        _k32.LocalFree(s)


def peer_of(conn):
    """The SID of the user running the pipe client's process, from Windows: never from a message."""
    pid = wintypes.ULONG()
    _check(_k32.GetNamedPipeClientProcessId(conn.fileno(), ctypes.byref(pid)))
    proc = _check(_k32.OpenProcess(0x1000, False, pid.value))       # PROCESS_QUERY_LIMITED_INFORMATION
    try:
        token = H()
        _check(_adv.OpenProcessToken(proc, 0x8, ctypes.byref(token)))    # TOKEN_QUERY
        try:
            return _token_sid(token)
        finally:
            _k32.CloseHandle(token)
    finally:
        _k32.CloseHandle(proc)


def _reader(handle):
    """read(path) for the client on pipe `handle`: server._read (its regular-file and size checks included) impersonating the
    client, so the path is opened with the person's rights (their links, junctions, drives, permissions), not SYSTEM's. No
    impersonation, no read. A thread that can't go back to SYSTEM ends the process: it must never carry on as the client."""
    def read(path):
        _check(_adv.ImpersonateNamedPipeClient(handle))
        try:
            if _on_read:
                _on_read()
            return server._read(path)
        finally:
            if not _adv.RevertToSelf():
                os._exit(1)
    return read


def _identify(conn):
    return peer_of(conn), _reader(conn.fileno())


def client(address):
    """multiprocessing's pipe client, asking only for what _PIPE_SD gives users: its GENERIC_WRITE includes
    FILE_CREATE_PIPE_INSTANCE, which they don't have. OSError when there is no pipe (or it stays busy)."""
    for _ in range(10):
        try:
            _winapi.WaitNamedPipe(address, 1000)
            h = _winapi.CreateFile(address, _CLIENT_ACCESS, 0, _winapi.NULL, _winapi.OPEN_EXISTING, _winapi.FILE_FLAG_OVERLAPPED,
                                   _winapi.NULL)
            break
        except OSError as e:
            if e.winerror not in (_winapi.ERROR_SEM_TIMEOUT, _winapi.ERROR_PIPE_BUSY):
                raise
    else:
        raise OSError("the helper's pipe stays busy")
    _winapi.SetNamedPipeHandleState(h, _winapi.PIPE_READMODE_MESSAGE, None, None)
    return connection.PipeConnection(h)


def _wake(address):
    try:
        client(address).close()
    except OSError:
        pass


def serve(helper, stop, address=ADDRESS):
    """The helper on the pipe until `stop` is set: a thread per connection (server.serve_channel)."""
    server.serve_channel(_Pipes(address), helper, stop, _identify, lambda: _wake(address))


# ------------------------------------------------------------ the service
_MAIN = ctypes.WINFUNCTYPE(None, D, ctypes.POINTER(wintypes.LPWSTR))
_HANDLER = ctypes.WINFUNCTYPE(D, D, D, P, P)


class _Status(ctypes.Structure):
    _fields_ = [(n, D) for n in ("type", "state", "accepted", "exit", "specific", "checkpoint", "wait")]


class _Entry(ctypes.Structure):
    _fields_ = [("name", wintypes.LPWSTR), ("main", _MAIN)]


def run_service():
    """Runs as the TonerHelper service: this thread goes to the service manager, which calls main on a thread of its own and
    control() on Stop and on shutdown. OSError 1063 when not started by the service manager. Errors go to helper.log in the
    data folder (types only)."""
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s", handlers=[
        logging.handlers.RotatingFileHandler(DATA_DIR / "helper.log", maxBytes=1 << 20, backupCount=1, delay=True)])
    stop, handle = threading.Event(), []

    def status(state, exit_code=0):
        # SERVICE_WIN32_OWN_PROCESS; Stop and shutdown accepted while running (4); ERROR_SERVICE_SPECIFIC_ERROR on failure
        _adv.SetServiceStatus(handle[0], ctypes.byref(_Status(0x10, state, 0x5 if state == 4 else 0, 1066 if exit_code else 0,
                                                              exit_code, 0, 5000 if state in (2, 3) else 0)))

    def control(code, event, data, context):
        if code in (1, 5) and handle:                   # SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN
            status(3)                                   # stop pending
            stop.set()
        return 0

    def main(argc, argv):
        h = _adv.RegisterServiceCtrlHandlerExW(SERVICE, ctypes.cast(on_control, P), None)
        if not h:
            return
        handle.append(h)
        status(2)                                       # start pending
        try:
            helper = server.Helper(Store(STORE_PATH, protect, unprotect))
            status(4)                                   # running
            serve(helper, stop)
        except Exception as e:                          # the pipe name taken, say
            log.error("helper: stopped: %s", type(e).__name__)
            status(1, 1)
            return
        status(1)                                       # stopped

    on_control, on_main = _HANDLER(control), _MAIN(main)
    table = (_Entry * 2)(_Entry(SERVICE, on_main), _Entry(None, _MAIN()))
    _check(_adv.StartServiceCtrlDispatcherW(table))


# ------------------------------------------------------------ install and uninstall (elevated, from TonerHelper.exe)
def _elevated():
    return bool(_shell.IsUserAnAdmin())


def _inside(path, folder):
    a, b = os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(folder))
    return a == b or a.startswith(b.rstrip("\\") + "\\")


def _guard():
    """PermissionError unless elevated; ValueError when a helper folder is in a user's profile."""
    if not _elevated():
        raise PermissionError("not running as an administrator")
    for d in (PROGRAM_DIR, DATA_DIR):
        if _inside(d, _PROFILES) or _inside(d, Path.home()):
            raise ValueError(f"{d} is in a user's profile")


def install_plan(src_dir):
    """The steps of install, in order: commands, and "copy"/"mkdir" done here (each a fresh folder made admin-only)."""
    return [["sc.exe", "stop", SERVICE], ["sc.exe", "delete", SERVICE], ["copy", str(src_dir), str(PROGRAM_DIR)],
            ["mkdir", str(DATA_DIR)], ["icacls", str(PROGRAM_DIR), *_ACL], ["icacls", str(DATA_DIR), *_ACL],
            ["sc.exe", "create", SERVICE, "binPath=", f'"{PROGRAM_DIR / "TonerHelper.exe"}" --service', "start=", "auto",
             "obj=", "LocalSystem", "DisplayName=", "Toner helper"],
            ["sc.exe", "failure", SERVICE, "reset=", "86400", "actions=", "restart/5000"], ["sc.exe", "start", SERVICE]]


def install(src_dir):
    """Puts the helper service in place from `src_dir` (TonerHelper.exe's own folder). Only elevated."""
    _guard()
    src = Path(src_dir).resolve()
    if _inside(src, PROGRAM_DIR):
        raise ValueError("installing from the program folder itself")
    for step in install_plan(src):
        _step(step)


def uninstall():
    """Stops and removes the service, its program folder and its store. Only elevated."""
    _guard()
    for step in [["sc.exe", "stop", SERVICE], ["sc.exe", "delete", SERVICE], ["rmdir", str(DATA_DIR)], ["rmdir", str(PROGRAM_DIR)],
                 ["forget-key"]]:
        _step(step)


def _step(step):
    if step[0] == "copy":
        _fresh(Path(step[2]))
        shutil.copytree(step[1], step[2], dirs_exist_ok=True)      # links followed: the copy holds files only
    elif step[0] == "mkdir":
        _fresh(Path(step[1]))
    elif step[0] == "rmdir":
        _remove(Path(step[1]))
    elif step[0] == "forget-key":
        forget_key()
    else:                                               # from System32, never the folder TonerHelper.exe runs from
        r = subprocess.run([str(_SYSTEM / step[0]), *step[1:]], capture_output=True)
        if r.returncode and step[1] not in ("stop", "delete"):       # no service to stop or delete: nothing to do
            raise OSError(f"{step[0]} {step[1]} failed ({r.returncode})")


def _security(path):
    """(owner SID, the SIDs the DACL lets change the object at `path`). Writers is None when anyone may (no DACL) or an allow
    ACE is of a kind this doesn't read (object or callback ACEs): such a folder isn't trusted."""
    owner, dacl, sd = P(), P(), P()
    err = _adv.GetNamedSecurityInfoW(str(path), 1, 0x1 | 0x4, ctypes.byref(owner), None, ctypes.byref(dacl), None,
                                     ctypes.byref(sd))          # SE_FILE_OBJECT; OWNER and DACL
    if err:
        raise ctypes.WinError(err)
    try:
        if not dacl.value:
            return _sid_str(owner), None
        writers = set()
        for i in range(ctypes.cast(dacl, ctypes.POINTER(ctypes.c_ushort))[2]):     # ACL header: rev, sbz1, size, AceCount
            ace = P()
            _check(_adv.GetAce(dacl, i, ctypes.byref(ace)))
            kind = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))[0]
            if kind == 1:                               # ACCESS_DENIED_ACE
                continue
            if kind != 0:                               # not a plain ACCESS_ALLOWED_ACE
                return _sid_str(owner), None
            if ctypes.cast(ace.value + 4, ctypes.POINTER(D))[0] & _WRITE:    # header (4 bytes), Mask, then the SID
                writers.add(_sid_str(ace.value + 8))
        return _sid_str(owner), writers
    finally:
        _k32.LocalFree(sd)


def _trusted(path):
    """The folder at `path` is owned by SYSTEM or Administrators and only they may change it, so nothing in it was put there by
    anyone else. A link or junction, or a folder whose security can't be read, is not."""
    if os.path.islink(path) or os.path.isjunction(path):
        return False
    try:
        owner, writers = _security(path)
    except OSError:
        return False
    return owner in _ADMINS and writers is not None and writers <= _ADMINS


def _remove(path):
    """Clears the name `path`. A folder only administrators could have written is deleted: renamed aside first, waiting up to
    30 s for a stopping service to let go of its files, then removed. Anything else (a folder a user made or can write to, a
    link, a junction) is only renamed aside to <name>.untrusted-<time> and left there untouched: deleting inside a tree its
    owner can change would let them point the deletion, as an administrator, anywhere (a junction swapped in mid-walk).
    OSError when it can't be moved aside, which stops the install."""
    if not os.path.lexists(path):
        return
    if not _trusted(path):
        aside = path.with_name(f"{path.name}.untrusted-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}")
        try:
            os.rename(path, aside)                      # MoveFileExW: the folder itself, nothing inside it is opened
        except OSError as e:
            raise OSError(f"{path} isn't admin-only and couldn't be moved aside") from e
        return
    old = path.with_name(f"{path.name}.old-{secrets.token_hex(4)}")
    for i in range(60):
        try:
            os.rename(path, old)
            break
        except PermissionError:
            if i == 59:
                raise
            time.sleep(0.5)
    shutil.rmtree(old)


def _fresh(path):
    """An empty folder at `path`, made with the admin-only ACL in the same step: nothing anyone else put there survives, and
    there is no moment when a user could add a file to it (ProgramData lets users create files in new folders)."""
    _remove(path)
    _mkdir_admin(path)


def _mkdir_admin(path):
    _check(_k32.CreateDirectoryW(str(path), ctypes.byref(_sa(_DIR_SD))))
