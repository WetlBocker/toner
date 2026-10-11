"""TFTP and SFTP servers for pushing firmware and configurations to devices and pulling files back.

Both serve ONE folder and nothing outside it. They are read-only until uploads are switched on, and can be limited to
chosen client addresses. Every transfer is reported to `on_event` as a dict:
    {time, proto, client, op, path, bytes, status ('ok' | 'failed' | 'denied'), note}
"""
import base64
import hashlib
import hmac
import ipaddress
import os
import posixpath
import socket
import struct
import threading
import time
from datetime import datetime
from core import quiet

PART = ".netcheck-part"                  # in-progress TFTP uploads; never served and never accepted as a name
_WINDOWS_DEVICES = {"con", "prn", "aux", "nul", "clock$"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}


# =============================================================================== shared safety checks
def resolve_path(root, name, allow_empty=False):
    """The real path of `name` inside `root`, or ValueError. Anything that could leave the folder is refused:
    '..', drive letters and alternate streams (':'), device names, links that point outside, odd characters."""
    text = str(name or "").replace("\\", "/")
    if "\x00" in text or any(ord(c) < 32 for c in text):
        raise ValueError("invalid characters in the file name")
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if not parts and not allow_empty:
        raise ValueError("no file name")
    for p in parts:
        if p == ".." or ":" in p or p.endswith((".", " ")) or p.lower().split(".")[0] in _WINDOWS_DEVICES \
                or p.lower().endswith(PART) or any(c in p for c in '<>"|?*'):
            raise ValueError(f"not allowed: {p!r}")
    base = os.path.realpath(root)
    real = os.path.realpath(os.path.join(base, *parts)) if parts else base
    try:
        inside = os.path.commonpath([os.path.normcase(base), os.path.normcase(real)]) == os.path.normcase(base)
    except ValueError:                                      # different drives
        inside = False
    if not inside:
        raise ValueError("outside the shared folder")
    return real


def risky_root(path):
    """Why this folder should not be shared (a drive root, the Windows folder, Program Files, a whole profile), or ''."""
    if not path or not os.path.isdir(path):
        return "Choose an existing folder."
    p = os.path.normcase(os.path.realpath(path)).rstrip("\\/")
    if os.path.splitdrive(p)[1] in ("", "\\", "/"):
        return "That is a whole drive. Choose a dedicated folder, for example C:\\TFTP."
    bad = [os.environ.get(v) for v in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "USERPROFILE", "APPDATA")]
    for b in bad:
        if b and os.path.normcase(os.path.realpath(b)).rstrip("\\/") == p:
            return f"{path} holds system or personal files. Choose a dedicated folder."
    return ""


def parse_allowed(text):
    """'10.0.0.0/24, 192.168.1.5' -> list of networks. Empty means everyone. Raises ValueError on a bad entry."""
    nets = []
    for item in str(text or "").replace(";", ",").replace(" ", ",").split(","):
        if item.strip():
            try:
                nets.append(ipaddress.ip_network(item.strip(), strict=False))
            except ValueError:
                raise ValueError(f"{item.strip()!r} is not an IP address or network such as 10.0.0.0/24.")
    return nets


def client_allowed(ip, nets):
    if not nets:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets if n.version == addr.version)


def local_addresses():
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)})
    except OSError:
        return []


def _stamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class _Base:
    def __init__(self, proto, root, port, bind, allow_write, allow_overwrite, allowed, max_bytes, on_event):
        self.proto, self.port, self.bind = proto, int(port), bind
        self.root = os.path.realpath(root)
        if not os.path.isdir(self.root):
            raise ValueError(f"{root} is not a folder.")
        self.allow_write, self.allow_overwrite = bool(allow_write), bool(allow_overwrite) and bool(allow_write)
        self.allowed = parse_allowed(allowed) if isinstance(allowed, str) else list(allowed or [])
        self.max_bytes = int(max_bytes)
        self.on_event = on_event
        self.stop_event = threading.Event()
        self.sock = None
        self.thread = None
        self.count = 0
        self.lock = threading.Lock()
        self.active = 0

    def emit(self, client, op, path, nbytes=0, status="ok", note=""):
        self.count += 1
        if self.on_event:
            try:
                self.on_event({"time": _stamp(), "proto": self.proto, "client": client, "op": op, "path": path,
                               "bytes": int(nbytes), "status": status, "note": note})
            except Exception:
                quiet.ignored()

    def stop(self):
        self.stop_event.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        if self.thread:
            self.thread.join(3)
        self.sock = self.thread = None

    @property
    def running(self):
        return bool(self.thread and self.thread.is_alive())


# =============================================================================== TFTP (RFC 1350, 2347, 2348, 2349)
RRQ, WRQ, DATA, ACK, ERROR, OACK = 1, 2, 3, 4, 5, 6
E_UNDEF, E_NOTFOUND, E_ACCESS, E_DISK, E_ILLEGAL, E_TID, E_EXISTS, E_NOUSER, E_OPTION = range(9)


def parse_request(data):
    """(opcode, filename, mode, {option: value}) from a TFTP read/write request. ValueError if malformed."""
    if len(data) < 4:
        raise ValueError("too short")
    op = struct.unpack("!H", data[:2])[0]
    if op not in (RRQ, WRQ):
        raise ValueError("not a request")
    parts = data[2:].split(b"\x00")
    if parts[-1] != b"" or len(parts) < 3:
        raise ValueError("not terminated")
    fields = [p.decode("utf-8", "replace") for p in parts[:-1]]
    rest = fields[2:]
    if len(rest) % 2:
        raise ValueError("option without a value")
    return op, fields[0], fields[1].lower(), {rest[i].lower(): rest[i + 1] for i in range(0, len(rest), 2)}


def _error(code, text):
    return struct.pack("!HH", ERROR, code) + text.encode("ascii", "replace") + b"\x00"


class _Abort(Exception):
    pass


class TftpServer(_Base):
    def __init__(self, root, port=69, bind="0.0.0.0", allow_write=False, allow_overwrite=False, allowed=(),
                 max_bytes=512 * 1024 * 1024, on_event=None, max_transfers=8, retries=5):
        super().__init__("tftp", root, port, bind, allow_write, allow_overwrite, allowed, max_bytes, on_event)
        self.max_transfers, self.retries = max_transfers, retries

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((self.bind, self.port))                   # OSError if the port is taken or needs more rights
        except OSError:
            s.close()
            raise
        s.settimeout(0.5)
        self.sock = s
        self.port = s.getsockname()[1]
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        s = self.sock
        while not self.stop_event.is_set():
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 4 or data[1] not in (RRQ, WRQ) or data[0] != 0:
                continue                                    # not a request: stray packets are ignored
            if not client_allowed(addr[0], self.allowed):
                self.emit(addr[0], "request", "", 0, "denied", "client is not on the allowed list")
                continue                                    # no answer, so the server is not revealed
            with self.lock:
                busy = self.active >= self.max_transfers
                if not busy:
                    self.active += 1
            if busy:
                self._reply_once(addr, _error(E_UNDEF, "Server busy"))
                continue
            threading.Thread(target=self._serve, args=(addr, data), daemon=True).start()

    def _reply_once(self, addr, packet):
        try:
            self.sock.sendto(packet, addr)
        except OSError:
            pass

    # ---- one transfer
    def _serve(self, client, data):
        ts = None
        try:
            try:
                op, name, mode, opts = parse_request(data)
            except ValueError:
                self._reply_once(client, _error(E_ILLEGAL, "Bad request"))
                return
            ts = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ts.bind((self._local_for(client[0]), 0))
            ip = client[0]
            if mode != "octet":
                ts.sendto(_error(E_ILLEGAL, "Only octet (binary) mode is supported"), client)
                self.emit(ip, "read" if op == RRQ else "write", name, 0, "failed", f"mode {mode} is not supported")
                return
            try:
                real = resolve_path(self.root, name)
            except ValueError as e:
                ts.sendto(_error(E_ACCESS, "Access violation"), client)
                self.emit(ip, "read" if op == RRQ else "write", name, 0, "denied", str(e))
                return
            (self._read if op == RRQ else self._write)(ts, client, name, real, opts)
        except _Abort as e:
            pass
        except OSError as e:
            self.emit(client[0], "transfer", "", 0, "failed", str(e))
        finally:
            if ts:
                ts.close()
            with self.lock:
                self.active -= 1

    def _local_for(self, ip):
        """Answer from the address the client can reach us on (matters when this PC has several)."""
        if self.bind not in ("", "0.0.0.0"):
            return self.bind
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((ip, 9))
            return probe.getsockname()[0]
        except OSError:
            return "0.0.0.0"
        finally:
            probe.close()

    @staticmethod
    def _options(opts, size):
        """Accept blksize / timeout / tsize. Returns (negotiated dict for the OACK, block size, timeout seconds)."""
        out, blk, tmo = {}, 512, 3
        if "blksize" in opts:
            try:
                blk = max(8, min(65464, int(opts["blksize"])))
                out["blksize"] = str(blk)
            except ValueError:
                pass
        if "timeout" in opts:
            try:
                tmo = max(1, min(255, int(opts["timeout"])))
                out["timeout"] = str(tmo)
            except ValueError:
                pass
        if "tsize" in opts:
            out["tsize"] = str(size if size is not None else opts["tsize"])
        return out, blk, tmo

    @staticmethod
    def _oack(opts):
        return struct.pack("!H", OACK) + b"".join(k.encode() + b"\x00" + v.encode() + b"\x00" for k, v in opts.items())

    def _wait(self, ts, client, packet, accept, timeout):
        """Send `packet` until a packet accepted by `accept(op, block, data)` arrives. Duplicates are ignored."""
        for _ in range(self.retries + 1):
            if self.stop_event.is_set():
                raise _Abort("server stopped")
            ts.sendto(packet, client)
            deadline = time.time() + timeout
            while True:
                left = deadline - time.time()
                if left <= 0 or self.stop_event.is_set():
                    break
                ts.settimeout(left)
                try:
                    data, addr = ts.recvfrom(70000)
                except socket.timeout:
                    break
                except ConnectionResetError:                # Windows reports a closed peer port this way
                    raise _Abort("the device went away")
                if addr != client:
                    ts.sendto(_error(E_TID, "Unknown transfer ID"), addr)
                    continue
                if len(data) < 4:
                    continue
                op, block = struct.unpack("!HH", data[:4])
                if op == ERROR:
                    raise _Abort(data[4:].rstrip(b"\x00").decode("utf-8", "replace") or "the device cancelled")
                if accept(op, block, data):
                    return data
        raise _Abort("timed out waiting for the device")

    def _read(self, ts, client, name, real, opts):
        ip = client[0]
        if not os.path.isfile(real):
            ts.sendto(_error(E_NOTFOUND, "File not found"), client)
            self.emit(ip, "read", name, 0, "failed", "file not found")
            return
        try:
            f = open(real, "rb")
        except OSError as e:
            ts.sendto(_error(E_ACCESS, "Cannot open file"), client)
            self.emit(ip, "read", name, 0, "failed", str(e))
            return
        sent, started = 0, time.time()
        with f:
            try:
                neg, blk, tmo = self._options(opts, os.path.getsize(real))
                if neg:
                    self._wait(ts, client, self._oack(neg), lambda op, b, d: op == ACK and b == 0, tmo)
                block = 1
                while True:
                    chunk = f.read(blk)
                    self._wait(ts, client, struct.pack("!HH", DATA, block) + chunk,
                               lambda op, b, d, want=block: op == ACK and b == want, tmo)
                    sent += len(chunk)
                    if len(chunk) < blk:
                        break
                    block = (block + 1) & 0xFFFF
            except _Abort as e:
                self.emit(ip, "read", name, sent, "failed", str(e))
                return
        self.emit(ip, "read", name, sent, "ok", f"{_rate(sent, time.time() - started)}")

    def _write(self, ts, client, name, real, opts):
        ip = client[0]
        refuse = None
        if not self.allow_write:
            refuse = (E_ACCESS, "Uploads are disabled", "uploads are switched off")
        elif os.path.isdir(real) or (os.path.exists(real) and not self.allow_overwrite):
            refuse = (E_EXISTS, "File already exists", "file exists and replacing is switched off")
        elif not os.path.isdir(os.path.dirname(real)):
            refuse = (E_NOTFOUND, "Folder does not exist", "the folder does not exist")
        elif "tsize" in opts and opts["tsize"].isdigit() and int(opts["tsize"]) > self.max_bytes:
            refuse = (E_DISK, "File too large", f"larger than the {self.max_bytes // 1048576} MB limit")
        if refuse:
            ts.sendto(_error(refuse[0], refuse[1]), client)
            self.emit(ip, "write", name, 0, "denied", refuse[2])
            return
        neg, blk, tmo = self._options(opts, None)           # a WRQ's tsize is the client's; it is echoed back
        part = real + PART
        got, started, ok = 0, time.time(), False
        try:
            with open(part, "wb") as out:
                first = self._oack(neg) if neg else struct.pack("!HH", ACK, 0)
                data = self._wait(ts, client, first, lambda op, b, d: op == DATA and b == 1, tmo)
                block = 1
                while True:
                    payload = data[4:]
                    got += len(payload)
                    if got > self.max_bytes:
                        ts.sendto(_error(E_DISK, "File too large"), client)
                        raise _Abort(f"larger than the {self.max_bytes // 1048576} MB limit")
                    out.write(payload)
                    ack = struct.pack("!HH", ACK, block)
                    if len(payload) < blk:
                        break
                    nxt = (block + 1) & 0xFFFF
                    data = self._wait(ts, client, ack, lambda op, b, d, want=nxt: op == DATA and b == want, tmo)
                    block = nxt
            if os.path.exists(real) and not self.allow_overwrite:
                raise _Abort("the file appeared during the upload")
            os.replace(part, real)                          # the file is complete before the last block is acknowledged
            ok = True
            ts.sendto(ack, client)
        except _Abort as e:
            self.emit(ip, "write", name, got, "failed", str(e))
        except OSError as e:
            try:
                ts.sendto(_error(E_DISK, "Cannot write the file"), client)
            except OSError:
                pass
            self.emit(ip, "write", name, got, "failed", str(e))
        finally:
            if not ok and os.path.exists(part):
                try:
                    os.remove(part)
                except OSError:
                    pass
        if ok:
            self.emit(ip, "write", name, got, "ok", _rate(got, time.time() - started))


def _rate(nbytes, seconds):
    return f"{nbytes * 8 / max(seconds, 0.001) / 1e6:.1f} Mbit/s"


# =============================================================================== SFTP (paramiko)
def load_host_key(path):
    """The server's identity. Created on first use and kept, so clients see the same fingerprint every time."""
    import paramiko
    if os.path.exists(path):
        return paramiko.RSAKey.from_private_key_file(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    key = paramiko.RSAKey.generate(3072)
    key.write_private_key_file(path)
    return key


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def _sftp_classes():
    """Built lazily so importing this module never needs paramiko."""
    import paramiko
    from paramiko import SFTPAttributes, SFTPHandle, SFTPServerInterface, SFTP_FAILURE, SFTP_OK, SFTP_OP_UNSUPPORTED, \
        SFTP_PERMISSION_DENIED, SFTP_NO_SUCH_FILE
    binary = getattr(os, "O_BINARY", 0)

    class Handle(SFTPHandle):
        def __init__(self, ctx, rel, flags):
            super().__init__(flags)
            self.ctx, self.rel, self.moved, self.writing = ctx, rel, 0, False

        def read(self, offset, length):
            data = super().read(offset, length)
            if isinstance(data, (bytes, bytearray)):
                self.moved += len(data)
            return data

        def write(self, offset, data):
            if offset + len(data) > self.ctx.srv.max_bytes:
                self.ctx.srv.emit(self.ctx.ip, "write", self.rel, self.moved, "failed", "larger than the size limit")
                return SFTP_FAILURE
            result = super().write(offset, data)
            if result == SFTP_OK:
                self.moved += len(data)
            return result

        def stat(self):
            try:
                return SFTPAttributes.from_stat(os.fstat((self.readfile or self.writefile).fileno()))
            except OSError as e:
                return SFTPServerInterface.convert_errno(e.errno)

        def chattr(self, attr):
            return SFTP_OK if self.ctx.srv.allow_write else SFTP_PERMISSION_DENIED

        def close(self):
            super().close()
            self.ctx.srv.emit(self.ctx.ip, "write" if self.writing else "read", self.rel, self.moved, "ok",
                              _rate(self.moved, time.time() - self.ctx.started) if self.moved else "")

    class Jail(SFTPServerInterface):
        def __init__(self, server, *a, ctx=None, **kw):
            super().__init__(server, *a, **kw)
            self.ctx = ctx
            self.srv = ctx.srv

        def _real(self, path, allow_empty=True):
            try:
                return resolve_path(self.srv.root, path, allow_empty=allow_empty)
            except ValueError as e:
                self.srv.emit(self.ctx.ip, "access", str(path), 0, "denied", str(e))
                return None

        def canonicalize(self, path):
            return posixpath.normpath("/" + str(path).replace("\\", "/").lstrip("/"))

        def list_folder(self, path):
            real = self._real(path)
            if real is None:
                return SFTP_PERMISSION_DENIED
            try:
                out = []
                for n in sorted(os.listdir(real)):
                    if n.lower().endswith(PART):
                        continue
                    try:
                        out.append(SFTPAttributes.from_stat(os.lstat(os.path.join(real, n)), n))
                    except OSError:
                        pass
                return out
            except OSError as e:
                return SFTPServerInterface.convert_errno(e.errno)

        def _stat(self, path, fn):
            real = self._real(path)
            if real is None:
                return SFTP_PERMISSION_DENIED
            try:
                return SFTPAttributes.from_stat(fn(real))
            except OSError as e:
                return SFTPServerInterface.convert_errno(e.errno)

        def stat(self, path):
            return self._stat(path, os.stat)

        def lstat(self, path):
            return self._stat(path, os.lstat)

        def open(self, path, flags, attr):
            writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC))
            real = self._real(path, allow_empty=False)
            rel = str(path)
            if real is None:
                return SFTP_PERMISSION_DENIED
            if writing:
                if not self.srv.allow_write:
                    self.srv.emit(self.ctx.ip, "write", rel, 0, "denied", "uploads are switched off")
                    return SFTP_PERMISSION_DENIED
                if os.path.exists(real) and not self.srv.allow_overwrite:
                    self.srv.emit(self.ctx.ip, "write", rel, 0, "denied", "file exists and replacing is switched off")
                    return SFTP_PERMISSION_DENIED
            elif not os.path.isfile(real):
                return SFTP_NO_SUCH_FILE
            try:
                fd = os.open(real, flags | binary, 0o644)
            except OSError as e:
                return SFTPServerInterface.convert_errno(e.errno)
            if flags & os.O_WRONLY:
                mode = "ab" if flags & os.O_APPEND else "wb"
            elif flags & os.O_RDWR:
                mode = "a+b" if flags & os.O_APPEND else "r+b"
            else:
                mode = "rb"
            h = Handle(self.ctx, rel, flags)
            h.writing = writing
            h.ctx = _Started(self.ctx)
            f = os.fdopen(fd, mode)
            h.filename = real
            h.readfile = f
            h.writefile = f
            return h

        def _change(self, what, path, fn, needs_replace=False):
            real = self._real(path, allow_empty=False)
            if real is None:
                return SFTP_PERMISSION_DENIED
            if not self.srv.allow_write or (needs_replace and not self.srv.allow_overwrite):
                self.srv.emit(self.ctx.ip, what, str(path), 0, "denied",
                              "uploads are switched off" if not self.srv.allow_write else "replacing and deleting are switched off")
                return SFTP_PERMISSION_DENIED
            try:
                fn(real)
            except OSError as e:
                self.srv.emit(self.ctx.ip, what, str(path), 0, "failed", str(e))
                return SFTPServerInterface.convert_errno(e.errno)
            self.srv.emit(self.ctx.ip, what, str(path), 0, "ok")
            return SFTP_OK

        def remove(self, path):
            return self._change("delete", path, os.remove, True)

        def rmdir(self, path):
            return self._change("delete", path, os.rmdir, True)

        def mkdir(self, path, attr):
            return self._change("mkdir", path, os.mkdir)

        def rename(self, oldpath, newpath):
            new = self._real(newpath, allow_empty=False)
            if new is None:
                return SFTP_PERMISSION_DENIED
            if os.path.exists(new):
                return SFTP_FAILURE
            return self._change("rename", oldpath, lambda old: os.rename(old, new), True)

        def chattr(self, path, attr):
            return SFTP_OK if self.srv.allow_write else SFTP_PERMISSION_DENIED

        def symlink(self, target_path, path):
            return SFTP_OP_UNSUPPORTED

        def readlink(self, path):
            return SFTP_OP_UNSUPPORTED

    class Auth(paramiko.ServerInterface):
        def __init__(self, srv, ip):
            self.srv, self.ip = srv, ip

        def get_allowed_auths(self, username):
            return "password"

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_auth_password(self, username, password):
            good_user = hmac.compare_digest(username.encode(), self.srv.username.encode())
            good_pass = hmac.compare_digest(password.encode(), self.srv.password.encode())
            if good_user and good_pass:
                self.srv.forgive(self.ip)
                self.srv.emit(self.ip, "login", "", 0, "ok", f"user {username}")
                return paramiko.AUTH_SUCCESSFUL
            self.srv.failed_login(self.ip, username)
            return paramiko.AUTH_FAILED

    return Jail, Auth


class _Started:
    """A per-connection context that also remembers when each file transfer began."""
    def __init__(self, ctx):
        self.srv, self.ip, self.started = ctx.srv, ctx.ip, time.time()


class _Ctx:
    def __init__(self, srv, ip):
        self.srv, self.ip, self.started = srv, ip, time.time()


class SftpServer(_Base):
    LOCK_AFTER, LOCK_SECONDS = 5, 300

    def __init__(self, root, username, password, port=2222, bind="0.0.0.0", host_key_path="", allow_write=False,
                 allow_overwrite=False, allowed=(), max_bytes=512 * 1024 * 1024, on_event=None, max_connections=8):
        super().__init__("sftp", root, port, bind, allow_write, allow_overwrite, allowed, max_bytes, on_event)
        if not str(username or "").strip():
            raise ValueError("Enter a user name.")
        if len(password or "") < 8:
            raise ValueError("The password must be at least 8 characters.")
        self.username, self.password = username.strip(), password
        self.host_key_path, self.max_connections = host_key_path, max_connections
        self.host_key = None
        self.fails = {}
        self.fail_lock = threading.Lock()

    # ---- brute-force protection: five wrong passwords from one address and it is refused for five minutes
    def locked(self, ip):
        with self.fail_lock:
            recent = [t for t in self.fails.get(ip, []) if time.time() - t < self.LOCK_SECONDS]
            self.fails[ip] = recent
            return len(recent) >= self.LOCK_AFTER

    def failed_login(self, ip, username):
        with self.fail_lock:
            self.fails.setdefault(ip, []).append(time.time())
        self.emit(ip, "login", "", 0, "denied", f"wrong user name or password (tried {username[:40]!r})")
        time.sleep(1)                                       # slows guessing down

    def forgive(self, ip):
        with self.fail_lock:
            self.fails.pop(ip, None)

    # ---- running
    def start(self):
        self.host_key = load_host_key(self.host_key_path)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0 if os.name == "nt" else 1)
        try:
            s.bind((self.bind, self.port))
        except OSError:
            s.close()
            raise
        s.listen(8)
        s.settimeout(0.5)
        self.sock = s
        self.port = s.getsockname()[1]
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    @property
    def fingerprint(self):
        return fingerprint(self.host_key) if self.host_key else ""

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            ip = addr[0]
            if not client_allowed(ip, self.allowed):
                self.emit(ip, "connect", "", 0, "denied", "client is not on the allowed list")
                conn.close()
                continue
            if self.locked(ip):
                self.emit(ip, "connect", "", 0, "denied", "too many wrong passwords; try again in a few minutes")
                conn.close()
                continue
            with self.lock:
                busy = self.active >= self.max_connections
                if not busy:
                    self.active += 1
            if busy:
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn, ip), daemon=True).start()

    def _serve(self, conn, ip):
        import paramiko
        Jail, Auth = _sftp_classes()
        transport = None
        try:
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, sftp_si=Jail, ctx=_Ctx(self, ip))
            transport.start_server(server=Auth(self, ip))
            channel = transport.accept(30)                  # keep the reference: a dropped channel is closed
            while transport.is_active() and not self.stop_event.is_set():
                time.sleep(0.3)
        except Exception as e:
            self.emit(ip, "connect", "", 0, "failed", f"{type(e).__name__}: {e}"[:200])
        finally:
            try:
                if transport:
                    transport.close()
                conn.close()
            except Exception:
                quiet.ignored()
            with self.lock:
                self.active -= 1


def new_password(n=16):
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))
