"""TFTP, SFTP (with SCP) and FTP servers for pushing firmware and configurations to devices and pulling files back.

All three serve ONE folder and nothing outside it. They are read-only until uploads are switched on, and can be limited to
chosen client addresses. Every transfer is reported to `on_event` as a dict:
    {time, proto, client, op, path, bytes, status ('ok' | 'failed' | 'denied'), note}
"""
import base64
import hashlib
import hmac
import ipaddress
import os
import posixpath
import shlex
import socket
import stat as statmod
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
        return ("That is a whole drive. Choose a dedicated folder, for example C:\\TFTP." if os.name == "nt" else
                "That is the whole file system. Choose a dedicated folder, for example ~/tftp.")
    bad = [os.environ.get(v) for v in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "USERPROFILE", "APPDATA")]
    if os.name != "nt":                          # Linux and macOS: the system's own folders, and the whole of a home
        bad += ["/etc", "/usr", "/bin", "/sbin", "/lib", "/var", "/boot", "/opt", "/root", "/home", "/dev", "/proc", "/sys",
                "/System", "/Library", "/Applications", "/Users", os.path.expanduser("~")]
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


def _limit(nbytes):
    """'512 MB', '4.0 GB' or '390 KB': the size limit as a person reads it."""
    for unit, size in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if nbytes >= size:
            n = nbytes / size
            return f"{n:.1f} {unit}" if unit == "GB" else f"{n:.0f} {unit}"
    return f"{nbytes} bytes"


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

        def check_channel_exec_request(self, channel, command):
            """Only `scp -f <path>` (a device downloading) and `scp -t <path>` (uploading, when uploads are on): the SCP
            protocol, for devices that have an SCP client but no SFTP client (Cisco IOS, ASA). Anything else is refused."""
            job = parse_scp_command(command)
            if job is None:
                self.srv.emit(self.ip, "exec", "", 0, "denied", f"refused command {str(command)[:60]!r}")
                return False
            threading.Thread(target=serve_scp, args=(self.srv, self.ip, channel, job), daemon=True).start()
            return True

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

    def __init__(self, root, username, password, port=22, bind="0.0.0.0", host_key_path="", allow_write=False,
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



# =============================================================================== SCP over the SFTP server's SSH
def parse_scp_command(command):
    """`scp -f path`, `scp -r -p -t path` ... -> {'mode': 'f'|'t', 'recursive', 'preserve', 'path'}; None for anything else."""
    if isinstance(command, bytes):                          # paramiko hands the exec request over as bytes
        command = command.decode("utf-8", "replace")
    try:
        words = shlex.split(str(command or ""), posix=True)
    except ValueError:
        return None
    if len(words) < 3 or words[0] not in ("scp", "/usr/bin/scp") or not words[-1]:
        return None
    job = {"mode": "", "recursive": False, "preserve": False, "path": words[-1]}
    for w in words[1:-1]:
        if not w.startswith("-") or len(w) < 2:
            return None
        for ch in w[1:]:
            if ch in "ft":
                if job["mode"]:
                    return None
                job["mode"] = ch
            elif ch == "r":
                job["recursive"] = True
            elif ch == "p":
                job["preserve"] = True
            elif ch not in "dvq":
                return None
    return job if job["mode"] else None


class _ScpFail(Exception):
    pass


def _scp_ack(chan):
    b = chan.recv(1)
    if b == b"\x00":
        return
    if b in (b"\x01", b"\x02"):
        text = b""
        while not text.endswith(b"\n") and len(text) < 4096:
            more = chan.recv(1)
            if not more:
                break
            text += more
        raise _ScpFail(text.decode("utf-8", "replace").strip() or "the client reported an error")
    raise _ScpFail("the client did not answer as scp does")


def _scp_line(chan):
    out = b""
    while not out.endswith(b"\n"):
        b = chan.recv(1)
        if not b:
            raise _ScpFail("the client closed the connection")
        out += b
        if len(out) > 4096:
            raise _ScpFail("the client sent a line that is too long")
    return out[:-1].decode("utf-8", "replace")


def serve_scp(srv, ip, chan, job):
    """One `scp -f` (send what the client asked for) or `scp -t` (receive) session on an SSH channel of the SFTP server."""
    chan.settimeout(60)
    status = 0
    time.sleep(0.05)                                        # let paramiko confirm the exec request before we might close the channel
    try:
        try:
            real = resolve_path(srv.root, job["path"], allow_empty=job["mode"] == "t")
        except ValueError as e:
            srv.emit(ip, "access", job["path"], 0, "denied", str(e))
            raise _ScpFail(f"scp: {job['path']}: Permission denied")
        if job["mode"] == "f":
            _scp_ack(chan)
            _scp_send(srv, ip, chan, job["path"], real, job)
        else:
            _scp_receive(srv, ip, chan, job["path"], real, job)
    except _ScpFail as e:
        status = 1
        try:
            chan.sendall(b"\x01" + str(e).encode("utf-8", "replace") + b"\n")
        except OSError:
            pass
    except (OSError, EOFError) as e:
        status = 1
        srv.emit(ip, "transfer", job["path"], 0, "failed", str(e)[:120])
    finally:
        try:
            chan.send_exit_status(status)
            chan.close()
        except Exception:
            quiet.ignored()


def _scp_send(srv, ip, chan, rel, real, job):
    if os.path.isdir(real):
        if not job["recursive"]:
            raise _ScpFail(f"scp: {rel}: not a regular file")
        chan.sendall(f"D0755 0 {os.path.basename(real.rstrip(os.sep)) or 'root'}\n".encode())
        _scp_ack(chan)
        for entry in sorted(os.scandir(real), key=lambda e: e.name.lower()):
            if entry.is_symlink() or entry.name.lower().endswith(PART):
                continue
            _scp_send(srv, ip, chan, posixpath.join(rel, entry.name), entry.path, job)
        chan.sendall(b"E\n")
        _scp_ack(chan)
        return
    if not os.path.isfile(real):
        srv.emit(ip, "read", rel, 0, "failed", "file not found")
        raise _ScpFail(f"scp: {rel}: No such file or directory")
    size, started, sent = os.path.getsize(real), time.time(), 0
    if job["preserve"]:
        st = os.stat(real)
        chan.sendall(f"T{int(st.st_mtime)} 0 {int(st.st_atime)} 0\n".encode())
        _scp_ack(chan)
    chan.sendall(f"C0644 {size} {os.path.basename(real)}\n".encode())
    _scp_ack(chan)
    try:
        with open(real, "rb") as fh:
            while True:
                if srv.stop_event.is_set():
                    raise _ScpFail("server stopped")
                block = fh.read(65536)
                if not block:
                    break
                chan.sendall(block)
                sent += len(block)
        chan.sendall(b"\x00")
        _scp_ack(chan)
    except (_ScpFail, OSError) as e:
        srv.emit(ip, "read", rel, sent, "failed", str(e)[:120])
        raise
    srv.emit(ip, "read", rel, sent, "ok", "scp " + _rate(sent, time.time() - started))


def _scp_receive(srv, ip, chan, rel, real, job):
    if not srv.allow_write:
        srv.emit(ip, "write", rel, 0, "denied", "uploads are switched off")
        raise _ScpFail("scp: uploads are switched off on this server")
    chan.sendall(b"\x00")
    stack = [(rel, real)]
    while True:
        try:
            kind = chan.recv(1)
        except socket.timeout:
            raise _ScpFail("timed out waiting for the client")
        if not kind:
            return
        line = _scp_line(chan)
        if kind in (b"\x01", b"\x02"):
            raise _ScpFail(line or "the client reported an error")
        if kind == b"T":
            chan.sendall(b"\x00")
            continue
        if kind == b"E":
            if len(stack) > 1:
                stack.pop()
            chan.sendall(b"\x00")
            continue
        parts = line.split(" ", 2)
        if kind not in (b"C", b"D") or len(parts) != 3 or not parts[1].isdigit():
            raise _ScpFail("the client sent something unexpected")
        size, name = int(parts[1]), parts[2]
        try:
            resolve_path(srv.root, name)                    # a plain name, inside the folder
            if "/" in name or "\\" in name or name in (".", ".."):
                raise ValueError("not a plain file name")
        except ValueError as e:
            srv.emit(ip, "access", name, 0, "denied", str(e))
            raise _ScpFail(f"scp: {name}: Permission denied")
        folder_rel, folder = stack[-1]
        if os.path.isdir(folder):
            target_rel, target = posixpath.join(folder_rel, name), os.path.join(folder, name)
        elif len(stack) == 1 and os.path.isdir(os.path.dirname(folder)):
            target_rel, target = folder_rel, folder              # `scp -t <newname>`: the file or folder takes that name, as OpenSSH does
        else:
            raise _ScpFail(f"scp: {folder_rel}: No such file or directory")
        if kind == b"D":
            if not job["recursive"]:
                raise _ScpFail("scp: a folder was sent without -r")
            if os.path.exists(target) and not os.path.isdir(target):
                raise _ScpFail(f"scp: {target_rel}: Not a directory")
            if not os.path.isdir(target):
                os.mkdir(target)
                srv.emit(ip, "mkdir", target_rel, 0, "ok", "scp")
            stack.append((target_rel, target))
            chan.sendall(b"\x00")
            continue
        if os.path.exists(target) and not srv.allow_overwrite:
            srv.emit(ip, "write", target_rel, 0, "denied", "file exists and replacing is switched off")
            raise _ScpFail(f"scp: {target_rel}: File exists and replacing is switched off")
        if size > srv.max_bytes:
            srv.emit(ip, "write", target_rel, 0, "denied", f"larger than the {_limit(srv.max_bytes)} limit")
            raise _ScpFail(f"scp: {target_rel}: larger than the size limit")
        chan.sendall(b"\x00")
        part, got, started = target + PART, 0, time.time()
        try:
            with open(part, "wb") as out:
                while got < size:
                    block = chan.recv(min(65536, size - got))
                    if not block:
                        raise _ScpFail("the client stopped sending in the middle of a file")
                    out.write(block)
                    got += len(block)
            _scp_ack(chan)                                  # the client's end-of-file byte
            os.replace(part, target)
        except BaseException:
            try:
                os.remove(part)
            except OSError:
                pass
            srv.emit(ip, "write", target_rel, got, "failed", "incomplete")
            raise
        srv.emit(ip, "write", target_rel, got, "ok", "scp " + _rate(got, time.time() - started))
        chan.sendall(b"\x00")


# =============================================================================== FTP (RFC 959, 2389, 2428, 3659)
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _ls_line(name, st):
    """One line of `LIST`, in the ls -l form every client reads."""
    kind = "d" if statmod.S_ISDIR(st.st_mode) else "-"
    t = time.localtime(st.st_mtime)
    when = (f"{_MONTHS[t.tm_mon - 1]} {t.tm_mday:2d} {t.tm_hour:02d}:{t.tm_min:02d}" if abs(time.time() - st.st_mtime) < 180 * 86400
            else f"{_MONTHS[t.tm_mon - 1]} {t.tm_mday:2d}  {t.tm_year}")
    return f"{kind}rw-r--r-- 1 toner toner {st.st_size:>12} {when} {name}"


def _mlsx_line(name, st):
    kind = "dir" if statmod.S_ISDIR(st.st_mode) else "file"
    modify = time.strftime("%Y%m%d%H%M%S", time.gmtime(st.st_mtime))
    return f"type={kind};size={st.st_size};modify={modify}; {name}"


class _FtpQuit(Exception):
    pass


class FtpServer(_Base):
    """A plain FTP server: user name and password, one folder, active (PORT) and passive (PASV, EPSV) data connections.
    Cisco IOS uses active mode unless `ip ftp passive` is configured, so both are needed. The password crosses the network
    in clear text, as FTP always does: for a management network."""
    LOCK_AFTER, LOCK_SECONDS = 5, 300
    IDLE_SECONDS = 300

    def __init__(self, root, username, password, port=21, bind="0.0.0.0", passive_ports=(50000, 50100), allow_write=False,
                 allow_overwrite=False, allowed=(), max_bytes=4 * 1024 * 1024 * 1024, on_event=None, max_connections=8,
                 advertise=""):
        super().__init__("ftp", root, port, bind, allow_write, allow_overwrite, allowed, max_bytes, on_event)
        if not str(username or "").strip():
            raise ValueError("Enter a user name.")
        if len(password or "") < 8:
            raise ValueError("The password must be at least 8 characters.")
        lo, hi = int(passive_ports[0]), int(passive_ports[1])
        if not (1 <= lo <= hi <= 65535):
            raise ValueError("The passive ports must be a range such as 50000 to 50100.")
        self.username, self.password = username.strip(), password
        self.passive_ports, self.max_connections, self.advertise = (lo, hi), max_connections, advertise
        self.fails = {}
        self.fail_lock = threading.Lock()

    # ---- brute-force protection, as the SFTP server
    def locked(self, ip):
        with self.fail_lock:
            recent = [t for t in self.fails.get(ip, []) if time.time() - t < self.LOCK_SECONDS]
            self.fails[ip] = recent
            return len(recent) >= self.LOCK_AFTER

    def failed_login(self, ip, username):
        with self.fail_lock:
            self.fails.setdefault(ip, []).append(time.time())
        self.emit(ip, "login", "", 0, "denied", f"wrong user name or password (tried {username[:40]!r})")
        time.sleep(1)

    def forgive(self, ip):
        with self.fail_lock:
            self.fails.pop(ip, None)

    # ---- running
    def start(self):
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
                try:
                    conn.sendall(b"421 Too many wrong passwords; try again in a few minutes.\r\n")
                except OSError:
                    pass
                conn.close()
                continue
            with self.lock:
                busy = self.active >= self.max_connections
                if not busy:
                    self.active += 1
            if busy:
                try:
                    conn.sendall(b"421 Too many connections.\r\n")
                except OSError:
                    pass
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn, ip), daemon=True).start()

    def _serve(self, conn, ip):
        try:
            _FtpSession(self, conn, ip).run()
        except Exception as e:
            self.emit(ip, "connect", "", 0, "failed", f"{type(e).__name__}: {e}"[:200])
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self.lock:
                self.active -= 1

    def passive_socket(self, local_ip):
        """A listening socket on a free port of the passive range, or None when every port is taken."""
        lo, hi = self.passive_ports
        for port in range(lo, hi + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind((local_ip if self.bind in ("", "0.0.0.0") else self.bind, port))
                s.listen(1)
                return s
            except OSError:
                s.close()
        return None


class _FtpSession:
    """One control connection."""

    def __init__(self, srv, conn, ip):
        self.srv, self.conn, self.ip = srv, conn, ip
        self.user, self.logged_in = "", False
        self.cwd = "/"
        self.pasv = None                                    # a listening socket from PASV / EPSV
        self.port_addr = None                               # (ip, port) from PORT / EPRT
        self.rename_from = None
        self.binary = True
        self.buf = b""

    # ---- plumbing
    def reply(self, text):
        try:
            self.conn.sendall((text + "\r\n").encode("utf-8", "replace"))
        except OSError:
            raise _FtpQuit                                  # the client hung up: the session just ends

    def readline(self):
        """One command line; raises _FtpQuit when the client went away or sat idle too long."""
        idle = time.time()
        while b"\n" not in self.buf:
            if self.srv.stop_event.is_set():
                raise _FtpQuit
            if time.time() - idle > self.srv.IDLE_SECONDS:
                self.reply("421 Timeout.")
                raise _FtpQuit
            try:
                data = self.conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                raise _FtpQuit
            if not data:
                raise _FtpQuit
            self.buf += data
            if len(self.buf) > 8192:
                self.reply("500 Line too long.")
                raise _FtpQuit
        line, _, self.buf = self.buf.partition(b"\n")
        return line.rstrip(b"\r").decode("utf-8", "replace")

    def run(self):
        self.conn.settimeout(1.0)
        self.reply("220 Toner FTP server ready.")
        try:
            while True:
                line = self.readline()
                if not line.strip():
                    continue
                verb, _, arg = line.partition(" ")
                verb, arg = verb.upper(), arg.strip()
                if verb not in ("USER", "PASS", "QUIT", "FEAT", "SYST", "NOOP", "OPTS", "HELP") and not self.logged_in:
                    self.reply("530 Please log in first.")
                    continue
                fn = getattr(self, "cmd_" + verb.lower(), None)
                if fn is None:
                    self.reply("502 Command not implemented.")
                    continue
                try:
                    fn(arg)
                except _FtpQuit:
                    raise
                except OSError as e:
                    self.reply(f"451 {str(e)[:100]}")
        except _FtpQuit:
            pass
        finally:
            self._close_pasv()

    def _close_pasv(self):
        if self.pasv is not None:
            try:
                self.pasv.close()
            except OSError:
                pass
            self.pasv = None

    def _local_ip(self):
        return self.conn.getsockname()[0]

    def _real(self, arg, allow_empty=True):
        """(path shown to the client, real path) for a name relative to the working folder, or None (refused, 550 sent)."""
        shown = posixpath.normpath(posixpath.join(self.cwd, arg.replace("\\", "/"))) if arg else self.cwd
        if not shown.startswith("/"):
            shown = "/" + shown
        try:
            return shown, resolve_path(self.srv.root, shown, allow_empty=allow_empty)
        except ValueError as e:
            self.srv.emit(self.ip, "access", arg, 0, "denied", str(e))
            self.reply("550 Permission denied.")
            return None

    def _data(self):
        """The data connection for the transfer about to start, or None (425 sent)."""
        if self.pasv is not None:
            listener, self.pasv = self.pasv, None
            listener.settimeout(15)
            try:
                d, addr = listener.accept()
            except (socket.timeout, OSError):
                self.reply("425 No data connection was made.")
                return None
            finally:
                listener.close()
            if addr[0] != self.ip:                          # only the client that asked may take its data
                d.close()
                self.srv.emit(self.ip, "access", "", 0, "denied", f"data connection from another address ({addr[0]})")
                self.reply("425 Data connection from another address refused.")
                return None
        elif self.port_addr is not None:
            d = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            d.settimeout(15)
            try:
                d.bind((self._local_ip(), 0))               # any source port: no client checks for port 20, and a fixed
                d.connect(self.port_addr)                   # one clashes with TIME_WAIT on back-to-back transfers
            except OSError as e:
                d.close()
                self.reply(f"425 Could not open the data connection: {str(e)[:80]}")
                self.port_addr = None
                return None
            self.port_addr = None
        else:
            self.reply("425 Use PORT or PASV first.")
            return None
        d.settimeout(30)
        return d

    # ---- signing in
    def cmd_user(self, arg):
        self.user, self.logged_in = arg, False
        self.reply("331 Password required.")

    def cmd_pass(self, arg):
        good = hmac.compare_digest(self.user.encode(), self.srv.username.encode()) and hmac.compare_digest(arg.encode(), self.srv.password.encode())
        if good:
            self.logged_in = True
            self.srv.forgive(self.ip)
            self.srv.emit(self.ip, "login", "", 0, "ok", f"user {self.user}")
            self.reply("230 Logged in.")
            return
        self.srv.failed_login(self.ip, self.user)
        self.reply("530 Login incorrect.")
        if self.srv.locked(self.ip):
            raise _FtpQuit

    def cmd_quit(self, arg):
        self.reply("221 Goodbye.")
        raise _FtpQuit

    # ---- the client asking what we are
    def cmd_syst(self, arg):
        self.reply("215 UNIX Type: L8")

    def cmd_feat(self, arg):
        self.reply("211-Features:\r\n UTF8\r\n SIZE\r\n MDTM\r\n MLST type*;size*;modify*;\r\n MLSD\r\n EPSV\r\n PASV\r\n211 End")

    def cmd_opts(self, arg):
        self.reply("200 OK." if arg.upper().startswith("UTF8") else "501 Option not understood.")

    def cmd_help(self, arg):
        self.reply("214 Toner FTP server: USER PASS QUIT SYST FEAT TYPE PWD CWD CDUP PASV EPSV PORT EPRT LIST NLST MLSD MLST SIZE MDTM RETR STOR DELE MKD RMD RNFR RNTO NOOP")

    def cmd_noop(self, arg):
        self.reply("200 OK.")

    def cmd_type(self, arg):
        t = arg.upper()[:1]
        if t in ("I", "L"):
            self.binary = True
            self.reply("200 Type set to I.")
        elif t == "A":
            self.binary = False
            self.reply("200 Type set to A.")
        else:
            self.reply("504 Only types A and I.")

    def cmd_mode(self, arg):
        self.reply("200 Mode S." if arg.upper() == "S" else "504 Only stream mode.")

    def cmd_stru(self, arg):
        self.reply("200 Structure F." if arg.upper() == "F" else "504 Only file structure.")

    def cmd_abor(self, arg):
        self._close_pasv()
        self.reply("226 Nothing to abort.")

    # ---- folders
    def cmd_pwd(self, arg):
        self.reply(f'257 "{self.cwd}" is the current folder.')

    def cmd_cwd(self, arg):
        got = self._real(arg)
        if got is None:
            return
        shown, real = got
        if not os.path.isdir(real):
            self.reply("550 No such folder.")
            return
        self.cwd = shown
        self.reply("250 OK.")

    def cmd_cdup(self, arg):
        self.cmd_cwd("..")

    def cmd_mkd(self, arg):
        if not self._may_write("mkdir", arg):
            return
        got = self._real(arg, allow_empty=False)
        if got is None:
            return
        shown, real = got
        try:
            os.mkdir(real)
        except OSError as e:
            self.srv.emit(self.ip, "mkdir", shown, 0, "failed", str(e)[:100])
            self.reply("550 Could not create the folder.")
            return
        self.srv.emit(self.ip, "mkdir", shown, 0, "ok")
        self.reply(f'257 "{shown}" created.')

    def cmd_rmd(self, arg):
        self._remove("rmdir", arg, os.rmdir)

    def cmd_dele(self, arg):
        self._remove("delete", arg, os.remove)

    def _may_write(self, what, arg, needs_replace=False):
        if not self.srv.allow_write:
            self.srv.emit(self.ip, what, arg, 0, "denied", "uploads are switched off")
            self.reply("550 Uploads are switched off on this server.")
            return False
        if needs_replace and not self.srv.allow_overwrite:
            self.srv.emit(self.ip, what, arg, 0, "denied", "replacing and deleting are switched off")
            self.reply("550 Replacing and deleting are switched off on this server.")
            return False
        return True

    def _remove(self, what, arg, fn):
        if not self._may_write(what, arg, needs_replace=True):
            return
        got = self._real(arg, allow_empty=False)
        if got is None:
            return
        shown, real = got
        try:
            fn(real)
        except OSError as e:
            self.srv.emit(self.ip, what, shown, 0, "failed", str(e)[:100])
            self.reply("550 Could not delete it.")
            return
        self.srv.emit(self.ip, what, shown, 0, "ok")
        self.reply("250 Deleted.")

    def cmd_rnfr(self, arg):
        if not self._may_write("rename", arg, needs_replace=True):
            return
        got = self._real(arg, allow_empty=False)
        if got is None:
            return
        if not os.path.exists(got[1]):
            self.reply("550 No such file.")
            return
        self.rename_from = got
        self.reply("350 Now send RNTO.")

    def cmd_rnto(self, arg):
        if self.rename_from is None:
            self.reply("503 Send RNFR first.")
            return
        src, self.rename_from = self.rename_from, None
        got = self._real(arg, allow_empty=False)
        if got is None:
            return
        shown, real = got
        if os.path.exists(real):
            self.reply("550 The new name is already in use.")
            return
        try:
            os.rename(src[1], real)
        except OSError as e:
            self.srv.emit(self.ip, "rename", src[0], 0, "failed", str(e)[:100])
            self.reply("550 Could not rename it.")
            return
        self.srv.emit(self.ip, "rename", src[0], 0, "ok", f"to {shown}")
        self.reply("250 Renamed.")

    # ---- data connections
    def cmd_pasv(self, arg):
        self._close_pasv()
        local = self._local_ip()
        s = self.srv.passive_socket(local)
        if s is None:
            self.reply("425 No passive port is free.")
            return
        self.pasv, self.port_addr = s, None
        port = s.getsockname()[1]
        shown = self.srv.advertise or local
        self.reply(f"227 Entering Passive Mode ({shown.replace('.', ',')},{port // 256},{port % 256}).")

    def cmd_epsv(self, arg):
        if arg.upper() == "ALL":
            self.reply("200 OK.")
            return
        self._close_pasv()
        s = self.srv.passive_socket(self._local_ip())
        if s is None:
            self.reply("425 No passive port is free.")
            return
        self.pasv, self.port_addr = s, None
        self.reply(f"229 Entering Extended Passive Mode (|||{s.getsockname()[1]}|)")

    def cmd_port(self, arg):
        parts = arg.split(",")
        if len(parts) != 6 or not all(p.strip().isdigit() for p in parts):
            self.reply("501 Bad PORT.")
            return
        n = [int(p) for p in parts]
        self._set_port(".".join(str(x) for x in n[:4]), n[4] * 256 + n[5])

    def cmd_eprt(self, arg):
        parts = arg.split(arg[:1]) if arg else []
        if len(parts) < 5 or parts[1] != "1" or not parts[4].isdigit():
            self.reply("501 Bad EPRT (only IPv4).")
            return
        self._set_port(parts[2], int(parts[4]))

    def _set_port(self, ip, port):
        if ip != self.ip or not (1 <= port <= 65535):        # no bouncing to third parties
            self.srv.emit(self.ip, "access", "", 0, "denied", f"PORT to another address refused ({ip}:{port})")
            self.reply("501 The data address must be your own.")
            return
        self._close_pasv()
        self.port_addr = (ip, port)
        self.reply("200 PORT OK.")

    # ---- listings
    def _entries(self, real):
        out = []
        for n in sorted(os.listdir(real)):
            if n.lower().endswith(PART):
                continue
            try:
                out.append((n, os.lstat(os.path.join(real, n))))
            except OSError:
                pass
        return out

    def _send_listing(self, arg, fmt):
        name = arg
        for flag in ("-a", "-l", "-la", "-al", "-A"):     # some clients send ls options
            if name.startswith(flag + " "):
                name = name[len(flag) + 1:]
            elif name == flag:
                name = ""
        got = self._real(name)
        if got is None:
            return
        shown, real = got
        if not os.path.exists(real):
            self.reply("550 No such file or folder.")
            return
        d = self._data()
        if d is None:
            return
        self.reply("150 Here comes the listing.")
        try:
            if os.path.isdir(real):
                lines = [fmt(n, st) for n, st in self._entries(real)]
            else:
                lines = [fmt(posixpath.basename(shown), os.stat(real))]
            d.sendall("".join(l + "\r\n" for l in lines).encode("utf-8", "replace"))
        except OSError as e:
            self.reply(f"426 The listing was not sent: {str(e)[:80]}")
            return
        finally:
            d.close()
        self.reply("226 Listing sent.")

    def cmd_list(self, arg):
        self._send_listing(arg, _ls_line)

    def cmd_nlst(self, arg):
        self._send_listing(arg, lambda n, st: n)

    def cmd_mlsd(self, arg):
        self._send_listing(arg, _mlsx_line)

    def cmd_mlst(self, arg):
        got = self._real(arg)
        if got is None:
            return
        shown, real = got
        if not os.path.exists(real):
            self.reply("550 No such file or folder.")
            return
        self.reply(f"250-Listing {shown}\r\n {_mlsx_line(shown, os.stat(real))}\r\n250 End")

    def cmd_size(self, arg):
        got = self._real(arg, allow_empty=False)
        if got is None:
            return
        if not os.path.isfile(got[1]):
            self.reply("550 No such file.")
            return
        self.reply(f"213 {os.path.getsize(got[1])}")

    def cmd_mdtm(self, arg):
        got = self._real(arg, allow_empty=False)
        if got is None:
            return
        if not os.path.isfile(got[1]):
            self.reply("550 No such file.")
            return
        self.reply("213 " + time.strftime("%Y%m%d%H%M%S", time.gmtime(os.path.getmtime(got[1]))))

    # ---- files
    def cmd_retr(self, arg):
        got = self._real(arg, allow_empty=False)
        if got is None:
            return
        shown, real = got
        if not os.path.isfile(real):
            self.srv.emit(self.ip, "read", shown, 0, "failed", "file not found")
            self.reply("550 File not found.")
            return
        d = self._data()
        if d is None:
            return
        size = os.path.getsize(real)
        self.reply(f"150 Opening data connection for {posixpath.basename(shown)} ({size} bytes).")
        sent, started = 0, time.time()
        try:
            with open(real, "rb") as fh, d:
                while True:
                    if self.srv.stop_event.is_set():
                        raise OSError("server stopped")
                    block = fh.read(65536)
                    if not block:
                        break
                    d.sendall(block)
                    sent += len(block)
        except OSError as e:
            self.srv.emit(self.ip, "read", shown, sent, "failed", str(e)[:100])
            self.reply(f"426 The transfer stopped: {str(e)[:80]}")
            return
        self.srv.emit(self.ip, "read", shown, sent, "ok", _rate(sent, time.time() - started))
        self.reply("226 Transfer complete.")

    def cmd_stor(self, arg):
        got = self._real(arg, allow_empty=False)
        if got is None:
            return
        shown, real = got
        if not self._may_write("write", shown, needs_replace=os.path.exists(real)):
            return
        if os.path.isdir(real) or not os.path.isdir(os.path.dirname(real)):
            self.reply("553 Cannot write there.")
            return
        d = self._data()
        if d is None:
            return
        self.reply("150 OK to send data.")
        part, got_bytes, started, ok = real + PART, 0, time.time(), False
        try:
            with open(part, "wb") as out, d:
                while True:
                    if self.srv.stop_event.is_set():
                        raise OSError("server stopped")
                    block = d.recv(65536)
                    if not block:
                        break
                    got_bytes += len(block)
                    if got_bytes > self.srv.max_bytes:
                        raise OSError(f"larger than the {_limit(self.srv.max_bytes)} limit")
                    out.write(block)
            if os.path.exists(real) and not self.srv.allow_overwrite:
                raise OSError("the file appeared during the upload")
            os.replace(part, real)
            ok = True
        except OSError as e:
            self.srv.emit(self.ip, "write", shown, got_bytes, "failed", str(e)[:100])
            self.reply(f"426 The upload was not kept: {str(e)[:80]}")
        finally:
            if not ok and os.path.exists(part):
                try:
                    os.remove(part)
                except OSError:
                    pass
        if ok:
            self.srv.emit(self.ip, "write", shown, got_bytes, "ok", _rate(got_bytes, time.time() - started))
            self.reply("226 Transfer complete.")


def new_password(n=16):
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))
