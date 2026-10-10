"""SCP: copy files to and from a device over SSH, with the classic `scp -t` (receive) and `scp -f` (send) protocol that
Linux, routers, switches and firewalls understand (Cisco needs `ip scp server enable`; Junos, Arista, MikroTik and
HPE have it on or one command away). Credentials, jump hosts and proxies work as they do for every other SSH use.

Safety on download: a device chooses the names of the files it sends, so each name is checked. A name with a path
separator, '.' or '..' is refused and nothing is written outside the folder you chose.
"""
import os
import re
import time

import paramiko

from core import jump, nettools

CHUNK = 32768
MAX_SIZE = 1 << 40
_PLAIN = re.compile(r"^[A-Za-z0-9_@%+=:,./~-]+$")


class ScpError(Exception):
    pass


class Cancelled(ScpError):
    pass


def quote(path):
    """The remote path as the remote shell should see it. Plain paths are sent as they are, which is what network
    devices expect (flash:/image.bin); anything with spaces or shell characters is single-quoted."""
    return path if _PLAIN.match(path) else "'" + path.replace("'", "'\\''") + "'"


def safe_name(name):
    if not name or name in (".", "..") or any(c in name for c in "/\\\x00\r\n") or (os.name == "nt" and ":" in name):
        raise ScpError(f"the device sent an unsafe file name ({name[:60]!r}); nothing was written")
    return name


def connect(host, port, user, password, dev=None, hostkey_mode="Trust on first use", timeout=15):
    """(paramiko client, [objects to close afterwards]). Goes through the device's jump host or proxy if it has one."""
    client = paramiko.SSHClient()
    nettools.configure_hostkeys(client, hostkey_mode)
    sock, extra = jump.open_channel(dev, timeout) if dev else (None, [])
    try:
        client.connect(host, port=port, username=user, password=password, timeout=timeout, banner_timeout=timeout,
                       auth_timeout=timeout, allow_agent=False, look_for_keys=False, sock=sock)
    except Exception:
        client.close()
        for c in extra:
            c.close()
        raise
    return client, extra


class Scp:
    def __init__(self, client, progress=None, cancel=None, timeout=30):
        """progress(kind, name, done, total): kind is 'file' (starting), 'bytes' (moving) or 'dir'."""
        self.client, self.progress, self.cancel, self.timeout = client, progress or (lambda *a: None), cancel, timeout
        self.files = self.bytes = 0
        self.skipped = []

    # ---------------------------------------------------------------- plumbing
    def _open(self, flags, path):
        chan = self.client.get_transport().open_session(timeout=self.timeout)
        chan.settimeout(self.timeout)
        chan.exec_command(f"scp {flags} {quote(path)}".replace("  ", " "))
        return chan

    def _check_cancel(self):
        if self.cancel is not None and self.cancel.is_set():
            raise Cancelled("cancelled")

    def _stderr(self, chan):
        out = b""
        try:
            while chan.recv_stderr_ready():
                out += chan.recv_stderr(4096)
        except (OSError, EOFError):
            pass
        return " ".join(out.decode("utf-8", "replace").split())

    def _byte(self, chan):
        try:
            b = chan.recv(1)
        except OSError as e:
            raise ScpError(f"the connection stopped answering ({e})") from None
        if not b:
            why = self._stderr(chan)
            raise ScpError(why or "the device closed the connection without answering. It may not allow scp "
                                  "(on Cisco IOS: ip scp server enable).")
        return b

    def _line(self, chan):
        out = b""
        while not out.endswith(b"\n"):
            out += self._byte(chan)
            if len(out) > 4096:
                raise ScpError("the device sent a line that is too long")
        return out[:-1].decode("utf-8", "replace")

    def _ack(self, chan):
        b = self._byte(chan)
        if b == b"\x00":
            return
        if b in (b"\x01", b"\x02"):
            raise ScpError(self._line(chan) or "the device reported an error")
        raise ScpError(f"unexpected reply from the device ({b!r}); is it really an scp service?")

    def _exact(self, chan, n):
        out = b""
        while len(out) < n:
            self._check_cancel()
            try:
                chunk = chan.recv(min(CHUNK, n - len(out)))
            except OSError as e:
                raise ScpError(f"the connection stopped answering ({e})") from None
            if not chunk:
                raise ScpError("the device stopped sending in the middle of a file")
            out += chunk
        return out

    # ---------------------------------------------------------------- upload
    def upload(self, local, remote, recursive=False, preserve=False):
        local = os.path.abspath(local)
        if os.path.isdir(local) and not recursive:
            raise ScpError(f"{local} is a folder: tick 'Include sub-folders' to send it")
        if not os.path.exists(local):
            raise ScpError(f"{local} does not exist")
        chan = self._open(("-r " if recursive else "") + ("-p " if preserve else "") + "-t", remote)
        try:
            self._ack(chan)
            self._send_tree(chan, local, preserve)
        finally:
            chan.close()
        return self.files, self.bytes

    def _send_tree(self, chan, path, preserve):
        self._check_cancel()
        name = safe_name(os.path.basename(path.rstrip("\\/")) or "root")
        st = os.stat(path)
        if preserve:
            chan.sendall(f"T{int(st.st_mtime)} 0 {int(st.st_atime)} 0\n".encode())
            self._ack(chan)
        if os.path.isdir(path):
            self.progress("dir", name, 0, 0)
            chan.sendall(f"D0755 0 {name}\n".encode())
            self._ack(chan)
            for entry in sorted(os.scandir(path), key=lambda e: e.name.lower()):
                if not entry.is_symlink():
                    self._send_tree(chan, entry.path, preserve)
            chan.sendall(b"E\n")
            self._ack(chan)
            return
        size = st.st_size
        self.progress("file", name, 0, size)
        chan.sendall(f"C0644 {size} {name}\n".encode())
        self._ack(chan)
        sent = 0
        with open(path, "rb") as fh:
            while True:
                self._check_cancel()
                block = fh.read(CHUNK)
                if not block:
                    break
                chan.sendall(block)
                sent += len(block)
                self.progress("bytes", name, sent, size)
        chan.sendall(b"\x00")
        self._ack(chan)
        self.files += 1
        self.bytes += sent

    # ---------------------------------------------------------------- download
    def download(self, remote, local, recursive=False, preserve=False, overwrite=False):
        chan = self._open(("-r " if recursive else "") + ("-p " if preserve else "") + "-f", remote)
        into_dir = os.path.isdir(local) or recursive
        if recursive:
            os.makedirs(local, exist_ok=True)
        stack, mtimes, first = [os.path.abspath(local)], None, True
        try:
            chan.sendall(b"\x00")
            while True:
                self._check_cancel()
                try:
                    kind = chan.recv(1)
                except OSError as e:
                    raise ScpError(f"the connection stopped answering ({e})") from None
                if not kind:
                    break
                if kind in (b"\x01", b"\x02"):
                    raise ScpError(self._line(chan) or "the device reported an error")
                line = self._line(chan)
                if kind == b"T":
                    parts = line.split()
                    mtimes = (int(parts[2]), int(parts[0])) if len(parts) >= 3 and parts[0].isdigit() and parts[2].isdigit() else None
                    chan.sendall(b"\x00")
                elif kind == b"D":
                    m = re.match(r"^(\d+) (\d+) (.+)$", line)
                    if not m:
                        raise ScpError(f"the device sent something unexpected ({line[:60]!r})")
                    if not recursive:
                        raise ScpError("the device sent a folder, but 'Include sub-folders' is not ticked")
                    path = os.path.join(stack[-1], safe_name(m.group(3)))
                    os.makedirs(path, exist_ok=True)
                    stack.append(path)
                    self.progress("dir", m.group(3), 0, 0)
                    chan.sendall(b"\x00")
                elif kind == b"E":
                    if len(stack) > 1:
                        stack.pop()
                    chan.sendall(b"\x00")
                elif kind == b"C":
                    m = re.match(r"^(\d+) (\d+) (.+)$", line)
                    if not m or int(m.group(2)) > MAX_SIZE:
                        raise ScpError(f"the device sent something unexpected ({line[:60]!r})")
                    size, name = int(m.group(2)), safe_name(m.group(3))
                    target = os.path.join(stack[-1], name) if (into_dir or not first) else os.path.abspath(local)
                    first = False
                    chan.sendall(b"\x00")
                    self._receive_file(chan, target, name, size, overwrite, mtimes if preserve else None)
                    mtimes = None
                    chan.sendall(b"\x00")
                else:
                    raise ScpError(f"unexpected data from the device ({kind!r}); is it really an scp service?")
        finally:
            chan.close()
        return self.files, self.bytes

    def _receive_file(self, chan, target, name, size, overwrite, mtimes):
        self.progress("file", name, 0, size)
        skip = os.path.exists(target) and not overwrite
        got, part = 0, target + ".toner-part"
        out = None if skip else open(part, "wb")
        try:
            while got < size:
                self._check_cancel()
                try:
                    block = chan.recv(min(CHUNK, size - got))
                except OSError as e:
                    raise ScpError(f"the connection stopped answering ({e})") from None
                if not block:
                    raise ScpError("the device stopped sending in the middle of a file")
                if out:
                    out.write(block)
                got += len(block)
                self.progress("bytes", name, got, size)
            self._ack(chan)                              # the sender's end-of-file byte
        except BaseException:
            if out:
                out.close()
                out = None
                try:
                    os.remove(part)
                except OSError:
                    pass
            raise
        finally:
            if out:
                out.close()
        if skip:
            self.skipped.append(target)
            return
        os.replace(part, target)
        if mtimes:
            os.utime(target, mtimes)
        self.files += 1
        self.bytes += got
