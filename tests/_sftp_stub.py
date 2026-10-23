"""An SFTP subsystem for the test SSH server (_ssh_shell.ShellServer): it serves one folder on this computer, so the Files
panel can be tried against a real paramiko SFTP channel. Modelled on paramiko's own stub server."""
import os
import posixpath

import paramiko
from paramiko import SFTPAttributes, SFTPHandle, SFTPServerInterface, SFTP_OK


class StubHandle(SFTPHandle):
    def stat(self):
        try:
            return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def chattr(self, attr):
        return SFTP_OK


class StubSftp(SFTPServerInterface):
    def __init__(self, server, *a, root="", slow=None, **kw):
        super().__init__(server, *a, **kw)
        self.root, self.slow = root, slow or (lambda: 0.0)         # slow(): seconds to sleep per write, read as it changes

    def _real(self, path):
        return os.path.join(self.root, posixpath.normpath("/" + str(path).replace("\\", "/")).lstrip("/").replace("/", os.sep))

    def canonicalize(self, path):
        p = posixpath.normpath("/" + str(path).replace("\\", "/"))
        return p if p.startswith("/") else "/" + p

    def list_folder(self, path):
        real = self._real(path)
        try:
            out = []
            for n in sorted(os.listdir(real)):
                a = SFTPAttributes.from_stat(os.lstat(os.path.join(real, n)))
                a.filename = n
                out.append(a)
            return out
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        try:
            return SFTPAttributes.from_stat(os.stat(self._real(path)))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        try:
            return SFTPAttributes.from_stat(os.lstat(self._real(path)))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def open(self, path, flags, attr):
        real = self._real(path)
        try:
            fd = os.open(real, flags | getattr(os, "O_BINARY", 0), 0o644)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        if flags & os.O_WRONLY:
            mode = "ab" if flags & os.O_APPEND else "wb"
        elif flags & os.O_RDWR:
            mode = "a+b" if flags & os.O_APPEND else "r+b"
        else:
            mode = "rb"
        f = os.fdopen(fd, mode)
        h = StubHandle(flags)
        h.filename = real
        h.readfile = f
        h.writefile = f
        if "w" in mode:
            import time
            orig, slow = h.write, self.slow

            def write(offset, data):
                if slow():
                    time.sleep(slow())                   # a slow link, so a transfer can be cancelled half way
                return orig(offset, data)
            h.write = write
        return h

    def _do(self, fn):
        try:
            fn()
            return SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def remove(self, path):
        return self._do(lambda: os.remove(self._real(path)))

    def rename(self, old, new):
        return self._do(lambda: os.rename(self._real(old), self._real(new)))

    def mkdir(self, path, attr):
        return self._do(lambda: os.mkdir(self._real(path)))

    def rmdir(self, path):
        return self._do(lambda: os.rmdir(self._real(path)))

    def chattr(self, path, attr):
        return SFTP_OK

    def symlink(self, target, path):
        return self._do(lambda: os.symlink(self._real(target), self._real(path)))

    def readlink(self, path):
        try:
            return os.readlink(self._real(path))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)


def attach(transport, root, slow=None):
    """Give a paramiko Transport (the test shell server's) an SFTP subsystem that serves `root`. slow: a function giving the
    seconds to sleep per write."""
    transport.set_subsystem_handler("sftp", paramiko.SFTPServer, sftp_si=StubSftp, root=root, slow=slow)
