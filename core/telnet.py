"""Telnet: a connection thread with the same shape as the SSH one (data / closed signals, send, resize, stop) and the
small part of the Telnet protocol a terminal needs. Python 3.13 no longer ships telnetlib, so this is our own."""
import re
import socket
import threading

from PySide6.QtCore import QThread, Signal

from core import proxy

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO, SGA, TTYPE, NAWS = 1, 3, 24, 31
_CR_ALONE = re.compile(rb"\r(?!\n)")


class TelnetFilter:
    """Turns what the server sends into terminal data plus the replies the protocol needs. It keeps its place between
    chunks, so a command split across two reads is still understood."""

    def __init__(self, term=b"xterm-256color", cols=100, rows=30):
        self.term, self.cols, self.rows = term, cols, rows
        self.state, self.cmd, self.sb = "data", 0, b""
        self.sent = set()                          # (command, option) replies already given: never answer twice (no loops)
        self.naws_on = False
        self.prev_cr = False

    @staticmethod
    def _cmd(cmd, opt):
        return bytes([IAC, cmd, opt])

    def _reply(self, out, cmd, opt):
        if (cmd, opt) not in self.sent:
            self.sent.add((cmd, opt))
            out += self._cmd(cmd, opt)
        return out

    def naws(self):
        w, h = int(self.cols), int(self.rows)
        body = bytes([w >> 8, w & 255, h >> 8, h & 255]).replace(b"\xff", b"\xff\xff")
        return bytes([IAC, SB, NAWS]) + body + bytes([IAC, SE])

    def set_size(self, cols, rows):
        """The bytes to send when the window changes size (empty until the server has asked for it)."""
        self.cols, self.rows = cols, rows
        return self.naws() if self.naws_on else b""

    def feed(self, data):
        """(terminal bytes, reply bytes)"""
        out, reply = bytearray(), b""
        for b in data:
            if self.state == "data":
                if b == IAC:
                    self.state = "iac"
                elif b == 0 and self.prev_cr:           # CR NUL is how Telnet sends a lone carriage return
                    self.prev_cr = False
                else:
                    out.append(b)
                    self.prev_cr = b == 13
            elif self.state == "iac":
                if b == IAC:
                    out.append(255)
                    self.state = "data"
                elif b in (DO, DONT, WILL, WONT):
                    self.cmd, self.state = b, "opt"
                elif b == SB:
                    self.sb, self.state = b"", "sb"
                else:
                    self.state = "data"                  # NOP, GA, ... nothing to do
            elif self.state == "opt":
                reply = self._negotiate(reply, self.cmd, b)
                self.state = "data"
            elif self.state == "sb":
                if b == IAC:
                    self.state = "sb_iac"
                else:
                    self.sb += bytes([b])
            elif self.state == "sb_iac":
                if b == SE:
                    reply += self._subnegotiate(self.sb)
                    self.state = "data"
                elif b == IAC:
                    self.sb += b"\xff"
                    self.state = "sb"
                else:
                    self.state = "data"
        return bytes(out), reply

    def _negotiate(self, reply, cmd, opt):
        if cmd == WILL:                                  # the server offers to do something
            return self._reply(reply, DO if opt in (ECHO, SGA) else DONT, opt)
        if cmd == WONT:
            return self._reply(reply, DONT, opt)
        if cmd == DO:                                    # the server asks us to do something
            if opt in (SGA, TTYPE, NAWS):
                first = (WILL, opt) not in self.sent
                reply = self._reply(reply, WILL, opt)
                if opt == NAWS and first:
                    self.naws_on = True
                    reply += self.naws()
                return reply
            return self._reply(reply, WONT, opt)
        return self._reply(reply, WONT, opt)             # DONT

    def _subnegotiate(self, sb):
        if len(sb) >= 2 and sb[0] == TTYPE and sb[1] == 1:       # SEND: tell it what terminal this is
            return bytes([IAC, SB, TTYPE, 0]) + self.term + bytes([IAC, SE])
        return b""

    @staticmethod
    def encode(data):
        """What to send for keystrokes: Enter is CR LF, and a literal 0xFF is doubled."""
        return _CR_ALONE.sub(b"\r\n", data).replace(b"\xff", b"\xff\xff")


class TelnetSession(QThread):
    data = Signal(bytes)
    closed = Signal(str)

    def __init__(self, host, port=23, cols=100, rows=30, timeout=15, dev=None):
        super().__init__()
        self.host, self.port, self.timeout, self.dev = host, int(port), timeout, dev
        self.filter = TelnetFilter(cols=cols, rows=rows)
        self.sock = None
        self._stop = False
        self._lock = threading.Lock()

    def _send_raw(self, data):
        try:
            with self._lock:
                if self.sock and data:
                    self.sock.sendall(data)
        except OSError:
            pass                                          # the connection has gone; run() reports it

    def send(self, data: bytes):
        self._send_raw(self.filter.encode(data))

    def resize(self, cols, rows):
        self._send_raw(self.filter.set_size(cols, rows))

    def stop(self):
        self._stop = True
        try:
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass

    def run(self):
        reason = "Connection closed by the remote host."
        try:
            self.sock = proxy.create_connection(self.dev, (self.host, self.port), self.timeout)
            if self._stop:
                raise InterruptedError
            self.sock.settimeout(0.3)
            while not self._stop:
                try:
                    chunk = self.sock.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                out, reply = self.filter.feed(chunk)
                self._send_raw(reply)
                if out:
                    self.data.emit(out)
        except InterruptedError:
            pass
        except ConnectionRefusedError:
            reason = f"Connection refused by {self.host}:{self.port}. Is Telnet switched on there?"
        except socket.gaierror:
            reason = f"Could not find {self.host}."
        except (socket.timeout, TimeoutError):
            reason = f"Timed out connecting to {self.host}:{self.port}."
        except OSError as e:
            reason = f"Connection failed: {e}" if not self._stop else reason
        finally:
            if self._stop:
                reason = "Disconnected by user."
            try:
                if self.sock:
                    self.sock.close()
            except OSError:
                pass
            self.closed.emit(reason)
