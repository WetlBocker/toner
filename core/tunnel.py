"""An SSH tunnel used as a proxy (Settings > Proxy > SSH tunnel), what `ssh -D` does.

Toner signs in to an SSH server (a bastion that may ask for a password, a one-time code or a YubiKey touch), keeps that
session open, and forwards connections through it. Everything else in Toner talks to a SOCKS5 listener on this computer
that belongs to the tunnel, so SSH, web requests and notifications all go through it the same way as through any proxy.
The listener is on 127.0.0.1 only and wants a random user name and password, so no other program can use the tunnel.
"""
import secrets
import socket
import struct
import threading
import time
from dataclasses import replace

import paramiko

from core import db, nettools, quiet
from core import proxy

OTP_WORDS = ("otp", "one-time", "one time", "verification", "passcode", "yubi", "token", "code", "authenticator", "duo", "press", "touch")

_tunnels = {}                       # (host, port, user) -> Tunnel
_open_lock = threading.Lock()       # one sign-in at a time, so two checks do not both ask for a code


def _key(cfg):
    return (cfg.host, cfg.port, cfg.username)


# ---------------------------------------------------------------- signing in
class _Client(paramiko.SSHClient):
    """SSHClient does the connecting and checks the server's host key (with Toner's host-key setting); the sign-in itself,
    which an ordinary client cannot do for a server that asks questions, is done by `login`."""
    login = None

    def _auth(self, username, *args, **kwargs):
        self.login(self._transport)


def _handler(cfg, errors):
    """Answers the server's questions. Paramiko calls this on its own thread, where an exception would stop the connection
    without a word, so a problem is kept in `errors` (and an empty answer given) for `_login` to raise."""
    def answer(title, instructions, prompts):
        out = []
        try:
            for text, _echo in prompts:
                low = text.lower()
                if any(w in low for w in OTP_WORDS):
                    out.append(proxy.one_time_code(replace(cfg, otp=cfg.otp or "ask"), prompt=text, reuse=False))
                elif "password" in low and cfg.password:
                    out.append(cfg.password)
                elif "password" in low:
                    out.append(proxy.ask_text(cfg, "Password", f"{cfg.label()} asks: {text.strip()}", secret=True))
                else:
                    out.append(proxy.ask_text(cfg, "Sign-in", f"{cfg.label()} asks: {text.strip()}"))
        except proxy.ProxyError as e:
            errors.append(e)
            out += [""] * (len(prompts) - len(out))
        return out
    return answer


def _login(t, cfg):
    """Password first when there is one, then the server's questions; whichever the server wants, in the order it wants."""
    errors = []
    handler = _handler(cfg, errors)
    wanted = ["password", "keyboard-interactive"] if cfg.password else ["keyboard-interactive", "password"]
    done, remaining = set(), None
    for _ in range(4):
        kind = next((k for k in wanted if k not in done and (remaining is None or k in remaining)), None)
        if kind is None:
            break
        done.add(kind)
        try:
            if kind == "password":
                remaining = t.auth_password(cfg.username, cfg.password or proxy.ask_text(
                    cfg, "Password", f"{cfg.label()} asks for the password of {cfg.username}.", secret=True))
            else:
                remaining = t.auth_interactive(cfg.username, handler)
        except paramiko.BadAuthenticationType as e:
            remaining = list(e.allowed_types)                 # not that way yet: the server says which ways it takes
            done.discard(kind)                                # (it may want this one later, after the other)
            continue
        except paramiko.AuthenticationException:
            if errors:
                raise errors[0] from None
            raise proxy.ProxyError(f"{cfg.label()} rejected the sign-in (user name, password or one-time code)") from None
        if not remaining:
            return
    if t.is_authenticated():
        return
    raise proxy.ProxyError(f"{cfg.label()} did not accept the sign-in"
                           + (f"; it still wants {', '.join(remaining)}, which Toner cannot do" if remaining else ""))


# ---------------------------------------------------------------- the local end
def _recvn(s, n):
    out = b""
    while len(out) < n:
        c = s.recv(n - len(out))
        if not c:
            raise OSError("closed")
        out += c
    return out


def _pipe(sock, chan):
    def up():
        try:
            while True:
                d = sock.recv(32768)
                if not d:
                    break
                chan.sendall(d)
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            try:
                chan.shutdown_write()
            except Exception:
                quiet.ignored()
    threading.Thread(target=up, daemon=True).start()
    try:
        while True:
            d = chan.recv(32768)
            if not d:
                break
            sock.sendall(d)
    except (OSError, EOFError, paramiko.SSHException):
        pass
    finally:
        for c in (chan, sock):
            try:
                c.close()
            except Exception:
                quiet.ignored()


class Tunnel:
    def __init__(self, cfg):
        self.cfg = cfg
        self.user, self.password = "toner", secrets.token_urlsafe(18)      # for the local listener only
        self.client = self.listener = None
        self.port = 0
        self.since = None

    # ------------------------------------------------------------ open and close
    def open(self, timeout=20):
        cfg = self.cfg
        client = _Client()
        nettools.configure_hostkeys(client, db.get_setting("hostkey_mode"))
        client.login = lambda t: _login(t, cfg)
        try:
            client.connect(cfg.host, port=cfg.port, username=cfg.username or "", timeout=timeout, banner_timeout=timeout,
                           auth_timeout=120, allow_agent=False, look_for_keys=False)
        except proxy.ProxyError:
            client.close()
            raise
        except (paramiko.SSHException, EOFError) as e:
            client.close()
            raise proxy.ProxyError(f"{cfg.label()}: {e}") from None
        except OSError as e:
            client.close()
            raise proxy.ProxyError(f"could not reach the proxy {cfg.label()}: {str(e) or type(e).__name__}") from None
        t = client.get_transport()
        t.set_keepalive(30)
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(32)
        self.client, self.listener, self.port, self.since = client, ls, ls.getsockname()[1], time.time()
        threading.Thread(target=self._accept, daemon=True).start()

    def alive(self):
        t = self.client.get_transport() if self.client else None
        return bool(t and t.is_active() and self.listener is not None)

    def close(self):
        ls, self.listener = self.listener, None
        for c in (ls, self.client):
            try:
                if c:
                    c.close()
            except Exception:
                quiet.ignored()

    # ------------------------------------------------------------ the SOCKS5 listener
    def _accept(self):
        ls = self.listener
        while ls is not None:
            try:
                c, _ = ls.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            c.settimeout(15)
            ver, n = _recvn(c, 2)
            methods = _recvn(c, n)
            if ver != 5 or 2 not in methods:
                c.sendall(b"\x05\xff")
                return
            c.sendall(b"\x05\x02")
            _recvn(c, 1)
            user = _recvn(c, _recvn(c, 1)[0]).decode("utf-8", "replace")
            pw = _recvn(c, _recvn(c, 1)[0]).decode("utf-8", "replace")
            if not (secrets.compare_digest(user, self.user) and secrets.compare_digest(pw, self.password)):
                c.sendall(b"\x01\x01")
                return
            c.sendall(b"\x01\x00")
            _ver, cmd, _rsv, atyp = _recvn(c, 4)
            if atyp == 1:
                host = socket.inet_ntoa(_recvn(c, 4))
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, _recvn(c, 16))
            else:
                host = _recvn(c, _recvn(c, 1)[0]).decode("idna", "replace")
            port = struct.unpack(">H", _recvn(c, 2))[0]
            if cmd != 1:
                c.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            try:
                chan = self.client.get_transport().open_channel("direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=15)
            except paramiko.ChannelException as e:
                c.sendall(bytes([5, {1: 2, 2: 5}.get(e.code, 1), 0, 1, 0, 0, 0, 0, 0, 0]))     # not allowed / refused / failure
                return
            except (paramiko.SSHException, EOFError, OSError, AttributeError):
                c.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            c.settimeout(None)
            _pipe(c, chan)
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                quiet.ignored()


# ---------------------------------------------------------------- the open tunnels
def get(cfg, connect=True):
    """The open tunnel for this proxy, signing in first (and asking for a code, if it wants one) when there is none."""
    t = _tunnels.get(_key(cfg))
    if t is not None and t.alive():
        return t
    if not connect:
        return None
    with _open_lock:
        t = _tunnels.get(_key(cfg))
        if t is not None and t.alive():
            return t
        if t is not None:
            t.close()
        t = Tunnel(cfg)
        t.open()
        _tunnels[_key(cfg)] = t
        return t


def is_open(cfg):
    t = _tunnels.get(_key(cfg))
    return bool(t and t.alive())


def close(cfg):
    t = _tunnels.pop(_key(cfg), None)
    if t:
        t.close()


def close_all():
    for k in list(_tunnels):
        t = _tunnels.pop(k, None)
        if t:
            t.close()
