"""The SSH tunnel (Settings > Proxy > SSH Tunnel): what PuTTY's Dynamic port forwarding and `ssh -D` do.

Toner signs in to an SSH server (a bastion that may ask for a password, a Duo option, a one-time code or a YubiKey touch),
keeps that session open, and listens on a SOCKS5 port on this computer (1080 unless changed). The proxy settings, for every
connection or for one device, then point at SOCKS5 127.0.0.1:1080, exactly as they would at PuTTY's port. A connection
through that port while the tunnel is closed signs in first. Like PuTTY's, the port is on 127.0.0.1 only and asks for no
sign-in of its own, so programs on this computer can use it while it is open.
"""
import json
import logging
import socket
import struct
import threading
import time
from dataclasses import replace

import paramiko

from core import db, nettools, quiet
from core import proxy
from core.version import VERSION

OTP_WORDS = ("otp", "one-time", "one time", "verification", "passcode", "yubi", "token", "code", "authenticator", "duo", "press", "touch")

_open_lock = threading.Lock()       # one sign-in at a time, so two checks do not both ask for a code


def _key(cfg):
    return (cfg.host, cfg.port, cfg.username)


def _note(text):
    """A line in ssh-tunnel.log (see _SignInLog). Never a password, passphrase or code."""
    logging.getLogger("paramiko.toner.tunnel").info("TONER: %s", text)


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
        _note(f"the server asks {len(prompts)} question(s): " + " | ".join(repr(p[0]) for p in prompts)
              + (f" (title {title!r})" if title else "") + (f" (instructions {instructions!r})" if instructions else ""))
        try:
            for text, _echo in prompts:
                low = text.lower()
                if any(w in low for w in OTP_WORDS):            # with the server's own instructions (Duo lists its options)
                    said = "\n".join(x for x in (instructions.strip(), text.strip()) if x)
                    out.append(proxy.one_time_code(replace(cfg, otp=cfg.otp or "ask"), prompt=said, reuse=False))
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


def load_key(cfg):
    """The private key in cfg.key_file. The saved password is tried as its passphrase; a protected key without one (or with
    the wrong one) makes Toner ask. Raises ProxyError with what to do."""
    import os
    path = os.path.expandvars(os.path.expanduser(cfg.key_file.strip().strip('"')))
    name = os.path.basename(path)
    if not os.path.isfile(path):
        raise proxy.ProxyError(f"{cfg.label()}: the key file {path} was not found")
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError as e:
        raise proxy.ProxyError(f"{cfg.label()}: the key file {name} could not be read ({e})") from None
    if head.startswith(b"PuTTY-User-Key-File"):
        raise proxy.ProxyError(f"{name} is a PuTTY key (.ppk). Open it in PuTTYgen and use Conversions > Export OpenSSH key, "
                               f"then choose the exported file")
    tried = cfg.password or None
    try:
        return paramiko.PKey.from_path(path, password=tried.encode() if tried else None)
    except paramiko.PasswordRequiredException:
        pass                                                  # protected, and no passphrase saved
    except Exception as e:
        said = str(e).lower()                                 # an OpenSSH-format key says so in a TypeError instead
        protected = isinstance(e, TypeError) or any(w in said for w in ("password", "passphrase", "encrypted"))
        if tried is None and not protected:
            raise proxy.ProxyError(f"{cfg.label()}: {name} is not a private key Toner can read ({e or type(e).__name__}). "
                                   f"It takes OpenSSH and PEM keys: RSA, ECDSA and Ed25519") from None
    typed = proxy.ask_text(cfg, "Key passphrase", f"The key file {name} for {cfg.label()} is protected"
                           + (" and the saved password is not its passphrase" if tried else "") + ". Type its passphrase.", secret=True)
    if not typed:
        raise proxy.ProxyError(f"{cfg.label()}: no passphrase was entered for the key file {name}")
    try:
        return paramiko.PKey.from_path(path, password=typed.encode())
    except Exception:
        raise proxy.ProxyError(f"{cfg.label()}: wrong passphrase for the key file {name}") from None


AFTER = {"none": "before Toner could sign in", "publickey": "after the key file was tried",
         "password": "after the password was sent", "keyboard-interactive": "after the answers were sent"}


def _closed(t, cfg, kind, errors=()):
    """The server hung up during the sign-in (paramiko then says only 'No existing session')."""
    if errors:
        return errors[0]
    why = t.get_exception()
    return proxy.ProxyError(f"{cfg.label()} closed the connection {AFTER.get(kind, 'during the sign-in')}"
                            + (f" ({why})" if why and str(why) else "")
                            + ". A server often hangs up after a wrong answer, or when a code or YubiKey touch takes too long. "
                              "Try again; if it keeps happening, check the user name and the server's log")


def _login(t, cfg):
    """Ask the server which ways it takes (as ssh does), then use them in this order: the key file, the password, the server's
    own questions. With a key file the saved password is the key's passphrase, so it is not sent as a password. A password is
    never typed into a question the server asks (paramiko would otherwise answer a one-time code prompt with it)."""
    errors = []
    pkey = load_key(cfg) if cfg.key_file else None
    plain = replace(cfg, password="") if pkey else cfg
    handler = _handler(plain, errors)
    # OpenSSH's and PuTTY's order: the server's questions before a bare password. Duo and other second steps live in
    # keyboard-interactive (the saved password answers its "Password:" question); the password method cannot ask for them,
    # so on such a server it fails even with the right password.
    wanted = (["publickey"] if pkey else []) + ["keyboard-interactive", "password"]
    done, remaining, key_refused = set(), None, False
    try:
        remaining = t.auth_none(cfg.username)              # 'none' is how a client asks; it is not a failed try
        if not remaining or t.is_authenticated():
            return
    except paramiko.BadAuthenticationType as e:
        remaining = list(e.allowed_types)
    except paramiko.SSHException:
        if not t.is_active():
            raise _closed(t, cfg, "none") from None
        remaining = None
    _note(f"the server takes: {', '.join(remaining) if remaining else '(it did not say)'}")
    for _ in range(6):
        kind = next((k for k in wanted if k not in done and (remaining is None or k in remaining)), None)
        if kind is None:
            break
        done.add(kind)
        _note(f"trying {kind}")
        if not t.is_active():
            raise _closed(t, cfg, kind, errors)
        try:
            if kind == "publickey":
                remaining = t.auth_publickey(cfg.username, pkey)
            elif kind == "password":
                remaining = t.auth_password(cfg.username, plain.password or proxy.ask_text(
                    cfg, "Password", f"{cfg.label()} asks for the password of {cfg.username}.", secret=True), fallback=False)
            else:
                remaining = t.auth_interactive(cfg.username, handler)
        except paramiko.BadAuthenticationType as e:
            remaining = list(e.allowed_types)                 # not that way yet: the server says which ways it takes
            _note(f"{kind} is not taken now; the server takes: {', '.join(remaining)}")
            done.discard(kind)                                # (it may want this one later, after the other)
            if kind in remaining:                             # it says it takes it after all: do not go round in circles
                done.add(kind)
            continue
        except paramiko.AuthenticationException:
            untried = [k for k in wanted if k not in done and (remaining is None or k in remaining)]
            if kind in ("publickey", "password") and t.is_active() and untried and not errors:
                _note(f"{kind} was refused; trying {untried[0]} next, as ssh does")
                key_refused = key_refused or kind == "publickey"
                continue                                      # (remaining stays what the server last said it takes)
            if errors:
                raise errors[0] from None
            if kind == "publickey" and t.is_active():
                key_refused = True
                break
            if not t.is_active() and kind != "password":
                raise _closed(t, cfg, kind) from None
            raise proxy.ProxyError(f"{cfg.label()} rejected the sign-in (user name, password or one-time code)"
                                   + (f". Check the user name: the server was given '{cfg.username}' (PuTTY's 'login as')"
                                      if "@" in cfg.username or "\\" in cfg.username else "")) from None
        except paramiko.SSHException as e:
            if not t.is_active():
                raise _closed(t, cfg, kind, errors) from None
            raise proxy.ProxyError(f"{cfg.label()}: {e}") from None
        _note(f"{kind} accepted" + (f"; the server also wants: {', '.join(remaining)}" if remaining else ""))
        if not remaining:
            return
    if t.is_authenticated():
        return
    if key_refused:
        raise proxy.ProxyError(f"{cfg.label()} did not accept the key file for {cfg.username}. Check that its public key is "
                               f"in ~/.ssh/authorized_keys for that user on the server")
    raise proxy.ProxyError(f"{cfg.label()} did not accept the sign-in"
                           + (f"; it still wants {', '.join(remaining)}, which Toner cannot do" if remaining else ""))


# ---------------------------------------------------------------- what happened, for when it does not work
LOG_CHANNEL = "paramiko.toner.tunnel"


logging.getLogger(LOG_CHANNEL).addHandler(logging.NullHandler())     # outside a sign-in, nothing is printed anywhere


def log_path():
    return db.db_path().parent / "ssh-tunnel.log"


class _SignInLog:
    """Writes the last sign-in (paramiko's own step-by-step log plus Toner's notes) to ssh-tunnel.log, replacing the one
    before. It says which algorithms were agreed, which sign-in methods the server offered and what it asked; it never
    holds a password, passphrase or code, because neither paramiko nor Toner logs those."""

    def __init__(self, cfg):
        self.cfg, self.handler = cfg, None
        self.logger = logging.getLogger(LOG_CHANNEL)

    def __enter__(self):
        try:
            self.handler = logging.FileHandler(log_path(), mode="w", encoding="utf-8")
            self.handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            self.logger.addHandler(self.handler)
            self.logger.setLevel(logging.DEBUG)
            self.logger.propagate = False
        except OSError:
            self.handler = None
        self.note(f"Toner {VERSION}, paramiko {paramiko.__version__}: SSH tunnel to {self.cfg.host}:{self.cfg.port} as "
                  f"{self.cfg.username or '(no user name)'}" + (", with a key file" if self.cfg.key_file else "")
                  + (", one-time code: " + self.cfg.otp if self.cfg.otp else ""))
        return self

    def note(self, text):
        self.logger.info("TONER: %s", text)

    def failed(self, err):
        self.logger.error("TONER: failed: %s", err)

    def where(self):
        return f"The steps were written to {log_path()}" if self.handler else ""

    def __exit__(self, *exc):
        if self.handler:
            self.logger.removeHandler(self.handler)
            self.handler.close()
        return False


def _before_sign_in(t, cfg, err, timeout):
    """paramiko says 'No existing session' when the SSH key exchange (the step before any sign-in) did not finish: the
    server hung up during it, or it took too long. Say which, and why if the transport knows."""
    why = t.get_exception() if t is not None else None
    why = f" ({why})" if why is not None and str(why) and str(why) != str(err) else ""
    if "No existing session" not in str(err):
        return f"{cfg.label()}: {err}{why}"
    if t is not None and t.is_active():
        return (f"{cfg.label()} did not finish the SSH key exchange within {timeout} seconds, so Toner never got as far as "
                f"sending the user name{why}. The server, or something between (a firewall inspecting SSH), may be stalling it")
    return (f"{cfg.label()} closed the connection during the SSH key exchange, before Toner sent the user name{why}. "
            f"The server may not accept the algorithms Toner offers, or may refuse this computer's address")


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
    def __init__(self, cfg, local_port=0):
        self.cfg = cfg
        self.local_port = int(local_port or 0)            # 0: any free port (used by the tests)
        self.client = self.listener = None
        self.port = 0
        self.since = None

    # ------------------------------------------------------------ open and close
    def _listen(self):
        """The local SOCKS5 port, taken before signing in, so a port that is in use is found before anyone is asked for a code."""
        ls = socket.socket()
        try:
            ls.bind(("127.0.0.1", self.local_port))
        except OSError:
            ls.close()
            raise proxy.ProxyError(f"port {self.local_port} on this computer is already in use (PuTTY or another tunnel may be "
                                   f"open with it). Close that, or choose another Local SOCKS Port") from None
        ls.listen(32)
        return ls

    def open(self, timeout=30):
        cfg = self.cfg
        ls = self._listen()
        try:
            self._sign_in(timeout)
        except BaseException:
            ls.close()
            raise
        self.client.get_transport().set_keepalive(30)
        self.listener, self.port, self.since = ls, ls.getsockname()[1], time.time()
        threading.Thread(target=self._accept, daemon=True).start()
        _note(f"SOCKS5 is on 127.0.0.1:{self.port}")
        return self

    def _sign_in(self, timeout):
        cfg = self.cfg
        client = _Client()
        nettools.configure_hostkeys(client, db.get_setting("hostkey_mode"))
        client.login = lambda t: _login(t, cfg)
        client.set_log_channel(LOG_CHANNEL)
        with _SignInLog(cfg) as trail:
            try:
                client.connect(cfg.host, port=cfg.port, username=cfg.username or "", timeout=timeout, banner_timeout=timeout,
                               auth_timeout=120, allow_agent=False, look_for_keys=False)
            except proxy.ProxyError as e:
                trail.failed(e)
                client.close()
                raise proxy.ProxyError(f"{e}. {trail.where()}") from None
            except (paramiko.SSHException, EOFError) as e:
                msg = _before_sign_in(client.get_transport(), cfg, e, timeout)
                trail.failed(msg)
                client.close()
                raise proxy.ProxyError(f"{msg}. {trail.where()}") from None
            except OSError as e:
                trail.failed(e)
                client.close()
                raise proxy.ProxyError(f"could not reach the proxy {cfg.label()}: {str(e) or type(e).__name__}") from None
            trail.note("signed in; the tunnel is open")
        self.client = client

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
            if ver != 5 or not ({0, 2} & set(methods)):
                c.sendall(b"\x05\xff")
                return
            if 0 in methods:                                  # like PuTTY's dynamic port: no sign-in on this computer's own port
                c.sendall(b"\x05\x00")
            else:                                             # a client set up with a user name: any is fine
                c.sendall(b"\x05\x02")
                _recvn(c, 1)
                _recvn(c, _recvn(c, 1)[0])
                _recvn(c, _recvn(c, 1)[0])
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


# ---------------------------------------------------------------- the settings (Settings > Proxy > SSH Tunnel)
SECRET = "service:ssh-tunnel"
OTP_SECRET = "service:ssh-tunnel-otp"
DEFAULTS = {"enabled": False, "host": "", "port": 22, "username": "", "key_file": "", "otp": "", "local_port": 1080,
            "autostart": False}
LOOPBACK = ("127.0.0.1", "localhost", "::1")


def settings():
    s = db.get_setting("ssh_tunnel")
    return {**DEFAULTS, **(s if isinstance(s, dict) else {})}


def config(s=None, password=None, otp_key=None):
    """The tunnel set up in Settings, as a Config (kind 'tunnel'), or None when it has no server."""
    s = s or settings()
    if not str(s.get("host") or "").strip():
        return None
    otp = s.get("otp") if s.get("otp") in ("ask", "totp") else ""
    return proxy.Config("tunnel", s["host"].strip(), int(s.get("port") or 22), (s.get("username") or "").strip(),
                        proxy._secret(SECRET) if password is None else password, otp,
                        (proxy._secret(OTP_SECRET) if otp == "totp" else "") if otp_key is None else otp_key,
                        str(s.get("key_file") or "").strip())


def enabled():
    s = settings()
    return bool(s["enabled"] and str(s["host"]).strip())


def serves(cfg):
    """Is this proxy setting (SOCKS5 to this computer's tunnel port) the SSH tunnel's local end?"""
    s = settings()
    return bool(cfg and cfg.kind == "socks5" and cfg.host.strip().lower() in LOOPBACK
                and int(cfg.port) == int(s["local_port"]) and enabled())


def ensure_for(cfg):
    """Before a connection through 127.0.0.1:<the tunnel's port>: sign in to the tunnel if it is set up but not open, the
    way a connection through any other proxy would reach it."""
    if serves(cfg) and not is_open():
        get()


def migrate():
    """1.5.2 to 1.5.5 had the SSH tunnel as a proxy type, globally or per device. It is now its own section: move it there
    and point those proxies at its SOCKS5 port, as it would be set up by hand. Returns True if anything changed."""
    changed = False
    s = db.get_setting("proxy")
    if isinstance(s, dict) and s.get("kind") == "tunnel":
        db.set_setting("ssh_tunnel", {**DEFAULTS, "enabled": True, "host": s.get("host", ""), "port": int(s.get("port") or 22),
                                      "username": s.get("username", ""), "key_file": s.get("key_file", ""),
                                      "otp": s.get("otp", "")})
        for old, new in ((proxy.GLOBAL_SECRET, SECRET), (proxy.GLOBAL_OTP, OTP_SECRET)):
            db.move_secret(old, new)
        db.set_setting("proxy", {**s, "kind": "socks5", "host": "127.0.0.1", "port": DEFAULTS["local_port"], "username": "",
                                 "otp": "", "key_file": ""})
        changed = True
    for d in db.list_devices():
        own = proxy.device_settings(d)
        if own.get("mode") != "custom" or own.get("kind") != "tunnel":
            continue
        if not settings()["host"]:                    # the first one becomes the SSH tunnel, with its password
            db.set_setting("ssh_tunnel", {**DEFAULTS, "enabled": True, "host": own.get("host", ""),
                                          "port": int(own.get("port") or 22), "username": own.get("username", ""),
                                          "key_file": own.get("key_file", ""), "otp": own.get("otp", "")})
            db.move_secret(db.secret_name(d["name"], "proxy"), SECRET)
            db.move_secret(db.secret_name(d["name"], "proxy_otp"), OTP_SECRET)
        d = {**d, "proxy": json.dumps({"mode": "custom", "kind": "socks5", "host": "127.0.0.1",
                                       "port": settings()["local_port"], "username": ""})}
        db.save_device(d)
        changed = True
    return changed


# ---------------------------------------------------------------- the open tunnel
_current = None


def _same(a, b):
    return a is not None and b is not None and _key(a) == _key(b)


def get(cfg=None, connect=True, local_port=None):
    """The open tunnel, signing in first (and asking for a code, if the server wants one) when it is not open. cfg None:
    the one set up in Settings, on its Local SOCKS Port; another cfg (an older device setting, the tests) gets any free port."""
    global _current
    if cfg is None:
        cfg = config()
        if cfg is None:
            raise proxy.ProxyError("no SSH tunnel is set up: fill in Settings > Proxy > SSH Tunnel")
    t = _current
    if t is not None and t.alive() and _same(t.cfg, cfg):
        return t
    if not connect:
        return None
    with _open_lock:
        t = _current
        if t is not None and t.alive() and _same(t.cfg, cfg):
            return t
        if t is not None:
            t.close()
            _current = None
        port = local_port if local_port is not None else (settings()["local_port"] if _same(cfg, config()) else 0)
        t = Tunnel(cfg, port)
        proxy.run_waiting(t.open)
        _current = t
        return t


def is_open(cfg=None):
    t = _current
    return bool(t and t.alive() and (cfg is None or _same(t.cfg, cfg)))


def status():
    """What the Settings page and the status strip show."""
    t = _current
    up = bool(t and t.alive())
    return {"enabled": enabled(), "open": up, "since": t.since if up else None, "port": t.port if up else settings()["local_port"],
            "label": (t.cfg if up else config() or proxy.Config("tunnel", "", 22)).label()}


def close(cfg=None):
    global _current
    t = _current
    if t is not None and (cfg is None or _same(t.cfg, cfg)):
        _current = None
        t.close()


def close_all():
    close()
