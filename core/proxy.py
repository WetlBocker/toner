"""Proxy support: one global setting for SSH, Telnet and TCP connections, and an optional override per device.

Modes (global, Settings > Proxy)
    none     connect directly, ignoring any Windows proxy
    manual   use the proxy given in Settings for SSH, Telnet and TCP, except the addresses in the bypass list

Per device (Inventory > the device > Access)
    default  follow the global setting
    none     always connect directly
    custom   always use this proxy (type, host, port, optional user name and password)

What goes through a proxy: SSH (checks, backups, sessions, the Command Runner) and TCP port and reachability checks. Web
connections never do (since 1.11.5): the vendor APIs, the Scanning lookups, the AI providers, notifications, web and
certificate checks and Demarc connect directly, ignoring the Windows proxy too. SNMP, ping, traceroute and the listeners
use UDP or ICMP, which ordinary proxies do not carry, so they always connect directly.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import socket
import struct
import threading
import time
from dataclasses import dataclass, replace
from urllib.parse import quote

import keyring

from core import db

GLOBAL_SECRET = "service:proxy"
GLOBAL_OTP = "service:proxy-otp"
KINDS = [("http", "HTTP proxy (CONNECT)"), ("socks5", "SOCKS5"), ("socks4", "SOCKS4")]
DEFAULT_PORTS = {"http": 8080, "socks5": 1080, "socks4": 1080}
# An SSH tunnel is set up on its own (core/tunnel.py) and used as SOCKS5 127.0.0.1:<its port>. A device or setting saved
# by 1.5.2 to 1.5.5 with the kind "tunnel" still works: it is sent through that tunnel.
OTP_MODES = [("", "None"), ("ask", "Ask me for it when connecting"), ("totp", "Make it from a secret key")]
MODES = [("none", "No proxy (connect directly)"),
         ("manual", "Use the proxy below")]
DEFAULTS = {"mode": "none", "kind": "http", "host": "", "port": 8080, "username": "", "bypass": "localhost, 127.0.0.1",
            "otp": "", "key_file": ""}
DIRECT = {"http": "", "https": ""}          # an empty address tells `requests` to ignore any proxy, even the Windows one


class ProxyError(OSError):
    """The proxy refused, could not be reached, or asked for credentials. Deliberately not a ConnectionError, so a run
    does not retry it: repeating a wrong proxy password is how accounts get locked out."""


class TargetRefused(ProxyError):
    """The proxy is fine and signed us in, but would not open the connection to that address (down, or not allowed).
    `code` is the SOCKS5 reply when there was one: 5 means the target itself refused, so it is up."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


@dataclass
class Config:
    kind: str
    host: str
    port: int
    username: str = ""
    password: str = ""
    otp: str = ""                    # "" none, "ask" ask for a code each time, "totp" make it from otp_key
    otp_key: str = ""
    key_file: str = ""               # SSH tunnel: a private key to sign in with (the password is its passphrase)

    def label(self):
        name = {**dict(KINDS), "tunnel": "SSH tunnel"}.get(self.kind, self.kind)
        return f"{name.split(' (')[0]} {self.host}:{self.port}"

    def url(self):
        scheme = {"http": "http", "socks5": "socks5h", "socks4": "socks4a"}[self.kind]
        cred = f"{quote(self.username, safe='')}:{quote(self.password, safe='')}@" if self.username else ""
        return f"{scheme}://{cred}{self.host}:{self.port}"


# ---------------------------------------------------------------- settings
def settings():
    s = db.get_setting("proxy")
    out = {**DEFAULTS, **(s if isinstance(s, dict) else {})}
    if out.get("mode") == "system":                   # the Windows-settings mode of 1.5 to 1.11.4 covered web connections only
        out["mode"] = "none"
    return out


def _secret(name):
    try:
        return keyring.get_password(db.SERVICE, name) or ""
    except Exception:
        return ""


def _config(s, password, otp_key=""):
    if not str(s.get("host") or "").strip():
        return None
    otp = s.get("otp") if s.get("otp") in ("ask", "totp") else ""
    kind = s.get("kind") or "http"
    return Config(kind, s["host"].strip(), int(s.get("port") or 8080), (s.get("username") or "").strip(),
                  password or "", otp, otp_key or "", str(s.get("key_file") or "").strip() if kind == "tunnel" else "")


def global_config(full=False):
    """The proxy chosen in Settings > Proxy ('Use the proxy below'), or None. Without its password and key unless full."""
    s = settings()
    if s["mode"] != "manual":
        return None
    if not full:
        return _config(s, "")
    return _config(s, _secret(GLOBAL_SECRET), _secret(GLOBAL_OTP) if s.get("otp") == "totp" else "")


def device_settings(dev):
    raw = (dev or {}).get("proxy") or ""
    try:
        data = json.loads(raw) if isinstance(raw, str) and raw else (raw or {})
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def bypassed(host, patterns):
    """Is `host` on the bypass list? Entries: a name, *.suffix or .suffix, an address, a network (10.0.0.0/8), <local>."""
    host = (host or "").strip().lower().rstrip(".")
    for item in str(patterns or "").replace(";", ",").replace(" ", ",").split(","):
        p = item.strip().lower()
        if not p:
            continue
        if p == "<local>" and "." not in host:
            return True
        if p == host:
            return True
        if p.startswith("*.") and host.endswith(p[1:]) or p.startswith(".") and host.endswith(p):
            return True
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(p, strict=False):
                return True
        except ValueError:
            pass
    return False


def resolve(dev=None, host=None, purpose="socket"):
    """How to reach `host` for `dev`: ('direct', None) or ('proxy', Config).
    purpose is 'web' for HTTP(S) requests, which always go direct, and 'socket' for SSH and raw TCP."""
    if purpose == "web":
        return "direct", None
    host = host or (dev or {}).get("host") or ""
    own = device_settings(dev)
    mode = own.get("mode", "default")
    if mode == "none":
        return "direct", None
    if mode == "custom":
        with db.within((dev or {}).get("org")):
            pw = (dev or {}).get("_proxy_secret") or _secret(db.secret_name(dev["name"], "proxy"))
            key = (dev or {}).get("_proxy_otp_secret") or (_secret(db.secret_name(dev["name"], "proxy_otp")) if own.get("otp") == "totp" else "")
        cfg = _config(own, pw, key)
        return ("proxy", cfg) if cfg else ("direct", None)
    s = settings()
    if s["mode"] == "manual":
        cfg = _config(s, _secret(GLOBAL_SECRET), _secret(GLOBAL_OTP) if s.get("otp") == "totp" else "")
        return ("proxy", cfg) if cfg and not bypassed(host, s.get("bypass")) else ("direct", None)
    return "direct", None


def for_device(dev=None, host=None):
    """The proxy to use for a socket connection (SSH, TCP), or None to connect directly."""
    how, cfg = resolve(dev, host, "socket")
    return cfg if how == "proxy" else None


def requests_kwargs(dev=None, host=None):
    """Extra arguments for requests.get/post: web connections go direct, ignoring Toner's proxy and the Windows one."""
    return {"proxies": dict(DIRECT)}


def web_kwargs(host, direct=True):
    """requests' proxies for an app-wide web connection: direct, like every web connection."""
    return {"proxies": dict(DIRECT)}


PROXY_ENV = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "all_proxy", "no_proxy")


def child_env(env, host, direct=False):
    """The environment for a command-line tool that reaches `host` (bw.exe, op.exe): no proxy at all (NO_PROXY=*), as for every
    web connection. Proxies set in the environment before Toner started are taken out."""
    env = {k: v for k, v in env.items() if k not in PROXY_ENV}
    env["NO_PROXY"] = "*"
    return env


def system_text():
    """What Windows is set to use, for the Settings page."""
    import urllib.request
    found = urllib.request.getproxies()
    return ", ".join(f"{k}: {v}" for k, v in found.items()) if found else ""


# ---------------------------------------------------------------- making connections
def _http_connect(cfg, host, port, timeout):
    s = socket.create_connection((cfg.host, cfg.port), timeout=timeout)
    try:
        target = f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"
        lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", "User-Agent: Toner", "Proxy-Connection: keep-alive"]
        if cfg.username:
            token = base64.b64encode(f"{cfg.username}:{cfg.password}".encode()).decode()
            lines.append(f"Proxy-Authorization: Basic {token}")
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        data = b""
        deadline = time.time() + timeout
        while b"\r\n\r\n" not in data:
            if time.time() > deadline:
                raise ProxyError(f"{cfg.label()} did not answer")
            chunk = s.recv(4096)
            if not chunk:
                raise ProxyError(f"{cfg.label()} closed the connection")
            data += chunk
            if len(data) > 65536:
                raise ProxyError(f"{cfg.label()} sent an unexpected reply")
        status = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = status.split(" ", 2)
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if code == 407:
            raise ProxyError(f"{cfg.label()} needs a user name and password" if not cfg.username
                             else f"{cfg.label()} rejected the user name or password")
        if code != 200:
            raise TargetRefused(f"{cfg.label()} would not connect to {host}:{port} ({status.strip()[:80]})")
        return s
    except BaseException:
        s.close()
        raise


SOCKS5_METHODS = {0: "no authentication", 1: "GSSAPI (Kerberos)", 2: "user name and password", 3: "CHAP", 5: "CRAM",
                  6: "SSL", 7: "NDS", 8: "a multi-authentication framework", 9: "a JSON parameter block"}
SOCKS5_REFUSALS = {1: "general failure", 2: "not allowed by the proxy's rules", 3: "network unreachable", 4: "host unreachable",
                   5: "refused by the target", 6: "TTL expired", 7: "command not supported", 8: "address type not supported"}


def _shown(data):
    """What a proxy sent, for an error message: text when it is text, hex when it is not."""
    data = bytes(data)[:24]
    text = data.decode("latin-1")
    if text and all(32 <= ord(c) < 127 or c in "\r\n" for c in text):
        return repr(text.strip())
    return " ".join("0x%02x" % b for b in data)


def _take(s, n, cfg, what):
    """Exactly n bytes from the proxy, or a ProxyError that says it stopped talking. `what` is what it was asked."""
    out = b""
    try:
        while len(out) < n:
            chunk = s.recv(n - len(out))
            if not chunk:
                break
            out += chunk
    except OSError as e:
        raise ProxyError(f"{cfg.label()} did not answer {what} ({e.__class__.__name__})") from None
    if len(out) < n:
        raise ProxyError(f"{cfg.label()} closed the connection instead of answering {what}"
                         + (f" (it sent {_shown(out)})" if out else ""))
    return out


def clean_key(text):
    """An authenticator secret key as typed (lower case, spaces, dashes) in the form it is kept."""
    return "".join(str(text).split()).replace("-", "").upper()


def _socks5_connect(cfg, host, port, timeout):
    """SOCKS5 (RFC 1928) with user name and password (RFC 1929). Written out here, not left to a library, so that an
    unexpected answer can be reported as what it was: a proxy that wants a second step says which one."""
    s = socket.create_connection((cfg.host, cfg.port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x02\x00\x02" if cfg.username else b"\x05\x01\x00")
        head = _take(s, 2, cfg, "the greeting")
        if head[0] != 5:
            raise ProxyError(_not_socks5(cfg, head, s))
        method = head[1]
        if method == 2:
            user, pw = cfg.username.encode(), cfg.password.encode()
            if not user or len(user) > 255 or len(pw) > 255:
                raise ProxyError(f"{cfg.label()} wants a user name and password" + (" (they must be under 255 bytes)" if user else
                                 ": enter them in the proxy settings"))
            s.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
            ans = _take(s, 2, cfg, "the login")
            if ans[0] != 1:
                raise ProxyError(f"{cfg.label()} answered the login with {_shown(ans)} where SOCKS5 has 0x01 0x00. "
                                 f"It may use its own second step after the password, which Toner cannot do")
            if ans[1] != 0:
                raise ProxyError(f"{cfg.label()} rejected the user name or password"
                                 + (" or the one-time code" if cfg.otp else ""))
        elif method == 0xFF:
            raise ProxyError(f"{cfg.label()} accepts none of the sign-in methods Toner offers (no sign-in, user name and "
                             f"password)" + ("" if cfg.username else "; enter a user name and password"))
        elif method != 0:
            what = SOCKS5_METHODS.get(method) or ("a method of its own (0x%02x)" % method if method >= 0x80 else "method 0x%02x" % method)
            raise ProxyError(f"{cfg.label()} asked to sign in with {what}, which Toner does not support. Toner can do "
                             f"'no sign-in' and 'user name and password' (with a one-time code added to the password)")
        try:
            addr = b"\x01" + ipaddress.IPv4Address(host).packed
        except ValueError:
            try:
                addr = b"\x04" + ipaddress.IPv6Address(host.strip("[]")).packed
            except ValueError:
                name = host.encode("idna") if host.isascii() is False else host.encode()
                if len(name) > 255:
                    raise ProxyError(f"the name {host[:40]}... is too long for SOCKS5") from None
                addr = b"\x03" + bytes([len(name)]) + name
        s.sendall(b"\x05\x01\x00" + addr + struct.pack(">H", port))
        rep = _take(s, 4, cfg, "the connection request")
        if rep[0] != 5:
            raise ProxyError(f"{cfg.label()} answered the request with {_shown(rep)}, which is not SOCKS5")
        if rep[1] != 0:
            raise TargetRefused(f"{cfg.label()} would not connect to {host}:{port} ({SOCKS5_REFUSALS.get(rep[1], 'error 0x%02x' % rep[1])})",
                                rep[1])
        tail = {1: 4, 4: 16}.get(rep[3])
        if tail is None and rep[3] == 3:
            tail = _take(s, 1, cfg, "the connection request")[0]
        _take(s, (tail or 0) + 2, cfg, "the connection request")
        s.settimeout(None)
        return s
    except BaseException:
        s.close()
        raise


def _not_socks5(cfg, head, s):
    """The first two bytes were not a SOCKS5 answer. Say what the proxy is instead, if that can be told."""
    try:
        s.settimeout(1)
        head += s.recv(40)
    except OSError:
        pass
    text = bytes(head).decode("latin-1", "replace")
    if text.startswith("SSH-"):
        return (f"{cfg.label()} is an SSH server ({_shown(head)}), not a SOCKS proxy. Use the port of its SOCKS service, "
                f"or open an SSH tunnel (ssh -D) first and point Toner at that")
    if text.startswith("HTTP/") or text[:2].isalpha():
        return f"{cfg.label()} answered {_shown(head)}: it looks like an HTTP proxy. Change the proxy type to HTTP proxy"
    if head[:1] == b"\x00" and len(head) >= 2:
        return f"{cfg.label()} answered as SOCKS4 ({_shown(head)}). Change the proxy type to SOCKS4"
    return f"{cfg.label()} sent {_shown(head)}, which is not a SOCKS5 answer"


# ---------------------------------------------------------------- one-time codes (2-step sign-in at the proxy)
def totp(key, now=None, digits=6, step=30):
    """The current code from an authenticator key (RFC 6238: HMAC-SHA1, 30 s, 6 digits)."""
    raw = clean_key(key)
    try:
        secret = base64.b32decode(raw + "=" * (-len(raw) % 8))
    except ValueError:
        raise ProxyError("the secret key for the one-time code is not valid (it is the letters and digits from the QR code setup)") from None
    n = int((time.time() if now is None else now) // step)
    h = hmac.new(secret, struct.pack(">Q", n), hashlib.sha1).digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


CODE_PROMPT = None            # set by the app: fn(title, text) -> the code typed, or "" / None if cancelled
_codes = {}                   # (proxy, user) -> (code, time) of the last code asked for
_ask_lock = threading.Lock()
CODE_REUSE_SECONDS = 25


def set_code_prompt(fn):
    global CODE_PROMPT
    CODE_PROMPT = fn


WAIT_HOOK = None              # set by the app: fn(work) runs work() and, on the window's thread, keeps the window responsive


def run_waiting(work):
    """Run work() for a sign-in that may ask questions. Called from a button (the window's own thread), the questions could
    not be shown while the window waits, so the app's hook keeps it responsive until the work is done."""
    return WAIT_HOOK(work) if WAIT_HOOK else work()


def forget_code(cfg):
    _codes.pop((cfg.host, cfg.port, cfg.username), None)


def ask_text(cfg, title, text, secret=False):
    """Ask the person at the window for something the proxy wants. Raises ProxyError when nobody can be asked."""
    if CODE_PROMPT is None:
        raise ProxyError(f"{cfg.label()} needs something typed ({title.lower()}), and Toner can only ask for it while you are "
                         f"at the window. For checks that run by themselves, set the code to 'Make it from a secret key'")
    with _ask_lock:
        got = (CODE_PROMPT(title, text, secret=True) if secret else CODE_PROMPT(title, text)) or ""
    return got if secret else "".join(got.split())


def one_time_code(cfg, prompt="", reuse=True):
    """The code for a proxy with two-step sign-in: made from the secret key, or typed by the person at the window.
    `prompt` is what the server itself said when it asked (an SSH tunnel's login); `reuse` allows a code typed a moment
    ago to be used again (a code sent with the password is wanted by every connection, a login by one)."""
    if cfg.otp == "totp":
        if not cfg.otp_key:
            raise ProxyError(f"{cfg.label()} needs a one-time code, but no secret key is saved for it")
        if 30 - time.time() % 30 < 1.5:                # one that is about to expire would be old by the time it arrives
            time.sleep(1.6)
        return totp(cfg.otp_key)
    key = (cfg.host, cfg.port, cfg.username)
    hit = _codes.get(key) if reuse else None
    if hit and time.time() - hit[1] < CODE_REUSE_SECONDS:
        return hit[0]
    said = prompt.strip()
    duo = any(w in said.lower() for w in ("duo", "option", "push"))
    if "\n" in said:                                   # a menu, such as Duo's list of options: show it as it is
        text = f"{cfg.label()} asks for a second step" + (f" for {cfg.username}" if cfg.username else "") + ":\n\n" + said
    else:
        text = (f"{cfg.label()} asks for a one-time code" + (f" for {cfg.username}" if cfg.username else "")
                + (f" ({said})" if said else "") + ".")
    text += ("\n\nType a passcode, or the number of an option (for example 1 for Duo Push) and then approve it on your phone."
             if duo else "\nType the current code from your authenticator app, or touch your YubiKey.")
    code = ask_text(cfg, "One-time code", text)
    if not code:
        raise ProxyError(f"{cfg.label()}: no one-time code was entered")
    if reuse:
        _codes[key] = (code, time.time())
    return code


def with_code(cfg):
    """cfg with the one-time code added to the end of its password (or in its place, when there is no password). An SSH
    tunnel answers the server's own question instead (see tunnel.py)."""
    return replace(cfg, password=cfg.password + one_time_code(cfg)) if cfg.otp and cfg.kind != "tunnel" else cfg


def effective(cfg):
    """What to connect to for this proxy. SOCKS5 to the SSH tunnel's port signs in to the tunnel first if it is not open;
    an older 'tunnel' setting becomes SOCKS5 to that tunnel's port."""
    from core import tunnel
    if cfg.kind == "tunnel":
        t = tunnel.get(cfg)
        return Config("socks5", "127.0.0.1", t.port)
    tunnel.ensure_for(cfg)
    return with_code(cfg)


LAST = {}                     # "host:port" of a proxy -> (worked, time, message) of the latest real connection through it


def last_result(cfg):
    return LAST.get(f"{cfg.host}:{cfg.port}")


def connect(cfg, host, port, timeout=15):
    """A TCP socket to host:port through the proxy. Raises ProxyError with a message that says what went wrong."""
    try:
        s = _connect(cfg, host, port, timeout)
    except TargetRefused:
        LAST[f"{cfg.host}:{cfg.port}"] = (True, time.time(), "")           # the proxy itself did its part
        raise
    except OSError as e:
        LAST[f"{cfg.host}:{cfg.port}"] = (False, time.time(), str(e))
        raise
    LAST[f"{cfg.host}:{cfg.port}"] = (True, time.time(), "")
    return s


def probe(cfg, timeout=3):
    """(reachable, message): does something answer as this kind of proxy? Nothing is sent that signs in, so it cannot use up
    a one-time code or count as a wrong password. For an SSH tunnel: is it open now?"""
    from core import tunnel
    if cfg.kind == "tunnel":
        return (True, f"{cfg.label()} is open") if tunnel.is_open(cfg) else (False, f"{cfg.label()} is not open")
    if tunnel.serves(cfg) and not tunnel.is_open():
        return False, f"{cfg.label()} is the SSH tunnel's port, and the tunnel ({tunnel.status()['label']}) is not open"
    try:
        s = socket.create_connection((cfg.host, cfg.port), timeout=timeout)
    except OSError as e:
        return False, f"{cfg.label()} did not answer ({str(e) or type(e).__name__})"
    try:
        if cfg.kind == "socks5":
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")
            try:
                head = s.recv(2)
            except OSError:
                head = b""
            if len(head) < 2 or head[0] != 5:
                return False, (_not_socks5(cfg, head, s) if head else f"{cfg.label()} did not answer as a SOCKS5 proxy")
        return True, f"{cfg.label()} answers"
    finally:
        s.close()


def _connect(cfg, host, port, timeout=15):
    port = int(port)
    try:
        used = effective(cfg)
        try:
            if used.kind == "http":
                return _http_connect(used, host, port, timeout)
            if used.kind == "socks5":
                return _socks5_connect(used, host, port, timeout)
        except TargetRefused:
            raise
        except ProxyError:
            if cfg.otp and cfg.kind != "tunnel":
                forget_code(cfg)                   # a refused code is not tried again, and not asked about twice in a row
            raise
        import socks
        return socks.create_connection((host, port), timeout=timeout, proxy_type=socks.SOCKS4, proxy_addr=cfg.host,
                                       proxy_port=cfg.port, proxy_rdns=True, proxy_username=cfg.username or None)
    except ProxyError:
        raise
    except OSError as e:
        what = str(e) or type(e).__name__
        if type(e).__module__.startswith("socks") and type(e).__name__ != "ProxyConnectionError":
            raise ProxyError(f"{cfg.label()}: {what}") from None          # the proxy answered, and refused
        raise ProxyError(f"could not reach the proxy {cfg.label()}: {what}") from None


def create_connection(dev, address, timeout=15):
    """socket.create_connection that honours the proxy settings for `dev` (None = the global setting)."""
    cfg = for_device(dev, address[0])
    if cfg:
        return connect(cfg, address[0], address[1], timeout)
    return socket.create_connection(address, timeout=timeout)


# ---------------------------------------------------------------- the Test buttons
def test_tunnel(cfg, host, port, timeout=8):
    """(ok, message) for a connection to host:port through `cfg`."""
    t0 = time.time()
    try:
        s = connect(cfg, host, port, timeout)
    except OSError as e:
        return False, str(e)
    s.close()
    return True, f"Connected to {host}:{port} through {cfg.label()} in {(time.time() - t0) * 1000:.0f} ms."


def test_web(host, port, direct=True, timeout=8):
    """(ok, message) for a direct web request, as every web connection is made."""
    import requests
    t0 = time.time()
    try:
        r = requests.get(f"https://{host}:{port}/", timeout=timeout, proxies=dict(DIRECT))
    except requests.RequestException as e:
        return False, f"{type(e).__name__}: {str(e)[:150]}"
    return True, f"Reached {host}:{port} directly, HTTP {r.status_code}, {(time.time() - t0) * 1000:.0f} ms."
