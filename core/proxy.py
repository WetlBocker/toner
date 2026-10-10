"""Proxy support: one global setting for every connection, and an optional override per device.

Modes (global, Settings > Proxy)
    none     connect directly, ignoring any Windows proxy
    system   use the Windows proxy settings for web connections (what a browser does). SSH and raw TCP stay direct,
             because a system web proxy is not normally meant for them and its exceptions list is for web addresses.
    manual   use the proxy given in Settings for everything that can be proxied, except the addresses in the bypass list

Per device (Inventory > the device > Access)
    default  follow the global setting
    none     always connect directly
    custom   always use this proxy (type, host, port, optional user name and password)

What can go through a proxy: SSH (checks, backups, the console), the web APIs of Fortinet, Palo Alto, Meraki and UniFi,
status pages, web / TCP / certificate checks, and notifications. SNMP, ping, traceroute and the listeners use UDP or
ICMP, which ordinary proxies do not carry, so they always connect directly.
"""
import base64
import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from urllib.parse import quote

import keyring

from core import db

GLOBAL_SECRET = "service:proxy"
KINDS = [("http", "HTTP proxy (CONNECT)"), ("socks5", "SOCKS5"), ("socks4", "SOCKS4")]
MODES = [("none", "No proxy (connect directly)"),
         ("system", "Use the Windows proxy settings (web connections only)"),
         ("manual", "Use the proxy below")]
DEFAULTS = {"mode": "system", "kind": "http", "host": "", "port": 8080, "username": "", "bypass": "localhost, 127.0.0.1"}
DIRECT = {"http": "", "https": ""}          # an empty address tells `requests` to ignore any proxy, even the Windows one


class ProxyError(OSError):
    """The proxy refused, could not be reached, or asked for credentials. Deliberately not a ConnectionError, so a run
    does not retry it: repeating a wrong proxy password is how accounts get locked out."""


@dataclass
class Config:
    kind: str
    host: str
    port: int
    username: str = ""
    password: str = ""

    def label(self):
        return f"{dict(KINDS).get(self.kind, self.kind).split(' (')[0]} {self.host}:{self.port}"

    def url(self):
        scheme = {"http": "http", "socks5": "socks5h", "socks4": "socks4a"}[self.kind]
        cred = f"{quote(self.username, safe='')}:{quote(self.password, safe='')}@" if self.username else ""
        return f"{scheme}://{cred}{self.host}:{self.port}"


# ---------------------------------------------------------------- settings
def settings():
    s = db.get_setting("proxy")
    return {**DEFAULTS, **(s if isinstance(s, dict) else {})}


def _secret(name):
    try:
        return keyring.get_password(db.SERVICE, name) or ""
    except Exception:
        return ""


def _config(s, password):
    if not str(s.get("host") or "").strip():
        return None
    return Config(s.get("kind") or "http", s["host"].strip(), int(s.get("port") or 8080), (s.get("username") or "").strip(),
                  password or "")


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
    """How to reach `host` for `dev`: ('direct', None), ('system', None) or ('proxy', Config).
    purpose is 'web' for HTTP(S) requests and 'socket' for SSH and raw TCP."""
    host = host or (dev or {}).get("host") or ""
    own = device_settings(dev)
    mode = own.get("mode", "default")
    if mode == "none":
        return "direct", None
    if mode == "custom":
        pw = (dev or {}).get("_proxy_secret") or _secret(db.secret_name(dev["name"], "proxy"))
        cfg = _config(own, pw)
        return ("proxy", cfg) if cfg else ("direct", None)
    s = settings()
    if s["mode"] == "manual":
        cfg = _config(s, _secret(GLOBAL_SECRET))
        return ("proxy", cfg) if cfg and not bypassed(host, s.get("bypass")) else ("direct", None)
    if s["mode"] == "system" and purpose == "web":
        return "system", None
    return "direct", None


def for_device(dev=None, host=None):
    """The proxy to use for a socket connection (SSH, TCP), or None to connect directly."""
    how, cfg = resolve(dev, host, "socket")
    return cfg if how == "proxy" else None


def requests_kwargs(dev=None, host=None):
    """Extra arguments for requests.get/post: the proxies to use. Pass dev=None for app-wide connections."""
    how, cfg = resolve(dev, host, "web")
    if how == "proxy":
        return {"proxies": {"http": cfg.url(), "https": cfg.url()}}
    return {"proxies": dict(DIRECT)} if how == "direct" else {}


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
            raise ProxyError(f"{cfg.label()} would not connect to {host}:{port} ({status.strip()[:80]})")
        return s
    except BaseException:
        s.close()
        raise


def connect(cfg, host, port, timeout=15):
    """A TCP socket to host:port through the proxy. Raises ProxyError with a message that says what went wrong."""
    port = int(port)
    try:
        if cfg.kind == "http":
            return _http_connect(cfg, host, port, timeout)
        import socks
        kind = {"socks5": socks.SOCKS5, "socks4": socks.SOCKS4}[cfg.kind]
        return socks.create_connection((host, port), timeout=timeout, proxy_type=kind, proxy_addr=cfg.host,
                                       proxy_port=cfg.port, proxy_rdns=True, proxy_username=cfg.username or None,
                                       proxy_password=cfg.password or None)
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


def test_web(host, port, direct, timeout=8):
    """(ok, message) for a web request that follows the system proxy (direct=False) or ignores it (direct=True)."""
    import requests
    t0 = time.time()
    try:
        r = requests.get(f"https://{host}:{port}/", timeout=timeout, **({"proxies": dict(DIRECT)} if direct else {}))
    except requests.RequestException as e:
        return False, f"{type(e).__name__}: {str(e)[:150]}"
    return True, f"Reached {host}:{port} ({'directly' if direct else 'using the Windows settings'}), HTTP {r.status_code}, " \
                 f"{(time.time() - t0) * 1000:.0f} ms."
