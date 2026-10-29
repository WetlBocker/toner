"""Is a device up? A TCP connection to its management port (SSH, or the API's HTTPS port), through its proxy or SSH tunnel
when it has one (the API vendors connect directly, as their API does). ICMP cannot go through a proxy, so this is how a device behind one is checked; it also tells "the device is
down" apart from "the login failed". A connection the device refuses still proves it is up."""
import socket
import time
from dataclasses import dataclass

from core import db, proxy
from drivers.base import FAIL, OK, Result

API_PORTS = {"fortinet": 443, "paloalto": 443}                  # checked through their API
SSH_VENDORS = ("cisco", "juniper", "arista", "hpe", "mikrotik")
VENDORS = SSH_VENDORS + tuple(API_PORTS)
TRACE_NEEDS_ICMP = "Traceroute needs ICMP from this computer; it cannot go through a proxy."


@dataclass
class Probe:
    state: str                  # 'answered', 'refused' (the device is up) or 'down'
    port: int
    ms: float = 0.0
    via_proxy: bool = False
    reason: str = ""

    @property
    def up(self):
        return self.state != "down"


def management_port(dev):
    """SSH for the SSH vendors (the device's own port, else the default SSH port); the API port for Fortinet and Palo Alto."""
    dev = dev or {}
    if dev.get("vendor") in API_PORTS:
        return int(dev.get("port") or API_PORTS[dev["vendor"]])
    return int(dev.get("port") or db.get_setting("default_ssh_port") or 22)


def probe(dev, host=None, port=None, timeout=5):
    """Open (and close) a TCP connection to the device, through its proxy or tunnel when it has one."""
    dev = dev or {}
    host = host or dev.get("host") or ""
    port = int(port or management_port(dev))
    cfg = None if dev.get("vendor") in API_PORTS else proxy.for_device(dev if dev.get("name") else None, host)      # the API connects directly
    t0 = time.time()
    ms = lambda: (time.time() - t0) * 1000
    try:
        s = proxy.connect(cfg, host, port, timeout) if cfg else socket.create_connection((host, port), timeout=timeout)
        s.close()
        return Probe("answered", port, ms(), bool(cfg))
    except proxy.TargetRefused as e:
        if getattr(e, "code", None) == 5:
            return Probe("refused", port, ms(), True)
        text = str(e)                                          # '... would not connect to h:22 (host unreachable)'
        return Probe("down", port, 0.0, True, text.rsplit(" (", 1)[-1].rstrip(")") if text.endswith(")") else text)
    except ConnectionRefusedError:
        return Probe("refused", port, ms(), bool(cfg))
    except (TimeoutError, socket.timeout):
        return Probe("down", port, 0.0, bool(cfg), "timed out")
    except OSError as e:
        return Probe("down", port, 0.0, bool(cfg), str(e) or type(e).__name__)


def row(dev, timeout=5):
    """The 'reachability' result row for a device."""
    p = probe(dev, timeout=timeout)
    through = " through the proxy" if p.via_proxy else ""
    if p.state == "answered":
        return Result(dev["name"], "reachability", OK, f"{p.ms:.0f} ms", f"port {p.port} answered{through}", numeric=p.ms)
    if p.state == "refused":
        return Result(dev["name"], "reachability", OK, f"{p.ms:.0f} ms", f"port {p.port} refused the connection, so the device is up",
                      numeric=p.ms)
    return Result(dev["name"], "reachability", FAIL, "no answer", f"port {p.port} did not answer{through}: {p.reason}")


def line(p, host):
    """One line of output for the Ping tool with Through the proxy (TCP) ticked."""
    where = f"TCP {host}:{p.port} " + ("through the proxy" if p.via_proxy else "direct")
    if p.state == "answered":
        return f"{where}: answered in {p.ms:.0f} ms"
    if p.state == "refused":
        return f"{where}: refused the connection in {p.ms:.0f} ms, so the device is up"
    return f"{where}: no answer: {p.reason}"
