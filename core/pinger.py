"""Ping, traceroute and MTR-style path monitoring using the system's own tools, with no admin rights needed: ping and tracert
on Windows, ping and traceroute on Linux and macOS (their flags and output differ; ping_args, trace_args and the parsers
below cover all three)."""
import math
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from core.platforms import LINUX, MAC, NO_WINDOW, WINDOWS


def ping_args(host, count=1, timeout_ms=1000):
    """The ping command: `count` echoes, each waiting up to timeout_ms for its reply."""
    if WINDOWS:
        return ["ping", "-n", str(count), "-w", str(int(timeout_ms)), host]
    if MAC:
        return ["ping", "-c", str(count), "-W", str(int(timeout_ms)), host]           # macOS: -W is in milliseconds
    return ["ping", "-c", str(count), "-W", str(max(1, math.ceil(timeout_ms / 1000))), host]   # Linux: in seconds


def trace_args(host, max_hops=30, timeout_ms=1000):
    if WINDOWS:
        return ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout_ms)), host]
    return ["traceroute", "-n", "-q", "1", "-m", str(max_hops), "-w", str(max(1, math.ceil(timeout_ms / 1000))), host]


def parse_rtt(out):
    """The round-trip time in one reply ('time=12ms', 'time<1ms', 'time=0.045 ms'), or None."""
    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", out or "", re.I)
    return float(m.group(1)) if m else None


def parse_summary(out):
    """(loss %, average ms or None) from ping's summary: Windows' '(25% loss)' / 'Average = 12ms', or Linux's and macOS'
    '25% packet loss' / 'rtt min/avg/max/mdev = 1.0/2.5/4.0/0.5 ms' ('round-trip ...' on macOS)."""
    out = out or ""
    m = re.search(r"\((\d+)% loss\)", out) or re.search(r"([\d.]+)% packet loss", out)
    loss = float(m.group(1)) if m else 100.0
    avg = re.search(r"Average = (\d+)ms", out)
    if avg:
        return loss, float(avg.group(1))
    avg = re.search(r"(?:rtt|round-trip)[^=]*=\s*[\d.]+/([\d.]+)/", out)
    return loss, (float(avg.group(1)) if avg else None)


def parse_hop(line):
    """(hop number, address or '*') from one line of tracert / traceroute -n, or None."""
    if WINDOWS:
        m = re.match(r"\s*(\d+)\s+(?:(?:<?\d+ ms|\*)\s+){3}(\S+)", line)
        if m:
            ip = m.group(2)
            return int(m.group(1)), "*" if ip.lower().startswith("request") else ip
        return None
    m = re.match(r"\s*(\d+)\s+(\*|[0-9a-fA-F:.]+)", line)
    return (int(m.group(1)), m.group(2)) if m else None


def ping_once(host, timeout_ms=1000):
    """Round-trip time in milliseconds, or None if there was no reply."""
    try:
        r = subprocess.run(ping_args(host, 1, timeout_ms), capture_output=True, text=True,
                           timeout=timeout_ms / 1000 + 5, creationflags=NO_WINDOW)
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = r.stdout or ""
    if "ttl=" not in out.lower() and "hlim=" not in out.lower():
        return None
    return parse_rtt(out)


def trace(host, max_hops=30, timeout_ms=800, cancel=None):
    """The router addresses on the way to `host`: [(hop number, ip or '*')]. Stops at the target."""
    hops = []
    p = subprocess.Popen(trace_args(host, max_hops, timeout_ms), stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, creationflags=NO_WINDOW)
    try:
        for line in p.stdout:
            if cancel is not None and cancel.is_set():
                break
            hop = parse_hop(line)
            if hop:
                hops.append(hop)
    finally:
        try:
            p.kill()
        except OSError:
            pass
    return hops


class HopStats:
    def __init__(self, number, address):
        self.number, self.address = number, address
        self.sent = self.lost = 0
        self.last = self.best = self.worst = None
        self.total = 0.0
        self.history = []                          # recent round-trip times (None = lost), for a graph

    def add(self, ms):
        self.sent += 1
        if ms is None:
            self.lost += 1
        else:
            self.last = ms
            self.best = ms if self.best is None else min(self.best, ms)
            self.worst = ms if self.worst is None else max(self.worst, ms)
            self.total += ms
        self.history.append(ms)
        del self.history[:-120]

    @property
    def loss(self):
        return self.lost / self.sent * 100 if self.sent else 0.0

    @property
    def avg(self):
        got = self.sent - self.lost
        return self.total / got if got else None


class Mtr:
    """Pings every hop on the path once a second and keeps loss and latency statistics per hop."""

    def __init__(self, host, interval=1.0, timeout_ms=1000):
        self.host, self.interval, self.timeout_ms = host, interval, timeout_ms
        self.hops = []
        self.cycles = 0
        self.stop_event = threading.Event()
        self.thread = None
        self.lock = threading.Lock()

    def discover(self):
        found = trace(self.host, cancel=self.stop_event)
        with self.lock:
            self.hops = [HopStats(n, ip) for n, ip in found]
        return len(self.hops)

    def start(self, on_update=None):
        def loop():
            if not self.hops:
                self.discover()
            while not self.stop_event.is_set():
                t0 = time.time()
                with self.lock:
                    hops = list(self.hops)
                with ThreadPoolExecutor(max_workers=max(1, len(hops))) as pool:
                    results = list(pool.map(lambda h: None if h.address == "*" else ping_once(h.address, self.timeout_ms),
                                            hops))
                with self.lock:
                    for h, ms in zip(hops, results):
                        h.add(ms)
                    self.cycles += 1
                if on_update:
                    on_update()
                self.stop_event.wait(max(0.0, self.interval - (time.time() - t0)))
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def snapshot(self):
        with self.lock:
            return list(self.hops)
