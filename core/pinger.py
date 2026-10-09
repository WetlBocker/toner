"""Ping, traceroute and MTR-style path monitoring using the Windows tools, with no admin rights needed."""
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def ping_once(host, timeout_ms=1000):
    """Round-trip time in milliseconds, or None if there was no reply."""
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", str(int(timeout_ms)), host], capture_output=True, text=True,
                           timeout=timeout_ms / 1000 + 5, creationflags=NO_WINDOW)
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = r.stdout or ""
    if "TTL=" not in out.upper() and "ttl=" not in out:
        return None
    m = re.search(r"time[=<]\s*(\d+)\s*ms", out, re.I)
    return float(m.group(1)) if m else None


def trace(host, max_hops=30, timeout_ms=800, cancel=None):
    """The router addresses on the way to `host`: [(hop number, ip or '*')]. Stops at the target."""
    hops = []
    p = subprocess.Popen(["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_ms), host], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, creationflags=NO_WINDOW)
    try:
        for line in p.stdout:
            if cancel is not None and cancel.is_set():
                break
            m = re.match(r"\s*(\d+)\s+(?:(?:<?\d+ ms|\*)\s+){3}(\S+)", line)
            if m:
                ip = m.group(2)
                hops.append((int(m.group(1)), "*" if ip.lower().startswith("request") else ip))
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
