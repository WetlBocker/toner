"""The one thread that pings for the UI: the live ping graph (Tools > Ping, forever at an interval until stopped) and the
small Ping window from a device's right-click menu (five echoes) both use it. Each reply is one `sample(number, ms)`
signal, `ms` None for a lost one. With `tcp_dev` the echo is a TCP connection to that device's management port through
its proxy (Through the proxy (TCP)) instead of ICMP, as core.reach does it."""
import threading
import time

from PySide6.QtCore import QThread, Signal

from core import pinger


class PingWorker(QThread):
    sample = Signal(int, object)                  # (echo number from 1, milliseconds or None for a lost reply)

    def __init__(self, host, count=None, interval=1.0, timeout_ms=1000, tcp_dev=None):
        """`count` None: keep going until `stop()`; a number: that many echoes, `interval` seconds apart."""
        super().__init__()
        self.host, self.count, self.interval, self.timeout_ms = host, count, interval, timeout_ms
        self.tcp_dev = tcp_dev
        self.stop_event = threading.Event()

    def once(self):
        if self.tcp_dev is None:
            return pinger.ping_once(self.host, self.timeout_ms)
        from core import reach
        p = reach.probe(self.tcp_dev, host=self.host, timeout=self.timeout_ms / 1000)
        return p.ms if p.up else None

    def run(self):
        n = 0
        while not self.stop_event.is_set() and (self.count is None or n < self.count):
            n += 1
            t0 = time.time()
            self.sample.emit(n, self.once())
            if self.count is not None and n >= self.count:
                return
            self.stop_event.wait(max(0.0, self.interval - (time.time() - t0)))

    def stop(self):
        self.stop_event.set()
