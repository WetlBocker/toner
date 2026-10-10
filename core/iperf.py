"""iperf3 throughput tests. Toner runs the iperf3 program (it is not bundled) and reads what it prints."""
import os
import re
import shutil
import subprocess

from core import nettools

UNITS = {"": 1e-6, "K": 1e-3, "M": 1.0, "G": 1e3, "T": 1e6}          # to megabits per second


def find_iperf3(configured=""):
    if configured and os.path.isfile(configured):
        return configured
    path = shutil.which("iperf3")
    if path:
        return path
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for cand in (os.path.join(here, "iperf3.exe"), os.path.join(here, "iperf3", "iperf3.exe"),
                 os.path.join(os.environ.get("ProgramFiles", ""), "iperf3", "iperf3.exe"),
                 os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WinGet", "Links", "iperf3.exe"),
                 r"C:\iperf3\iperf3.exe"):
        if os.path.isfile(cand):
            return cand
    return None


def _int(value, low, high, what):
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{what} must be a whole number.")
    if not low <= n <= high:
        raise ValueError(f"{what} must be between {low} and {high}.")
    return n


def check_bandwidth(text):
    t = (text or "").strip()
    if t and not re.fullmatch(r"\d+(\.\d+)?[KkMmGg]?", t):
        raise ValueError("Bandwidth looks like 100M, 1G or 500K (bits per second).")
    return t


def client_args(host, port=5201, seconds=10, streams=1, reverse=False, udp=False, bandwidth="", ip_version=0):
    """Argument list for an iperf3 client test. Every value is checked; no shell is involved."""
    args = ["-c", nettools.check_host(host), "-p", str(_int(port, 1, 65535, "Port")),
            "-t", str(_int(seconds, 1, 3600, "Duration")), "-P", str(_int(streams, 1, 128, "Streams")),
            "-f", "m", "--forceflush"]
    if reverse:
        args.append("-R")
    if udp:
        args.append("-u")
    bw = check_bandwidth(bandwidth)
    if bw:
        args += ["-b", bw]
    if ip_version in (4, 6):
        args.append(f"-{ip_version}")
    return args


def server_args(port=5201, one_off=False, bind=""):
    args = ["-s", "-p", str(_int(port, 1, 65535, "Port")), "-f", "m", "--forceflush"]
    if bind.strip():
        args += ["-B", nettools.check_host(bind)]
    if one_off:
        args.append("-1")
    return args


_LINE = re.compile(r"^\[\s*(?P<id>\w+)\]\s+(?P<a>[\d.]+)-(?P<b>[\d.]+)\s+sec\s+[\d.]+\s+\w?Bytes\s+"
                   r"(?P<rate>[\d.]+)\s+(?P<unit>[KMGT]?)bits/sec(?P<rest>.*)$")


def parse_line(line):
    """One iperf3 text line -> {stream, start, end, mbps, retransmits, role} or None.
    role is 'sender' / 'receiver' on the closing summary lines and '' on a one-second interval."""
    m = _LINE.match(line.strip())
    if not m:
        return None
    rest = m.group("rest").strip()
    role = "sender" if rest.endswith("sender") else "receiver" if rest.endswith("receiver") else ""
    retr = re.match(r"(\d+)\b", rest)
    return {"stream": m.group("id"), "start": float(m.group("a")), "end": float(m.group("b")),
            "mbps": float(m.group("rate")) * UNITS[m.group("unit")], "retransmits": int(retr.group(1)) if retr else None,
            "role": role}


class Summary:
    """Collects the lines of one test. With several streams only the [SUM] lines count."""
    def __init__(self):
        self.rows = []

    def feed(self, text):
        self.rows += [r for r in map(parse_line, text.splitlines()) if r]
        return self

    def _use(self):
        multi = any(r["stream"] == "SUM" for r in self.rows)
        return [r for r in self.rows if (r["stream"] == "SUM") == multi]

    @property
    def intervals(self):
        return [r for r in self._use() if not r["role"]]

    @property
    def sender(self):
        found = [r for r in self._use() if r["role"] == "sender"]
        return found[-1] if found else None

    @property
    def receiver(self):
        found = [r for r in self._use() if r["role"] == "receiver"]
        return found[-1] if found else None

    def text(self):
        parts = []
        if self.sender:
            r = self.sender
            parts.append(f"Sent {r['mbps']:.1f} Mbit/s" + (f" ({r['retransmits']} retransmits)" if r["retransmits"] is not None else ""))
        if self.receiver:
            parts.append(f"Received {self.receiver['mbps']:.1f} Mbit/s")
        return "   ".join(parts)


def run_test(exe, args, seconds=10):
    """Run iperf3 to the end. Returns (Summary, raw output). Raises OSError if the program cannot be started
    and subprocess.TimeoutExpired if it hangs."""
    r = subprocess.run([exe] + list(args), capture_output=True, text=True, timeout=seconds + 30,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), errors="replace")
    out = (r.stdout or "") + (r.stderr or "")
    return Summary().feed(out), out


def failure_reason(output):
    """The useful line from a failed iperf3 run ('iperf3: error - unable to connect to server: ...')."""
    for line in (output or "").splitlines():
        if "error" in line.lower():
            return line.strip().replace("iperf3: ", "")[:140]
    return " ".join((output or "").split())[:140] or "no answer from the iperf3 server"
