"""Logic behind the Tools tab: input validation, nmap profiles, SSH session, fallback scanner."""
import ipaddress
import os
import re
import shutil
import socket
from concurrent.futures import ThreadPoolExecutor

import paramiko
from PySide6.QtCore import QThread, Signal
from core import legacyssh  # noqa: F401  (ssh-rsa and SHA-1 key exchange for older devices; see Settings > Security)
from core import quiet

# ---------- input validation ----------
# Targets must start with a letter or digit so they can never be read as a command-line option
# (e.g. "-oN file"). Processes are always started with an argument list, never through a shell.
_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,252}$")
_PORTS = re.compile(r"^\d{1,5}([,\-]\d{1,5})*$")


def check_target(text):
    t = (text or "").strip()
    if not _TARGET.match(t):
        raise ValueError("Enter a hostname, IP address, CIDR (10.0.0.0/24) or range (10.0.0.1-50).")
    return t


_LABEL = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")


def check_host(text):
    """A device address: an IP address or a DNS name (short names and FQDNs). Returns it cleaned."""
    t = (text or "").strip().rstrip(".")
    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", t):
        # numbers and dots only is meant as an IP address (10.0.025, 10.0.0, 10.0.0.256), never a name, so no DNS lookup is worth making
        raise ValueError(f"'{t}' is not a valid IP address. An IPv4 address is four numbers from 0 to 255, without leading zeros, separated by dots, e.g. 10.0.0.25.")
    if ":" in t and re.fullmatch(r"[0-9A-Fa-f:.%]+", t):
        raise ValueError(f"'{t}' is not a valid IPv6 address.")
    if t and len(t) <= 253 and all(_LABEL.match(label) for label in t.split(".")):
        return t
    raise ValueError("Host must be an IP address or DNS name, e.g. 10.0.0.2 or core-sw1.corp.example.com "
                     "(no http://, port or path).")


def resolve_host(host):
    """Resolve through the system resolver (honours DNS suffixes and the hosts file). Returns the IP."""
    try:
        return socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0]
    except socket.gaierror:
        raise ValueError(f"DNS lookup failed for '{host}'. Check the name, or use the IP address.") from None


def check_ports(text):
    p = (text or "").replace(" ", "")
    if not _PORTS.match(p):
        raise ValueError("Ports look like: 22,80,443 or 1-1024 or 22,8000-8100.")
    return p


def parse_ports(text):
    ports = set()
    for part in check_ports(text).split(","):
        lo, _, hi = part.partition("-")
        lo, hi = int(lo), int(hi or lo)
        if not (1 <= lo <= hi <= 65535):
            raise ValueError("Ports must be between 1 and 65535.")
        ports.update(range(lo, hi + 1))
    return sorted(ports)


# ---------- nmap ----------
NMAP_PROFILES = {
    "Quick scan (top 100 ports)": ["-T4", "-F"],
    "Default scan (top 1000 ports)": ["-T4"],
    "Service and version detection": ["-T4", "-sV"],
    "Ping sweep (find live hosts)": ["-sn"],
    "All TCP ports": ["-T4", "-p-"],
    "Custom ports": ["-T4", "-p", "{ports}"],
}


def find_nmap():
    path = shutil.which("nmap")
    if path:
        return path
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if base:
            cand = os.path.join(base, "Nmap", "nmap.exe")
            if os.path.exists(cand):
                return cand
    return None


def nmap_args(profile, target, ports=""):
    args = [check_ports(ports) if a == "{ports}" else a for a in NMAP_PROFILES[profile]]
    return args + [check_target(target)]


# ---------- built-in TCP connect scanner (used when nmap is not installed) ----------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445, 465, 514, 587,
                636, 993, 995, 1433, 1521, 3306, 3389, 5060, 5432, 5900, 8080, 8443]
MAX_CONNECTIONS = 20000


def expand_hosts(target):
    t = check_target(target)
    if "/" in t:
        net = ipaddress.ip_network(t, strict=False)
        if net.num_addresses > 256:
            raise ValueError("The built-in scanner handles up to a /24. Install nmap for larger scans.")
        hosts = list(net.hosts()) or [net.network_address]
        return [str(h) for h in hosts]
    if re.search(r"\d-\d", t) and re.fullmatch(r"[\d.\-]+", t):
        raise ValueError("Ranges need nmap. Use a single host or a CIDR such as 10.0.0.0/24.")
    return [t]


def count_addresses(target):
    """How many addresses a scan target covers: a host is 1, 10.0.0.0/16 is 65536, 10.0.0.1-50 is 50."""
    t = check_target(target)
    try:
        if "/" in t:
            return ipaddress.ip_network(t, strict=False).num_addresses
        m = re.fullmatch(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", t)
        if m:
            return max(1, int(m.group(3)) - int(m.group(2)) + 1)
    except ValueError:
        pass
    return 1


def service_name(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return ""


class TcpScan(QThread):
    line = Signal(str)

    def __init__(self, target, ports):
        super().__init__()
        self.target, self.ports = target, ports
        self._stop = False

    def stop(self):
        self._stop = True

    def _probe(self, host, port):
        if self._stop:
            return None
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return host, port
        except OSError:
            return None

    def run(self):
        try:
            hosts = expand_hosts(self.target)
            if len(hosts) * len(self.ports) > MAX_CONNECTIONS:
                raise ValueError(f"Too many connections ({len(hosts) * len(self.ports)}). "
                                 "Narrow the targets or ports, or install nmap.")
        except ValueError as e:
            self.line.emit(f"Error: {e}")
            return
        self.line.emit(f"Built-in TCP connect scan: {len(hosts)} host(s), {len(self.ports)} port(s) each")
        found = 0
        with ThreadPoolExecutor(max_workers=150) as pool:
            for hit in pool.map(lambda hp: self._probe(*hp), ((h, p) for h in hosts for p in self.ports)):
                if hit:
                    found += 1
                    svc = service_name(hit[1])
                    self.line.emit(f"{hit[0]}:{hit[1]}/tcp  open  {svc}")
        self.line.emit("Stopped." if self._stop else f"Done. {found} open port(s) found.")


# ---------- subnet calculator ----------
def subnet_info(text):
    t = (text or "").strip()
    if not t:
        raise ValueError("Enter an address with a prefix, e.g. 192.168.1.10/24 or 10.0.0.0/255.255.255.0")
    iface = ipaddress.ip_interface(t)
    net = iface.network
    lines = [f"Address:      {iface.ip}", f"Network:      {net.network_address}/{net.prefixlen}",
             f"Netmask:      {net.netmask}"]
    if net.version == 4:
        lines += [f"Wildcard:     {net.hostmask}", f"Broadcast:    {net.broadcast_address}"]
        hosts = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
        if hosts > 0:
            first = net.network_address + (1 if net.prefixlen < 31 else 0)
            last = net.broadcast_address - (1 if net.prefixlen < 31 else 0)
            lines.append(f"Host range:   {first} - {last}")
        lines.append(f"Usable hosts: {max(hosts, 0):,}")
        lines.append(f"Private:      {'yes' if net.is_private else 'no'}")
    else:
        lines.append(f"Addresses:    {net.num_addresses:,}")
    return "\n".join(lines)


# ---------- SSH host keys ----------
HOSTKEY_MODES = ["Trust on first use", "Always trust", "Reject unknown hosts"]


def known_hosts_path():
    from core import db
    return db.db_path().parent / "known_hosts"


def list_host_keys():
    """[(host, key type, SHA256 fingerprint)] for every key Toner has saved."""
    path = known_hosts_path()
    out = []
    if path.exists():
        hk = paramiko.HostKeys()
        hk.load(str(path))
        for host, keys in hk.items():
            for ktype, key in keys.items():
                out.append((host, ktype, key.fingerprint))
    return sorted(out)


def forget_host_key(host=None):
    """Forget one host's saved key, or all of them (host=None)."""
    path = known_hosts_path()
    if not path.exists():
        return
    if host is None:
        path.write_text("", encoding="utf-8")
        return
    hk = paramiko.HostKeys()
    hk.load(str(path))
    if host in hk:
        del hk[host]
        hk.save(str(path))


# ---------- SSH session ----------
def configure_hostkeys(client, mode):
    """Host-key policy shared by the console and jump hosts: keys are remembered in a file; a known host whose key
    changed is always refused; an unknown one is saved on first use, or refused in 'Reject unknown hosts' mode."""
    if mode == "Always trust":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return
    path = known_hosts_path()
    path.touch(exist_ok=True)
    client.load_host_keys(str(path))
    client.set_missing_host_key_policy(paramiko.RejectPolicy() if mode == "Reject unknown hosts"
                                       else paramiko.AutoAddPolicy())


class SshSession(QThread):
    """Interactive shell over SSH. Emits raw bytes for a terminal emulator to interpret."""
    data = Signal(bytes)
    closed = Signal(str)

    def __init__(self, host, port, user, password, init_cmd="", cols=100, rows=30,
                 hostkey_mode="Trust on first use", timeout=15, jump_dev=None):
        super().__init__()
        self.jump_dev = jump_dev                 # inventory device that is reached through a jump host
        self.host, self.port, self.user, self.password = host, port, user, password
        self.init_cmd = init_cmd
        self.hostkey_mode, self.timeout = hostkey_mode, timeout
        self.cols, self.rows = cols, rows
        self.chan = None
        self._stop = False

    def send(self, data: bytes):
        try:
            if self.chan and not self.chan.closed:
                self.chan.send(data)
        except (OSError, EOFError, paramiko.SSHException):
            pass                                    # connection already dropped; run() reports it

    def resize(self, cols, rows):
        self.cols, self.rows = cols, rows
        try:
            if self.chan and not self.chan.closed:
                self.chan.resize_pty(width=cols, height=rows)
        except (OSError, EOFError, paramiko.SSHException):
            pass

    def stop(self):
        """Disconnect now. Closing the channel wakes the read loop immediately."""
        self._stop = True
        try:
            if self.chan:
                self.chan.close()
        except Exception:
            quiet.ignored()

    def run(self):
        client = paramiko.SSHClient()
        reason = "Connection closed by the remote host."
        extra = []
        try:
            configure_hostkeys(client, self.hostkey_mode)
            sock = None
            if self.jump_dev:
                from core import jump
                sock, extra = jump.open_channel(self.jump_dev, self.timeout)
            client.connect(self.host, port=self.port, username=self.user, password=self.password,
                           timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout,
                           allow_agent=False, look_for_keys=False, sock=sock)
            if self._stop:                                  # cancelled while connecting
                raise InterruptedError
            client.get_transport().set_keepalive(30)
            self.chan = client.invoke_shell(term="xterm-256color", width=self.cols, height=self.rows)
            self.chan.settimeout(0.3)
            if self.init_cmd:
                self.chan.send(self.init_cmd + "\r")
            while not self._stop and not self.chan.closed:
                try:
                    chunk = self.chan.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                self.data.emit(chunk)
        except InterruptedError:
            pass
        except paramiko.BadHostKeyException:
            reason = (f"HOST KEY CHANGED for {self.host}. It does not match the key saved earlier: the "
                      "device may have been replaced or reset, or something is impersonating it. "
                      "Connection refused. If the change is expected, forget the saved key under "
                      "Settings > Security.")
        except Exception as e:
            if self._stop:
                reason = "Disconnected by user."
            elif "not found in known_hosts" in str(e):
                reason = (f"{self.host} is not a known host and the policy is 'Reject unknown hosts'. "
                          "Connect once with 'Trust on first use' to save its key.")
            else:
                reason = f"Connection failed: {type(e).__name__}: {e}"
        finally:
            if self._stop:
                reason = "Disconnected by user."
            client.close()
            for c in extra:
                try:
                    c.close()
                except Exception:
                    quiet.ignored()
            self.closed.emit(reason)
