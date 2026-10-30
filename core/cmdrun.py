"""Run the same command(s) on many devices and collect the output.

Three kinds of device take commands:
- network devices Toner already logs into over SSH (Cisco, Juniper, Arista, HPE, MikroTik): their own command line;
- Windows computers Toner can reach itself (this PC, or over WinRM): PowerShell;
- Fortinet and Palo Alto firewalls, over SSH, with the SSH login stored on the device (Edit device > Access); their checks use the API key.
A Windows computer that reports by agent cannot be commanded: the agent only sends."""
import base64
import io
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.netconn import connect as ConnectHandler      # netmiko's, with Toner's fixes for some devices (ASA)
from core.netconn import any_mode

from core import db, profiles, vendors, winmon
from core import quiet

# ---------------------------------------------------------------- which devices, and how
KINDS = {"ssh": "network device (SSH)", "cli": "firewall (SSH)", "windows": "Windows computer (PowerShell)"}


def kind_of(dev):
    """'ssh', 'windows' or 'cli' for a device that can take commands (whatever its state); '' for one that cannot."""
    vendor = dev.get("vendor")
    if vendor == "windows":
        return "windows"
    if vendor in vendors.CLI_TYPES:
        return "cli"
    return "ssh" if vendors.get(vendor).get("kind") == "ssh" else ""


# why a device cannot take commands: the short reason (shown beside its name) and what to do about it (its tooltip)
HELP = {"reports by agent": "This computer reports through an agent, which only sends and takes no commands. Monitor it with WinRM (Edit device) to run commands on it.",
        "no SSH login": "Add an SSH user name and SSH password for this firewall: Edit device > Access. Its checks use the API key; the Command Runner and config backups use the SSH login.",
        "not supported": "Commands cannot be run on this kind of device."}


def runnable(dev):
    """(True, '') when commands can be run on this device now, or (False, a short reason, a key of HELP)."""
    kind = kind_of(dev)
    if not kind:
        return False, "not supported"
    if kind == "windows" and winmon.transport(dev) == "agent":
        return False, "reports by agent"
    if kind == "cli" and not ((dev.get("username") or "").strip() and profiles.secret(dev, "ssh")):
        return False, "no SSH login"
    return True, ""


# ---------------------------------------------------------------- the read-only guard
# first words of commands that only read; everything else needs the operator's explicit say-so
READ_ONLY = ("show", "display", "get", "ping", "traceroute", "tracert", "dir", "more", "list", "monitor", "diagnose",
             "diag", "/system resource print", "/interface print", "/ip address print", "/export", "/ping", "/tool traceroute",
             "/tool torch")
DANGEROUS = ("reload", "reboot", "restart", "erase", "format", "delete", "write erase", "factory", "reset", "shutdown",
             "no ", "clear", "configure", "conf t", "commit", "copy ", "request ", "/system reset", "/system reboot",
             "/system shutdown", "execute", "set ", "unset", "config ")
# words that change something even after a looking first word (diagnose sys session clear, diagnose sys kill ...); a filter after | is only text
CHANGE_WORDS = {"clear", "kill", "reset", "reboot", "restart", "delete", "erase", "format", "flush", "shutdown", "stop", "upgrade"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def read_only(command):
    if _CONTROL.search((command or "").strip()):           # a line break inside would reach the device as a second command
        return False
    c = (command or "").strip().lower()
    if not c:
        return True
    if not c.startswith(READ_ONLY) or any(c.startswith(d) for d in DANGEROUS):
        return False
    if c.startswith("/") and re.search(r"[;\[\]{}]|\bfile=", c):   # RouterOS: ; runs another command, [ ] one inside, file= writes
        return False
    return not set(c.split("|", 1)[0].split()) & CHANGE_WORDS


# PowerShell. A command is read-only when it is a chain of cmdlets that only look (Get-, Test-, Measure-, Select-, Sort-, Where-, Format-,
# Group-, ConvertTo-...), commands Windows has for looking (hostname, ipconfig, whoami, systeminfo, netstat, tasklist ...) and their usual
# short names, with nothing that could run something else: no variables set, redirection, sub-expressions, calls, or script blocks other than
# a plain comparison on $_ in Where-Object, Select-Object or Sort-Object.
_PS_VERBS = ("get-", "test-", "measure-", "select-", "sort-", "where-", "format-", "group-", "convertto-", "convertfrom-json", "compare-",
             "resolve-", "out-string")
_PS_ALIASES = {"gci", "dir", "ls", "gps", "ps", "gsv", "gc", "cat", "type", "gcm", "gm", "gi", "gp", "gl", "pwd", "measure", "select", "sort",
               "where", "?", "ft", "fl", "fw", "group", "gwmi", "gcim", "gip", "gu", "gjb", "ghy", "gh", "gtz", "gdr", "gmo", "gal"}
_PS_NATIVE = {"hostname", "ipconfig", "whoami", "systeminfo", "netstat", "tasklist", "quser", "nslookup", "ping", "tracert", "pathping",
              "arp", "getmac", "driverquery", "gpresult", "qwinsta", "query", "w32tm", "sc", "netsh", "route", "net", "wevtutil", "nltest",
              "dsregcmd", "fsutil", "vol", "ver", "date", "time"}
# for the commands that can also change things, only these forms read
_PS_NATIVE_FORMS = {
    "w32tm": re.compile(r"^w32tm\s+/(query|monitor|tz|stripchart)\b", re.I),
    "sc": re.compile(r"^sc(\.exe)?\s+(\\\\\S+\s+)?(query|queryex|qc|qdescription|qfailure|qtriggerinfo|enumdepend|getdisplayname|getkeyname)\b", re.I),
    "netsh": lambda p: _netsh_reads(p),
    "route": re.compile(r"^route\s+print\b", re.I),
    "net": lambda p: _net_reads(p),
    "wevtutil": re.compile(r"^wevtutil\s+(qe|gl|el|gli)\b", re.I),
    "gpresult": re.compile(r"^gpresult(\.exe)?(?!.*\s/[hxf](\s|$))", re.I),       # /h and /x write a report file
    "nltest": re.compile(r"^nltest\s+/(dsgetdc|dclist|sc_query|domain_trusts|parentdomain|whowill|server)\b", re.I),
    "fsutil": re.compile(r"^fsutil\s+(volume\s+diskfree|fsinfo|behavior\s+query|dirty\s+query)\b", re.I),
    "query": re.compile(r"^query\s+(user|session|process|termserver)\b", re.I),
    "arp": re.compile(r"^arp\s+-a\b", re.I),
    "dsregcmd": re.compile(r"^dsregcmd\s+/status\b", re.I),
}
# net: each form that looks, and how many names it may be given (`net user bob` shows bob; `net user bob secret` sets his password)
_NET_READS = {"statistics": 1, "share": 1, "user": 1, "localgroup": 1, "group": 1, "view": 1, "accounts": 0, "config": 1, "time": 1,
              "session": 1, "file": 1, "use": 0}
_NET_OPTIONS = {"/domain", "/all"}                                           # the only switches that change nothing
_NETSH_VERBS = {"add", "set", "delete", "del", "reset", "dump", "exec", "install", "uninstall", "start", "stop", "import", "export",
                "connect", "disconnect", "flush", "renew", "release", "commit", "apply", "load", "save"}
# PowerShell takes these as quotes too, so they could end a string this check still thinks is open
_PS_QUOTES = "‘’‚‛“”„"


def _net_reads(p):
    words = re.findall(r'"[^"]*"|\'[^\']*\'|\S+', p)[1:]
    if not words or words[0].lower() not in _NET_READS:
        return False
    rest = words[1:]
    names = [w for w in rest if not w.startswith("/")]
    return (len(names) <= _NET_READS[words[0].lower()] and not any("=" in w for w in rest)
            and all(w.lower() in _NET_OPTIONS for w in rest if w.startswith("/")))


def _netsh_reads(p):
    """`netsh <context> show ...`: only plain context words before `show` (a rule *named* show is still an add)."""
    words = [w.lower() for w in p.split()[1:]]
    if "show" not in words:
        return False
    return all(re.fullmatch(r"[a-z0-9]+", w) and w not in _NETSH_VERBS for w in words[:words.index("show")])


_SAFE_BLOCK = re.compile(r"^[\w\s$_.'\"\-*?,@\[\]!:%/\\+~#]*$")           # inside { }: names, values and comparisons, never calls or assignments
_BLOCK_OWNERS = {"where-object", "where", "?", "select-object", "select", "sort-object", "sort", "group-object", "group", "measure-object"}


def _plain_condition(inner):
    """True when what is inside { } is only variables ($_.Name), operators (-eq, -like, -and ...), numbers and quoted values: no bare word that
    could be a command."""
    bare = re.sub(r"'[^']*'|\"[^\"]*\"", " ", inner)
    for tok in re.split(r"[\s,]+", bare):
        if tok and not re.match(r"^(\$|-[A-Za-z]|\d|[!@*?.()\[\]:%/+~#])", tok):
            return False
    return True


def _ps_segments(text):
    """The pieces of a PowerShell line split at |, ; and line breaks outside quotes, with every {...} reduced to {} after checking it is a
    plain comparison. Returns None when the line has anything that could run something else."""
    out, cur, i, n = [], "", 0, len(text)
    quote = ""
    while i < n:
        ch = text[i]
        if quote:
            if ch == "`":
                return None
            if quote == '"' and ch == "$" and text[i + 1:i + 2] == "(":
                return None
            cur += ch
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            cur += ch
        elif ch == "`":
            return None
        elif ch == "$" and text[i + 1:i + 2] == "(":
            return None
        elif ch in "&<>()":                                  # ( ) would run the command inside as an argument
            return None
        elif ch == "{":
            depth, j = 1, i + 1
            while j < n and depth:
                depth += (text[j] == "{") - (text[j] == "}")
                j += 1
            inner = text[i + 1:j - 1]
            owner = re.findall(r"[\w?-]+\s*$", cur)
            if depth or "{" in inner or not _SAFE_BLOCK.match(inner) or "=" in inner or not _plain_condition(inner):
                return None
            if not owner or owner[-1].strip().lower() not in _BLOCK_OWNERS:
                return None
            cur += "{}"
            i = j
            continue
        elif ch == "}":
            return None
        elif ch in "|;\n\r":
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
        i += 1
    if quote:
        return None
    out.append(cur.strip())
    return out


def read_only_ps(command):
    """True when a PowerShell command line only looks at things."""
    c = (command or "").strip()
    if not c:
        return True
    if any(q in c for q in _PS_QUOTES):
        return False
    parts = _ps_segments(c)
    if not parts or any(not p for p in parts):
        return False
    for p in parts:
        first = p.split(None, 1)[0].lower().rstrip(":")
        name = first[:-4] if first.endswith(".exe") else first
        if first.startswith(_PS_VERBS) or first in _PS_ALIASES:
            continue
        if name in _PS_NATIVE:
            form = _PS_NATIVE_FORMS.get(name)
            if form is not None and not (form(p) if callable(form) else form.match(p)):
                return False
            continue
        return False
    return True


def read_only_for(kind, command):
    return read_only_ps(command) if kind == "windows" else read_only(command)


def risky_commands(devs, commands):
    """The commands that could change at least one of these devices (each judged by the kind of device it would run on)."""
    kinds = {kind_of(d) for d in devs} - {""}
    return [c for c in commands if any(not read_only_for(k, c) for k in kinds)]


def split_commands(text):
    return [l.strip() for l in (text or "").splitlines() if l.strip() and not l.strip().startswith("#")]


# ---------------------------------------------------------------- running them
def _blank(dev):
    return {"device": dev["name"], "ok": False, "outputs": [], "error": "", "seconds": 0.0}


def _run_ssh(dev, commands, opts, read_timeout, out):
    from drivers import DRIVERS
    cls = DRIVERS.get(dev["vendor"])
    drv = cls(dev, {}, opts or db.runtime_options())
    drv.plat = dev.get("platform") or cls.DEFAULT_PLATFORM
    drv.session_log = out.get("_log")
    with drv.connect() as c:
        try:
            c.enable()
        except Exception:
            quiet.ignored()
        prompt = any_mode(c)                        # 'conf t' and the like change the prompt
        for cmd in commands:
            out["outputs"].append((cmd, c.send_command(cmd, read_timeout=read_timeout, expect_string=prompt)))


def _run_cli(dev, commands, opts, read_timeout, out):
    """A firewall's own command line, over SSH, with the login stored on the device (its API key is for the checks)."""
    user, pw = (dev.get("username") or "").strip(), profiles.secret(dev, "ssh")
    if not user or not pw:
        raise ValueError("no SSH login is stored for this device: Edit device > Access, SSH user name and SSH password")
    t = int((opts or db.runtime_options()).get("ssh_timeout", 20))
    port = int(db.get_setting("default_ssh_port") or 22)
    args = dict(device_type=vendors.CLI_TYPES[dev["vendor"]], host=dev["host"], username=user, password=pw,
                port=port, timeout=t, conn_timeout=t)
    if out.get("_log") is not None:
        args["session_log"] = out["_log"]
    from core import jump
    sock, closers = jump.open_channel({**dev, "port": port}, t)     # through the proxy or SSH tunnel, as the checks go
    if sock is not None:
        args["sock"] = sock
    try:
        with ConnectHandler(**args) as c:
            prompt = any_mode(c)
            for cmd in commands:
                out["outputs"].append((cmd, c.send_command(cmd, read_timeout=read_timeout, expect_string=prompt)))
    finally:
        for x in closers:
            try:
                x.close()
            except Exception:
                quiet.ignored()


def ps_script(commands):
    """One PowerShell script that runs each command and prints every command's output as one line of JSON. The commands travel as base64, so
    nothing in them can break out of the script around them."""
    items = ",".join("'" + base64.b64encode(c.encode("utf-8")).decode("ascii") + "'" for c in commands)
    return f"""
$ErrorActionPreference = 'Continue'
$list = @({items})
$res = foreach ($b in $list) {{
    $c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b))
    try {{ $t = (& {{ Invoke-Expression $c }} *>&1 | Out-String -Width 220).TrimEnd() }} catch {{ $t = 'ERROR: ' + $_.Exception.Message }}
    [ordered]@{{ command = $c; output = [string]$t }}
}}
[ordered]@{{ results = @($res) }} | ConvertTo-Json -Depth 4 -Compress
"""


def parse_ps(text):
    text = text or ""
    start = text.find("{")
    if start < 0:
        raise ValueError("the computer returned no answer" + (f": {text.strip()[:200]}" if text.strip() else ""))
    data = json.loads(text[start:text.rfind("}") + 1])
    rows = data.get("results") if isinstance(data, dict) else None
    if isinstance(rows, dict):
        rows = [rows]                                    # PowerShell 5.1 turns a list of one into the item itself
    if not isinstance(rows, list):
        raise ValueError("the answer was not understood")
    return [(str(r.get("command") or ""), str(r.get("output") or "")) for r in rows if isinstance(r, dict)]


def _run_windows(dev, commands, opts, read_timeout, out):
    how = winmon.transport(dev)
    script = ps_script(commands)
    timeout = max(60, read_timeout * max(1, len(commands)))
    if how == "local":
        rows = winmon.collect_local(timeout=timeout, script=script, parser=parse_ps)
    elif how == "winrm":
        rows = winmon.collect_winrm(dev, dev.get("password") or profiles.secret(dev, "main"), timeout=timeout, script=script, parser=parse_ps)
    else:
        raise RuntimeError("this computer reports through an agent, which takes no commands")
    out["outputs"].extend(rows)


def run_on_device(dev, commands, opts=None, read_timeout=60):
    """Run the commands on one device (one SSH session, or one PowerShell run). Returns {'device','ok','outputs':[(command, text)],'error','seconds'}."""
    start = time.time()
    dev = profiles.resolve(dev)
    out = _blank(dev)
    kind = kind_of(dev)
    if not kind:
        out["error"] = "no way to run commands on this kind of device (Cisco, Juniper, Arista, HPE and MikroTik by SSH, Windows by PowerShell, Fortinet and Palo Alto by SSH)"
        return out
    if kind in ("ssh", "cli"):
        out["_log"] = io.BytesIO()                  # what was sent and received (netmiko leaves the passwords out)
    try:
        {"ssh": _run_ssh, "cli": _run_cli, "windows": _run_windows}[kind](dev, commands, opts, read_timeout, out)
        out["ok"] = True
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    path = _save_session(dev, out.pop("_log", None))
    if path and out["error"]:
        out["error"] += f" The session was written to {path}"
    out["seconds"] = time.time() - start
    return out


def session_file(dev):
    from core import sessionlog
    safe = re.sub(r"[^\w.-]+", "_", dev["name"])[:60]
    return sessionlog.log_dir() / f"command-runner-{safe}.log"


def _save_session(dev, buf):
    """Write the last Command Runner session with this device to the SSH logs folder (one file per device, replaced each
    time), so a failure can be looked at. Returns its path, or None when there was nothing to write."""
    data = buf.getvalue() if buf is not None else b""
    if not data:
        return None
    try:
        path = session_file(dev)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path
    except OSError:
        return None


def run_many(devices, commands, workers=8, on_result=None, opts=None, cancel=None):
    results = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        def one(d):
            with db.within(d.get("org")):                  # its passwords, jump host and proxy are in its own organization
                r = run_on_device(d, commands, opts)
            if d.get("key") and d["key"] != d["name"]:     # Global: another organization's device, named with it
                r["device"] = db.label_org(d["key"])
            return r
        futs = [pool.submit(one, d) for d in devices]
        for f in as_completed(futs):
            r = f.result()
            results.append(r)
            if on_result:
                on_result(r)
            if cancel is not None and cancel.is_set():
                for g in futs:
                    g.cancel()
                break
    return sorted(results, key=lambda r: r["device"].lower())
