"""Readers for the output of common switch, router and firewall commands, shared by the SSH drivers. Each one is a plain function of the text the
device printed, so it is tested with samples of real output. When the text is not what the function expects it returns None (or an empty list):
the check says nothing, rather than guessing, and the driver keeps what the device said for a bug report."""
import calendar
import re
from datetime import datetime

OK, WARN, FAIL = "OK", "WARN", "FAIL"

_PART = re.compile(r"\b(fan|fans|blower|power|psu|ps\d|rps|supply|temp|temperature|sensor|cooling|thermal)\b", re.I)
_GOOD = re.compile(r"\b(ok|normal|good|healthy|up|online|operational|green|powering)\b", re.I)
_BAD = re.compile(r"\b(fail|failed|failure|faulty|fault|critical|shutdown|bad|abnormal|not ok|notok|defective|alarm|overtemp|over-temp|too hot|stopped|dead|lost|red|check)\b", re.I)
_MINOR = re.compile(r"\b(warning|warn|minor|major|degraded|high|low|yellow)\b", re.I)
_EMPTY = re.compile(r"\b(not present|absent|not installed|unsupported|n/a|not connected|empty|removed|unavailable|disabled|no fault)\b", re.I)
_TITLE = re.compile(r"^\s*(?:[A-Za-z]+ ){0,2}(fans?|power supply|power supplies|temperatures?|cooling|sensors?|thermal)\s*:?\s*$", re.I)


def scan_environment(text):
    """Fans, power supplies and temperature sensors in the output of an environment command: (lines understood, [(level, line)] with a problem).
    None when nothing in the text looks like a fan, power supply or sensor with a status. A table under a heading such as 'Fan:' counts
    row by row (its rows may not name the part); an empty power-supply bay is not a fault."""
    seen, problems, in_table = 0, [], False
    for raw in (text or "").splitlines():
        line = " ".join(raw.split())
        if not line:
            in_table = False
            continue
        if _TITLE.match(line):
            in_table = True
            continue
        if line.startswith(("%", "Invalid", "^", "-", "=")) or not (in_table or _PART.search(line)):
            continue
        clean = line.replace("no fault", "")
        if _EMPTY.search(line) and not _BAD.search(clean):
            continue
        bad, minor, good = _BAD.search(clean), _MINOR.search(clean), _GOOD.search(clean)
        if bad:
            seen += 1
            problems.append((FAIL, line[:90]))
        elif minor and not good:
            seen += 1
            problems.append((WARN, line[:90]))
        elif good:
            seen += 1
    return (seen, problems) if seen else None


def deep_status(obj, path=""):
    """Walk parsed JSON (Arista's 'show ... | json') and list every 'status' / 'state' that is not a good one: [(level, 'path: value')]."""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                found += deep_status(v, f"{path}{k}/")
            elif str(k).lower() in ("status", "state", "systemstatus", "powerstatus", "operstatus") and isinstance(v, str):
                low = v.lower()
                if low in ("ok", "powerok", "coolingok", "temperatureok", "normal", "good", "up", "present", "active", "ready", "online", "poweredon", "on", "") \
                        or "ok" == low[-2:] or low.startswith(("absent", "notpresent", "notinstalled", "unknown")):
                    continue
                found.append((FAIL if re.search(r"fail|critical|shutdown|bad|notok|fault|over|high|loss", low) else WARN, f"{path}{k}: {v}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found += deep_status(v, f"{path}{i}/")
    return found


# ---------------------------------------------------------------- time
_IOS_STAMP = re.compile(r"(\d{1,2}):(\d{2}):(\d{2})(?:\.\d+)?\s+(?:[A-Za-z]{2,5}\s+)?(?:[A-Za-z]{3}\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4})")


def ios_time(text):
    """'10:21:33 UTC Tue Oct 6 2026' or '10:21:33.123 UTC Tue Oct  6 2026' or '10:21:33 Oct 6 2026' -> datetime (no zone: both stamps use the device's)."""
    m = _IOS_STAMP.search(text or "")
    if not m:
        return None
    months = {name: i for i, name in enumerate(calendar.month_abbr) if name}
    try:
        return datetime(int(m.group(6)), months[m.group(4).capitalize()], int(m.group(5)), int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except (KeyError, ValueError):
        return None


def unsaved_ios(text):
    """Output of `show running-config | include ^! Last configuration change|^! NVRAM config last updated`:
    (True, 'changed 10:21 and not saved') when the running configuration is newer than the saved one; (False, '') when they match; None if unreadable."""
    changed = saved = None
    for line in (text or "").splitlines():
        if "Last configuration change" in line:
            changed = ios_time(line)
        elif "NVRAM config last updated" in line:
            saved = ios_time(line)
    if changed is None and saved is None:
        return None
    if changed is None:
        return False, ""
    if saved is None:
        return True, "the running configuration has never been saved"
    if (changed - saved).total_seconds() > 10:
        return True, f"changed {changed:%Y-%m-%d %H:%M}, last saved {saved:%Y-%m-%d %H:%M}"
    return False, ""


def ntp_state(text):
    """'synchronized' / 'unsynchronized' / None (NTP off or output not understood). Cisco, Arista and most others print the word."""
    low = (text or "").lower()
    if "not enabled" in low or "not configured" in low or "no associations" in low or not low.strip():
        return None
    if re.search(r"\bun-?synchroni[sz]ed\b|\bnot synchroni[sz]ed\b", low):
        return "unsynchronized"
    if re.search(r"synchroni[sz]ed", low):
        return "synchronized"
    return None


def junos_ntp(text):
    """`show ntp associations`: a line starting with * is the peer the clock follows."""
    peers = [ln for ln in (text or "").splitlines() if re.match(r"^[ *+#o.x-]\S+\s+\S+\s+\d+\s", ln)]
    if not peers:
        return None
    return "synchronized" if any(p.startswith(("*", "o")) for p in peers) else "unsynchronized"


# ---------------------------------------------------------------- storage
def flash_usage(text):
    """`dir flash:` / `dir bootflash:` end with '7651819520 bytes total (6342328320 bytes free)' -> (used %, free bytes); None if absent.
    An ASA writes '(7804764160 bytes free/94% free)'."""
    m = re.search(r"(\d+)\s+bytes total\s*\((\d+)\s+bytes free[^)]*\)", text or "")
    if not m or int(m.group(1)) == 0:
        return None
    total, free = int(m.group(1)), int(m.group(2))
    return (total - free) / total * 100, free


# ---------------------------------------------------------------- Cisco
def stack_members(text):
    """`show switch`: [(number, role, state)] for each member; [] when the switch is not stacked or the output is not a table.
    Newer software has a hardware-version column before the state; older software does not."""
    rows = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*\*?\s*(\d+)\s+(Active|Standby|Member)\s+\S+\s+\d+\s+\S+\s+(.+?)\s*$", line) or             re.match(r"^\s*\*?\s*(\d+)\s+(Active|Standby|Member)\s+\S+\s+\d+\s+(.+?)\s*$", line)
        if m:
            rows.append((m.group(1), m.group(2), m.group(3)))
    return rows



def hsrp_groups(text):
    """`show standby brief` / `show vrrp brief`: [(interface, group, state)]."""
    rows = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\S+)\s+(\d+)\s+\d+\s+(?:P\s+)?(Active|Standby|Init|Listen|Speak|Learn|Master|Backup|Disabled)\b", line) or \
            re.match(r"^\s*(\S+)\s+(\d+)\s+\d+\s+\d+\s+(?:[YN]\s+)?[YN]?\s*(Master|Backup|Init)\b", line)          # VRRP: priority, timer, owner and preempt flags, state
        if m:
            rows.append((m.group(1), m.group(2), m.group(3)))
    return rows


def etherchannels(text):
    """`show etherchannel summary`: [(channel, flags, [(member, flags)])]. Flags such as 'SU' (in use), 'SD' (down), 'P' (bundled), 'D' (down), 's' (suspended)."""
    out = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(\d+)\s+(Po\d+)\((\w+)\)\s+\S+\s*(.*)$", line)
        if m:
            out.append((m.group(2), m.group(3), re.findall(r"(\S+?)\((\w+)\)", m.group(4))))
    return out


def asa_cpu(text):
    """`show cpu usage`: 'CPU utilization for 5 seconds = 1%; 1 minute: 2%; 5 minutes: 3%' -> 3; None if absent."""
    m = re.search(r"5\s+minutes?\s*[:=]\s*(\d+)\s*%", text or "")
    return int(m.group(1)) if m else None


def asa_memory(text):
    """`show memory`: 'Used memory:  3544279040 bytes (41%)' -> 41.0; None if absent. Worked out from the byte counts when the
    percentage is missing."""
    t = text or ""
    m = re.search(r"Used memory:\s+(\d+)\s+bytes\s*\(\s*(\d+)\s*%\s*\)", t)
    if m:
        return float(m.group(2))
    used, total = re.search(r"Used memory:\s+(\d+)", t), re.search(r"Total memory:\s+(\d+)", t)
    if used and total and int(total.group(1)):
        return int(used.group(1)) / int(total.group(1)) * 100
    return None


def asa_uptime(text):
    """`show version`: 'fw1 up 12 days 3 hours' -> '12 days 3 hours' (the unit's own line, not 'failover cluster up ...'); None if absent."""
    for m in re.finditer(r"^(\S+)\s+up\s+((?:\d+\s+[a-z]+\s*)+)$", text or "", re.M | re.I):
        if m.group(1).lower() not in ("cluster", "failover"):
            return m.group(2).strip()
    return None


def asa_interfaces(text):
    """`show interface`: [{'interface', 'nameif', 'link_status', 'input_errors', 'crc'}]. Toner's own reading: the ntc-templates
    one stops at any line it does not know (an ASAv in Azure prints some) and does not read the error counters."""
    rows, cur = [], None
    for line in (text or "").splitlines():
        m = re.match(r'^Interface\s+(\S+?)(?:\s+"([^"]*)")?,?\s+is\s+(.+?),\s+line\s+protocol\s+is\s+(\S+)', line.strip())
        if m:
            cur = {"interface": m.group(1), "nameif": m.group(2) or "", "link_status": m.group(3).strip(), "input_errors": 0, "crc": 0}
            rows.append(cur)
            continue
        e = re.search(r"(\d+)\s+input errors,\s+(\d+)\s+CRC", line)
        if e and cur is not None:
            cur["input_errors"], cur["crc"] = int(e.group(1)), int(e.group(2))
    return rows


def bgp_running(text):
    """`show ip bgp summary` (IOS, NX-OS) / `show bgp summary` (ASA): BGP is configured when it names its router identifier."""
    return bool(re.search(r"BGP router identifier", text or "", re.I))


def ospf_running(text):
    """`show ip ospf` (IOS, NX-OS) / `show ospf` (ASA): 'Routing Process "ospf 1" with ID 10.0.0.1' when OSPF is configured."""
    return bool(re.search(r"Routing Process\b.*\bwith ID", text or "", re.I))


def eigrp_neighbors(text):
    """`show ip eigrp neighbors` (IOS, NX-OS) / `show eigrp neighbors` (ASA): (running, [(address, interface)]). A configured
    process prints its heading ('EIGRP-IPv4 Neighbors for AS(100)', 'IP-EIGRP neighbors for process 100') even with no neighbors;
    a neighbor that goes down simply leaves the table."""
    t = text or ""
    running = bool(re.search(r"EIGRP\S*\s+neighbors\s+for", t, re.I))
    rows = re.findall(r"^\s*\d+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+\d+\s+\S+\s+\d+", t, re.M)
    return running or bool(rows), rows


def asa_failover(text):
    """`show failover`: (state of this unit, state of the other, [problems]); None when failover is off or the output is not understood."""
    if not text or "Failover Off" in text or "not supported" in text.lower():
        return None
    this = re.search(r"This host:\s*(\S+)\s*-\s*([A-Za-z ]+?)\s*$", text, re.M)
    other = re.search(r"Other host:\s*(\S+)\s*-\s*([A-Za-z ]+?)\s*$", text, re.M)
    if not this or not other:
        return None
    problems = [f"{who}: {st}" for who, st in (("this unit", this.group(2)), ("the other unit", other.group(2)))
                if re.search(r"Failed|Not Detected|Unknown|Disabled", st, re.I)]
    return this.group(2).strip(), other.group(2).strip(), problems


# ---------------------------------------------------------------- Juniper, Arista
def junos_core_dumps(text):
    """`show system core-dumps` lists files, or says there are none (no such file / no core dumps)."""
    t = text or ""
    if re.search(r"no such file|cannot access|no core", t, re.I):
        return []
    return [m.group(1) for m in re.finditer(r"(/var/(?:crash|tmp|db)\S*core\S*)", t)]


def junos_bfd_down(text):
    """`show bfd session`: the addresses of sessions that are not Up."""
    return [m.group(1) for m in re.finditer(r"(?m)^\s*(\d+\.\d+\.\d+\.\d+)\s+(Down|Init|AdminDown)\b", text or "")]


def mlag_problems(data):
    """Arista `show mlag | json`: None when MLAG is not set up, else [problems]."""
    if not isinstance(data, dict) or str(data.get("state", "disabled")).lower() in ("disabled", ""):
        return None
    out = []
    if str(data.get("negStatus", "connected")).lower() not in ("connected",):
        out.append(f"peer {data.get('negStatus')}")
    if str(data.get("peerLinkStatus", "up")).lower() not in ("up",):
        out.append(f"peer link {data.get('peerLinkStatus')}")
    if str(data.get("configSanity", "consistent")).lower() not in ("consistent",):
        out.append(f"configuration {data.get('configSanity')}")
    ports = data.get("mlagPorts") or {}
    if int(ports.get("Inactive", 0) or 0) or int(ports.get("Active-partial", 0) or 0):
        out.append(f"{int(ports.get('Inactive', 0) or 0)} inactive and {int(ports.get('Active-partial', 0) or 0)} partly active MLAG ports")
    return out


# ---------------------------------------------------------------- MikroTik
def _mt_bytes(text):
    m = re.match(r"\s*([\d.]+)\s*([KMGT]?i?B)", text or "", re.I)
    if not m:
        return None
    return float(m.group(1)) * {"b": 1, "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3, "tib": 1024 ** 4, "kb": 1000, "mb": 1000 ** 2, "gb": 1000 ** 3}.get(m.group(2).lower(), 1)


def mikrotik_disk(kv):
    """`/system resource print` fields -> used % of the flash, or None."""
    total, free = _mt_bytes(kv.get("total-hdd-space", "")), _mt_bytes(kv.get("free-hdd-space", ""))
    return (total - free) / total * 100 if total and free is not None else None


def mikrotik_health(text):
    """`/system health print` (v6 'name: value' lines and v7 'name=temperature value=45' rows): ({'temperature': 45.0, ...}, voltage or None)."""
    temps, volt = {}, None
    for m in re.finditer(r"(?m)^\s*((?:cpu-|board-|sfp-|switch-|phy-)?temperature\d*)\s*:\s*(-?\d+(?:\.\d+)?)\s*C", text or ""):
        temps[m.group(1)] = float(m.group(2))
    for m in re.finditer(r"name=((?:cpu-|board-|sfp-|switch-|phy-)?temperature\d*)\s+value=(-?\d+(?:\.\d+)?)", text or ""):
        temps[m.group(1)] = float(m.group(2))
    v = re.search(r"(?m)^\s*voltage\s*:\s*([\d.]+)\s*V", text or "") or re.search(r"name=voltage\s+value=([\d.]+)", text or "")
    if v:
        volt = float(v.group(1))
    return temps, volt


def mikrotik_firmware(text):
    """`/system routerboard print`: (running, upgrade) firmware versions, or None on a virtual router."""
    cur, up = re.search(r"(?m)^\s*current-firmware:\s*(\S+)", text or ""), re.search(r"(?m)^\s*upgrade-firmware:\s*(\S+)", text or "")
    return (cur.group(1), up.group(1)) if cur and up else None


def mikrotik_ntp(text):
    """`/system ntp client print`: 'off', 'synchronized', 'unsynchronized' or None."""
    t = text or ""
    if re.search(r"(?m)^\s*enabled:\s*no", t):
        return "off"
    st = re.search(r"(?m)^\s*status:\s*(\S+)", t)
    if st:
        return "synchronized" if st.group(1).lower().startswith("synchron") else "unsynchronized"
    return None
