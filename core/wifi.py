"""This computer's Wi-Fi: the current connection and the networks in range. Read from Windows' `netsh wlan` (the labels are
matched in English; the signal strength is also found by its '%' sign, so that still works elsewhere), and on Linux from
NetworkManager's `nmcli` (its terse output, the same fields in the same shape)."""
import re
import subprocess

_KEY = re.compile(r"^\s*([^:]+?)\s+:\s+(.*?)\s*$")
_MAC = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")


def _netsh(*args, timeout=20):
    r = subprocess.run(["netsh", "wlan", *args], capture_output=True, text=True, timeout=timeout, errors="replace",
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return (r.stdout or "") + (r.stderr or "")


def band_of(channel, band_text=""):
    """'5 GHz' from the text when Windows gives it, else guessed from the channel number (2.4 GHz is 1-14)."""
    m = re.search(r"(2\.4|5|6)\s*GHz", band_text or "", re.I)
    if m:
        return f"{m.group(1)} GHz"
    try:
        return "2.4 GHz" if int(channel) <= 14 else "5 GHz"
    except (TypeError, ValueError):
        return ""


def _int(text):
    m = re.search(r"\d+", text or "")
    return int(m.group(0)) if m else None


# ---------------------------------------------------------------- the connection
def parse_interfaces(text):
    """`netsh wlan show interfaces` -> one dict per adapter."""
    out, cur = [], None
    for line in (text or "").splitlines():
        m = _KEY.match(line)
        if not m:
            continue
        key, val = m.group(1).strip().lower(), m.group(2)
        if key == "name":
            cur = {"name": val}
            out.append(cur)
        elif cur is not None:
            cur[key] = val
            if "%" in val and "signal" not in cur and re.fullmatch(r"\d{1,3}%", val):
                cur["signal"] = val                      # other languages label it differently
    for d in out:
        d["signal_pct"] = _int(d.get("signal"))
        d["connected"] = d.get("state", "").lower() == "connected" or bool(d.get("ssid") and d.get("bssid"))
        d["channel_no"] = _int(d.get("channel"))
        d["band_text"] = band_of(d["channel_no"], d.get("band", ""))
        d["rx"], d["tx"] = _int(d.get("receive rate (mbps)")), _int(d.get("transmit rate (mbps)"))
    return out


def interfaces():
    """(adapters, error text). An empty list with no error means this computer has no Wi-Fi adapter."""
    from core.platforms import WINDOWS
    if not WINDOWS:
        return _nm_interfaces()
    try:
        text = _netsh("show", "interfaces")
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], f"{type(e).__name__}: {e}"
    return parse_interfaces(text), ""


def current(adapters):
    """The adapter to report on: the first connected one, else the first."""
    return next((a for a in adapters if a["connected"]), adapters[0] if adapters else None)


# ---------------------------------------------------------------- the networks in range
def parse_networks(text):
    """`netsh wlan show networks mode=bssid` -> one dict per access point (BSSID)."""
    nets, ssid, auth, enc, cur = [], "", "", "", None
    for line in (text or "").splitlines():
        m = re.match(r"^\s*SSID\s+\d+\s*:\s*(.*?)\s*$", line)
        if m:
            ssid, auth, enc, cur = m.group(1), "", "", None
            continue
        m = re.match(r"^\s*BSSID\s+\d+\s*:\s*(.*?)\s*$", line)
        if m:
            cur = {"ssid": ssid or "(hidden)", "bssid": m.group(1).lower(), "auth": auth, "encryption": enc,
                   "signal": None, "channel": None, "radio": "", "band": ""}
            nets.append(cur)
            continue
        m = _KEY.match(line) or re.match(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$", line)
        if not m:
            continue
        key, val = m.group(1).strip().lower(), m.group(2)
        if cur is None:
            if key == "authentication":
                auth = val
            elif key == "encryption":
                enc = val
        elif key == "signal":
            cur["signal"] = _int(val)
        elif key == "channel":
            cur["channel"] = _int(val)
        elif key == "radio type":
            cur["radio"] = val
        elif key == "band":
            cur["band"] = val
    for n in nets:
        n["band"] = band_of(n["channel"], n["band"])
    return nets


def scan():
    """(access points, error text). Windows may need Location access switched on to list networks."""
    from core.platforms import WINDOWS
    if not WINDOWS:
        return _nm_scan()
    try:
        text = _netsh("show", "networks", "mode=bssid", timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], f"{type(e).__name__}: {e}"
    nets = parse_networks(text)
    if not nets:
        low = text.lower()
        if "location" in low or "elevation" in low or "permission" in low:
            return [], ("Windows would not list networks. Turn on Settings > Privacy & security > Location "
                        "(and 'Let desktop apps access your location'), then scan again.")
        if "no wireless interface" in low or "wlan autoconfig service is not running" in low:
            return [], "This computer has no Wi-Fi adapter, or the WLAN AutoConfig service is not running."
        return [], "No networks were found."
    return nets, ""


# ---------------------------------------------------------------- Linux: NetworkManager (nmcli)
NM_AP_FIELDS = "ACTIVE,SSID,BSSID,CHAN,FREQ,SIGNAL,RATE,SECURITY,DEVICE"
NM_MISSING = "nmcli was not found. On Linux, Toner reads Wi-Fi through NetworkManager (nmcli)."


def _nmcli(*args, timeout=20):
    r = subprocess.run(["nmcli", "-t", *args], capture_output=True, text=True, timeout=timeout, errors="replace")
    return r.stdout or "", r.returncode, (r.stderr or "").strip()


def nm_fields(line):
    """One line of nmcli's terse output, split on the colons it does not escape (a BSSID's colons have a backslash before them)."""
    out, cur, i = [], "", 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur += line[i + 1]
            i += 2
            continue
        if c == ":":
            out.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    out.append(cur)
    return out


def band_of_freq(freq):
    mhz = _int(freq)
    if not mhz:
        return ""
    return "2.4 GHz" if mhz < 3000 else "5 GHz" if mhz < 5925 else "6 GHz"


def parse_nm_networks(text):
    """`nmcli -t -f ACTIVE,SSID,BSSID,CHAN,FREQ,SIGNAL,RATE,SECURITY,DEVICE dev wifi list` -> one dict per access point."""
    nets = []
    for line in (text or "").splitlines():
        f = nm_fields(line)
        if len(f) < 9:
            continue
        active, ssid, bssid, chan, freq, signal, rate, security, device = f[:9]
        nets.append({"ssid": ssid or "(hidden)", "bssid": bssid.lower(), "auth": security if security not in ("", "--") else "Open",
                     "encryption": "", "signal": _int(signal), "channel": _int(chan), "radio": "",
                     "band": band_of_freq(freq) or band_of(_int(chan)), "active": active == "yes", "rate": _int(rate),
                     "device": device})
    return nets


def parse_nm_interfaces(dev_text, ap_text):
    """`nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device` and the access point list -> adapters, shaped like netsh's."""
    aps = parse_nm_networks(ap_text)
    out = []
    for line in (dev_text or "").splitlines():
        f = nm_fields(line)
        if len(f) < 4 or f[1] != "wifi":
            continue
        name, _t, state, conn = f[:4]
        ap = next((a for a in aps if a["active"] and a["device"] in ("", name)), None)
        d = {"name": name, "state": state, "ssid": ap["ssid"] if ap else (conn if conn not in ("", "--") else ""),
             "bssid": ap["bssid"] if ap else "", "signal": f"{ap['signal']}%" if ap and ap["signal"] is not None else "",
             "channel": str(ap["channel"]) if ap and ap["channel"] else "", "authentication": ap["auth"] if ap else ""}
        d["signal_pct"] = ap["signal"] if ap else None
        d["connected"] = state.startswith("connected") and ap is not None
        d["channel_no"] = ap["channel"] if ap else None
        d["band_text"] = ap["band"] if ap else ""
        d["rx"], d["tx"] = (ap["rate"] if ap else None), None
        out.append(d)
    return out


def _nm_interfaces():
    try:
        devs, code, err = _nmcli("-f", "DEVICE,TYPE,STATE,CONNECTION", "device")
        if code:
            return [], err or "nmcli could not list the network devices."
        aps, _c, _e = _nmcli("-f", NM_AP_FIELDS, "device", "wifi", "list", "--rescan", "no")
    except FileNotFoundError:
        return [], NM_MISSING
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], f"{type(e).__name__}: {e}"
    return parse_nm_interfaces(devs, aps), ""


def _nm_scan():
    try:
        text, code, err = _nmcli("-f", NM_AP_FIELDS, "device", "wifi", "list", "--rescan", "yes", timeout=40)
    except FileNotFoundError:
        return [], NM_MISSING
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], f"{type(e).__name__}: {e}"
    nets = parse_nm_networks(text)
    if not nets:
        return [], err or "No networks were found."
    return nets, ""


def channel_usage(nets):
    """{band: {channel: number of access points}}, for spotting a crowded channel."""
    out = {}
    for n in nets:
        if n["channel"] is not None:
            out.setdefault(n["band"] or "?", {}).setdefault(n["channel"], 0)
            out[n["band"] or "?"][n["channel"]] += 1
    return out


def best_channels(nets):
    """The least used of the three non-overlapping 2.4 GHz channels (1, 6, 11), counting neighbours one channel
    either side as sharing it. Returns (channel, {1: n, 6: n, 11: n})."""
    use = channel_usage(nets).get("2.4 GHz", {})
    load = {c: sum(n for ch, n in use.items() if abs(ch - c) <= 2) for c in (1, 6, 11)}
    return min(load, key=lambda c: (load[c], c)), load
