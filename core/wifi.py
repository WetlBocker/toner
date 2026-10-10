"""This computer's Wi-Fi, read from Windows (`netsh wlan`): the current connection and the networks in range.
The labels are matched in English; the signal strength is also found by its '%' sign, so that still works elsewhere."""
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
