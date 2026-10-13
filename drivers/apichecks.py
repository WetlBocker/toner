"""Readers for the answers of the Fortinet, Palo Alto and Meraki APIs, kept apart from the drivers so they can be tested on samples. Each takes what
the API returned and gives a small, plain result; anything that is not in the expected shape gives None or an empty list, never a guess."""
import re
from datetime import date, datetime, timezone


def _epoch_days(value, now):
    """Days from now until a Unix time (seconds or milliseconds), or from an ISO date text; None if it is neither."""
    try:
        t = float(value)
        if t > 1e12:
            t /= 1000.0
        if t < 1e9:
            return None
        return (datetime.fromtimestamp(t, timezone.utc) - now).total_seconds() / 86400
    except (TypeError, ValueError):
        pass
    try:
        when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return (when - now).total_seconds() / 86400
    except ValueError:
        return None


# ---------------------------------------------------------------- Fortinet
def fortinet_licenses(results, now=None):
    """`monitor/license/status`: [(name, days left, status text)] for every entitlement that has an expiry time (FortiCare support, FortiGuard
    services). The reply nests them by service; every dictionary with an 'expires' is one."""
    now = now or datetime.now(timezone.utc)
    out = []

    def walk(obj, path):
        if isinstance(obj, dict):
            if "expires" in obj and not isinstance(obj["expires"], (dict, list)):
                days = _epoch_days(obj["expires"], now)
                if days is not None:
                    out.append((" ".join(p.replace("_", " ") for p in path[-2:]) or "license", days, str(obj.get("status") or "")))
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    walk(v, path + [str(k)])
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, path)
    walk(results, [])
    return out


def fortinet_cert_days(certs, now=None):
    """`monitor/system/available-certificates`: [(name, days left)] for certificates that you manage (the factory ones are ignored)."""
    now = now or datetime.now(timezone.utc)
    out = []
    for c in certs if isinstance(certs, list) else []:
        if not isinstance(c, dict) or str(c.get("source", "user")).lower() in ("factory", "builtin", "fortinet"):
            continue
        for key in ("valid_to", "exp_date", "expires", "expiry", "not_after", "validity_end"):
            if key in c:
                days = _epoch_days(c[key], now)
                if days is not None:
                    out.append((str(c.get("name") or c.get("cn") or "certificate"), days))
                break
    return out


def fortinet_ha_sync(members):
    """`monitor/system/ha-checksums`: the names of configuration parts whose checksums differ between cluster members ([] = in sync, None = not a cluster)."""
    if not isinstance(members, list) or len(members) < 2:
        return None
    tables = []
    for m in members:
        cs = m.get("checksum") if isinstance(m, dict) else None
        if isinstance(cs, list):
            tables.append({str(x.get("name")): str(x.get("checksum")) for x in cs if isinstance(x, dict)})
        elif isinstance(cs, dict):
            tables.append({str(k): str(v) for k, v in cs.items()})
    if len(tables) < 2:
        return None
    return sorted(name for name in set().union(*tables) if len({t.get(name) for t in tables}) > 1)


def fortinet_log_disk(result):
    """`monitor/log/current-disk-usage`: percent used, or None."""
    if not isinstance(result, dict):
        return None
    used, total = result.get("used"), result.get("total")
    try:
        return float(used) / float(total) * 100 if float(total) > 0 else None
    except (TypeError, ValueError):
        return None


def fortinet_status_list(rows, name_keys=("name", "serial", "wtp-id", "switch-id", "fortiswitch")):
    """Managed FortiAPs and FortiSwitches: (online, [names of those not online]). 'online', 'connected' and 'up' are good."""
    good = {"online", "connected", "up", "authorized", "ok"}
    down = []
    rows = rows if isinstance(rows, list) else []
    for r in rows:
        if not isinstance(r, dict):
            continue
        state = str(r.get("status") or r.get("connection_status") or r.get("state") or "").lower()
        if state and state not in good:
            down.append(next((str(r[k]) for k in name_keys if r.get(k)), "?"))
    return len(rows) - len(down), down


# ---------------------------------------------------------------- Palo Alto
def pan_licenses(entries, today=None):
    """`request license info`: [(feature, days left or None for 'Never', expired?)] from <entry> elements (children feature, expires, expired)."""
    today = today or date.today()
    out = []
    for e in entries or []:
        feature = (e.findtext("feature") or "license").strip()
        expires, expired = (e.findtext("expires") or "").strip(), (e.findtext("expired") or "").strip().lower() == "yes"
        if not expires or expires.lower() == "never":
            out.append((feature, None, expired))
            continue
        try:
            days = (datetime.strptime(expires, "%B %d, %Y").date() - today).days
        except ValueError:
            continue
        out.append((feature, days, expired or days < 0))
    return out


def pan_content_ages(system, today=None):
    """The age in days of each content package in `show system info` (application, threat, antivirus, WildFire ...): [(name, days)]."""
    today = today or date.today()
    out = []
    for el in system:
        tag = el.tag.lower()
        if not tag.endswith("release-date") or not (el.text or "").strip():
            continue
        m = re.match(r"(\d{4})/(\d{2})/(\d{2})", el.text.strip())
        if m:
            try:
                out.append((tag[:-len("-release-date")] or "content", (today - date(int(m.group(1)), int(m.group(2)), int(m.group(3)))).days))
            except ValueError:
                continue
    return out


def pan_disk(text):
    """`show system disk-space` (df output in the reply): (highest used %, mount) over the partitions that matter, or None."""
    worst = None
    for m in re.finditer(r"(?m)^(\S+)\s+\S+\s+\S+\s+\S+\s+(\d+)%\s+(/\S*)\s*$", text or ""):
        fs, pct, mount = m.group(1), int(m.group(2)), m.group(3)
        if fs.startswith(("tmpfs", "devtmpfs", "none", "udev")) or mount.startswith(("/dev", "/sys", "/proc", "/run")):
            continue
        if worst is None or pct > worst[0]:
            worst = (pct, mount)
    return worst


def pan_panorama(text):
    """`show panorama-status`: True connected, False not connected, None when no Panorama server is configured."""
    t = text or ""
    if not re.search(r"Panorama Server\s+\d\s*:\s*\S", t):
        return None
    m = re.search(r"Connected\s*:\s*(yes|no)", t, re.I)
    return None if not m else m.group(1).lower() == "yes"


def pan_last_commit(jobs):
    """`show jobs all` <job> elements: (result, finished) of the newest commit job, or None."""
    best = None
    for j in jobs or []:
        if (j.findtext("type") or "").lower() != "commit":
            continue
        try:
            n = int(j.findtext("id") or 0)
        except ValueError:
            continue
        if best is None or n > best[0]:
            best = (n, (j.findtext("result") or "").upper(), j.findtext("tfin") or "")
    return (best[1], best[2]) if best else None


# ---------------------------------------------------------------- Meraki
def meraki_alerts(rows):
    """Assurance alerts: (critical, warning, [titles of the worst few]). Only alerts that are still active count."""
    crit = warn = 0
    titles = []
    for a in rows if isinstance(rows, list) else []:
        if not isinstance(a, dict) or a.get("resolvedAt") or a.get("dismissedAt"):
            continue
        sev = str(a.get("severity") or "").lower()
        if sev == "critical":
            crit += 1
        elif sev == "warning":
            warn += 1
        else:
            continue
        titles.append(f"{(a.get('network') or {}).get('name', '') or ''} {a.get('title') or a.get('type') or ''}".strip())
    return crit, warn, titles[:4]


def meraki_vpn(rows):
    """appliance VPN statuses: (peers total, [descriptions of unreachable peers])."""
    total, bad = 0, []
    for r in rows if isinstance(rows, list) else []:
        for key in ("merakiVpnPeers", "thirdPartyVpnPeers"):
            for p in r.get(key) or []:
                total += 1
                if str(p.get("reachability") or "reachable").lower() != "reachable":
                    bad.append(f"{r.get('networkName', '?')} to {p.get('networkName') or p.get('name') or '?'}")
    return total, bad


def meraki_uplink_quality(rows):
    """uplinksLossAndLatency: (worst loss %, worst latency ms, label of the worst) from the most recent sample of each uplink."""
    worst_loss, worst_lat, label = 0.0, 0.0, ""
    for r in rows if isinstance(rows, list) else []:
        series = [p for p in (r.get("timeSeries") or []) if isinstance(p, dict) and (p.get("lossPercent") is not None or p.get("latencyMs") is not None)]
        if not series:
            continue
        last = series[-1]
        loss, lat = float(last.get("lossPercent") or 0), float(last.get("latencyMs") or 0)
        if loss > worst_loss or lat > worst_lat:
            label = f"{r.get('serial', '?')} {r.get('uplink', '')}".strip()
        worst_loss, worst_lat = max(worst_loss, loss), max(worst_lat, lat)
    return (worst_loss, worst_lat, label) if label or worst_loss or worst_lat else None
