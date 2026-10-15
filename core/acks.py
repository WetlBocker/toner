"""Acknowledged and snoozed problems.

A device's problems can be put aside from the Overview:
- Acknowledge: "I know, I am on it". It stays acknowledged while its problems stay the same or get better. A new problem, or one that
  gets worse, ends it, so nothing new is ever hidden.
- Snooze for a while: hidden until the time is up, unless something gets worse first.

Put-aside devices drop out of "Needs attention" (they can be shown again, marked) and are not announced by the notification channels.
Their checks still run, are recorded and count in the Overview's numbers: the problem is still there, it is just being handled."""
from datetime import datetime, timedelta

from core import db

SETTING = "acks"
SEV = {"OK": 0, "WARN": 1, "FAIL": 2, "ERROR": 3}
_FMT = "%Y-%m-%d %H:%M:%S"


def _load():
    raw = db.get_setting(SETTING)
    return dict(raw) if isinstance(raw, dict) else {}


def _save(data):
    db.set_setting(SETTING, data)


def _sig(problems):
    """{check: severity} for [(check, status, ...)] (worst status per check)."""
    out = {}
    for p in problems:
        check, status = p[0], p[1]
        out[check] = max(out.get(check, 0), SEV.get(status, 0))
    return out


def put_aside(device, problems, hours=None, who="", now=None):
    """Acknowledge (hours=None) or snooze for `hours` the device's current problems [(check, status, message)]."""
    now = now or datetime.now()
    data = _load()
    data[device] = {"sig": _sig(problems), "until": (now + timedelta(hours=hours)).strftime(_FMT) if hours else "",
                    "at": now.strftime(_FMT), "by": who}
    _save(data)
    return data[device]


def clear(device):
    data = _load()
    if data.pop(device, None) is not None:
        _save(data)
        return True
    return False


def state(device, problems, now=None, data=None, save=True):
    """'acknowledged', 'snoozed' or None for a device with these current problems. An entry that no longer applies is removed."""
    now = now or datetime.now()
    own = data is None
    data = _load() if own else data
    entry = data.get(device)
    if not entry:
        return None
    current = _sig(problems)
    was = entry.get("sig") or {}
    ended = not current                                                 # healthy again: nothing left to put aside
    if entry.get("until"):
        try:
            ended = ended or now >= datetime.strptime(entry["until"], _FMT)
        except ValueError:
            ended = True
        ended = ended or max(current.values(), default=0) > max(was.values(), default=0)      # something got worse
    else:
        ended = ended or any(check not in was or sev > was[check] for check, sev in current.items())   # new, or worse
    if ended:
        data.pop(device, None)
        if own and save:
            _save(data)
        return None
    return "snoozed" if entry.get("until") else "acknowledged"


def put_aside_devices(health, now=None):
    """{device: (state, entry)} for every device in device_health() output that is acknowledged or snoozed (entries that ended are removed)."""
    data = _load()
    before = len(data)
    out = {}
    for name in list(data):
        problems = (health.get(name) or {}).get("problems", [])
        st = state(name, problems, now, data=data, save=False)
        if st:
            out[name] = (st, data[name])
    if len(data) != before:
        _save(data)
    return out


def held_by_results(results, now=None):
    """The devices whose problems in these fresh results are still put aside (for notifications)."""
    data = _load()
    if not data:
        return set()
    from core.alerts import base
    problems = {}
    for r in results:
        problems.setdefault(base(r.device), [])
        if r.status != "OK":
            problems[base(r.device)].append((r.check, r.status))
    before = len(data)
    held = {d for d in list(data) if d in problems and state(d, problems[d], now, data=data, save=False)}
    if len(data) != before:
        _save(data)
    return held
