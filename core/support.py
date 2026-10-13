"""Support, warranty and licence end dates, read from a device's custom fields (Edit device > Tags and fields), for every kind of device:

    support=2027-06        warranty=2026-12-31        eol=2029-01        licence_expires=2026-11-30

The number of days left is graded with Settings > Thresholds > 'Support, warranty and licence days left'. The result is on the device's
Results row like any other check, so it can alert and appears in reports. A date with a typo is reported, not ignored."""
import calendar
import json
import re
from datetime import date, datetime

from drivers.base import Result, OK, ERROR, grade_low

# field name (lower case, spaces and dashes as underscores) -> what the row is called
KEYS = {"support": "support ends", "support_end": "support ends", "support_ends": "support ends", "support_until": "support ends",
        "support_expires": "support ends", "end_of_support": "support ends", "eos": "support ends",
        "warranty": "warranty ends", "warranty_end": "warranty ends", "warranty_ends": "warranty ends", "warranty_until": "warranty ends",
        "warranty_expires": "warranty ends", "eol": "end of life", "end_of_life": "end of life",
        "licence": "licence ends", "license": "licence ends", "licence_expires": "licence ends", "license_expires": "licence ends",
        "licence_end": "licence ends", "license_end": "licence ends", "subscription": "subscription ends", "subscription_end": "subscription ends",
        "subscription_expires": "subscription ends", "contract": "contract ends", "contract_end": "contract ends", "contract_expires": "contract ends"}


def parse_date(text):
    """2027-06 (the last day of June), 2027-06-30, 2027/06/30, 30.06.2027 or 30/06/2027 -> a date; None if it is none of those."""
    t = str(text or "").strip()
    m = re.fullmatch(r"(\d{4})[-/](\d{1,2})", t)
    try:
        if m:
            y, mo = int(m.group(1)), int(m.group(2))
            return date(y, mo, calendar.monthrange(y, mo)[1])
        m = re.fullmatch(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", t)
        if m:
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        m = re.fullmatch(r"(\d{1,2})[./](\d{1,2})[./](\d{4})", t)               # day first: this is not an American tool's date
        if m:
            return date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
    except ValueError:
        return None
    return None


def rows(dev, thresholds, today=None):
    """Result rows for every support-style date in the device's custom fields."""
    try:
        fields = json.loads(dev.get("fields") or "{}") if isinstance(dev.get("fields"), str) else (dev.get("fields") or {})
    except ValueError:
        return []
    today = today or datetime.now().date()
    t = thresholds["support_days"]
    out, seen = [], set()
    for key, raw in (fields or {}).items():
        label = KEYS.get(re.sub(r"[\s-]+", "_", str(key).strip().lower()))
        if not label:
            continue
        if label in seen:                                    # two fields for the same thing: the first one counts
            continue
        seen.add(label)
        when = parse_date(raw)
        if when is None:
            out.append(Result(dev["name"], label, ERROR, str(raw), f"'{raw}' is not a date: use 2027-06-30 or 2027-06"))
            continue
        days = (when - today).days
        status = grade_low(days, t["warn"], t["fail"])
        value = f"{days} days" if days >= 0 else f"ended {-days} days ago"
        out.append(Result(dev["name"], label, status, value, when.isoformat() if status != OK else "", numeric=float(days)))
    return out
