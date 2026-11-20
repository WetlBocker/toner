"""How long each report or scan period is. Shared by the schedules (the trend report, scans, and the reports to come)."""
from datetime import datetime, timedelta

FMT = "%Y-%m-%d %H:%M:%S"
DAYS = {"daily": 1, "weekly": 7, "biweekly": 14, "monthly": 28, "quarterly": 91}
LABELS = {"": "Off", "daily": "Daily", "weekly": "Weekly", "biweekly": "Bi-Weekly", "monthly": "Monthly", "quarterly": "Quarterly"}


def is_due(kind, last, now=None):
    """True when a schedule of this kind, last run at `last` (a string in FMT), should run now. Off (or unknown) is never due; never run,
    or an unreadable date, is due."""
    if kind not in DAYS:
        return False
    try:
        then = datetime.strptime(last, FMT)
    except (TypeError, ValueError):
        return True
    return (now or datetime.now()) - then >= timedelta(days=DAYS[kind])
