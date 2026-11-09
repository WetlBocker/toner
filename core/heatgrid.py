"""The rows and columns of a heatmap read by date: a row per date and a column per hour up to 30 days, else a row per week
(labelled with its Monday) and a column per weekday. Times are naive local datetimes."""
from datetime import datetime, timedelta

DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def label(d):
    return f"{DAYS[d.weekday()][:3]} {d.day} {d:%b}"


class Grid:
    def __init__(self, start, end):
        self.start, self.end = start, end
        self.hourly = (end - start) <= timedelta(days=30)
        first, last = start.date(), end.date()
        if not self.hourly:
            first, last = first - timedelta(days=first.weekday()), last - timedelta(days=last.weekday())
        step = 1 if self.hourly else 7
        n = (last - first).days // step + 1
        self._dates = [last - timedelta(days=step * i) for i in range(n)]  # newest first
        self.rows = [label(d) for d in self._dates]
        self.cols = [f"{h:02d}" for h in range(24)] if self.hourly else list(DAYS)

    def cell(self, t):
        """(x, y) of the square holding t, or None outside the range."""
        if not self.start <= t <= self.end:
            return None
        d = t.date() if self.hourly else t.date() - timedelta(days=t.weekday())
        return (t.hour if self.hourly else t.weekday()), self._dates.index(d)

    def slot(self, x, y):
        """(from, to) of the square at (x, y): an hour, or a date."""
        if self.hourly:
            a = datetime.combine(self._dates[y], datetime.min.time()) + timedelta(hours=x)
            return a, a + timedelta(hours=1)
        a = datetime.combine(self._dates[y] + timedelta(days=x), datetime.min.time())
        return a, a + timedelta(days=1)


def layout(start, end):
    return Grid(start, end)
