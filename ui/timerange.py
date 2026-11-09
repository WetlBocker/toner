"""The time range of the History page (and the device page): the last few hours, or a span of dates picked from a calendar."""
from datetime import datetime, time, timedelta

from PySide6.QtCore import QDate, Signal
from PySide6.QtWidgets import QComboBox, QDateEdit, QHBoxLayout, QLabel, QSpinBox, QWidget


class TimeRange(QWidget):
    """Last [n] hours (8 to start with) or From [date] to [date]. `changed` fires once for each change."""
    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.mode = QComboBox()
        self.mode.addItems(["Last hours", "Dates"])
        self.hours = QSpinBox()
        self.hours.setRange(1, 24 * 366)
        self.hours.setPrefix("Last ")
        self.hours.setSuffix(" hours")
        self.hours.setValue(8)
        self.hours.setKeyboardTracking(False)                 # one change when typing stops, not one per digit
        self.d1, self.d2 = QDateEdit(QDate.currentDate()), QDateEdit(QDate.currentDate())
        self.dates = QWidget()
        dl = QHBoxLayout(self.dates)
        dl.setContentsMargins(0, 0, 0, 0)
        for text, edit in (("From", self.d1), ("to", self.d2)):
            edit.setCalendarPopup(True)
            edit.setDisplayFormat("yyyy-MM-dd")
            edit.dateChanged.connect(self.changed)
            label = QLabel(text)
            label.setBuddy(edit)
            dl.addWidget(label)
            dl.addWidget(edit)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        for w in (self.mode, self.hours, self.dates):
            lay.addWidget(w)
        self.mode.currentIndexChanged.connect(self._mode)
        self.hours.valueChanged.connect(self.changed)
        self._mode(emit=False)

    def _mode(self, *_, emit=True):
        dates = self.mode.currentIndex() == 1
        self.hours.setVisible(not dates)
        self.dates.setVisible(dates)
        if emit:
            self.changed.emit()

    def _set(self, mode, fill):
        """Set the controls quietly, then say so once."""
        parts = (self.mode, self.hours, self.d1, self.d2)
        for w in parts:
            w.blockSignals(True)
        self.mode.setCurrentIndex(mode)
        fill()
        for w in parts:
            w.blockSignals(False)
        self._mode()

    def set_hours(self, n):
        self._set(0, lambda: self.hours.setValue(int(n)))

    def set_dates(self, d1, d2):
        a, b = sorted((d1, d2))
        self._set(1, lambda: (self.d1.setDate(QDate(a.year, a.month, a.day)), self.d2.setDate(QDate(b.year, b.month, b.day))))

    def _days(self):
        return sorted((self.d1.date().toPython(), self.d2.date().toPython()))     # the end is never before the start

    def span(self):
        """(start, end) as datetimes: the last n hours up to now, or the first day's 00:00 to the end of the last day."""
        if self.mode.currentIndex() == 0:
            now = datetime.now()
            return now - timedelta(hours=self.hours.value()), now
        a, b = self._days()
        return datetime.combine(a, time.min), datetime.combine(b, time.max)

    def describe(self):
        """'Last 8 hours' or 'From 2026-11-01 to 2026-11-08', for exports and the Assistant."""
        if self.mode.currentIndex() == 0:
            return f"Last {self.hours.value()} hours"
        a, b = self._days()
        return f"From {a:%Y-%m-%d} to {b:%Y-%m-%d}"
