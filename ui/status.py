"""One set of status colours for the whole app.

fill(status) is the soft colour a status pill is painted with (OK, WARN, FAIL, ERROR; chosen in Settings > Appearance).
ink(status) is the same hue made strong enough to read as text, a dot, a number or a line on the current theme's background:
deeper on the light theme, brighter on the dark one. Everything that colours something by status asks here, so a pill, the word
in a list, a dot on an icon and a big number on the Overview always agree, and follow a change of colours or theme at once."""
from PySide6.QtGui import QColor

from core import reports
from ui import theme

GREY = "#9e9e9e"


def dark():
    return bool((theme.current() or {}).get("dark"))


def fill(status):
    """The pill colour for a status, or None for a word that is not a status (Not checked, Disabled)."""
    return reports.COLORS.get(status)


def text_on(status):
    """The colour of the word written on a pill."""
    return reports.fg_for(reports.COLORS.get(status, "#ffffff"))


def _lum(c):
    f = lambda x: x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(c.redF()) + 0.7152 * f(c.greenF()) + 0.0722 * f(c.blueF())


def contrast(a, b):
    la, lb = sorted((_lum(QColor(a)), _lum(QColor(b))))
    return (lb + 0.05) / (la + 0.05)


def ink(status):
    """The status colour as text, dots and lines on this theme: the pill's hue, made deep (light theme) or bright (dark theme)
    enough to read against the background (contrast 4.5 or better, as for normal text)."""
    base = reports.COLORS.get(status)
    if not base:
        return GREY
    t = theme.current() or {}
    bg = QColor(t.get("surface") or ("#1c1f25" if dark() else "#ffffff"))
    h, s, _l, _a = QColor(base).getHslF()
    s = min(1.0, max(s, 0.62 if dark() else 0.70)) if h >= 0 else 0.0      # a grey chosen by hand stays grey
    h = max(h, 0.0)
    fail_h = QColor(reports.COLORS.get("FAIL", "#ff0000")).hslHueF()
    if not dark() and 0.10 < h < 0.19 and not 0.02 < fail_h < 0.13:     # yellow made dark enough to read turns olive: lean it to
        h = 0.095                                                        # amber, unless FAIL is orange itself (colour-blind palette)
    light = 0.62 if dark() else 0.42
    step = 0.02 if dark() else -0.02
    c = QColor.fromHslF(h, s, light)
    while contrast(c, bg) < 4.5 and 0.18 < light < 0.9:
        light += step
        c = QColor.fromHslF(h, s, light)
    return c.name()


def qink(status):
    return QColor(ink(status))


def level(value, warn, fail, lower_is_worse=False):
    """'OK', 'WARN' or 'FAIL' for a number against two limits, for tools that colour a value (days left, signal)."""
    if lower_is_worse:
        return "FAIL" if value < fail else "WARN" if value < warn else "OK"
    return "FAIL" if value >= fail else "WARN" if value >= warn else "OK"


def pill_css(status):
    """A QLabel style that makes the label a pill in this status's colour."""
    bg = fill(status) or GREY
    return f"background:{bg}; color:{reports.fg_for(bg)}; border-radius:11px; padding:1px 10px; font-weight:600;"
