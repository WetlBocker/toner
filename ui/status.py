"""One set of status colours for the whole app.

fill(status) is the soft colour a status pill is painted with (OK, WARN, FAIL, ERROR; chosen in Settings > Appearance).
ink(status) is the same hue made strong enough to read as text, a dot, a number or a line on the current theme's panels and page:
deeper on the light theme, brighter on the dark one. chip(status) is the pill it is shown in: a faint tint with the ink tuned
against that tint, except ERROR (Toner could not reach the device or run the check), the one solid chip, so it is the loudest.
Everything that colours something by status asks here, so a pill, the word in a list, a dot on an icon and a big number on the
Overview always agree, and follow a change of colours or theme at once."""
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


def _grounds():
    """The colours status ink is read on: the panels (surface) and the page (bg)."""
    t = theme.current() or {}
    return [QColor(t.get("surface") or ("#1c1f25" if dark() else "#ffffff")), QColor(t.get("bg") or t.get("surface") or ("#1c1f25" if dark() else "#ffffff"))]


def ink(status, grounds=None):
    """The status colour as text, dots and lines on this theme: the pill's hue, made deep (light theme) or bright (dark theme)
    enough to read against the panels and the page, or against `grounds` (contrast 4.5 or better, as for normal text)."""
    base = reports.COLORS.get(status)
    if not base:
        return GREY
    grounds = grounds or _grounds()
    h, s, _l, _a = QColor(base).getHslF()
    s = min(1.0, max(s, 0.62 if dark() else 0.70)) if h >= 0 else 0.0      # a grey chosen by hand stays grey
    h = max(h, 0.0)
    fail_h = QColor(reports.COLORS.get("FAIL", "#ff0000")).hslHueF()
    if not dark() and 0.10 < h < 0.19 and not 0.02 < fail_h < 0.13:     # yellow made dark enough to read turns olive: lean it to
        h = 0.095                                                        # amber, unless FAIL is orange itself (colour-blind palette)
    light = 0.62 if dark() else 0.42
    step = 0.02 if dark() else -0.02
    c = QColor.fromHslF(h, s, light)
    while min(contrast(c, g) for g in grounds) < 4.6 and 0.18 < light < 0.9:      # (4.6: a little over 4.5, as the colour is rounded to #rrggbb)
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


def _over(top, under):
    """`top` (with its alpha) laid over the solid colour `under`."""
    a = top.alphaF()
    return QColor.fromRgbF(*(a * x + (1 - a) * y for x, y in zip((top.redF(), top.greenF(), top.blueF()), (under.redF(), under.greenF(), under.blueF()))))


def chip(status, solid=None):
    """The chip a status is shown in: (background, ink) as QColors. Most are soft: the ink with most of its alpha taken away, so the
    chip sits quietly on any theme, with the word and its icon in an ink tuned to read on that tint. ERROR is solid: its colour
    filled in, the word in whichever of the theme's text or panel colour reads best on it. solid=False: soft whatever the status
    (a tinted row, where a solid one would shout)."""
    surface = _grounds()[0]
    if status == "ERROR" if solid is None else solid:
        bg = QColor(ink(status))
        t = theme.current() or {}
        words = max((QColor(t.get("text", "#000000")), QColor(t.get("surface", "#ffffff")), QColor("#ffffff"), QColor("#000000")),
                    key=lambda c: contrast(c, bg))
        return bg, words
    bg = QColor(ink(status))
    bg.setAlpha(38 if dark() else 26)
    return bg, QColor(ink(status, [_over(bg, g) for g in _grounds()] + [surface]))


def radius():
    """A chip's corner radius in the current Look (square in Terminal, a pill elsewhere)."""
    t = theme.current() or {}
    return int(t.get("r_chip", 11))


def chip_css(status):
    """A QLabel style that makes the label a status chip."""
    bg, c = chip(status)
    return (f"background: rgba({bg.red()},{bg.green()},{bg.blue()},{bg.alpha()}); color:{c.name()}; "
            f"border-radius:{radius()}px; padding:1px 10px; font-weight:600;")


ICONS = {"OK": "ok-fill", "WARN": "warn-fill", "FAIL": "fail-fill", "ERROR": "fail-fill"}
SHAPES = {"OK": "round", "WARN": "triangle", "FAIL": "square", "ERROR": "ring"}     # so a dot says its status without its colour


def mark(p, center, status, size=14, soft=False, halo=None):
    """A device's status as a small mark at `center` (QPointF): round OK, triangle WARN, square FAIL, a hollow ring for ERROR (Toner
    could not reach it), a small grey dot when not checked. soft: filled with a tint (on a panel), else solid (on a coloured tile).
    halo: a colour drawn round it first, to set it off from what is under it."""
    from PySide6.QtCore import QPointF, QRectF, Qt
    from PySide6.QtGui import QPainterPath, QPen
    color = QColor(ink(status)) if fill(status) else QColor(GREY)
    shape = SHAPES.get(status, "dot")
    r = size / 2 if shape != "dot" else size / 3
    x, y = center.x(), center.y()

    def path(rad):
        out = QPainterPath()
        if shape == "triangle":
            out.moveTo(x, y - rad * 1.1)
            out.lineTo(x + rad * 1.05, y + rad * 0.8)
            out.lineTo(x - rad * 1.05, y + rad * 0.8)
            out.closeSubpath()
        elif shape == "square":
            out.addRoundedRect(QRectF(x - rad * 0.85, y - rad * 0.85, rad * 1.7, rad * 1.7), 2, 2)
        else:
            out.addEllipse(QPointF(x, y), rad, rad)
        return out
    p.save()
    if halo is not None:
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(halo))
        p.drawPath(path(r + 2))
    if shape == "ring":
        p.setPen(QPen(color, max(2.0, size / 5)))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(path(r - size / 10))
    else:
        tint = QColor(color)
        tint.setAlphaF(0.35 if dark() else 0.25)
        p.setPen(QPen(color, 2) if soft else Qt.PenStyle.NoPen)
        p.setBrush(tint if soft else color)
        p.drawPath(path(r - (1 if soft else 0)))
    p.restore()


def glyph(status, size=10, color=None):
    """The small filled icon drawn before a status word, in its ink (or `color`: the chip's own word colour)."""
    from ui import icons
    name = ICONS.get(status)
    return icons.icon(name, color or ink(status)).pixmap(size, size) if name else None
