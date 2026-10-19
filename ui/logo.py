"""The Toner logo, 4C Midnight: a white RJ45 plug on deep navy, one cyan pin, and two cyan signal arcs above the latch.

Drop-in replacement for ui/logo.py with the same functions (paint, pixmap, icon, write_ico), so nothing that imports it
changes. Drawn in code, so it is sharp at every size. `python -m ui.logo` writes assets/toner.png and toner.ico.
At 24 px and below the five thin pins become three thick ones and the strokes are heavier, so the icon stays readable.
"""
import os
import struct

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap

NAVY, TONE, PLUG = "#0b1b2b", "#22d3ee", "#ffffff"
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def paint(p, size):
    """Draw the logo into a size x size square (a 120 x 120 grid scaled to fit)."""
    u = size / 120.0
    small = size <= 24
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(NAVY))
    p.drawRoundedRect(QRectF(0, 0, size, size), 27 * u, 27 * u)

    # signal arcs: the upper half of two circles centred on the latch
    pen = QPen(QColor(TONE), (9 if small else 6) * u, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    for r in ((19,) if small else (9, 19)):
        p.drawArc(QRectF(60 * u - r * u, 34 * u - r * u, 2 * r * u, 2 * r * u), 0, 180 * 16)

    # the plug: latch, then body
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(PLUG))
    p.drawRoundedRect(QRectF(44 * u, 42 * u, 32 * u, 16 * u), 5 * u, 5 * u)
    p.drawRoundedRect(QRectF(28 * u, 54 * u, 64 * u, 52 * u), 10 * u, 10 * u)

    # the pins: the middle one is the tone
    pins = (44, 58, 72) if small else (42, 50, 58, 66, 74)
    w = (7 if small else 4) * u
    for x in pins:
        p.setBrush(QColor(TONE if x == 58 else NAVY))
        p.drawRoundedRect(QRectF((x - (1.5 if small else 0)) * u, 66 * u, w, 28 * u), w / 2, w / 2)


def pixmap(size, ratio=1.0):
    pm = QPixmap(int(size * ratio), int(size * ratio))
    pm.setDevicePixelRatio(ratio)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    paint(p, size)
    p.end()
    return pm


def icon():
    ic = QIcon()
    for s in SIZES:
        ic.addPixmap(pixmap(s))
    return ic


def _png(size):
    data = QByteArray()
    buf = QBuffer(data)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    pixmap(size).save(buf, "PNG")
    return bytes(data)


def write_ico(path, sizes=(16, 24, 32, 48, 64, 128, 256)):
    """A multi-size .ico (PNG images inside, as Windows Vista and later read them)."""
    images = [(s, _png(s)) for s in sizes]
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for s, png in images:
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(png), offset + len(blobs))
        blobs += png
    with open(path, "wb") as fh:
        fh.write(head + entries + blobs)


if __name__ == "__main__":
    from PySide6.QtWidgets import QApplication
    app = QApplication([])
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
    os.makedirs(out, exist_ok=True)
    pixmap(512).save(os.path.join(out, "toner.png"))
    write_ico(os.path.join(out, "toner.ico"))
    print("wrote", out)
