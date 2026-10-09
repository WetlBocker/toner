"""The Toner logo: a tone probe (the tool used to trace cables) sending out signal waves. Drawn in code, so it is
sharp at every size and there is no image file to ship; `python -m ui.logo` writes assets/toner.png and toner.ico."""
import math
import os
import struct

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QIcon, QLinearGradient, QPainter, QPen, QPixmap

TOP, BOTTOM, SPARK = "#3b82f6", "#1e3a8a", "#fbbf24"      # blue to deep blue, with an amber tone at the probe tip
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def paint(p, size):
    """Draw the logo into a size x size square."""
    u = size / 100.0
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    g = QLinearGradient(0, 0, size, size)
    g.setColorAt(0, QColor(TOP))
    g.setColorAt(1, QColor(BOTTOM))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(g))
    p.drawRoundedRect(QRectF(0, 0, size, size), 24 * u, 24 * u)

    small = size <= 24
    tip = QPointF(43 * u, 57 * u)
    # the probe: a thick rounded handle running down and to the left from the tip
    p.setPen(QPen(QColor("#ffffff"), (17 if small else 13) * u, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawLine(QPointF(17 * u, 83 * u), tip)
    # the signal: arcs spreading up and to the right, fading as they travel
    radii, alphas = ((19, 34), (255, 255)) if small else ((19, 31, 43), (255, 200, 140))
    width = (9 if small else 6.5) * u
    for r, a in zip(radii, alphas):
        c = QColor("#ffffff")
        c.setAlpha(a)
        p.setPen(QPen(c, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(QRectF(tip.x() - r * u, tip.y() - r * u, 2 * r * u, 2 * r * u), 8 * 16, 74 * 16)
    # the tone itself
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(SPARK))
    p.drawEllipse(tip, (9 if small else 8) * u, (9 if small else 8) * u)


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
    data, buf = QByteArray(), None
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
