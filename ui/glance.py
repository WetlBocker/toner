"""Network at a glance: the devices as a small map on the Overview. A dot per device in its status colour, the links Tools > Topology
found between them (dashed in the status colour when an end is down), a slow pulsing ring on a device that is down and a quick one
on a device being checked. Clicking a dot opens the device. Before a topology scan there are no links: the dots sit in a grid with a hint."""
from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import QWidget
from core import db, scope
from ui import motion, theme
from ui import status as st

LABELS_UP_TO = 12               # names are drawn when there are no more devices than this (else on hover)
DOWN = ("FAIL", "ERROR")
NO_MAP = "No map yet. Run a scan in Tools > Topology to draw the links between your devices."


class GlanceMap(QWidget):
    open_device = Signal(str)

    def __init__(self):
        super().__init__()
        self.setMinimumHeight(170)
        self.setMouseTracking(True)
        self.nodes = {}                 # name -> (x, y) in 0..1
        self.links = []                 # [(a, b)]
        self.status = {}                # name -> 'OK' | 'WARN' | 'FAIL' | 'ERROR'
        self.checking = set()           # devices being checked now
        self.scanned = False
        self._sig = None                # what the layout was made for, so it is not laid out again for nothing
        self._hover = None
        self.pulse = 0.0                # 0..1, the pulsing rings
        self._anim = None
        self.summary = ""

    # ---- data
    def refresh(self, health=None):
        """Read the devices, their latest status and the links Topology found."""
        from core import topology
        devs = scope.keep(db.list_devices())
        names = [d["key"] for d in devs]
        health = health if health is not None else db.device_health()
        self.status = {n: health[n]["status"] for n in names if n in health}
        k = topology.last()
        rows = k.get("rows") or []
        self.scanned = bool(rows)
        links = []
        if rows:
            try:
                nodes, raw = topology.build_graph(rows)
                keep = set(names)
                links = sorted({tuple(sorted((l["a"], l["b"]))) for l in raw if l["a"] in keep and l["b"] in keep and l["a"] != l["b"]})
            except Exception:
                links = []
        sig = (tuple(names), tuple(links))
        if sig != self._sig:
            self._sig = sig
            self.links = links
            self.nodes = self._layout(names, links)
        down = sum(1 for n in names if self.status.get(n) in DOWN)
        self.summary = f"{down} of {len(names)} down" if down else f"all {len(names)} up" if names else ""
        self.setToolTip("")
        self.setAccessibleName("Map of " + ", ".join(f"{n} {self.status.get(n, 'not checked')}" for n in names) if names else "No devices")
        self._pulsing()
        self.update()

    def _layout(self, names, links):
        """Positions in 0..1: a grid with no links, else Topology's own layout."""
        if not names:
            return {}
        if not links:
            cols = max(1, min(6, int(len(names) ** 0.5 + 0.999)))
            rows = (len(names) + cols - 1) // cols
            return {n: ((i % cols + 0.5) / cols, 0.12 + 0.5 * (i // cols + 0.5) / rows) for i, n in enumerate(names)}    # the hint sits below
        from core import topology
        nodes = {n: {} for n in names}
        ls = [{"a": a, "b": b} for a, b in links]
        pos = topology.layout(nodes, ls, 1000, 600, iterations=200, seed=7)
        xs, ys = [p[0] for p in pos.values()], [p[1] for p in pos.values()]
        x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
        sx, sy = max(1.0, x1 - x0), max(1.0, y1 - y0)
        return {n: (0.08 + 0.84 * (p[0] - x0) / sx, 0.12 + 0.76 * (p[1] - y0) / sy) for n, p in pos.items()}

    def set_checking(self, names):
        """The devices a run is on now (an accent ring on each)."""
        self.checking = set(names)
        self._pulsing()
        self.update()

    def _pulsing(self):
        want = motion.enabled() and self.isVisible() and (self.checking or any(s in DOWN for s in self.status.values()))
        if want and self._anim is None:
            self._anim = motion.animate(self, 1800, self._on_pulse, loop=True, curve=motion.QEasingCurve.Type.Linear)
        elif not want and self._anim is not None:
            self._anim.stop()
            self._anim = None
            self.pulse = 0.0

    def _on_pulse(self, v):
        self.pulse = float(v)
        self.update()

    def showEvent(self, e):
        super().showEvent(e)
        self._pulsing()

    def hideEvent(self, e):
        super().hideEvent(e)
        if self._anim is not None:
            self._anim.stop()
            self._anim = None

    # ---- drawing
    def _pt(self, name):
        x, y = self.nodes[name]
        return QPointF(10 + x * (self.width() - 20), 8 + y * (self.height() - 16))

    def _at(self, pos):
        for n in self.nodes:
            p = self._pt(n)
            if (p.x() - pos.x()) ** 2 + (p.y() - pos.y()) ** 2 <= 12 ** 2:
                return n
        return None

    def paintEvent(self, _e):
        t = theme.current() or {}
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        muted = QColor(t.get("muted", "#888888"))
        if not self.nodes:
            p.setPen(muted)
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap, "No devices yet")
            return
        accent = QColor(t.get("accent", "#2563eb"))
        for a, b in self.links:
            if a not in self.nodes or b not in self.nodes:
                continue
            bad = next((self.status.get(n) for n in (a, b) if self.status.get(n) in DOWN), None)
            pen = QPen(st.qink(bad) if bad else QColor(muted))
            pen.setWidthF(1.5)
            if bad:
                pen.setStyle(Qt.PenStyle.DashLine)
            else:
                pen.setColor(QColor(muted.red(), muted.green(), muted.blue(), 150))
            p.setPen(pen)
            p.drawLine(self._pt(a), self._pt(b))
        labels = len(self.nodes) <= LABELS_UP_TO
        fm = QFontMetrics(p.font())
        for n in self.nodes:
            c = self._pt(n)
            status = self.status.get(n)
            ink = st.qink(status) if status else QColor(st.GREY)
            ring = accent if n in self.checking else ink if status in DOWN else None
            if ring is not None:
                r = 8 + 9 * self.pulse
                col = QColor(ring)
                col.setAlphaF(max(0.0, 0.9 * (1 - self.pulse)))
                pen = QPen(col)
                pen.setWidthF(2)
                p.setPen(pen)
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawEllipse(QRectF(c.x() - r, c.y() - r, 2 * r, 2 * r))
            fill = QColor(ink)
            fill.setAlphaF(0.35 if t.get("dark") else 0.25)
            p.setPen(QPen(ink, 2))
            p.setBrush(fill)
            p.drawEllipse(QRectF(c.x() - 7, c.y() - 7, 14, 14))
            if labels or n == self._hover:
                p.setPen(ink if status in DOWN else muted)
                text = fm.elidedText(db.label_org(n), Qt.TextElideMode.ElideRight, 120)
                w = fm.horizontalAdvance(text)
                p.drawText(QPointF(c.x() - w / 2, c.y() + (22 if self.nodes[n][1] >= 0.5 or not self.scanned else -13)), text)
        if not self.scanned:
            p.setPen(muted)
            f = p.font()
            f.setPointSizeF(max(7.0, f.pointSizeF() - 1))
            p.setFont(f)
            p.drawText(QRectF(8, self.height() - 34, self.width() - 16, 30), Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap, NO_MAP)

    # ---- the mouse
    def mouseMoveEvent(self, e):
        n = self._at(e.position())
        if n != self._hover:
            self._hover = n
            self.setCursor(Qt.CursorShape.PointingHandCursor if n else Qt.CursorShape.ArrowCursor)
            self.setToolTip(f"{db.label_org(n)}: {self.status.get(n, 'not checked')}" if n else "")
            self.update()

    def leaveEvent(self, e):
        super().leaveEvent(e)
        self._hover = None
        self.update()

    def mousePressEvent(self, e):
        n = self._at(e.position())
        if n:
            self.open_device.emit(n)
