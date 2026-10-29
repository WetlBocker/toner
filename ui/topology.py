"""Tools > Discover > Topology: a workbench with a left rail (filters, diagram options, checks) and a stage with three tabs:
the Layer 2 map (LLDP / CDP), the Layer 3 map (BGP, OSPF, EIGRP) and the Links table. Tiles are coloured by role with a
glyph, a status dot and the name and address beneath; a click opens a detail card, a double-click the device, a right-click
the inventory's own device actions. The data comes from core/topology (discovery, roles, layouts, the kept discovery)."""
import csv
from datetime import datetime

from PySide6.QtCore import QPointF, QRectF, Qt, QThread, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QFontDatabase, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QFileDialog, QFrame, QGraphicsItem, QGraphicsObject, QGraphicsScene, QGraphicsView,
                               QGridLayout, QHBoxLayout, QLabel, QListWidget, QMenu, QMessageBox, QPushButton, QScrollArea, QStackedWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from core import db, topology
from ui import theme
from ui.finder import FilterButton, SearchBox, device_sections, shown_devices
from ui.toast import toast

TILE = 40                                   # a tile's side
ONE_WAY = "#E79B4B"                         # a link seen from one end only: dashed amber, as the legend says
DOWN = "#D9534F"
LAYERS = ("l2", "l3")


def _t():
    return theme.current() or {}


def _mono():
    f = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    f.setPointSizeF(8.0)
    return f


def _muted(text=""):
    lab = QLabel(text)
    lab.setProperty("muted", True)
    lab.setWordWrap(True)
    return lab


def _heading(text):
    lab = QLabel(text.upper())
    lab.setProperty("muted", True)
    f = lab.font()
    f.setPointSizeF(max(7.5, f.pointSizeF() - 1.5))
    f.setBold(True)
    f.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 108)
    lab.setFont(f)
    return lab


class Segment(QWidget):
    """A row of choices where one is down: Both | CDP | LLDP."""
    changed = Signal(str)

    def __init__(self, choices, current=None):
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.buttons = {}
        for key, label in choices:
            b = QPushButton(label)
            b.setCheckable(True)
            b.setProperty("segment", True)
            self.group.addButton(b)
            self.buttons[key] = b
            lay.addWidget(b)
            b.toggled.connect(lambda on, k=key: on and self.changed.emit(k))
        self.set(current or choices[0][0])

    def value(self):
        return next((k for k, b in self.buttons.items() if b.isChecked()), None)

    def set(self, key):
        if key in self.buttons:
            self.buttons[key].setChecked(True)


# =============================================================================== the map's items
def _glyph(role):
    """A small white path per role, drawn inside a 24 x 24 box centred on the tile."""
    p = QPainterPath()
    if role in ("router", "l3switch", "switch"):
        if role == "router":
            p.addEllipse(QRectF(-9, -9, 18, 18))
            for dx, dy in ((-9, 0), (9, 0), (0, -9), (0, 9)):
                p.moveTo(0, 0)
                p.lineTo(dx, dy)
            p.moveTo(-9, 0); p.lineTo(-5, -3); p.moveTo(-9, 0); p.lineTo(-5, 3)
            p.moveTo(9, 0); p.lineTo(5, -3); p.moveTo(9, 0); p.lineTo(5, 3)
        else:
            for y, left in ((-5, True), (5, False)):
                p.moveTo(-9, y); p.lineTo(9, y)
                if left:
                    p.moveTo(-9, y); p.lineTo(-5, y - 3); p.moveTo(-9, y); p.lineTo(-5, y + 3)
                else:
                    p.moveTo(9, y); p.lineTo(5, y - 3); p.moveTo(9, y); p.lineTo(5, y + 3)
            if role == "l3switch":
                p.addEllipse(QRectF(-2.5, -2.5, 5, 5))
    elif role == "firewall":
        p.addRect(QRectF(-10, -8, 20, 16))
        p.moveTo(-10, -2.5); p.lineTo(10, -2.5); p.moveTo(-10, 2.5); p.lineTo(10, 2.5)
        p.moveTo(-3, -8); p.lineTo(-3, -2.5); p.moveTo(3, -2.5); p.lineTo(3, 2.5); p.moveTo(-3, 2.5); p.lineTo(-3, 8)
    elif role == "wlc":
        p.addRect(QRectF(-10, 0, 20, 8))
        p.moveTo(0, 0); p.lineTo(0, -9)
        p.moveTo(-6, -6); p.lineTo(0, -9); p.lineTo(6, -6)
    elif role == "ap":
        p.addEllipse(QRectF(-2.5, 1, 5, 5))
        p.moveTo(-6, -2); p.quadTo(0, -8, 6, -2)
        p.moveTo(-10, -6); p.quadTo(0, -16, 10, -6)
    elif role == "phone":
        p.moveTo(-8, -8); p.lineTo(-4, -8); p.lineTo(-2, -2); p.lineTo(-5, 0)
        p.quadTo(-2, 5, 3, 7); p.lineTo(5, 4); p.lineTo(10, 7); p.lineTo(9, 10)
        p.quadTo(-9, 8, -8, -8)
    elif role == "server":
        for y in (-9, -2, 5):
            p.addRect(QRectF(-9, y, 18, 5))
    else:
        p.addEllipse(QRectF(-8, -8, 16, 16))
        p.moveTo(0, -3); p.lineTo(0, 3); p.moveTo(0, 5); p.lineTo(0, 6)
    return p


class NodeItem(QGraphicsObject):
    """A device tile: a rounded square in its role colour with a glyph, a status dot at the corner, the caption and a
    second line (address or platform) beneath on a translucent backing."""
    def __init__(self, name, role, status, inventory, caption, sub="", group=None):
        super().__init__()
        self.name, self.role, self.status, self.inventory, self.caption, self.sub, self.group = name, role, status, inventory, caption, sub, group
        self.edges = []
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setZValue(2)
        self.setAcceptHoverEvents(True)
        self._font = QFont()
        self._font.setPointSizeF(8.5)
        self._mono = _mono()
        self._w = max(TILE + 20, 8 * max(len(caption), len(sub or "")) + 10)

    def boundingRect(self):
        return QRectF(-self._w / 2, -TILE / 2 - 4, self._w, TILE + 46)

    def paint(self, p, option, widget=None):
        t = _t()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        tile = QRectF(-TILE / 2, -TILE / 2, TILE, TILE)
        color = QColor(topology.ROLE_COLORS.get(self.role, topology.ROLE_COLORS["unknown"]))
        p.setPen(QPen(QColor(t.get("bg", "#0f171b")), 2, Qt.PenStyle.DashLine if self.group else Qt.PenStyle.SolidLine) if (self.group or not self.inventory)
                 else Qt.PenStyle.NoPen)
        p.setBrush(QBrush(color if self.inventory or self.group else color.lighter(115)))
        if not self.inventory and not self.group:
            p.setOpacity(0.82)
        p.drawRoundedRect(tile, 9, 9)
        p.setOpacity(1.0)
        p.setPen(QPen(QColor("#ffffff"), 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        p.setBrush(Qt.BrushStyle.NoBrush)
        if self.group:
            p.setFont(QFont(self._font.family(), 11, QFont.Weight.Bold))
            p.drawText(tile, Qt.AlignmentFlag.AlignCenter, str(self.group))
        else:
            p.drawPath(_glyph(self.role))
        if self.status:                                             # the latest health result, as a dot on the corner
            dot = {"OK": "#2fb37a", "WARN": "#e2a33b", "FAIL": "#e2573f", "ERROR": "#a66cd9"}.get(self.status, "#888888")
            p.setPen(QPen(QColor(t.get("bg", "#0f171b")), 2))
            p.setBrush(QBrush(QColor(dot)))
            p.drawEllipse(QRectF(TILE / 2 - 8, -TILE / 2 - 2, 10, 10))
        if self.isSelected():
            p.setPen(QPen(QColor(t.get("accent", "#55b6d4")), 2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(tile.adjusted(-4, -4, 4, 4), 11, 11)
        y = TILE / 2 + 4
        for text, font, color in ((self.caption, self._font, t.get("text", "#e1e8ec")), (self.sub, self._mono, t.get("muted", "#93a3ad"))):
            if not text:
                continue
            p.setFont(font)
            r = p.fontMetrics().boundingRect(text).adjusted(-3, -1, 3, 1)
            r.moveCenter(QPointF(0, y + r.height() / 2).toPoint())
            bg = QColor(t.get("bg", "#0f171b"))
            bg.setAlphaF(0.85)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(bg))
            p.drawRoundedRect(QRectF(r), 3, 3)
            p.setPen(QColor(color))
            p.drawText(QRectF(r), Qt.AlignmentFlag.AlignCenter, text)
            y += r.height() + 1

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for e in self.edges:
                e.refresh()
        return super().itemChange(change, value)

    def _view(self):
        views = self.scene().views() if self.scene() else []
        return views[0] if views else None

    def mousePressEvent(self, e):
        super().mousePressEvent(e)
        v = self._view()
        if v is not None and v.on_select and e.button() == Qt.MouseButton.LeftButton:
            v.on_select(self.name)

    def mouseDoubleClickEvent(self, e):
        v = self._view()
        if v is not None and v.on_open:
            v.on_open(self.name)
        super().mouseDoubleClickEvent(e)


class EdgeItem(QGraphicsItem):
    """A link: a line whose colour and dash say what it is, with a port label at each end in monospace."""
    def __init__(self, a, b, link, layer, short_ports=True, tip=""):
        super().__init__()
        self.a, self.b, self.link, self.layer, self.short_ports = a, b, link, layer, short_ports
        self.setZValue(1)
        self.setToolTip(tip)
        self.setAcceptHoverEvents(True)
        self._mono = _mono()
        a.edges.append(self)
        b.edges.append(self)
        self.refresh()

    def _ends(self):
        return self.a.pos(), self.b.pos()

    def refresh(self):
        self.prepareGeometryChange()
        self.update()

    def boundingRect(self):
        p1, p2 = self._ends()
        return QRectF(p1, p2).normalized().adjusted(-70, -24, 70, 24)

    def _pen(self):
        t = _t()
        l = self.link
        width = 1.6 + (0.9 if l.get("count", 1) > 1 else 0)
        if l.get("change") == "gone":
            return QPen(QColor(DOWN), width, Qt.PenStyle.DotLine)
        if l.get("down"):
            return QPen(QColor(DOWN), width + 0.4)
        if self.layer == "l3":
            pen = QPen(QColor(topology.L3_COLORS.get(l.get("protocol"), t.get("muted", "#8d9ea8"))), width + 0.4)
        else:
            pen = QPen(QColor(t.get("accent", "#55b6d4")) if l.get("change") == "new" else QColor(t.get("muted", "#8d9ea8")), width + (1.0 if l.get("change") == "new" else 0))
        if not l.get("both") and not l.get("group_link"):
            pen.setStyle(Qt.PenStyle.DashLine)
            if self.layer == "l2":
                pen.setColor(QColor(ONE_WAY))
        return pen

    def paint(self, p, option, widget=None):
        t = _t()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p1, p2 = self._ends()
        p.setPen(self._pen())
        p.drawLine(p1, p2)
        labels = ((self.link.get("a_port") or "", p1, p2), (self.link.get("b_port") or "", p2, p1))
        if self.layer == "l3":
            mid = (p1 + p2) / 2
            text = self.link.get("protocol", "") + (f" AS {self.link['as']}" if self.link.get("as") else "") + (f" · {self.link['state']}" if self.link.get("state") else "")
            labels = ((text, mid, mid),)
        p.setFont(self._mono)
        fm = p.fontMetrics()
        for text, at, toward in labels:
            if not text:
                continue
            text = topology.short_port(text).upper() if self.short_ports and self.layer == "l2" else text
            if self.short_ports and self.layer == "l2":
                text = text[:1] + text[1:].lower() if text[:2] in ("GI", "TE", "FA", "PO", "HU", "FO") else text.lower()
            d = toward - at
            n = (d.x() ** 2 + d.y() ** 2) ** 0.5 or 1
            centre = QPointF(at.x() + d.x() / n * 56, at.y() + d.y() / n * 30) if at != toward else at
            r = fm.boundingRect(text).adjusted(-3, -1, 3, 1)
            r.moveCenter(centre.toPoint())
            bg = QColor(t.get("bg", "#0f171b"))
            bg.setAlphaF(0.9)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(bg))
            p.drawRoundedRect(QRectF(r), 3, 3)
            p.setPen(QColor(t.get("muted", "#93a3ad")))
            p.drawText(QRectF(r), Qt.AlignmentFlag.AlignCenter, text)


# =============================================================================== the map
class MapView(QGraphicsView):
    def __init__(self, layer):
        super().__init__()
        self.layer = layer
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.on_select = self.on_open = self.on_menu = self.on_moved = None
        self.boxes, self.lines = {}, []
        self.legend = QFrame(self)
        self.legend.setProperty("card", True)
        self.legend_lay = QHBoxLayout(self.legend)
        self.legend_lay.setContentsMargins(10, 6, 10, 6)
        self.legend_lay.setSpacing(12)
        self.zoom_box = QFrame(self)
        zl = QVBoxLayout(self.zoom_box)
        zl.setContentsMargins(0, 0, 0, 0)
        zl.setSpacing(4)
        self.zoom_in, self.zoom_out, self.fit_btn = QPushButton("+"), QPushButton("−"), QPushButton("⤢")
        for b, tip in ((self.zoom_in, "Zoom in"), (self.zoom_out, "Zoom out"), (self.fit_btn, "Fit the whole map")):
            b.setFixedSize(32, 32)
            b.setToolTip(tip)
            zl.addWidget(b)
        self.zoom_in.clicked.connect(lambda: self.scale(1.2, 1.2))
        self.zoom_out.clicked.connect(lambda: self.scale(1 / 1.2, 1 / 1.2))
        self.fit_btn.clicked.connect(self.fit)
        self.card = Card(self)
        self.card.hide()

    def drawBackground(self, p, rect):
        t = _t()
        p.fillRect(rect, QColor(t.get("bg", "#0f171b")))
        p.setPen(QPen(QColor(t.get("border", "#1b262c")), 1.2))
        step = 22
        x0, y0 = int(rect.left()) - int(rect.left()) % step, int(rect.top()) - int(rect.top()) % step
        pts = [QPointF(x, y) for x in range(x0, int(rect.right()) + step, step) for y in range(y0, int(rect.bottom()) + step, step)]
        if len(pts) < 20000:
            p.drawPoints(pts)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._place()

    def _place(self):
        self.legend.adjustSize()
        self.legend.move(12, self.height() - self.legend.height() - 12)
        self.zoom_box.adjustSize()
        self.zoom_box.move(self.width() - self.zoom_box.width() - 12, self.height() - self.zoom_box.height() - 12)
        self.card.move(self.width() - self.card.width() - 12, 12)

    def wheelEvent(self, e):
        f = 1.15 if e.angleDelta().y() > 0 else 1 / 1.15
        self.scale(f, f)

    def mouseReleaseEvent(self, e):
        super().mouseReleaseEvent(e)
        if self.on_moved and self.boxes:
            self.on_moved()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and self.itemAt(e.pos()) is None and self.on_select:
            self.on_select(None)
        super().mousePressEvent(e)

    def contextMenuEvent(self, e):
        it = self.itemAt(e.pos())
        while it is not None and not isinstance(it, NodeItem):
            it = it.parentItem()
        if it is not None and self.on_menu:
            self.on_menu(it.name, e.globalPos())
        else:
            super().contextMenuEvent(e)

    def set_legend(self, entries):
        """[(kind, colour, text)]: kind 'swatch' or 'line' / 'dash' / 'dot' / 'thick'."""
        while self.legend_lay.count():
            w = self.legend_lay.takeAt(0).widget()
            if w:
                w.deleteLater()
        for kind, colour, text in entries:
            lab = QLabel()
            if kind == "swatch":
                lab.setText(f'<span style="background:{colour};border-radius:3px">&nbsp;&nbsp;&nbsp;</span> {text}')
            else:
                style = {"line": "solid", "dash": "dashed", "dot": "dotted", "thick": "solid"}[kind]
                width = "4px" if kind == "thick" else "2px"
                lab.setText(f'<span style="border-bottom:{width} {style} {colour}">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span> {text}')
            lab.setProperty("muted", True)
            self.legend_lay.addWidget(lab)
        self._place()

    def draw(self, nodes, links, positions, roles, status, opts):
        sc = self.scene()
        sc.clear()
        self.boxes, self.lines = {}, []
        devs = {d["key"]: d for d in db.list_devices()}
        for name, info in nodes.items():
            x, y = positions.get(name, (0, 0))
            caption = short_name(name, opts.get("drop_domain", True)) if not info.get("group") else name.split(" » ", 1)[1]
            dev = devs.get(name)
            if opts.get("show_platform") and dev:
                sub = dev.get("platform") or dev.get("details") or ""
            elif opts.get("show_ip", True):
                sub = (dev.get("host") if dev else info.get("addr")) or ""
            else:
                sub = ""
            n = NodeItem(name, roles.get(name, "unknown"), status.get(name, "") if info.get("inventory") else "", info.get("inventory", False),
                         caption, sub, info.get("count") if info.get("group") else None)
            n.setPos(x, y)
            n.setToolTip(f"{db.label(name)}\n{topology.ROLE_NAMES.get(roles.get(name, 'unknown'))}" + (f"\n{info['addr']}" if info.get("addr") else "")
                         + ("" if info.get("inventory") else "\nnot in the inventory") + "\nClick for details, double-click to open, right-click for actions")
            sc.addItem(n)
            self.boxes[name] = n
        for l in links:
            if l["a"] in self.boxes and l["b"] in self.boxes:
                e = EdgeItem(self.boxes[l["a"]], self.boxes[l["b"]], l, self.layer, opts.get("short_ports", True), link_tip(l, self.layer))
                sc.addItem(e)
                self.lines.append(e)
        sc.setSceneRect(sc.itemsBoundingRect().adjusted(-80, -80, 80, 80))
        self.fit()

    def fit(self):
        self.resetTransform()
        if self.scene().items():
            self.fitInView(self.scene().sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def current_positions(self):
        return {name: (it.pos().x(), it.pos().y()) for name, it in self.boxes.items()}

    def highlight(self, words):
        """Search: the boxes whose caption or address has every word stay bright, with their neighbours; the rest fade."""
        if not words:
            keep = set(self.boxes)
        else:
            keep = {name for name, it in self.boxes.items() if all(w in f"{it.caption} {it.sub} {db.label(name)}".lower() for w in words)}
            for e in self.lines:
                if e.a.name in keep or e.b.name in keep:
                    keep |= {e.a.name, e.b.name}
        for name, it in self.boxes.items():
            it.setOpacity(1.0 if name in keep else 0.16)
        for e in self.lines:
            e.setOpacity(1.0 if e.a.name in keep and e.b.name in keep else 0.12)


def short_name(name, drop_domain):
    return topology.short_name(name, drop_domain)


def link_tip(l, layer):
    if layer == "l3":
        lines = [f"{db.label(l['a'])}  <->  {db.label(l['b'])}", l.get("protocol", "") + (f", AS {l['as']}" if l.get("as") else ""), l.get("state", "")]
    else:
        lines = [f"{db.label(l['a'])} {l.get('a_port', '')}  <->  {db.label(l['b'])} {l.get('b_port', '')}", ", ".join(sorted(l.get("protocols") or [])), l.get("speed", "")]
    if l.get("count", 1) > 1:
        lines.append(f"{l['count']} links merged")
    if not l.get("both") and not l.get("group_link") and l.get("change") != "gone":
        lines.append("seen from one end only")
    if l.get("down"):
        lines.append("a port is down" if layer == "l2" else "the adjacency is down")
    if l.get("change") == "new":
        lines.append("new since the discovery before")
    elif l.get("change") == "gone":
        lines.append("gone since the discovery before")
    return "\n".join(x for x in lines if x)


# =============================================================================== the detail card
class Card(QFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setProperty("card", True)
        self.setFixedWidth(300)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 12, 12)
        head = QHBoxLayout()
        self.title = QLabel("")
        f = self.title.font()
        f.setPointSizeF(f.pointSizeF() + 2)
        f.setBold(True)
        self.title.setFont(f)
        self.title.setWordWrap(True)
        self.close_btn = QPushButton("×")
        self.close_btn.setFixedSize(24, 24)
        self.close_btn.setFlat(True)
        head.addWidget(self.title, 1)
        head.addWidget(self.close_btn, 0, Qt.AlignmentFlag.AlignTop)
        lay.addLayout(head)
        self.role = _muted("")
        lay.addWidget(self.role)
        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(12)
        self.grid.setVerticalSpacing(3)
        lay.addLayout(self.grid)
        self.links_head = _heading("Links")
        lay.addWidget(self.links_head)
        self.links = QLabel("")
        self.links.setWordWrap(True)
        self.links.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(self.links)
        self.acts = QHBoxLayout()
        self.acts.setSpacing(6)
        lay.addLayout(self.acts)
        self.close_btn.clicked.connect(self.hide)
        self._buttons = []

    def show_node(self, name, info, role, facts, links, actions):
        self.title.setText(db.label(name) if not info.get("group") else name.split(" » ", 1)[1])
        self.role.setText(topology.ROLE_NAMES.get(role, "Device") + ("" if info.get("inventory") else "  ·  not in the inventory"))
        while self.grid.count():
            w = self.grid.takeAt(0).widget()
            if w:
                w.deleteLater()
        for i, (k, v) in enumerate(facts):
            kl, vl = _muted(k), QLabel(str(v))
            vl.setWordWrap(True)
            self.grid.addWidget(kl, i, 0)
            self.grid.addWidget(vl, i, 1)
        self.links_head.setText(f"{len(links)} LINK{'S' if len(links) != 1 else ''}")
        t = _t()
        rows = []
        for l in links:
            dot = DOWN if l.get("down") or l.get("change") == "gone" else ("#2fb37a" if l.get("both") else t.get("muted", "#888"))
            other = l["b"] if l["a"] == name else l["a"]
            mine = l.get("a_port") if l["a"] == name else l.get("b_port")
            theirs = l.get("b_port") if l["a"] == name else l.get("a_port")
            what = f"{l.get('protocol', '')} {l.get('state', '')}".strip() if "protocol" in l and "protocols" not in l else f"<code>{mine or ''}</code> → {db.label(other)} <code>{theirs or ''}</code>"
            if "protocol" in l and "protocols" not in l:
                what = f"{l.get('protocol')} → {db.label(other)} <span style='color:{t.get('muted', '#888')}'>{l.get('state', '')}</span>"
            rows.append(f"<span style='color:{dot}'>●</span> {what}")
        self.links.setText("<br>".join(rows) or "<i>none</i>")
        for b in self._buttons:
            b.deleteLater()
        self._buttons = []
        for label, fn in actions:
            b = QPushButton(label)
            b.clicked.connect(fn)
            self.acts.addWidget(b)
            self._buttons.append(b)
        self.adjustSize()
        self.show()
        self.raise_()


# =============================================================================== the tab
class TopologyWorker(QThread):
    done = Signal(list, list, dict)
    step = Signal(str)

    def __init__(self, devices):
        super().__init__()
        self.devices = devices

    def run(self):
        rows, l3, errors = topology.collect(self.devices, on_done=self.step.emit)
        self.done.emit(rows, l3, errors)


LINK_COLS = ["Layer", "Seen from", "Device A", "Port A", "Device B", "Port B", "Protocol", "Link", "Change"]


class TopologyTab(QWidget):
    open_device = Signal(str)                # a tile's device key: open its details
    open_ssh = Signal(str)                   # ... an SSH session to it
    run_checks = Signal(list)                # ... run its checks
    ping = Signal(str)                       # ... ping it
    add_device = Signal(dict)                # a neighbour not in the inventory: {'name', 'host', 'vendor'} for Add device
    inventory_action = Signal(str, str)      # (action, device key): 'edit', 'scan', 'tags', 'delete', as the inventory's right-click does them

    def __init__(self):
        super().__init__()
        self.worker = None
        self.rows, self.l3rows, self.at, self.prev_rows, self.prev_l3 = [], [], "", [], []
        self.nodes, self.links, self.nodes3, self.links3, self.roles = {}, [], {}, [], {}
        self.drawn = {"l2": ({}, []), "l3": ({}, [])}
        self.selected = {"l2": None, "l3": None}
        # ---- the rail
        rail = QWidget()
        rail.setFixedWidth(290)
        rl = QVBoxLayout(rail)
        rl.setContentsMargins(12, 12, 12, 12)
        rl.setSpacing(8)
        self.go = QPushButton("Discover neighbours")
        self.go.setProperty("primary", True)
        self.go.setToolTip("Asks the devices shown that can report neighbours: SNMP, an SSH login, or a firewall's API")
        self.status = _muted("")
        rl.addWidget(self.go)
        rl.addWidget(self.status)
        rl.addSpacing(6)
        rl.addWidget(_heading("Filters"))
        self.funnel = FilterButton(lambda: device_sections(topology.devices()))
        self.protocol = Segment((("both", "Both"), ("CDP", "CDP"), ("LLDP", "LLDP")))
        self.seen = Segment((("all", "All"), ("both", "Both ends"), ("one", "One end")))
        for label, w in (("Discovery", self.funnel), ("Protocol", self.protocol), ("Seen from", self.seen)):
            row = QHBoxLayout()
            row.addWidget(QLabel(label))
            row.addStretch(1)
            row.addWidget(w)
            rl.addLayout(row)
        rl.addSpacing(6)
        rl.addWidget(_heading("Diagram"))
        self.endpoints = Segment((("group", "Group"), ("each", "Each"), ("hide", "Hide")))
        self.layout_mode = Segment((("tiers", "Tiers"), ("organic", "Organic")))
        for label, w in (("Endpoints", self.endpoints), ("Layout", self.layout_mode)):
            row = QHBoxLayout()
            row.addWidget(QLabel(label))
            row.addStretch(1)
            row.addWidget(w)
            rl.addLayout(row)
        self.show_ip = QCheckBox("Show management IP")
        self.show_platform = QCheckBox("Show platform / model")
        self.merge = QCheckBox("Merge parallel links")
        self.short_ports = QCheckBox("Short port names")
        self.drop_domain = QCheckBox("Drop domain from names")
        for box, on, tip in ((self.show_ip, True, ""), (self.show_platform, False, ""), (self.merge, True, "One thicker line where several cables join the same two devices"),
                             (self.short_ports, True, "GigabitEthernet1/0/1 becomes Gi1/0/1"), (self.drop_domain, True, "sw1.corp.local becomes sw1")):
            box.setChecked(on)
            if tip:
                box.setToolTip(tip)
            rl.addWidget(box)
        rl.addSpacing(6)
        rl.addWidget(_heading("Checks"))
        tiles = QHBoxLayout()
        self.stat_devices, self.stat_links, self.stat_oneway = self._tile("devices"), self._tile("links"), self._tile("one-way")
        for t in (self.stat_devices, self.stat_links, self.stat_oneway):
            tiles.addWidget(t[0])
        rl.addLayout(tiles)
        self.changes_line = _muted("")
        rl.addWidget(self.changes_line)
        self.oneway_list = QListWidget()
        self.oneway_list.setMaximumHeight(120)
        self.oneway_list.setToolTip("Links one device reported and the other did not: the other's data was not loaded, CDP or LLDP is off on that port, or the cabling changed")
        rl.addWidget(self.oneway_list)
        rl.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidget(rail)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setFixedWidth(306)
        # ---- the stage
        bar = QHBoxLayout()
        self.tab_l2, self.tab_l3, self.tab_links = QPushButton("Layer 2"), QPushButton("Layer 3"), QPushButton("Links")
        self.tab_group = QButtonGroup(self)
        for b in (self.tab_l2, self.tab_l3, self.tab_links):
            b.setCheckable(True)
            b.setProperty("segment", True)
            self.tab_group.addButton(b)
            bar.addWidget(b)
        self.tab_l2.setChecked(True)
        bar.addStretch(1)
        self.find = SearchBox("Find device", "Type part of a name or address: the matching boxes and their neighbours stay bright, the rest fade.", page=self)
        self.relayout_btn = QPushButton("Re-run layout")
        self.relayout_btn.setToolTip("Lays the boxes out afresh and forgets where you dragged them")
        self.save_btn = QPushButton("Save picture...")
        menu = QMenu(self.save_btn)
        menu.addAction("PNG image", lambda: self.save_picture("png"))
        menu.addAction("SVG drawing", lambda: self.save_picture("svg"))
        self.save_btn.setMenu(menu)
        for w in (self.find, self.relayout_btn, self.save_btn):
            bar.addWidget(w)
        self.l2, self.l3 = MapView("l2"), MapView("l3")
        for v in (self.l2, self.l3):
            v.on_select = lambda name, layer=v.layer: self.select(name, layer)
            v.on_open = self._open
            v.on_menu = lambda name, pos, layer=v.layer: self.node_menu(name, pos, layer)
            v.on_moved = lambda layer=v.layer: self._moved(layer)
        links_page = QWidget()
        ll = QVBoxLayout(links_page)
        ll.setContentsMargins(0, 0, 0, 0)
        lbar = QHBoxLayout()
        self.links_filter = Segment((("all", "All"), ("oneway", "One-way"), ("both", "Both ends"), ("one", "One end")))
        self.links_count = _muted("")
        self.csv_btn = QPushButton("Download CSV")
        lbar.addWidget(self.links_filter)
        lbar.addWidget(self.links_count, 1)
        lbar.addWidget(self.csv_btn)
        ll.addLayout(lbar)
        from ui.tools2 import _table
        self.table = _table(LINK_COLS)
        ll.addWidget(self.table, 1)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.l2)
        self.stack.addWidget(self.l3)
        self.stack.addWidget(links_page)
        stage = QVBoxLayout()
        stage.setContentsMargins(0, 0, 0, 0)
        stage.addLayout(bar)
        stage.addWidget(self.stack, 1)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(scroll)
        lay.addLayout(stage, 1)
        # ---- wiring
        self.go.clicked.connect(self.start)
        self.tab_l2.toggled.connect(lambda on: on and self.stack.setCurrentIndex(0))
        self.tab_l3.toggled.connect(lambda on: on and self.stack.setCurrentIndex(1))
        self.tab_links.toggled.connect(lambda on: on and self.stack.setCurrentIndex(2))
        self.relayout_btn.clicked.connect(self.relayout)
        self.find.textChanged.connect(lambda _t: self._highlight())
        self.funnel.changed.connect(self.redraw)
        for seg in (self.protocol, self.seen, self.endpoints, self.layout_mode, self.links_filter):
            seg.changed.connect(lambda _k: self.redraw())
        for box in (self.show_ip, self.show_platform, self.merge, self.short_ports, self.drop_domain):
            box.toggled.connect(lambda _on: self.redraw())
        self.csv_btn.clicked.connect(self.download_csv)
        self.oneway_list.itemClicked.connect(lambda it: (self.find.setText(it.data(Qt.ItemDataRole.UserRole) or ""), self.tab_l2.setChecked(True)))
        self.refresh()
        self._load()

    def _tile(self, label):
        box = QFrame()
        box.setProperty("card", True)
        l = QVBoxLayout(box)
        l.setContentsMargins(8, 6, 8, 6)
        l.setSpacing(0)
        n = QLabel("0")
        f = n.font()
        f.setPointSizeF(f.pointSizeF() + 5)
        f.setBold(True)
        n.setFont(f)
        l.addWidget(n)
        l.addWidget(_muted(label))
        return box, n

    def refresh(self):
        pass                                              # the funnel reads the inventory each time it opens

    # ---------------------------------------------------------------- data in
    def _load(self):
        k = topology.last()
        if k["rows"] or k["l3"]:
            self._apply(k["rows"], k["l3"], {}, k["at"], k["prev_rows"], k["prev_l3"])

    def reset_view(self):
        """Another organization was picked: its own last discovery, or nothing."""
        self.rows, self.l3rows, self.at, self.prev_rows, self.prev_l3 = [], [], "", [], []
        self.nodes, self.links, self.nodes3, self.links3 = {}, [], {}, []
        for v in (self.l2, self.l3):
            v.scene().clear()
            v.boxes, v.lines = {}, []
            v.card.hide()
        self.table.setRowCount(0)
        self.status.setText("")
        self._load()

    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def start(self):
        if self.running():
            return
        devs = shown_devices(topology.devices(), self.find, self.funnel)
        if not devs:
            QMessageBox.information(self, "Topology", topology.NOTHING)
            return
        self.go.setEnabled(False)
        self.total, self.n = len(devs), 0
        self.status.setText(f"Asking {len(devs)} device(s)...")
        self.worker = TopologyWorker(devs)
        self.worker.step.connect(self._step)
        self.worker.done.connect(self._done)
        self.worker.start()

    def _step(self, name):
        self.n += 1
        self.status.setText(f"{self.n} of {self.total} answered...")

    def _done(self, rows, l3, errors):
        self.go.setEnabled(True)
        k = topology.last()
        topology.remember(rows, l3)
        self._apply(rows, l3, errors, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), k["rows"], k["l3"])

    def _apply(self, rows, l3, errors, at, prev_rows, prev_l3):
        self.rows, self.l3rows, self.at, self.prev_rows, self.prev_l3, self.errors = rows, l3, at, prev_rows, prev_l3, errors
        nodes, links = topology.build_graph(rows)
        if prev_rows:
            nodes, links = topology.mark_changes(nodes, links, topology.build_graph(prev_rows)[1])
        self.nodes, self.links = nodes, links
        nodes3, links3 = topology.build_l3(l3, nodes)
        if prev_l3:
            nodes3, links3 = topology.mark_l3_changes(nodes3, links3, topology.build_l3(prev_l3, nodes)[1])
        self.nodes3, self.links3 = nodes3, links3
        self.roles = topology.roles_for({**nodes3, **nodes}, rows)
        self.redraw()

    # ---------------------------------------------------------------- drawing
    def opts(self):
        return {"show_ip": self.show_ip.isChecked(), "show_platform": self.show_platform.isChecked(), "merge": self.merge.isChecked(),
                "short_ports": self.short_ports.isChecked(), "drop_domain": self.drop_domain.isChecked(), "endpoints": self.endpoints.value(),
                "layout": self.layout_mode.value(), "protocol": self.protocol.value(), "seen": self.seen.value()}

    def _filtered_l2(self):
        """The Layer 2 graph after the rail's filters: protocol, seen from, the funnel, then grouping and merging."""
        o = self.opts()
        links = [l for l in self.links if (o["protocol"] == "both" or o["protocol"] in l.get("protocols", set()) or l["change"] == "gone")
                 and (o["seen"] == "all" or (o["seen"] == "both") == bool(l.get("both")))]
        keep = {d["key"] for d in shown_devices([d for d in db.list_devices()], SearchBox("x"), self.funnel)} if self.funnel.active() else None
        if keep is not None:
            links = [l for l in links if l["a"] in keep or l["b"] in keep]
        nodes = {n: info for n, info in self.nodes.items() if any(n in (l["a"], l["b"]) for l in links)}
        nodes, links = topology.group_endpoints(nodes, links, self.roles, o["endpoints"])
        for l in links:
            if l["b"] in nodes and nodes[l["b"]].get("group"):
                l["group_link"] = True
        if o["merge"]:
            links = topology.merge_parallel(links)
        return nodes, links

    def _filtered_l3(self):
        o = self.opts()
        links = [l for l in self.links3 if o["seen"] == "all" or (o["seen"] == "both") == bool(l.get("both"))]
        nodes = {n: info for n, info in self.nodes3.items() if any(n in (l["a"], l["b"]) for l in links)}
        return nodes, links

    def redraw(self):
        if not (self.nodes or self.nodes3):
            return
        o = self.opts()
        status = topology.latest_status()
        roles = dict(self.roles)
        for layer, view, (nodes, links) in (("l2", self.l2, self._filtered_l2()), ("l3", self.l3, self._filtered_l3())):
            for n, info in nodes.items():
                if info.get("group"):
                    roles[n] = info["role"]
            fixed = topology.positions(layer)
            if o["layout"] == "tiers":
                pos = topology.tiers_layout(nodes, links, roles, topology.top_tier(layer))
                pos.update({k: v for k, v in fixed.items() if k in nodes})
            else:
                pos = topology.layout(nodes, links, 1000, 620, fixed=fixed)
            self.drawn[layer] = (nodes, links)
            view.draw(nodes, links, pos, roles, status, o)
            view.card.hide()
        self._legends()
        self._fill_table()
        self._stats()
        self._highlight()

    def _legends(self):
        used = {self.roles.get(n, "unknown") for n in self.drawn["l2"][0]} | {info.get("role") for info in self.drawn["l2"][0].values() if info.get("group")}
        t = _t()
        self.l2.set_legend([("swatch", topology.ROLE_COLORS[r], topology.ROLE_NAMES[r]) for r in topology.ROLES if r in used]
                           + [("line", t.get("muted", "#8d9ea8"), "Link"), ("thick", t.get("muted", "#8d9ea8"), "Merged links"), ("dash", ONE_WAY, "One-way"),
                              ("thick", t.get("accent", "#55b6d4"), "New"), ("dot", DOWN, "Gone"), ("line", DOWN, "Port down")])
        self.l3.set_legend([("line", topology.L3_COLORS[p], p) for p in topology.L3_PROTOCOLS] + [("dash", t.get("muted", "#8d9ea8"), "One end"), ("line", DOWN, "Down"), ("dot", DOWN, "Gone")])

    def _highlight(self):
        for v in (self.l2, self.l3):
            v.highlight(self.find.words())

    def _stats(self):
        nodes, links = self.drawn["l2"]
        live = [l for l in links if l["change"] != "gone"]
        oneway = [l for l in live if not l.get("both") and not l.get("group_link")]
        live3 = [l for l in self.drawn["l3"][1] if l["change"] != "gone"]
        self.stat_devices[1].setText(str(len({*nodes, *self.drawn["l3"][0]})))
        self.stat_links[1].setText(f"{len(live)} + {len(live3)}")
        self.stat_links[0].setToolTip("Layer 2 links + Layer 3 adjacencies")
        self.stat_oneway[1].setText(str(len(oneway)))
        new = sum(1 for l in links + self.drawn["l3"][1] if l["change"] == "new")
        gone = sum(1 for l in links + self.drawn["l3"][1] if l["change"] == "gone")
        both = sum(1 for l in live if l.get("both"))
        parts = [f"{both} confirmed from both ends, {len(oneway)} seen from one end"] if live else []
        if new or gone:
            parts.append(f"since the discovery before: {new} new, {gone} gone")
        self.changes_line.setText(". ".join(parts) + ("." if parts else ""))
        msg = (f"{self.at[:16]}: " if self.at else "") + f"{len(live)} link(s) between {len(nodes)} device(s)" + (f", {len(live3)} routing adjacencies." if live3 else ".")
        errors = getattr(self, "errors", {}) or {}
        if errors:
            msg += f"  {len(errors)} device(s) failed: " + "; ".join(f"{db.label(k)}: {v[:60]}" for k, v in list(errors.items())[:3])
        self.status.setText(msg)
        self.oneway_list.clear()
        for l in oneway[:50]:
            from PySide6.QtWidgets import QListWidgetItem
            it = QListWidgetItem(f"{db.label(l['a'])} {l.get('a_port', '')} → {db.label(l['b'])}")
            it.setData(Qt.ItemDataRole.UserRole, db.label(l["a"]))
            self.oneway_list.addItem(it)
        self.tab_links.setText(f"Links  {len(live) + len(live3)}")

    def _table_rows(self):
        out = []
        for layer, (nodes, links) in (("Layer 2", self.drawn["l2"]), ("Layer 3", self.drawn["l3"])):
            for l in links:
                if l.get("group_link"):
                    continue
                seen = "gone" if l["change"] == "gone" else "both ends" if l.get("both") else "one end"
                proto = l.get("protocol") if layer == "Layer 3" else ", ".join(sorted(l.get("protocols") or []))
                link = ("down" if l.get("down") else l.get("speed", "")) if layer == "Layer 2" else (l.get("state", "") + (f" AS {l['as']}" if l.get("as") else ""))
                out.append((layer, seen, db.label(l["a"]), l.get("a_port", ""), db.label(l["b"]), l.get("b_port", ""), proto, link, l["change"]))
        return out

    def _fill_table(self):
        f = self.links_filter.value()
        rows = [r for r in self._table_rows() if f == "all" or (f == "oneway" and r[1] == "one end") or (f == "both" and r[1] == "both ends") or (f == "one" and r[1] == "one end")]
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for j, v in enumerate(r):
                self.table.setItem(i, j, QTableWidgetItem(str(v)))
        self.table.resizeColumnsToContents()
        self.links_count.setText(f"{len(rows)} of {len(self._table_rows())} links")

    # ---------------------------------------------------------------- the user's hand
    def relayout(self):
        for layer in LAYERS:
            topology.save_positions(None, layer)
        self.redraw()

    def _moved(self, layer):
        view = self.l2 if layer == "l2" else self.l3
        topology.save_positions(view.current_positions(), layer)

    def _open(self, name):
        if self._info(name).get("inventory"):
            self.open_device.emit(name)

    def _info(self, name):
        for layer in LAYERS:
            if name in self.drawn[layer][0]:
                return self.drawn[layer][0][name]
        return self.nodes.get(name) or self.nodes3.get(name) or {}

    def _desc(self, name):
        return next((r.get("remote_desc", "") for r in self.rows if topology._key(r["remote_name"]) == topology._key(name)), "")

    def select(self, name, layer):
        view = self.l2 if layer == "l2" else self.l3
        self.selected[layer] = name
        if not name:
            view.card.hide()
            return
        nodes, links = self.drawn[layer]
        info = nodes.get(name, {})
        dev = db.find_device(name) if info.get("inventory") else None
        facts = []
        if dev:
            facts += [("Vendor", dev.get("vendor") or ""), ("Platform", dev.get("platform") or dev.get("details") or ""), ("Address", dev.get("host") or "")]
            sw = db.software_of(dev)
            if sw.get("version"):
                facts.append(("Version", sw["version"]))
        else:
            facts += [("Address", info.get("addr") or ""), ("Platform", self._desc(name))]
            if info.get("group"):
                facts = [("Members", ", ".join(db.label(m) for m in info["members"][:12]) + (" …" if len(info["members"]) > 12 else ""))]
        via = {r["via"] for r in self.rows if r["device"] == name and r.get("via")}
        if via:
            facts.append(("Source", ", ".join(sorted(via)) + (f", {self.at[:16]}" if self.at else "")))
        mine = [l for l in links if name in (l["a"], l["b"])]
        pinned = name in topology.top_tier(layer)
        if info.get("inventory"):
            actions = [("Details", lambda: self.open_device.emit(name)), ("SSH", lambda: self.open_ssh.emit(name)),
                       ("Run checks", lambda: self.run_checks.emit([name])), ("Ping", lambda: self.ping.emit(name))]
        elif info.get("group"):
            actions = [("Show each", lambda: self.endpoints.set("each"))]
        else:
            actions = [("Add to inventory...", lambda: self._add(name))]
        actions.append(("Take off the top tier" if pinned else "Put on the top tier", lambda: self.toggle_top(name, layer)))
        view.card.show_node(name, info, self.roles.get(name, info.get("role", "unknown")), [f for f in facts if f[1]], mine, actions)
        view._place()

    def toggle_top(self, name, layer):
        top = topology.top_tier(layer)
        top ^= {name}
        topology.pin_top(top, layer)
        self.layout_mode.set("tiers")
        self.redraw()

    def _add(self, name):
        info = self._info(name)
        self.add_device.emit({"name": name, "host": info.get("addr", ""), "vendor": topology.guess_vendor(self._desc(name))})

    def node_actions(self, name, layer="l2"):
        """[(label, what it does)] for a tile's right-click: the inventory's device actions, the map's own, or Add to inventory."""
        info = self._info(name)
        pinned = name in topology.top_tier(layer)
        tier = ("Take off the top tier" if pinned else "Put on the top tier", lambda: self.toggle_top(name, layer))
        if info.get("inventory"):
            return [("Details...", lambda: self.open_device.emit(name)), ("Edit...", lambda: self.inventory_action.emit("edit", name)),
                    ("Open SSH session", lambda: self.open_ssh.emit(name)), ("Run Checks", lambda: self.run_checks.emit([name])),
                    ("Scan for vulnerabilities", lambda: self.inventory_action.emit("scan", name)),
                    ("Edit tags, folder, profile...", lambda: self.inventory_action.emit("tags", name)), ("Ping", lambda: self.ping.emit(name)), tier,
                    ("Delete...", lambda: self.inventory_action.emit("delete", name))]
        if info.get("group"):
            return [("Show each", lambda: self.endpoints.set("each")), tier]
        return [("Add to inventory...", lambda: self._add(name)), tier]

    def node_menu(self, name, pos, layer="l2"):
        menu = QMenu(self)
        for label, fn in self.node_actions(name, layer):
            if label == "Delete...":
                menu.addSeparator()
            menu.addAction(label, fn)
        menu.exec(pos)

    def save_picture(self, kind):
        view = self.l3 if self.tab_l3.isChecked() else self.l2
        if not view.boxes:
            toast(self, "Nothing to save yet. Discover neighbours first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save picture", f"topology-{view.layer}.{kind}", "PNG image (*.png)" if kind == "png" else "SVG drawing (*.svg)")
        if not path:
            return
        sc = view.scene()
        if kind == "svg":
            from PySide6.QtSvg import QSvgGenerator
            from PySide6.QtCore import QSize
            g = QSvgGenerator()
            g.setFileName(path)
            g.setSize(QSize(int(sc.sceneRect().width()), int(sc.sceneRect().height())))
            g.setViewBox(sc.sceneRect())
            p = QPainter(g)
            sc.render(p)
            p.end()
            return
        from PySide6.QtGui import QImage
        img = QImage(int(sc.sceneRect().width() * 2), int(sc.sceneRect().height() * 2), QImage.Format.Format_ARGB32)
        img.fill(QColor(_t().get("bg", "#ffffff")))
        p = QPainter(img)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        sc.render(p)
        p.end()
        img.save(path)

    def download_csv(self):
        rows = self._table_rows()
        if not rows:
            toast(self, "Nothing to save yet. Discover neighbours first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Download CSV", "topology-links.csv", "CSV (*.csv)")
        if path:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(LINK_COLS)
                w.writerows(rows)

    def shutdown(self):
        if self.worker:
            self.worker.wait(5000)
