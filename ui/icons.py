"""Small line icons drawn from SVG paths, tinted to the current theme (no image files to ship)."""
from PySide6.QtCore import QByteArray, QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QImage, QPainter, QPixmap, QPolygonF
from PySide6.QtSvg import QSvgRenderer

# 24x24 viewBox, stroke-only, in the style of common open icon sets.
PATHS = {
    "dashboard": '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/>'
                 '<rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    "results": '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    "inventory": '<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/>'
                 '<path d="M7 7h.01M7 17h.01"/>',
    "history": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "reports": '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>'
               '<path d="M9 13h6M9 17h6"/>',
    "tools": '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-.6-.6-2.4z"/>',
    "configs": '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
    "scanning": '<path d="M12 3l8 3v6c0 4.5-3.4 7.8-8 9-4.6-1.2-8-4.5-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
    "sessions": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
    "automation": '<path d="M13 3L5 14h6l-1 7 8-11h-6z"/>',
    "about": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    "warn": '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',
    "fail": '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
    "check": '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    "panel": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
    "chev-down": '<path d="M6 9l6 6 6-6"/>', "chev-up": '<path d="M6 15l6-6 6 6"/>',
    "folder": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    "device": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    "settings": '<path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/>'
                '<circle cx="8" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
}


# Solid versions (a filled shape with the mark cut out of it), for the status tiles: name -> (shape, mark)
FILLED = {
    "ok-fill": ('<circle cx="12" cy="12" r="10"/>', '<path d="M7.5 12.5l3 3 6-6.5"/>'),
    "warn-fill": ('<path d="M12 2.5l10.5 18.5h-21z"/>', '<path d="M12 9.5v5M12 17.5h.01"/>'),
    "fail-fill": ('<circle cx="12" cy="12" r="10"/>', '<path d="M8.5 8.5l7 7M15.5 8.5l-7 7"/>'),
}


def _render_filled(name, color, size):
    shape, mark = FILLED[name]
    img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    head = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
    QSvgRenderer(QByteArray((head + f'fill="{color}" stroke="{color}" stroke-width="1.5" stroke-linejoin="round">{shape}</svg>').encode())).render(p, QRectF(0, 0, size, size))
    p.setCompositionMode(QPainter.CompositionMode.CompositionMode_DestinationOut)       # the mark is cut out of the shape
    QSvgRenderer(QByteArray((head + f'fill="none" stroke="#000000" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">{mark}</svg>').encode())).render(p, QRectF(0, 0, size, size))
    p.end()
    return QPixmap.fromImage(img)


def _render(name, color, size):
    if name in FILLED:
        return _render_filled(name, color, size)
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" '
           f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{PATHS[name]}</svg>')
    img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    QSvgRenderer(QByteArray(svg.encode())).render(p, QRectF(0, 0, size, size))
    p.end()
    return QPixmap.fromImage(img)


def icon(name, normal, selected=None, size=40):
    """A QIcon with a normal colour and (optionally) another for the selected state of a list or tab."""
    ic = QIcon()
    ic.addPixmap(_render(name, normal, size), QIcon.Mode.Normal, QIcon.State.Off)
    ic.addPixmap(_render(name, selected or normal, size), QIcon.Mode.Selected, QIcon.State.Off)
    ic.addPixmap(_render(name, selected or normal, size), QIcon.Mode.Active, QIcon.State.Off)
    return ic


def _marker(p, shape, cx, cy, r, color):
    """A status mark: circle (OK), triangle (WARN), square (FAIL) or diamond (ERROR), so the state does not rest on colour alone."""
    pts = {"triangle": [(0, -1.15), (1.05, 0.85), (-1.05, 0.85)], "square": [(-0.9, -0.9), (0.9, -0.9), (0.9, 0.9), (-0.9, 0.9)],
           "diamond": [(0, -1.2), (1.2, 0), (0, 1.2), (-1.2, 0)]}.get(shape)
    if pts is None:
        p.drawEllipse(QPointF(cx, cy), r, r)
    else:
        p.drawPolygon(QPolygonF([QPointF(cx + x * r, cy + y * r) for x, y in pts]))


def icon_with_dot(name, normal, dot, size=40, shape="circle"):
    """An icon with a small status mark in its bottom-right corner (the health of a device)."""
    pm = _render(name, normal, size)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    r = size * 0.19
    cx = cy = size - r * 1.25
    p.setBrush(QColor("#ffffff"))              # a pale ring so the mark reads on light and dark rows alike
    p.setPen(Qt.PenStyle.NoPen)
    _marker(p, shape, cx, cy, r * 1.32, QColor("#ffffff"))
    p.setBrush(QColor(dot))
    _marker(p, shape, cx, cy, r, QColor(dot))
    p.end()
    ic = QIcon()
    ic.addPixmap(pm, QIcon.Mode.Normal, QIcon.State.Off)
    ic.addPixmap(pm, QIcon.Mode.Selected, QIcon.State.Off)
    return ic


def png_path(name, color, size=24):
    """Write a tinted icon to a cache folder and return its path, for stylesheet `image: url(...)` rules."""
    import os, tempfile
    folder = os.path.join(tempfile.gettempdir(), "toner_ui")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{name}_{color.lstrip('#')}.png")
    if not os.path.exists(path):
        _render(name, color, size).save(path, "PNG")
    return path.replace("\\", "/")
