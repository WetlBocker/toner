"""Small line icons drawn from SVG paths, tinted to the current theme (no image files to ship)."""
from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QImage, QPainter, QPixmap
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
    "about": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    "check": '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    "chev-down": '<path d="M6 9l6 6 6-6"/>', "chev-up": '<path d="M6 15l6-6 6 6"/>',
    "folder": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    "device": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    "settings": '<path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/>'
                '<circle cx="8" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
}


def _render(name, color, size):
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


def png_path(name, color, size=24):
    """Write a tinted icon to a cache folder and return its path, for stylesheet `image: url(...)` rules."""
    import os, tempfile
    folder = os.path.join(tempfile.gettempdir(), "toner_ui")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{name}_{color.lstrip('#')}.png")
    if not os.path.exists(path):
        _render(name, color, size).save(path, "PNG")
    return path.replace("\\", "/")
