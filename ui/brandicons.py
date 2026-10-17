"""Small coloured marks for the notification services (Discord, Slack, Teams, ...), drawn from SVG so no image files ship.

They are simplified glyphs in each service's usual colours, enough to tell the channels apart at a glance; they are not the
services' official artwork.
"""
from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QImage, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

# 64x64 canvases
SVG = {
    # a blurple tile with the white face-and-ears mark
    "discord": '<rect width="64" height="64" rx="14" fill="#5865F2"/>'
               '<path d="M16 22 Q22 17 29 16 L31 20 Q32 20 33 20 L35 16 Q42 17 48 22 Q53 31 52 44 Q46 49 40 50 L37 46 '
               'Q32 47 27 46 L24 50 Q18 49 12 44 Q11 31 16 22Z" fill="#fff"/>'
               '<ellipse cx="25" cy="35" rx="4" ry="4.8" fill="#5865F2"/><ellipse cx="39" cy="35" rx="4" ry="4.8" fill="#5865F2"/>',
    # four coloured pills and their round ends, as a pinwheel
    "slack": '<rect x="25" y="6" width="10" height="24" rx="5" fill="#36C5F0"/><circle cx="14" cy="20" r="5.5" fill="#36C5F0"/>'
             '<rect x="34" y="25" width="24" height="10" rx="5" fill="#2EB67D"/><circle cx="44" cy="14" r="5.5" fill="#2EB67D"/>'
             '<rect x="29" y="34" width="10" height="24" rx="5" fill="#ECB22E"/><circle cx="50" cy="44" r="5.5" fill="#ECB22E"/>'
             '<rect x="6" y="29" width="24" height="10" rx="5" fill="#E01E5A"/><circle cx="20" cy="50" r="5.5" fill="#E01E5A"/>',
    # a violet tile, a white T, and the lighter head-and-shoulders dot
    "teams": '<rect width="64" height="64" rx="14" fill="#5059C9"/><circle cx="46" cy="18" r="8" fill="#7B83EB"/>'
             '<path d="M12 22h30v8H31v22h-8V30H12z" fill="#fff"/>',
    "email": '<rect x="5" y="13" width="54" height="38" rx="6" fill="#3B82F6"/>'
             '<path d="M8 19 L32 38 L56 19" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>',
    # three joined nodes
    "webhook": '<path d="M32 14 L16 46 M32 14 L48 46 M16 46 L48 46" fill="none" stroke="#64748B" stroke-width="5" stroke-linecap="round"/>'
               '<circle cx="32" cy="14" r="9" fill="#F59E0B"/><circle cx="16" cy="46" r="9" fill="#10B981"/><circle cx="48" cy="46" r="9" fill="#3B82F6"/>',
    # a green tile with a terminal prompt
    "ntfy": '<rect width="64" height="64" rx="14" fill="#338574"/>'
            '<path d="M17 21 L31 32 L17 43" fill="none" stroke="#fff" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>'
            '<path d="M35 45 H49" fill="none" stroke="#fff" stroke-width="6" stroke-linecap="round"/>',
    # the four panes
    "desktop": '<rect x="6" y="6" width="25" height="25" rx="2" fill="#0078D4"/><rect x="33" y="6" width="25" height="25" rx="2" fill="#0078D4"/>'
               '<rect x="6" y="33" width="25" height="25" rx="2" fill="#0078D4"/><rect x="33" y="33" width="25" height="25" rx="2" fill="#0078D4"/>',
    # ---- where passwords are kept (Settings > Security > Store passwords in)
    # Toner's own vault: a padlock on a slate tile
    "toner": '<rect width="64" height="64" rx="14" fill="#334155"/>'
             '<path d="M22 29 V22 A10 10 0 0 1 42 22 V29" fill="none" stroke="#fff" stroke-width="5"/>'
             '<rect x="16" y="28" width="32" height="24" rx="4" fill="#fff"/><circle cx="32" cy="39" r="4" fill="#334155"/>',
    # a blue tile with a white shield, its right half lighter
    "bitwarden": '<rect width="64" height="64" rx="14" fill="#175DDC"/>'
                 '<path d="M16 12 H48 V34 Q48 46 32 54 Q16 46 16 34 Z" fill="#fff"/>'
                 '<path d="M32 17 H43 V34 Q43 43 32 48 Z" fill="#175DDC" opacity=".35"/>',
    # the same shield on a dark tile, with a cog for "your own server"
    "vaultwarden": '<rect width="64" height="64" rx="14" fill="#1F2937"/>'
                   '<path d="M16 12 H48 V34 Q48 46 32 54 Q16 46 16 34 Z" fill="#fff"/>'
                   '<circle cx="32" cy="31" r="9" fill="none" stroke="#1F2937" stroke-width="4" stroke-dasharray="4 3"/>'
                   '<circle cx="32" cy="31" r="3.5" fill="#1F2937"/>',
    # a yellow tile with a black K
    "keeper": '<rect width="64" height="64" rx="14" fill="#FFC700"/>'
              '<path d="M20 14 H28 V29 L39 14 H48 L35 32 L48 50 H39 L28 35 V50 H20 Z" fill="#111"/>',
    # a blue disc with a white keyhole
    "onepassword": '<circle cx="32" cy="32" r="29" fill="#0572EC"/><circle cx="32" cy="32" r="21" fill="none" stroke="#fff" stroke-width="4"/>'
                   '<rect x="28.5" y="19" width="7" height="26" rx="3.5" fill="#fff"/>',
}
_cache = {}


def _pixmap(name, size):
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">{SVG[name]}</svg>'
    img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    QSvgRenderer(QByteArray(svg.encode())).render(p, QRectF(0, 0, size, size))
    p.end()
    return QPixmap.fromImage(img)


def vault_icon(kind):
    """The mark for a place passwords are kept: 'toner', 'bitwarden', 'vaultwarden', 'keeper', 'onepassword'."""
    return channel_icon(kind if kind in SVG else "toner")


def channel_icon(ctype):
    """The mark for a notification channel type ('discord', 'slack', ...). An unknown type gets the generic webhook mark."""
    name = ctype if ctype in SVG else "webhook"
    if name not in _cache:
        ic = QIcon()
        for size in (16, 24, 32, 48, 64):               # sharp at any display scale
            ic.addPixmap(_pixmap(name, size))
        _cache[name] = ic
    return _cache[name]
