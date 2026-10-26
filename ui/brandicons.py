"""Small coloured marks for the notification services (Discord, Slack, Teams, ...), drawn from SVG so no image files ship.

They are simplified glyphs in each service's usual colours, enough to tell the channels apart at a glance (Teams follows its
own logo closely); drawn here rather than shipped as image files, so every system shows the same thing.
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
    # Microsoft Teams: the purple T tile in front of two people (the back one darker), in Teams' own colours
    "teams": '<circle cx="51" cy="15" r="6.5" fill="#5059C9"/>'
             '<path d="M42 25h16.5a3.5 3.5 0 0 1 3.5 3.5V43a10 10 0 0 1-10 10h0a10 10 0 0 1-10-10z" fill="#5059C9"/>'
             '<circle cx="34" cy="12.5" r="9" fill="#7B83EB"/>'
             '<path d="M20 24h28a3 3 0 0 1 3 3v17a15 15 0 0 1-15 15h0a15 15 0 0 1-15-15z" fill="#7B83EB"/>'
             '<rect x="3" y="16" width="32" height="32" rx="4" fill="#4B53BC"/>'
             '<path d="M10 23.5h18v5h-6.5V42h-5V28.5H10z" fill="#fff"/>',
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

# ---- the Assistant's providers (Settings > AI). BRAND_SVG holds each company's own mark as published on its brand page, the whole
# SVG file unmodified, one for light surfaces and one for dark (see core/assistant). Until a mark is there, a plain tile stands in.
# OpenAI: the Blossom from https://openai.com/brand/ (openai-logos.zip, fetched 2026-10-25, used under OpenAI's Marks usage terms:
# unmodified, in its own colours, never more prominent than Toner's own mark). Its file keeps the clear space OpenAI prescribes.
OPENAI_BLOSSOM_BLACK = '<svg width="716" height="716" viewBox="0 0 716 716" fill="none" xmlns="http://www.w3.org/2000/svg">\n<path d="M508.749 317.399C516.777 287.314 508.991 253.884 485.389 230.282C461.788 206.681 428.36 198.895 398.273 206.923C376.231 184.928 343.39 174.956 311.148 183.596C278.906 192.234 255.45 217.292 247.36 247.361C217.291 255.451 192.233 278.91 183.595 311.149C174.957 343.391 184.927 376.232 206.924 398.274C198.896 428.359 206.683 461.789 230.284 485.391C253.885 508.992 287.313 516.779 317.401 508.75C339.442 530.745 372.286 540.717 404.525 532.079C436.767 523.441 460.223 498.384 468.313 468.315C498.383 460.224 523.44 436.766 532.078 404.526C540.716 372.285 530.747 339.443 508.749 317.402V317.399ZM470.899 244.776C486.892 260.77 493.488 282.601 490.687 303.412L415.577 260.046C412.411 258.218 408.509 258.218 405.345 260.046L317.401 310.82V277.526C317.401 275.191 318.652 273.005 320.676 271.837L387.644 233.174C414.178 218.353 448.346 222.223 470.901 244.776H470.899ZM357.837 311.144L398.275 334.491V381.185L357.837 404.532L317.398 381.185V334.491L357.837 311.144ZM264.776 269.693C265.207 239.305 285.644 211.649 316.453 203.393C338.3 197.54 360.505 202.744 377.127 215.573L302.014 258.937C298.848 260.764 296.898 264.144 296.898 267.798V369.346L268.065 352.699C266.043 351.531 264.776 349.353 264.776 347.017V269.691V269.693ZM203.391 316.454C209.244 294.608 224.854 277.978 244.276 269.999V356.73C244.276 360.384 246.226 363.763 249.392 365.591L337.337 416.365L308.503 433.013C306.481 434.181 303.961 434.188 301.939 433.02L234.971 394.357C208.868 378.789 195.138 347.261 203.391 316.454ZM244.775 470.9C228.781 454.906 222.186 433.075 224.986 412.264L300.096 455.63C303.263 457.457 307.164 457.457 310.328 455.63L398.273 404.856V438.149C398.273 440.485 397.022 442.671 394.997 443.839L328.029 482.502C301.495 497.322 267.327 493.452 244.772 470.9H244.775ZM450.897 445.982C450.466 476.371 430.029 504.027 399.22 512.283C377.373 518.136 355.168 512.932 338.547 500.102L413.659 456.738C416.826 454.911 418.775 451.532 418.775 447.877V346.329L447.609 362.977C449.631 364.145 450.897 366.323 450.897 368.659V445.985V445.982ZM512.282 399.221C506.429 421.068 490.819 437.697 471.397 445.676V358.946C471.397 355.292 469.448 351.912 466.281 350.085L378.336 299.311L407.17 282.663C409.192 281.495 411.712 281.487 413.734 282.655L480.702 321.318C506.805 336.887 520.536 368.415 512.282 399.221Z" fill="black"/>\n</svg>\n'
OPENAI_BLOSSOM_WHITE = '<svg width="716" height="716" viewBox="0 0 716 716" fill="none" xmlns="http://www.w3.org/2000/svg">\n<path d="M508.749 317.399C516.777 287.314 508.991 253.884 485.389 230.282C461.788 206.681 428.36 198.895 398.273 206.923C376.231 184.928 343.39 174.956 311.148 183.596C278.906 192.234 255.45 217.292 247.36 247.361C217.291 255.451 192.233 278.91 183.595 311.149C174.957 343.391 184.927 376.232 206.924 398.274C198.896 428.359 206.683 461.789 230.284 485.391C253.885 508.992 287.313 516.779 317.401 508.75C339.442 530.745 372.286 540.717 404.525 532.079C436.767 523.441 460.223 498.384 468.313 468.315C498.383 460.224 523.44 436.766 532.078 404.526C540.716 372.285 530.747 339.443 508.749 317.402V317.399ZM470.899 244.776C486.892 260.77 493.488 282.601 490.687 303.412L415.577 260.046C412.411 258.218 408.509 258.218 405.345 260.046L317.401 310.82V277.526C317.401 275.191 318.652 273.005 320.676 271.837L387.644 233.174C414.178 218.353 448.346 222.223 470.901 244.776H470.899ZM357.837 311.144L398.275 334.491V381.185L357.837 404.532L317.398 381.185V334.491L357.837 311.144ZM264.776 269.693C265.207 239.305 285.644 211.649 316.453 203.393C338.3 197.54 360.505 202.744 377.127 215.573L302.014 258.937C298.848 260.764 296.898 264.144 296.898 267.798V369.346L268.065 352.699C266.043 351.531 264.776 349.353 264.776 347.017V269.691V269.693ZM203.391 316.454C209.244 294.608 224.854 277.978 244.276 269.999V356.73C244.276 360.384 246.226 363.763 249.392 365.591L337.337 416.365L308.503 433.013C306.481 434.181 303.961 434.188 301.939 433.02L234.971 394.357C208.868 378.789 195.138 347.261 203.391 316.454ZM244.775 470.9C228.781 454.906 222.186 433.075 224.986 412.264L300.096 455.63C303.263 457.457 307.164 457.457 310.328 455.63L398.273 404.856V438.149C398.273 440.485 397.022 442.671 394.997 443.839L328.029 482.502C301.495 497.322 267.327 493.452 244.772 470.9H244.775ZM450.897 445.982C450.466 476.371 430.029 504.027 399.22 512.283C377.373 518.136 355.168 512.932 338.547 500.102L413.659 456.738C416.826 454.911 418.775 451.532 418.775 447.877V346.329L447.609 362.977C449.631 364.145 450.897 366.323 450.897 368.659V445.985V445.982ZM512.282 399.221C506.429 421.068 490.819 437.697 471.397 445.676V358.946C471.397 355.292 469.448 351.912 466.281 350.085L378.336 299.311L407.17 282.663C409.192 281.495 411.712 281.487 413.734 282.655L480.702 321.318C506.805 336.887 520.536 368.415 512.282 399.221Z" fill="white"/>\n</svg>\n'
BRAND_SVG = {"openai": {"light": OPENAI_BLOSSOM_BLACK, "dark": OPENAI_BLOSSOM_WHITE}}
PROVIDER_FALLBACK = {
    "claude": '<rect width="64" height="64" rx="14" fill="#D97757"/><path d="M20 16h8l12 32h-8z M36 16h8L32 48h-8z" fill="#fff"/>',
    "openai": '<rect width="64" height="64" rx="14" fill="#000"/><circle cx="32" cy="32" r="15" fill="none" stroke="#fff" stroke-width="5"/>',
    "gemini": '<rect width="64" height="64" rx="14" fill="#1F6FEB"/><path d="M32 12 Q34 30 52 32 Q34 34 32 52 Q30 34 12 32 Q30 30 32 12Z" fill="#fff"/>',
}


def _pixmap_doc(svg, size):
    """Render a whole SVG document (its own viewBox) into a square of `size` pixels, keeping its proportions."""
    img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    r = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    box = r.viewBoxF()
    w, h = (box.width(), box.height()) if box.width() > 0 and box.height() > 0 else (r.defaultSize().width() or 1, r.defaultSize().height() or 1)
    scale = size / max(w, h)
    dw, dh = w * scale, h * scale
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    r.render(p, QRectF((size - dw) / 2, (size - dh) / 2, dw, dh))
    p.end()
    return QPixmap.fromImage(img)


def on_dark():
    """True when the window's surfaces are dark (the white marks are for those)."""
    from PySide6.QtGui import QColor
    from ui import theme
    t = theme.current() or {}
    return QColor(t.get("surface", "#ffffff")).lightness() < 128


def has_brand_mark(provider):
    return provider in BRAND_SVG


def provider_icon(provider):
    """The mark of an Assistant provider: 'claude', 'openai' or 'gemini'. A company's own mark comes in a light and a dark version;
    the theme picks."""
    variant = "dark" if on_dark() else "light"
    key = f"provider:{provider}:{variant}"
    if key not in _cache:
        ic = QIcon()
        for size in (16, 24, 32, 48, 64):
            if provider in BRAND_SVG:
                ic.addPixmap(_pixmap_doc(BRAND_SVG[provider][variant], size))
            else:
                svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">{PROVIDER_FALLBACK.get(provider, PROVIDER_FALLBACK["claude"])}</svg>'
                ic.addPixmap(_pixmap_doc(svg, size))
        _cache[key] = ic
    return _cache[key]


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
