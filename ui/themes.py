"""The themes: every colour theme as a table of tokens, and the pure maths that turns a chosen theme plus the knobs
(Look, Panels, Contrast, the interactive themes' own settings) into the colours the window is painted with.

Nothing here touches Qt or the database, so it is cheap to test. ui/theme.py turns the result into a palette and a stylesheet."""
from datetime import datetime

# ---- the fixed themes. Each is the nine base colours plus `dark`; `glow` paints a soft wash of the accent at the top of the page,
# `aurora` the drifting sky-blue to violet wash (Aurora only). hover, scroll, icon and accent_hover are derived when not given,
# so Midnight and Daylight keep every value they had before.
BASE_KEYS = ("bg", "surface", "surface2", "border", "text", "muted", "input", "accent", "accent_text")
FIXED = {
    "Aurora":   dict(dark=True,  bg="#0a0e17", surface="#111727", surface2="#18203a", border="#27304d", text="#eef2ff", muted="#9aa6c8", input="#080c14", accent="#38bdf8", accent_text="#061421", aurora=True, glow=True,
                     note="A slow sky-blue to violet wash that drifts across the page, a faint constellation behind the panels, and motion in every change. Toner's own look."),
    "Ember":    dict(dark=True,  bg="#17140f", surface="#1f1b15", surface2="#2a241c", border="#3b3327", text="#f4eee3", muted="#b1a593", input="#14110d", accent="#f2a54a", accent_text="#1a1409", glow=True,
                     note="Warm charcoal with an amber accent and a soft glow at the top."),
    "Harbor":   dict(dark=True,  bg="#1a1e29", surface="#222736", surface2="#2b3142", border="#39405a", text="#e8ebf2", muted="#a3abbf", input="#171b25", accent="#8fb0ff", accent_text="#0f1424",
                     note="Blue-grey, softer and less stark than Midnight."),
    "Moss":     dict(dark=True,  bg="#0f1915", surface="#15211c", surface2="#1d2c25", border="#2c3f36", text="#eaf2ed", muted="#9fb6aa", input="#0c1410", accent="#e9bd4f", accent_text="#171205", glow=True,
                     note="Deep green with a gold accent, so OK stays its own green."),
    "Slate":    dict(dark=True,  bg="#1c1c1f", surface="#242428", surface2="#2d2d32", border="#3b3b42", text="#ececef", muted="#a4a4ad", input="#18181b", accent="#ff8a65", accent_text="#1c1c1f",
                     note="Plain grey, no blue in it, with a coral accent."),
    "Dusk":     dict(dark=True,  bg="#1a1626", surface="#221d33", surface2="#2c2642", border="#3d3557", text="#efeaf7", muted="#aaa1c2", input="#16121f", accent="#ffb38a", accent_text="#241a10", glow=True,
                     note="Indigo evening with a peach accent and a glow."),
    "Carbon":   dict(dark=True,  bg="#0a0a0a", surface="#141414", surface2="#1e1e1e", border="#2c2c2c", text="#f2f2f2", muted="#a3a3a3", input="#0f0f0f", accent="#ffffff", accent_text="#0a0a0a",
                     note="Near-black with a white accent. Only the status colours are in colour."),
    "Nordic":   dict(dark=True,  bg="#2e3440", surface="#3b4252", surface2="#434c5e", border="#4c566a", text="#eceff4", muted="#b4bccb", input="#2b303b", accent="#88c0d0", accent_text="#2e3440",
                     note="Muted blue-grey with a frost accent, lower contrast for long evenings."),
    "Plum":     dict(dark=True,  bg="#1d1420", surface="#26192b", surface2="#322238", border="#46324d", text="#f3ebf5", muted="#b7a4bd", input="#180f1b", accent="#5ad7e6", accent_text="#0f2327", glow=True,
                     note="Dark aubergine with an aqua accent and a glow."),
    "Cocoa":    dict(dark=True,  bg="#1f1715", surface="#291f1c", surface2="#352926", border="#4a3a35", text="#f6ece6", muted="#bba79e", input="#1a1310", accent="#f5c26b", accent_text="#2a1d05", glow=True,
                     note="Dark brown with cream text and a honey accent."),
    "Steel":    dict(dark=True,  bg="#2b3038", surface="#343a44", surface2="#3d444f", border="#4b535f", text="#e9ecf0", muted="#b2bac6", input="#272c34", accent="#5db7ff", accent_text="#0b1c2a",
                     note="Mid grey, neither dark nor light, with a sky-blue accent."),
    "Lagoon":   dict(dark=True,  bg="#0e1f22", surface="#13292d", surface2="#1a353a", border="#27484e", text="#e8f3f3", muted="#9db8ba", input="#0b1a1c", accent="#ff8c69", accent_text="#2a1008", glow=True,
                     note="Deep teal water with a coral accent and a glow."),
    "High contrast": dict(dark=True, bg="#000000", surface="#000000", surface2="#1a1a1a", border="#ffffff", text="#ffffff", muted="#e0e0e0", input="#000000", accent="#ffd600", accent_text="#000000",
                     hover="#262626", scroll="#9a9a9a", icon="#ffffff",
                     note="Black, white borders and a yellow accent, for low vision or bright rooms."),
    "Linen":    dict(dark=False, bg="#f5f1ea", surface="#fffdf9", surface2="#ebe5db", border="#d8d0c3", text="#24201a", muted="#6a6256", input="#fbf8f3", accent="#c04d28", accent_text="#ffffff",
                     note="Warm paper with a terracotta accent."),
    "Mist":     dict(dark=False, bg="#eef1f5", surface="#f8fafc", surface2="#e2e7ee", border="#cfd6df", text="#1f2631", muted="#5c6675", input="#f3f5f8", accent="#3b6fd6", accent_text="#ffffff",
                     note="Cool light grey, easier on the eyes than pure white."),
    "Sand":     dict(dark=False, bg="#efe9dd", surface="#faf7f0", surface2="#e6dfd0", border="#d2c9b7", text="#2a241a", muted="#6b6356", input="#f5f1e8", accent="#0f766e", accent_text="#ffffff", glow=True,
                     note="Warm sand with a deep teal accent."),
    "Arctic":   dict(dark=False, bg="#e9f0f6", surface="#f9fbfd", surface2="#dde6ee", border="#c6d2de", text="#142033", muted="#52627a", input="#f3f7fa", accent="#1d3f8a", accent_text="#ffffff",
                     note="Pale ice blue with a navy accent."),
    "Clay":     dict(dark=False, bg="#f3ebe7", surface="#fcf8f6", surface2="#eadfd9", border="#d9c9c0", text="#2d2320", muted="#6f5f58", input="#f8f2ef", accent="#4a5d8a", accent_text="#ffffff",
                     note="Rosy warm light with a dusty blue accent."),
    # the two Toner had before 1.12, every value as it was
    "Midnight": dict(dark=True,  bg="#081420", surface="#0b1b2b", surface2="#12283d", border="#223a52", text="#f4f8fb", muted="#9fb3c6", input="#081420", accent="#22d3ee", accent_text="#0b1b2b",
                     hover="#163149", scroll="#2f4a63", icon="#b6c8d8", accent_hover="#67e8f9",
                     note="The dark theme Toner had before 1.12."),
    "Daylight": dict(dark=False, bg="#f3f6f9", surface="#ffffff", surface2="#e6edf3", border="#cbd6e0", text="#0b1b2b", muted="#4a5b6c", input="#f3f6f9", accent="#0e7490", accent_text="#ffffff",
                     hover="#eaf0f5", scroll="#b4c2cf", icon="#4a5b6c", accent_hover="#0b5f74",
                     note="The light theme Toner had before 1.12."),
}
MORNING = dict(dark=False, bg="#f7f1e6", surface="#fffaf1", surface2="#eee5d5", border="#dccfbb", text="#2b241b", muted="#6e6356", input="#fbf6ee", accent="#d98b2b", accent_text="#2b1d05", glow=True)

# the interactive themes: a base palette plus a rule
INTERACTIVE = {
    "Your colour":          "Pick the accent; everything that uses it follows. Dark or light base.",
    "Follows health":       "The accent and the glow take the colour of the worst status on the network.",
    "Time of day":          "Light and warm in the morning, cool at midday, indigo in the evening, dark at night. Toner follows the clock.",
    "Follows organization": "The accent is the colour of the organization you are looking at, the same dot the switcher shows.",
}
SYSTEM = "System"
SYSTEM_NOTE = "Daylight or Midnight, following Windows."
GROUPS = [("Dark", ["Aurora", "Ember", "Harbor", "Moss", "Slate", "Dusk", "Carbon", "Nordic", "Plum", "Cocoa", "Steel", "Lagoon", "High contrast"]),
          ("Light", ["Linen", "Mist", "Sand", "Arctic", "Clay"]),
          ("Interactive", list(INTERACTIVE)),
          ("Classic", ["Midnight", "Daylight"])]
NAMES = [SYSTEM] + [n for _g, ns in GROUPS for n in ns]
DEFAULT_THEME = SYSTEM

LOOKS = ["Standard", "Soft", "Sharp", "Terminal"]
MOTIONS = ["Off", "Subtle", "Lively"]
PANELS = ["Bordered", "Flat", "Raised"]
CONTRASTS = ["Normal", "More", "Most"]
BASES = ["Dark", "Light"]
DEFAULT_LOOK = dict(theme=SYSTEM, look="Standard", motion="Subtle", panels="Bordered", contrast="Normal",
                    custom_accent="#38bdf8", custom_base="Dark", custom_tint=False)

# the status colours a theme card's chips are drawn with (the window itself follows Settings > Appearance > Status colours)
STATUS = {True: dict(OK="#34d399", WARN="#ffb020", FAIL="#fb7185", ERROR="#a99cff"),
          False: dict(OK="#047857", WARN="#b45309", FAIL="#be123c", ERROR="#6250d6")}
TIME_OF_DAY = {"morning": MORNING, "midday": "Mist", "evening": "Dusk", "night": "Harbor"}
GLOBAL_ORG_COLOUR = "#22d3ee"          # Follows organization while Global is picked: Midnight's cyan


def note(name):
    """The one-line description of a theme (the card's tooltip)."""
    if name == SYSTEM:
        return SYSTEM_NOTE
    if name in INTERACTIVE:
        return INTERACTIVE[name]
    return FIXED.get(name, {}).get("note", "")


def kind(name):
    """'dark', 'light', 'interactive' or 'follows Windows'."""
    if name == SYSTEM:
        return "follows Windows"
    if name in INTERACTIVE:
        return "interactive"
    return "dark" if FIXED.get(name, {}).get("dark") else "light"


def legacy_name(theme):
    """The theme a setting written before 1.12 means ("Dark", "Light"), or the name itself when it is a theme."""
    return {"Dark": "Midnight", "Light": "Daylight"}.get(theme, theme if theme in NAMES else SYSTEM)


# ---- colour maths (hex strings in, hex strings out)
def _rgb(h):
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _hex(r, g, b):
    return "#%02x%02x%02x" % (max(0, min(255, int(round(r)))), max(0, min(255, int(round(g)))), max(0, min(255, int(round(b)))))


def mix(a, b, m):
    """a moved m of the way (0..1) toward b."""
    (r1, g1, b1), (r2, g2, b2) = _rgb(a), _rgb(b)
    return _hex(r1 + (r2 - r1) * m, g1 + (g2 - g1) * m, b1 + (b2 - b1) * m)


def rgba(h, alpha):
    r, g, b = _rgb(h)
    return f"rgba({r},{g},{b},{alpha})"


def luminance(h):
    def f(x):
        x /= 255
        return x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4
    r, g, b = _rgb(h)
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def contrast(a, b):
    la, lb = sorted((luminance(a), luminance(b)))
    return (lb + 0.05) / (la + 0.05)


def text_on(accent):
    """Dark or white text on a filled button of this colour."""
    return "#0f1424" if luminance(accent) > 0.4 else "#ffffff"


def period(hour):
    return "morning" if hour < 11 else "midday" if hour < 17 else "evening" if hour < 21 else "night"


def _palette(name):
    return dict(FIXED[name])


def resolve(look, ctx=None):
    """The colours for a chosen look. look: {theme, look, panels, contrast, custom_accent, custom_base, custom_tint} (missing keys take
    DEFAULT_LOOK's). ctx: {system_dark, hour, worst, org_colour, status}; worst is the worst status on the network ('OK', 'WARN', 'FAIL',
    'ERROR' or None before any run), status maps a status to its ink colour (for Follows health), org_colour the organization's colour
    ('' for Global). Returns the token dict: the base colours, hover/scroll/icon/accent_hover filled in, dark, glow, aurora, name."""
    look = {**DEFAULT_LOOK, **(look or {})}
    ctx = {"system_dark": False, "hour": datetime.now().hour, "worst": None, "org_colour": "", "status": None, **(ctx or {})}
    name = look["theme"]
    if name == SYSTEM:
        p = _palette("Midnight" if ctx["system_dark"] else "Daylight")
    elif name == "Your colour":
        light = look.get("custom_base") == "Light"
        p = _palette("Daylight" if light else "Harbor")
        accent = str(look.get("custom_accent") or DEFAULT_LOOK["custom_accent"]).lower()
        p.update(accent=accent, accent_text=text_on(accent))
        p.pop("accent_hover", None)
        if look.get("custom_tint"):
            p.update(bg=mix(p["bg"], accent, 0.07), surface=mix(p["surface"], accent, 0.05), surface2=mix(p["surface2"], accent, 0.07),
                     border=mix(p["border"], accent, 0.12), glow=True)
            for k in ("hover", "scroll", "icon"):
                p.pop(k, None)
    elif name == "Follows health":
        p = _palette("Harbor")
        status = ctx["status"] or STATUS[True]
        worst = ctx["worst"] or "OK"
        hue = status.get("OK" if worst == "OK" else "WARN" if worst == "WARN" else "FAIL") or STATUS[True]["OK"]
        p.update(accent=hue, accent_text=text_on(hue), glow=True, bg=mix(p["bg"], hue, 0.05), surface=mix(p["surface"], hue, 0.04))
    elif name == "Time of day":
        pal = TIME_OF_DAY[period(int(ctx["hour"]))]
        p = dict(pal) if isinstance(pal, dict) else _palette(pal)
    elif name == "Follows organization":
        p = _palette("Harbor")
        colour = (ctx["org_colour"] or GLOBAL_ORG_COLOUR).lower()
        p.update(accent=colour, accent_text=text_on(colour), glow=True)
    else:
        p = _palette(name if name in FIXED else "Midnight")
    p.pop("note", None)
    dark = bool(p.get("dark"))
    lvl = {"More": 1, "Most": 2}.get(look.get("contrast"), 0)
    if lvl:
        p["muted"] = mix(p["muted"], p["text"], 0.4 * lvl)
        p["border"] = mix(p["border"], p["text"], 0.22 * lvl)
    if look.get("panels") == "Flat":
        p["border"] = mix(p["border"], p["bg"], 0.6)
        if dark:
            p["surface"] = mix(p["surface"], p["text"], 0.025)
    p.setdefault("hover", mix(p["surface"], p["text"], 0.08 if dark else 0.05))
    p.setdefault("scroll", mix(p["surface"], p["text"], 0.28 if dark else 0.22))
    p.setdefault("icon", mix(p["muted"], p["text"], 0.3) if dark else p["muted"])
    p.setdefault("accent_hover", mix(p["accent"], "#ffffff", 0.18) if dark else mix(p["accent"], "#000000", 0.12))
    p.update(dark=dark, glow=bool(p.get("glow")), aurora=bool(p.get("aurora")), name=name,
             look=look.get("look") or "Standard", panels=look.get("panels") or "Bordered", motion=look.get("motion") or "Subtle",
             contrast=look.get("contrast") or "Normal")
    return p


def uses(name):
    """Which parts of the context a theme reads, so it is only re-applied when one of them changed."""
    return {"System": ("system_dark",), "Follows health": ("worst",), "Time of day": ("period",), "Follows organization": ("org_colour",)}.get(name, ())
