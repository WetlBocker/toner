"""Toner theme tokens: the Midnight (dark) and Daylight (light) palettes from the 4C plug icon.
Inputs use the page colour, as in Demarc.

Drop-in for ui/theme.py. Keys match what theme.tokens() builds, so the stylesheet and palette code need no change.
See README.md for the three small edits to ui/theme.py.
"""

TONER_ACCENT = ("#0e7490", "#22d3ee")          # (light-mode, dark-mode): teal on Daylight, cyan on Midnight

# Standard style. accent_hover, accent_soft and select are still computed by theme.tokens() from the accent.
STANDARD = {
    False: dict(   # Daylight
        bg="#f3f6f9", surface="#ffffff", surface2="#e6edf3", border="#cbd6e0",
        text="#0b1b2b", muted="#4a5b6c", hover="#eaf0f5", input="#f3f6f9",
        scroll="#b4c2cf", icon="#4a5b6c", accent_text="#ffffff", accent_hover="#0b5f74",
    ),
    True: dict(    # Midnight
        bg="#081420", surface="#0b1b2b", surface2="#12283d", border="#223a52",
        text="#f4f8fb", muted="#9fb3c6", hover="#163149", input="#081420",
        scroll="#2f4a63", icon="#b6c8d8", accent_text="#0b1b2b", accent_hover="#67e8f9",
    ),
}

# Ops console style: the same hues, deeper and flatter.
OPS = {
    False: dict(
        bg="#e8eef3", surface="#ffffff", surface2="#f0f4f8", border="#c7d3de",
        text="#0b1b2b", muted="#4a5b6c", hover="#e3eaf0", input="#e8eef3", scroll="#b4c2cf",
    ),
    True: dict(
        bg="#050e17", surface="#08141f", surface2="#0d1d2c", border="#1a3044",
        text="#dce6ee", muted="#8ca3b8", hover="#102538", input="#050e17", scroll="#26425b", icon="#b3c5d5",
    ),
}

# Status colours. The names and meanings are unchanged (OK, WARN, FAIL, ERROR); only the values move to the new palette.
# Always shown with an icon or the status name, never colour alone.
STATUS = {
    False: dict(ok="#047857", warn="#b45309", fail="#be123c", error="#6250d6"),
    True: dict(ok="#34d399", warn="#ffb020", fail="#fb7185", error="#a99cff"),
}


def overrides(dark, ops=False):
    """The Toner palette for one mode, to be applied over the dict built in theme.tokens()."""
    t = dict(STANDARD[bool(dark)])
    if ops:
        t.update(OPS[bool(dark)])
    return t
