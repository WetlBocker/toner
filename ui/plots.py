"""Graphs drawn with pyqtgraph, in the Toner theme: what every graph shares (its colours, and none of pyqtgraph's own menus or
buttons, whose words are not Toner's)."""
import pyqtgraph as pg
from PySide6.QtGui import QColor

from ui import theme


def colours():
    """The theme's colours a graph uses: surface, border, muted, text, accent (QColors)."""
    tk = theme.current() or {}
    col = lambda k, d: QColor(tk.get(k, d))
    return (col("surface", "#ffffff"), col("border", "#dddddd"), col("muted", "#777777"), col("text", "#222222"),
            col("accent", "#0e7490"))


def plot_widget(**kw):
    """A pyqtgraph PlotWidget without its own menu and "A" (auto-range) button."""
    w = pg.PlotWidget(**kw)
    w.setMenuEnabled(False)
    w.hideButtons()
    return w


def restyle(plot):
    """Paint a plot in the current theme: its background and its axes."""
    surface, border, muted, _text, _accent = colours()
    plot.setBackground(surface)
    for name in ("left", "bottom"):
        ax = plot.getAxis(name)
        ax.setPen(pg.mkPen(border))
        ax.setTextPen(pg.mkPen(muted))
    return surface, border, muted


def card_style(widget, name):
    """The rounded card a graph sits on (the widget's objectName is `name`)."""
    surface, border, _m, _t, _a = colours()
    widget.setObjectName(name)
    widget.setStyleSheet(f"QFrame#{name} {{ background: {surface.name()}; border: 1px solid {border.name()}; border-radius: 10px; }}")
