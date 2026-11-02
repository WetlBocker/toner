"""A chart drawn by ECharts on a web page inside a Qt widget (QtWebEngine), in Toner's theme.

Use it with a builder from ui.chartspec: `view.draw(lambda p: chartspec.donut(p, counts))`. The builder gets the current
palette (theme tokens and status colours) and is called again on `restyle()`, so a theme change recolours every chart. A
click on a bar or a slice arrives as `clicked(dict)` (what the page reported: name, value, series, and the `extra` the
builder attached). `to_png(path, done)` saves the picture at 2x for reports.

QtWebEngine is a large, optional piece: when it cannot be imported (a copy built without it, or a Linux without its
libraries) the widget shows a line saying so and the rest of the page works as before. `available()` says which.
Nothing here is reached by cli.py, so the headless service never loads it."""
import json
import os

from PySide6.QtCore import QObject, Qt, QUrl, Signal, Slot, QTimer
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from core import paths, quiet
from ui import chartspec, status as st, theme

_WEB = None                           # (QWebEngineView, QWebEnginePage, QWebChannel) once imported, False when it cannot be


def available():
    """True when QtWebEngine can be used in this copy."""
    return _web() is not False


def _web():
    global _WEB
    if _WEB is None:
        try:
            from PySide6.QtWebEngineWidgets import QWebEngineView
            from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings
            from PySide6.QtWebChannel import QWebChannel
            _WEB = (QWebEngineView, QWebEnginePage, QWebEngineSettings, QWebChannel)
        except Exception:             # not installed, or its libraries are missing on this computer
            quiet.ignored("QtWebEngine is not available: charts show a note instead")
            _WEB = False
    return _WEB


def page_path():
    """assets/chart.html, beside the program (PyInstaller copies the assets folder next to the code)."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for base in (here, paths.app_dir(), os.path.join(paths.app_dir(), "_internal")):
        p = os.path.join(base, "assets", "chart.html")
        if os.path.exists(p):
            return p
    return os.path.join(here, "assets", "chart.html")


def palette():
    """ui.chartspec's palette for the theme in use: its tokens, and the status inks that read against its surface."""
    tokens = theme.current() or {}
    inks = {s: st.ink(s) for s in ("OK", "WARN", "FAIL", "ERROR")}
    inks["N/A"] = st.GREY
    return chartspec.palette(tokens, inks)


class _Bridge(QObject):
    """What the page can call over the web channel: clicked(json) for a click on the chart, ready() when its channel is up.
    The Python side listens to `chart_clicked` and `channel_ready`."""
    chart_clicked = Signal(dict)
    channel_ready = Signal()

    @Slot(str)
    def clicked(self, payload):
        try:
            self.chart_clicked.emit(json.loads(payload))
        except Exception:
            quiet.ignored()

    @Slot()
    def ready(self):
        self.channel_ready.emit()


class ChartView(QWidget):
    clicked = Signal(dict)

    def __init__(self, min_height=220, parent=None):
        super().__init__(parent)
        self._builder = None
        self._loaded = False
        self._view = None
        self.setMinimumHeight(min_height)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        web = _web()
        if not web:
            self.note = QLabel("Charts need QtWebEngine, which this copy of Toner does not have.")
            self.note.setProperty("muted", True)
            self.note.setWordWrap(True)
            self.note.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(self.note)
            return
        QWebEngineView, QWebEnginePage, QWebEngineSettings, QWebChannel = web
        self._view = QWebEngineView(self)
        self._view.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self._view.setAccessibleName("Chart")
        page = self._view.page()
        page.setBackgroundColor(Qt.GlobalColor.transparent)
        s = page.settings()
        s.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, True)
        s.setAttribute(QWebEngineSettings.WebAttribute.ShowScrollBars, False)
        self._bridge = _Bridge(self)
        self._bridge.chart_clicked.connect(self.clicked)
        self._channel = QWebChannel(page)
        self._channel.registerObject("bridge", self._bridge)
        page.setWebChannel(self._channel)
        self._view.loadFinished.connect(self._on_loaded)
        lay.addWidget(self._view)
        self._view.setUrl(QUrl.fromLocalFile(page_path()))

    # ---- what to show
    def draw(self, builder):
        """`builder(palette) -> option dict` (see ui.chartspec). Kept, so restyle() can draw it again in new colours."""
        self._builder = builder
        self._push()

    def clear(self, text=""):
        self.draw(lambda p: chartspec.empty(text))

    def restyle(self):
        self._push(theme_too=True)

    def to_png(self, path, done=None):
        """Save the chart as a PNG (2x). `done(ok)` is called afterwards; without QtWebEngine it is called with False."""
        if self._view is None or not self._loaded:
            if done:
                done(False)
            return

        def got(data_url):
            ok = False
            try:
                if data_url and "," in data_url:
                    import base64
                    with open(path, "wb") as f:
                        f.write(base64.b64decode(data_url.split(",", 1)[1]))
                    ok = True
            except Exception:
                quiet.ignored()
            if done:
                done(ok)
        self._view.page().runJavaScript("toner.dataURL()", got)

    # ---- plumbing
    def _on_loaded(self, ok):
        self._loaded = bool(ok)
        if ok:
            self._push(theme_too=True)

    def _push(self, theme_too=False):
        if self._view is None or not self._loaded:
            return
        p = palette()
        js = ""
        if theme_too:
            js += "toner.setTheme(%s);" % json.dumps({"muted": p["muted"], "background": "transparent", "surface": p["surface"]})
        if self._builder is not None:
            try:
                opt = self._builder(p)
            except Exception as e:            # a chart that cannot be built must not take the page down
                quiet.ignored("chart builder failed")
                opt = chartspec.empty(f"This chart could not be drawn: {e}")
            js += "toner.setOption(%s);" % json.dumps(opt, default=str)
        if js:
            self._view.page().runJavaScript(js)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self._view is not None and self._loaded:
            QTimer.singleShot(0, lambda: self._view.page().runJavaScript("toner.resize()"))


def prepare_application():
    """Call before the QApplication is made: QtWebEngine wants to share OpenGL contexts between its views and the window.
    Harmless when QtWebEngine is missing or never used."""
    from PySide6.QtCore import QCoreApplication
    try:
        QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)
    except Exception:
        quiet.ignored()
