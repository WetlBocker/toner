"""A Remote Desktop session inside a Toner tab.

It hosts the Remote Desktop control Windows itself ships (mstscax.dll, the client that mstsc.exe is built on), so the session stays inside the
Toner window and uses Windows' own sign-in: the control asks for the password when the connection starts, and Toner never sees or keeps it.
The pane offers what the terminal panes do (state_changed, connected(), connect_now(), disconnect_now(), shutdown()), so the Sessions
section treats it like any other tab."""
import time

from PySide6.QtCore import QSize, QTimer, Qt, Signal
from PySide6.QtNetwork import QAbstractSocket, QTcpSocket
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from core import audit, sessions

DISCONNECTED, CONNECTED, CONNECTING = 0, 1, 2             # the control's Connected property
POLL_MS = 400
PROBE_SECONDS = 6


class RdpUnavailable(Exception):
    """This computer has no Remote Desktop control that Toner can host."""


def make_control():
    """The Remote Desktop control, ready to sit in a layout."""
    try:
        from PySide6.QtAxContainer import QAxWidget
    except ImportError:
        raise RdpUnavailable("Qt's ActiveX support is not part of this copy of Toner.") from None
    from PySide6.QtGui import QGuiApplication
    if QGuiApplication.platformName() != "windows":                      # the control needs a real Windows window to live in
        raise RdpUnavailable(f"it needs Qt's Windows display, not '{QGuiApplication.platformName()}'.")
    ax = QAxWidget()
    if not ax.setControl(sessions.PROG_ID):
        raise RdpUnavailable("Windows' Remote Desktop control (mstscax.dll) could not be started.")
    return ax


class Stage(QWidget):
    """Holds the control. With an aspect ratio set, the control is the largest picture of that shape that fits, centred, so a
    fixed-size desktop is scaled up (or down) to the tab without being stretched. Without one, it fills the tab."""

    def __init__(self, control):
        super().__init__()
        self.control = control
        self.aspect = 0.0
        self.setStyleSheet("background: #1b1b1b;")
        control.setParent(self)
        self.setMinimumSize(320, 200)

    def set_aspect(self, w, h):
        self.aspect = (w / h) if (w and h) else 0.0
        self.relayout()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self.relayout()

    def relayout(self):
        W, H = self.width(), self.height()
        if self.aspect <= 0 or W <= 0 or H <= 0:
            self.control.setGeometry(0, 0, W, H)
            return
        w, h = (W, int(W / self.aspect)) if W / H < self.aspect else (int(H * self.aspect), H)
        self.control.setGeometry((W - w) // 2, (H - h) // 2, w, h)


class RdpPane(QWidget):
    state_changed = Signal(object)
    logs_changed = Signal()

    def __init__(self, spec, control=None):
        super().__init__()
        self.spec = spec
        self.ax = control if control is not None else make_control()
        self.up = False                                   # from the moment we start connecting until it has ended
        self._seen = False                                # the control has reported connecting or connected since we asked
        self._asked_at = 0.0
        self._was_connected = False
        self._probe = None
        self.status = QLabel("Not connected.")
        self.reconnect_btn, self.disconnect_btn = QPushButton("Reconnect"), QPushButton("Disconnect")
        self.reconnect_btn.setAutoDefault(False)
        self.disconnect_btn.setAutoDefault(False)
        self.fill = QCheckBox("Fill the window")
        self.fill.setToolTip("On: the remote desktop takes the size of this tab and follows it when the window changes. "
                             "Off: it keeps the session's own size and is scaled to fit the tab.")
        self.fill.setChecked(bool((spec.get("options") or {}).get("fullscreen", False)))
        self.stage = Stage(self.ax)
        bar = QHBoxLayout()
        bar.addWidget(self.status, 1)
        bar.addWidget(self.fill)
        bar.addWidget(self.reconnect_btn)
        bar.addWidget(self.disconnect_btn)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 6, 0, 0)
        lay.addLayout(bar)
        lay.addWidget(self.stage, 1)
        self.fill.toggled.connect(self._fill_toggled)
        self.reconnect_btn.clicked.connect(self.connect_now)
        self.disconnect_btn.clicked.connect(self.disconnect_now)
        self.timer = QTimer(self)
        self.timer.setInterval(POLL_MS)
        self.timer.timeout.connect(self._poll)
        self.resize_timer = QTimer(self)
        self.resize_timer.setSingleShot(True)
        self.resize_timer.setInterval(500)
        self.resize_timer.timeout.connect(self._resize_session)
        self._set_up(False)

    @property
    def kind(self):
        return "rdp"

    def apply_settings(self):
        """Nothing here follows Settings > Terminal."""

    def connected(self):
        return self.up

    def sizeHint(self):
        return QSize(900, 600)

    # ---------------------------------------------------------------- the control
    def _get(self, name):
        try:
            return self.ax.dynamicCall(name)
        except Exception:
            return None

    def _put(self, name, value):
        try:
            self.ax.dynamicCall(name, [value])
        except Exception:
            pass

    def _sub(self, *names):
        """A group of the control's settings (older versions of the control have fewer): the newest one that exists."""
        for n in names:
            try:
                obj = self.ax.querySubObject(n)
            except Exception:
                obj = None
            if obj is not None:
                return obj
        return None

    @staticmethod
    def _set(obj, name, value):
        if obj is not None:
            try:
                obj.setProperty(name, value)
            except Exception:
                pass

    def _state(self):
        try:
            return int(self._get("Connected") or 0)
        except (TypeError, ValueError):
            return 0

    def _room(self):
        """The room for the picture in the tab, in the pixels the remote desktop is measured in."""
        r = self.stage.devicePixelRatioF()
        return int(self.stage.width() * r), int(self.stage.height() * r)

    def _scale(self, fit):
        """The display's scale (150 on a 150% screen), in the steps Remote Desktop accepts, when the desktop is made to fill the tab; 100 otherwise
        (a fixed-size desktop is simply scaled to the tab as a picture)."""
        if not fit:
            return 100
        return max(100, min(500, int(round(self.stage.devicePixelRatioF() * 100 / 25.0)) * 25))

    def _apply(self):
        """Give the control the session's settings (everything but the password, which Windows asks for)."""
        spec = {**self.spec, "options": {**(self.spec.get("options") or {}), "fullscreen": self.fill.isChecked()}}
        w, h = self._room()
        s = sessions.rdp_settings(spec, w, h)
        s["scale"] = self._scale(s["fit"])
        self._cfg = s
        self.stage.set_aspect(0 if s["fit"] else s["width"], s["height"])
        self._put("Server", s["server"])
        self._put("UserName", s["username"])
        self._put("Domain", s["domain"])
        self._put("DesktopWidth", s["width"])
        self._put("DesktopHeight", s["height"])
        self._put("ColorDepth", 32)
        adv = self._sub("AdvancedSettings9", "AdvancedSettings8", "AdvancedSettings7", "AdvancedSettings6", "AdvancedSettings5", "AdvancedSettings2")
        for name, value in (("RDPPort", s["port"]), ("DesktopScaleFactor", s["scale"]), ("DeviceScaleFactor", 100), ("EnableCredSspSupport", True), ("AuthenticationLevel", 2), ("SmartSizing", True),
                            ("RedirectClipboard", s["clipboard"]), ("RedirectDrives", s["drives"]), ("RedirectPrinters", s["printers"]),
                            ("ConnectToAdministerServer", s["admin"]), ("ConnectToServerConsole", s["admin"]),
                            ("DisplayConnectionBar", False), ("PinConnectionBar", False), ("GrabFocusOnConnect", True)):
            self._set(adv, name, value)
        if s["gateway"]:
            gw = self._sub("TransportSettings3", "TransportSettings2", "TransportSettings")
            for name, value in (("GatewayHostname", s["gateway"]), ("GatewayUsageMethod", 1), ("GatewayProfileUsageMethod", 1), ("GatewayCredsSource", 4)):
                self._set(gw, name, value)

    # ---------------------------------------------------------------- connecting
    def _set_up(self, on):
        self.up = on
        self.reconnect_btn.setEnabled(not on)
        self.disconnect_btn.setEnabled(on)
        self.state_changed.emit(self)

    def connect_now(self):
        if self.up:
            return
        sp = self.spec
        self._was_connected = self._seen = False
        self._set_up(True)
        self.status.setText(f"Connecting to {sp['host']}:{sp['port']}...")
        audit.log("session opened", f"rdp {sp['name']} ({sp['host']})")
        self._begin_probe()

    def _begin_probe(self):
        """A quick look first, so a wrong address or a closed port is said in words (the control only reports that it did not connect)."""
        sp = self.spec
        self._probe = QTcpSocket(self)
        self._probe.connected.connect(self._reachable)
        self._probe.errorOccurred.connect(self._unreachable)
        self._probe_timer = QTimer(self)
        self._probe_timer.setSingleShot(True)
        self._probe_timer.timeout.connect(lambda: self._unreachable(None))
        self._probe_timer.start(PROBE_SECONDS * 1000)
        self._probe.connectToHost(sp["host"], int(sp["port"]))

    def _end_probe(self):
        if self._probe is not None:
            self._probe_timer.stop()
            self._probe.blockSignals(True)
            self._probe.abort()
            self._probe.deleteLater()
            self._probe = None

    def _reachable(self):
        if self._probe is None:
            return
        self._end_probe()
        self._start_control()

    def _unreachable(self, _err):
        if self._probe is None:
            return
        sp = self.spec
        why = self._probe.errorString() if self._probe.error() != QAbstractSocket.SocketError.UnknownSocketError else f"no answer in {PROBE_SECONDS} seconds"
        self._end_probe()
        self.status.setText(f"Could not reach {sp['host']}:{sp['port']} ({why}). Check the address, that Remote Desktop is turned on there, and the firewall.")
        self._set_up(False)

    def _start_control(self):
        self._apply()
        self._asked_at = time.monotonic()
        self.status.setText(f"Connecting to {self.spec['host']}...  (Windows asks for the password if it needs one)")
        try:
            self.ax.dynamicCall("Connect()")
        except Exception as e:
            self.status.setText(f"Remote Desktop could not start: {e}")
            self._set_up(False)
            return
        self.timer.start()
        self.ax.setFocus()

    def disconnect_now(self):
        if not self.up:
            return
        if self._probe is not None:
            self._end_probe()
            self.status.setText("Not connected.")
            self._set_up(False)
            return
        self.disconnect_btn.setEnabled(False)
        self.status.setText("Disconnecting...")
        try:
            self.ax.dynamicCall("Disconnect()")
        except Exception:
            pass

    def _poll(self):
        st = self._state()
        sp = self.spec
        if st in (CONNECTING, CONNECTED):
            self._seen = True
        if st == CONNECTED and not self._was_connected:
            self._was_connected = True
            self.status.setText(f"Connected to {sp['host']}.  Click the picture to type into it, and click another tab to leave it.")
            self.state_changed.emit(self)
            self.resize_timer.start()
        elif st == DISCONNECTED and (self._seen or time.monotonic() - self._asked_at > 8):
            self.timer.stop()
            if self._was_connected:
                self.status.setText(f"Disconnected from {sp['host']}.")
            else:
                self.status.setText(f"The connection to {sp['host']} was not made. Check the user name and password, that the account may use "
                                    "Remote Desktop, and the server's 'network level authentication' setting.")
            self._set_up(False)

    # ---------------------------------------------------------------- the picture follows the tab
    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self._was_connected and getattr(self, "_cfg", {}).get("fit"):
            self.resize_timer.start()

    def _resize_session(self):
        """Ask the server for a desktop the size of the tab, when the tab is set to fill the window (a server that cannot just has its picture scaled)."""
        if not (self._was_connected and getattr(self, "_cfg", {}).get("fit")):
            return
        w, h = self._room()
        self._send_size(max(320, w), max(240, h), self._scale(True))      # the screen may have changed since connecting

    def _send_size(self, w, h, scale=100):
        try:
            self.ax.dynamicCall("UpdateSessionDisplaySettings(uint,uint,uint,uint,uint,uint,uint)", [w, h, 0, 0, 0, scale, 100])
        except Exception:
            pass

    def _fill_toggled(self, on):
        """Switch this tab between filling the window and keeping the session's own size, while connected or not."""
        if not getattr(self, "_cfg", None):
            return
        spec = {**self.spec, "options": {**(self.spec.get("options") or {}), "fullscreen": on}}
        w, h = self._room()
        s = sessions.rdp_settings(spec, w, h)
        s["scale"] = self._scale(s["fit"])
        self._cfg = s
        self.stage.set_aspect(0 if s["fit"] else s["width"], s["height"])
        if self._was_connected:
            self._send_size(s["width"], s["height"], s["scale"])

    def shutdown(self):
        self.timer.stop()
        self.resize_timer.stop()
        self._end_probe()
        if self._state() != DISCONNECTED:
            try:
                self.ax.dynamicCall("Disconnect()")
            except Exception:
                pass
            deadline = time.monotonic() + 1.5               # give the control a moment to say goodbye before it is destroyed
            while self._state() != DISCONNECTED and time.monotonic() < deadline:
                time.sleep(0.05)
        self.up = False
