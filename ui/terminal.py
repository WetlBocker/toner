"""A terminal emulator widget: pyte keeps the screen state, this widget draws it and handles input."""
import re

import pyte
from PySide6.QtCore import QEvent, QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontDatabase, QFontMetricsF, QGuiApplication, QPainter, QPen
from PySide6.QtWidgets import QMenu, QWidget

SCHEMES = {
    "Dark": {"bg": "#1e1e1e", "fg": "#d4d4d4", "colors": {
        "black": "#000000", "red": "#cd3131", "green": "#0dbc79", "brown": "#e5e510", "yellow": "#e5e510",
        "blue": "#2472c8", "magenta": "#bc3fbc", "cyan": "#11a8cd", "white": "#e5e5e5",
        "brightblack": "#666666", "brightred": "#f14c4c", "brightgreen": "#23d18b",
        "brightbrown": "#f5f543", "brightyellow": "#f5f543", "brightblue": "#3b8eea",
        "brightmagenta": "#d670d6", "brightcyan": "#29b8db", "brightwhite": "#ffffff"}},
    "Light": {"bg": "#ffffff", "fg": "#1e1e1e", "colors": {
        "black": "#000000", "red": "#b3261e", "green": "#1b7f3b", "brown": "#8a6d00", "yellow": "#8a6d00",
        "blue": "#1a56b0", "magenta": "#8e2a8e", "cyan": "#0b7a8c", "white": "#555555",
        "brightblack": "#666666", "brightred": "#d33a30", "brightgreen": "#2e9e4f",
        "brightbrown": "#a07900", "brightyellow": "#a07900", "brightblue": "#2f6fd0",
        "brightmagenta": "#aa44aa", "brightcyan": "#1496aa", "brightwhite": "#333333"}},
}
_HEX = re.compile(r"^[0-9a-fA-F]{6}$")

# Sequences that switch modes pyte does not implement. We act on them ourselves.
ALT_ON = (b"\x1b[?1049h", b"\x1b[?1047h", b"\x1b[?47h")
ALT_OFF = (b"\x1b[?1049l", b"\x1b[?1047l", b"\x1b[?47l")
APP_ON, APP_OFF = b"\x1b[?1h", b"\x1b[?1l"
MARKERS = ALT_ON + ALT_OFF + (APP_ON, APP_OFF)
_MARKER_RE = re.compile(b"|".join(re.escape(m) for m in MARKERS))

KEYS = {
    Qt.Key.Key_Return: b"\r", Qt.Key.Key_Enter: b"\r", Qt.Key.Key_Backspace: b"\x7f",
    Qt.Key.Key_Tab: b"\t", Qt.Key.Key_Escape: b"\x1b", Qt.Key.Key_Delete: b"\x1b[3~",
    Qt.Key.Key_Insert: b"\x1b[2~", Qt.Key.Key_PageUp: b"\x1b[5~", Qt.Key.Key_PageDown: b"\x1b[6~",
    Qt.Key.Key_F1: b"\x1bOP", Qt.Key.Key_F2: b"\x1bOQ", Qt.Key.Key_F3: b"\x1bOR", Qt.Key.Key_F4: b"\x1bOS",
    Qt.Key.Key_F5: b"\x1b[15~", Qt.Key.Key_F6: b"\x1b[17~", Qt.Key.Key_F7: b"\x1b[18~",
    Qt.Key.Key_F8: b"\x1b[19~", Qt.Key.Key_F9: b"\x1b[20~", Qt.Key.Key_F10: b"\x1b[21~",
    Qt.Key.Key_F11: b"\x1b[23~", Qt.Key.Key_F12: b"\x1b[24~",
}
ARROWS = {Qt.Key.Key_Up: b"A", Qt.Key.Key_Down: b"B", Qt.Key.Key_Right: b"C", Qt.Key.Key_Left: b"D",
          Qt.Key.Key_Home: b"H", Qt.Key.Key_End: b"F"}


class _Screen(pyte.HistoryScreen):
    """HistoryScreen that forwards the terminal's replies (cursor position reports etc.)."""
    reply = None

    def write_process_input(self, data):
        if self.reply:
            self.reply(data.encode())

    def resize(self, lines=None, columns=None):
        """Shrink like a real terminal: drop blank rows below the cursor, push the rest into scrollback.
        (pyte's own resize deletes rows from the top, which throws away the session.)"""
        lines = lines or self.lines
        if lines < self.lines:
            excess = self.lines - lines
            free, y = 0, self.lines - 1
            while free < excess and y > self.cursor.y and all(c.data.strip() == "" for c in self.buffer[y].values()):
                free += 1
                y -= 1
            push = excess - free
            if push:
                for row in range(push):
                    self.history.top.append(self.buffer[row])
                kept = {row - push: self.buffer[row] for row in range(push, self.lines)}
                self.buffer.clear()
                self.buffer.update(kept)
                self.cursor.y = max(0, self.cursor.y - push)
            self.lines = lines
        super().resize(lines, columns)


class TerminalView(QWidget):
    data_out = Signal(bytes)          # keystrokes to send to the remote side
    resized = Signal(int, int)        # (columns, rows)

    def __init__(self, cols=100, rows=30):
        super().__init__()
        self.cols, self.rows = cols, rows
        self.scroll = 0               # lines scrolled back from the live view
        self.sel = None               # ((line, col), (line, col)) in absolute line numbers
        self.app_cursor = False
        self.carry = b""
        self.scrollback = 5000
        self.bg, self.fg, self.pal = QColor("#1e1e1e"), QColor("#d4d4d4"), SCHEMES["Dark"]["colors"]
        self._make_screens()
        self.configure()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_InputMethodEnabled, False)
        self.setCursor(Qt.CursorShape.IBeamCursor)
        self.setMinimumSize(int(self.cw * 40), int(self.ch * 8))

    def configure(self, family="Consolas", size=10, scheme="Dark", scrollback=5000):
        """Apply font and colours now; the scrollback length applies from the next session."""
        font = QFont(family, size)
        font.setStyleHint(QFont.StyleHint.Monospace)
        if family not in QFontDatabase.families():
            font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
            font.setPointSize(size)
        self.setFont(font)
        self._metrics()
        sch = SCHEMES.get(scheme, SCHEMES["Dark"])
        self.bg, self.fg, self.pal = QColor(sch["bg"]), QColor(sch["fg"]), sch["colors"]
        self.scrollback = max(100, int(scrollback))
        self.setMinimumSize(int(self.cw * 40), int(self.ch * 8))
        self.resizeEvent(None)               # new cell size -> new grid size
        self.update()

    # ---------- screen state ----------
    def _make_screens(self):
        self.main = _Screen(self.cols, self.rows, history=self.scrollback)
        self.alt = _Screen(self.cols, self.rows, history=0)
        for s in (self.main, self.alt):
            s.reply = self.data_out.emit
        self.main_stream, self.alt_stream = pyte.ByteStream(self.main), pyte.ByteStream(self.alt)
        self.use_alt = False

    @property
    def screen(self):
        return self.alt if self.use_alt else self.main

    @property
    def stream(self):
        return self.alt_stream if self.use_alt else self.main_stream

    def reset(self):
        self.carry = b""
        self.scroll, self.sel, self.app_cursor = 0, None, False
        self._make_screens()
        self.update()

    def feed(self, data: bytes):
        data = self.carry + data
        self.carry = b""
        # hold back a trailing, incomplete mode-switch sequence until the rest arrives
        for n in range(min(len(data), 8), 0, -1):
            tail = data[-n:]
            if tail[:1] == b"\x1b" and any(m.startswith(tail) and m != tail for m in MARKERS):
                self.carry, data = tail, data[:-n]
                break
        pos = 0
        for m in _MARKER_RE.finditer(data):
            self.stream.feed(data[pos:m.start()])
            pos = m.end()
            seq = m.group()
            if seq in ALT_ON:
                self.use_alt = True
                self.alt.reset()
                self.scroll = 0
            elif seq in ALT_OFF:
                self.use_alt = False
            else:
                self.app_cursor = seq == APP_ON
        self.stream.feed(data[pos:])
        if self.scroll:
            self.scroll = min(self.scroll, len(self.main.history.top))
        self.update()

    # ---------- geometry ----------
    def _metrics(self):
        fm = QFontMetricsF(self.font())
        self.cw, self.ch, self.ascent = fm.horizontalAdvance("M"), fm.height(), fm.ascent()

    def resizeEvent(self, e):
        cols, rows = max(20, int(self.width() // self.cw)), max(5, int(self.height() // self.ch))
        if (cols, rows) != (self.cols, self.rows):
            self.cols, self.rows = cols, rows
            self.main.resize(rows, cols)
            self.alt.resize(rows, cols)
            self.resized.emit(cols, rows)
        if e is not None:                    # configure() calls this directly with no event
            super().resizeEvent(e)

    # ---------- drawing ----------
    def _color(self, name, default):
        if not name or name == "default":
            return default
        if name in self.pal:
            return QColor(self.pal[name])
        if _HEX.match(name):
            return QColor("#" + name)
        return default

    def _line(self, idx):
        """Line `idx` of the combined history + screen, as a {col: Char} mapping."""
        hist = self.main.history.top if not self.use_alt else ()
        if idx < len(hist):
            return hist[idx]
        return self.screen.buffer[idx - len(hist)]

    def _first_visible(self):
        hist = 0 if self.use_alt else len(self.main.history.top)
        return hist - self.scroll

    def paintEvent(self, _):
        p = QPainter(self)
        p.fillRect(self.rect(), self.bg)
        p.setFont(self.font())
        first = self._first_visible()
        sel = self._sel_range()
        for row in range(self.rows):
            idx = first + row
            line = self._line(idx)
            y = row * self.ch
            col = 0
            while col < self.cols:
                c = line[col]
                key = (c.fg, c.bg, c.bold, c.reverse, c.underscore, c.strikethrough)
                end = col + 1
                while end < self.cols and (line[end].fg, line[end].bg, line[end].bold, line[end].reverse,
                                           line[end].underscore, line[end].strikethrough) == key:
                    end += 1
                fg, bg = self._color(c.fg, self.fg), self._color(c.bg, self.bg)
                if c.reverse:
                    fg, bg = bg, fg
                rect = QRectF(col * self.cw, y, (end - col) * self.cw, self.ch)
                if bg != self.bg:
                    p.fillRect(rect, bg)
                text = "".join(line[i].data or " " for i in range(col, end))
                if text.strip():
                    f = QFont(self.font())
                    f.setBold(bool(c.bold))
                    f.setUnderline(bool(c.underscore))
                    f.setStrikeOut(bool(c.strikethrough))
                    p.setFont(f)
                    p.setPen(fg)
                    p.drawText(QPointF(rect.left(), y + self.ascent), text)
                col = end
            if sel and sel[0][0] <= idx <= sel[1][0]:
                c0 = sel[0][1] if idx == sel[0][0] else 0
                c1 = sel[1][1] if idx == sel[1][0] else self.cols - 1
                p.fillRect(QRectF(c0 * self.cw, y, (c1 - c0 + 1) * self.cw, self.ch), QColor(120, 160, 255, 90))
        cur = self.screen.cursor
        if not self.scroll and not cur.hidden and 0 <= cur.y < self.rows:
            r = QRectF(cur.x * self.cw, cur.y * self.ch, self.cw, self.ch)
            if self.hasFocus():
                cur_col = QColor(self.fg)
                cur_col.setAlpha(170)
                p.fillRect(r, cur_col)
            else:
                p.setPen(QPen(self.fg))
                p.drawRect(r.adjusted(0, 0, -1, -1))

    # ---------- selection / clipboard ----------
    def _cell(self, pos):
        col = min(max(int(pos.x() // self.cw), 0), self.cols - 1)
        row = min(max(int(pos.y() // self.ch), 0), self.rows - 1)
        return self._first_visible() + row, col

    def _sel_range(self):
        if not self.sel or self.sel[0] == self.sel[1]:
            return None
        a, b = sorted(self.sel)
        return a, b

    def selected_text(self):
        rng = self._sel_range()
        if not rng:
            return ""
        (l0, c0), (l1, c1) = rng
        out = []
        for idx in range(l0, l1 + 1):
            line = self._line(idx)
            a = c0 if idx == l0 else 0
            b = c1 if idx == l1 else self.cols - 1
            out.append("".join(line[i].data or " " for i in range(a, b + 1)).rstrip())
        return "\n".join(out)

    def copy(self):
        t = self.selected_text()
        if t:
            QGuiApplication.clipboard().setText(t)

    def paste(self):
        t = QGuiApplication.clipboard().text()
        if t:
            self.data_out.emit(t.replace("\r\n", "\r").replace("\n", "\r").encode())

    def mousePressEvent(self, e):
        self.setFocus()
        if e.button() == Qt.MouseButton.LeftButton:
            self.sel = (self._cell(e.position()), self._cell(e.position()))
            self.update()

    def mouseMoveEvent(self, e):
        if self.sel and e.buttons() & Qt.MouseButton.LeftButton:
            self.sel = (self.sel[0], self._cell(e.position()))
            self.update()

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.MiddleButton:
            self.paste()

    def contextMenuEvent(self, e):
        m = QMenu(self)
        m.addAction("Copy", self.copy).setEnabled(bool(self.selected_text()))
        m.addAction("Paste", self.paste)
        m.addAction("Clear scrollback", lambda: (self.main.history.top.clear(), setattr(self, "scroll", 0), self.update()))
        m.exec(e.globalPos())

    def wheelEvent(self, e):
        if self.use_alt:
            return
        step = 3 if e.angleDelta().y() > 0 else -3
        self.scroll = min(max(self.scroll + step, 0), len(self.main.history.top))
        self.update()

    # ---------- keyboard ----------
    def focusNextPrevChild(self, _next):
        return False                          # Tab belongs to the remote shell

    def focusInEvent(self, e):
        self.update()
        super().focusInEvent(e)

    def focusOutEvent(self, e):
        self.update()
        super().focusOutEvent(e)

    def event(self, e):
        if e.type() == QEvent.Type.ShortcutOverride and self.for_shell(e):
            e.accept()                        # a key for the device, ahead of the window's shortcuts (Ctrl+K, Ctrl+B ...)
            return True
        return super().event(e)

    @staticmethod
    def for_shell(e):
        """Is this a key the terminal sends to the device? Ctrl+1 to Ctrl+9 stay with the window, to change page."""
        key, ctrl = e.key(), bool(e.modifiers() & Qt.KeyboardModifier.ControlModifier)
        if ctrl and Qt.Key.Key_0 <= key <= Qt.Key.Key_9:
            return False
        return (key in KEYS or key in ARROWS or (ctrl and (Qt.Key.Key_A <= key <= Qt.Key.Key_Z or key == Qt.Key.Key_BracketLeft))
                or bool(e.text()))

    def keyPressEvent(self, e):
        key, mods = e.key(), e.modifiers()
        ctrl, shift = bool(mods & Qt.KeyboardModifier.ControlModifier), bool(mods & Qt.KeyboardModifier.ShiftModifier)
        alt = bool(mods & Qt.KeyboardModifier.AltModifier)
        if ctrl and shift and key == Qt.Key.Key_C:
            return self.copy()
        if ctrl and shift and key == Qt.Key.Key_V:
            return self.paste()
        if shift and key in (Qt.Key.Key_PageUp, Qt.Key.Key_PageDown):
            page = self.rows - 1
            self.scroll = min(max(self.scroll + (page if key == Qt.Key.Key_PageUp else -page), 0),
                              len(self.main.history.top))
            return self.update()
        if key in ARROWS:
            prefix = b"\x1bO" if self.app_cursor else b"\x1b["
            data = prefix + ARROWS[key]
            if ctrl:
                data = b"\x1b[1;5" + ARROWS[key]
        elif key in KEYS:
            data = KEYS[key]
        elif ctrl and Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
            data = bytes([key - Qt.Key.Key_A + 1])
        elif ctrl and key == Qt.Key.Key_BracketLeft:
            data = b"\x1b"
        elif e.text():
            data = e.text().encode()
        else:
            return super().keyPressEvent(e)
        if alt and not ctrl:
            data = b"\x1b" + data
        if self.scroll:                       # typing jumps back to the live view
            self.scroll = 0
            self.update()
        self.sel = None
        self.data_out.emit(data)
