"""The Assistant in the window: the round side button, the panel that slides out beside the page, and the Automation/AI > Assistant
page that shows what it has cost and lists the conversations. The work is in core/assistant; this is the furniture."""
import threading

from PySide6.QtCore import QEvent, QPoint, QSize, Qt, QThread, Signal
from PySide6.QtGui import QFont, QTextCursor, QTextDocumentFragment
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QPushButton, QSizePolicy, QTableWidget,
                               QTableWidgetItem, QTextEdit, QToolButton, QVBoxLayout, QWidget)

from core import db, orgs
from core import assistant as AI
from core.assistant import agent, store, tools as T
from ui import brandicons, theme
from ui.widgets import EmptyHint, filling, flow

BUTTON = 44                     # the round button's size
PANEL_WIDTH = 420               # the panel's width the first time it opens
MIN_WIDTH = 320                 # narrower than this and the buttons would not fit on one row
PLACEHOLDER = "Ask about what is on screen, or anything in this organization"


def fmt_tokens(n):
    return f"{int(n or 0):,}"


def usage_line(tokens_in, tokens_out, cost, priced=True):
    """The line under each answer: '1,234 tokens in, 567 out · USD 0.02' (or 'no price known' for a model not in the table)."""
    money = f"USD {cost:.2f}" if cost >= 0.005 else f"USD {cost:.4f}" if cost else "USD 0"
    return f"{fmt_tokens(tokens_in)} tokens in, {fmt_tokens(tokens_out)} out  ·  " + (money if priced else "no price known for this model")


class Worker(QThread):
    event = Signal(str, object)

    def __init__(self, conv_id, org, question, screen):
        super().__init__()
        self.conv_id, self.org, self.question, self.screen = conv_id, org, question, screen
        self.cancel = threading.Event()

    def run(self):
        agent.run_turn(self.conv_id, self.org, self.question, self.screen, lambda kind, payload: self.event.emit(kind, payload), self.cancel)


def button_place():
    """Where the button sits: ('left' or 'right', how far down the window as 0..1), from the setting, kept sane."""
    raw = db.get_setting("assistant_button") or {}
    side = "left" if raw.get("side") == "left" else "right"
    try:
        y = min(1.0, max(0.0, float(raw.get("y", 0.5))))
    except (TypeError, ValueError):
        y = 0.5
    return side, y


class SideButton(QToolButton):
    """The round button at a side edge of the window, carrying the connected provider's mark. A click opens the panel; a drag
    moves it, and on release it snaps to the nearest side edge at the height it was dropped (remembered per computer)."""
    moved = Signal(str, float)                      # the side it snapped to, and how far down the window (0..1)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._press = self._start = None
        self._dragging = False
        self.setFixedSize(BUTTON, BUTTON)
        self.setIconSize(QSize(24, 24))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("Assistant")
        self.setCheckable(True)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.set_provider(AI.provider_id())
        self.restyle()

    def set_provider(self, provider):
        self.provider = provider
        self.setIconSize(QSize(*brandicons.mark_size(provider, BUTTON)))
        self.setIcon(brandicons.provider_icon(provider))

    # ---- dragging
    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._press, self._start, self._dragging = e.globalPosition().toPoint(), self.pos(), False
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e):
        if self._press is None or not (e.buttons() & Qt.MouseButton.LeftButton):
            return super().mouseMoveEvent(e)
        delta = e.globalPosition().toPoint() - self._press
        if not self._dragging and delta.manhattanLength() < QApplication.startDragDistance():
            return
        self._dragging = True
        parent = self.parentWidget()
        new = self._start + delta
        if parent is not None:
            new = QPoint(min(max(0, new.x()), max(0, parent.width() - self.width())), min(max(0, new.y()), max(0, parent.height() - self.height())))
        self.move(new)

    def mouseReleaseEvent(self, e):
        if self._dragging and e.button() == Qt.MouseButton.LeftButton:
            self._dragging, self._press = False, None
            self.setDown(False)                     # a drag is not a click
            parent = self.parentWidget()
            if parent is not None and parent.width() > 0 and parent.height() > 0:
                side = "left" if self.x() + self.width() / 2 < parent.width() / 2 else "right"
                y = min(1.0, max(0.0, (self.y() + self.height() / 2) / parent.height()))
                self.moved.emit(side, y)
            e.accept()
            return
        self._press = None
        super().mouseReleaseEvent(e)

    def dragging(self):
        return self._dragging

    def restyle(self):
        self.set_provider(getattr(self, "provider", AI.provider_id()))    # the mark's light or dark version follows the theme
        t = theme.current() or {}
        self.setStyleSheet(f"QToolButton {{ border-radius: {BUTTON // 2}px; border: 1px solid {t.get('border', '#ccc')}; background: {t.get('surface', '#fff')}; padding: 0px; }}"
                           f"QToolButton:hover {{ background: {t.get('hover', '#eee')}; }}"
                           f"QToolButton:checked {{ border-color: {t.get('accent', '#2563eb')}; }}")


class AssistantPanel(QWidget):
    """The transcript, the tool steps as they happen, a line per answer with tokens and cost, and the input box."""
    turn_done = Signal()                            # an answer landed (the Automation/AI page refreshes its totals)
    close_requested = Signal()

    def __init__(self, screen_fn=lambda: {}):
        super().__init__()
        self.screen_fn = screen_fn
        self.worker = None
        self.org = db.home()
        self.current = {}                           # organization -> the conversation open in it
        self.title = QLabel("Assistant")
        self.title.setProperty("title", True)
        self.model_line = QLabel("")
        self.model_line.setProperty("muted", True)
        self.model_line.setWordWrap(True)
        self.view = QTextEdit()
        self.view.setReadOnly(True)
        self.view.setAcceptRichText(True)
        self.view.setFrameShape(QTextEdit.Shape.NoFrame)
        self.hint = EmptyHint(self.view, "Ask a question", "The Assistant reads this organization's devices, results, backups and logs, and what is on screen.", wrap=True)
        self.input = QPlainTextEdit()
        self.input.setPlaceholderText(PLACEHOLDER)
        self.input.setFixedHeight(84)
        self.input.installEventFilter(self)
        self.send_btn, self.stop_btn, self.new_btn = QPushButton("Send"), QPushButton("Stop"), QPushButton("New conversation")
        self.send_btn.setProperty("primary", True)
        self.stop_btn.setEnabled(False)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setProperty("muted", True)
        buttons = flow(self.new_btn, self.stop_btn, self.send_btn)        # wraps onto a second row when the panel is narrow
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(8)
        lay.addWidget(self.title)
        lay.addWidget(self.model_line)
        lay.addWidget(self.view, 1)
        lay.addWidget(self.status)
        lay.addWidget(self.input)
        lay.addLayout(buttons)
        self.setMinimumWidth(MIN_WIDTH)
        self.send_btn.clicked.connect(self.send)
        self.stop_btn.clicked.connect(self.stop)
        self.new_btn.clicked.connect(self.new_conversation)
        self.entries = []                           # what the transcript holds, for the tests and for reloading
        self._answer_start = None
        self.show_model()

    # ---- which conversation
    def conv_id(self):
        return self.current.get(self.org)

    def set_org(self, org):
        """The sidebar switched organization: show that organization's conversation (its newest, or none yet)."""
        if self.running():
            self.stop()
        self.org = int(org or 0)
        if self.org not in self.current:
            with db.within(self.org):
                rows = store.list_conversations(1)
            self.current[self.org] = rows[0]["id"] if rows else None
        self.reload()

    def open_conversation(self, conv_id, org=None):
        if self.running():
            self.stop()
        self.org = int(org if org is not None else self.org)
        self.current[self.org] = conv_id
        self.reload()

    def new_conversation(self):
        if self.running():
            self.stop()
        self.current[self.org] = None
        self.reload()

    def reload(self):
        """Redraw the transcript from what is stored."""
        self.view.clear()
        self.entries = []
        self.status.setText("")
        self.show_model()
        cid = self.conv_id()
        if cid:
            conv = store.get(cid, self.org)
            if conv is None:
                self.current[self.org] = None
            else:
                for t in store.turns(cid, self.org):
                    if t["kind"] == "user":
                        self._user(t["text"])
                    elif t["kind"] == "assistant":
                        self._begin_answer()
                        self._end_answer(t["text"])
                        self._line(usage_line(t["tokens_in"], t["tokens_out"], t["cost"], True), "muted")
                    elif t["kind"] == "tool":
                        self._line(t["text"], "muted")
                    else:
                        self._line(t["text"], "note")
        self.hint.setVisible(not self.entries)
        self.view.moveCursor(QTextCursor.MoveOperation.End)

    def show_model(self):
        s = AI.state()
        self.model_line.setText(f"{AI.PROVIDERS[AI.provider_id()]['label']}  ·  {s.get('model') or AI.model_for()}" if s.get("connected") else "")

    # ---- the transcript
    def _color(self, what):
        t = theme.current() or {}
        return {"muted": t.get("muted", "#666"), "note": t.get("muted", "#666"), "accent": t.get("accent", "#2563eb")}.get(what, t.get("text", "#000"))

    def _html(self, text):
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")

    def _append_html(self, html):
        """One more paragraph at the end of the transcript."""
        self.view.append(html)
        self.view.moveCursor(QTextCursor.MoveOperation.End)
        self.view.ensureCursorVisible()
        self.hint.setVisible(False)

    def _user(self, text):
        self.entries.append(("user", text))
        self._append_html(f'<b style="color:{self._color("accent")}">You</b>')
        self._append_html(self._html(text))

    def _line(self, text, what="muted"):
        self.entries.append((what, text))
        self._append_html(f'<i style="color:{self._color(what)}">{self._html(text)}</i>')

    def _begin_answer(self):
        self.view.moveCursor(QTextCursor.MoveOperation.End)
        self._header_start = self.view.textCursor().position()
        self.entries.append(("assistant", ""))
        self._append_html(f'<b style="color:{self._color("muted")}">Assistant</b>')
        self._append_html("")                                   # the answer's own paragraph, filled as the text streams in
        self.view.moveCursor(QTextCursor.MoveOperation.End)
        self._answer_start = self.view.textCursor().position()
        self._answer_text = ""

    def _drop_empty_answer(self):
        """Take back an 'Assistant' heading that nothing followed."""
        if self._answer_start is None or self.entries[-1] != ("assistant", ""):
            return
        cur = self.view.textCursor()
        cur.setPosition(self._header_start)
        cur.movePosition(QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor)
        cur.removeSelectedText()
        self.view.setTextCursor(cur)
        self.entries.pop()
        self._answer_start = None

    def _add_text(self, piece):
        self._answer_text += piece
        self.entries[-1] = ("assistant", self._answer_text)
        cur = self.view.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        cur.insertText(piece)
        self.view.setTextCursor(cur)
        self.view.ensureCursorVisible()

    def _end_answer(self, text):
        """The whole answer is in: show it as the model wrote it (headings, lists, code) instead of the streamed plain text."""
        if self._answer_start is None:
            return
        self.entries[-1] = ("assistant", text)
        cur = self.view.textCursor()
        cur.setPosition(self._answer_start)
        cur.movePosition(QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor)
        cur.removeSelectedText()
        cur.insertFragment(QTextDocumentFragment.fromMarkdown(text or ""))
        self.view.setTextCursor(cur)
        self.view.moveCursor(QTextCursor.MoveOperation.End)
        self._answer_start = None

    # ---- asking
    def running(self):
        return bool(self.worker and self.worker.isRunning())

    def can_send(self):
        """Why nothing can be sent right now, or ''."""
        if not AI.connected():
            return AI.state().get("text") or AI.STRIP_OFF
        if AI.spend_reached():
            return AI.limit_text()
        return ""

    def send(self):
        if self.running():
            return False
        question = self.input.toPlainText().strip()
        if not question:
            return False
        why = self.can_send()
        if why:
            self.status.setText(why)
            return False
        self.status.setText("")
        with db.within(self.org):
            if not self.conv_id():
                self.current[self.org] = store.create(AI.provider_id(), AI.model_for(), question)
            else:
                conv = store.get(self.conv_id())
                if conv is None or conv["provider"] != AI.provider_id():        # the provider changed since: a fresh conversation
                    self.current[self.org] = store.create(AI.provider_id(), AI.model_for(), question)
        try:
            screen = self.screen_fn() or {}
        except Exception:                                   # noqa: BLE001  (a page that cannot describe itself does not stop the question)
            screen = {}
        self.input.clear()
        self._user(question)
        self._begin_answer()
        self.worker = Worker(self.conv_id(), self.org, question, screen)
        self.worker.event.connect(self._event)
        self.worker.finished.connect(self._finished)
        self._buttons(True)
        self.worker.start()
        return True

    def stop(self):
        if self.running():
            self.worker.cancel.set()
            self.status.setText("Stopping…")

    def _event(self, kind, payload):
        if kind == "text":
            self._add_text(payload)
        elif kind == "tool":
            if self._answer_text:
                self._end_answer(self._answer_text)         # the text so far stays, the step goes under it
            else:
                self._drop_empty_answer()                   # nothing said yet: the step comes first, the answer's heading after it
            self._line(payload, "muted")
            self._begin_answer()
            self._answer_text = ""
        elif kind == "done":
            self._end_answer(payload["text"])
            if payload.get("note"):
                self._line(payload["note"], "note")
            self._line(usage_line(payload["tokens_in"], payload["tokens_out"], payload["cost"], payload.get("priced", True)), "muted")
            self.turn_done.emit()
        elif kind == "stopped":
            self._end_answer(self._answer_text)
            self._line("Stopped.", "note")
        elif kind == "error":
            self._end_answer(self._answer_text)
            self._line(payload, "note")
            self.status.setText(payload)

    def _finished(self):
        self._buttons(False)
        if self.status.text() == "Stopping…":
            self.status.setText("")

    def _buttons(self, busy):
        self.send_btn.setEnabled(not busy)
        self.input.setEnabled(not busy)
        self.stop_btn.setEnabled(busy)
        self.new_btn.setEnabled(not busy)

    def eventFilter(self, obj, ev):
        if obj is self.input and ev.type() == QEvent.Type.KeyPress and ev.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) \
                and not ev.modifiers() & Qt.KeyboardModifier.ShiftModifier:
            self.send()                                     # Enter sends; Shift+Enter makes a new line
            return True
        return super().eventFilter(obj, ev)

    def shutdown(self):
        if self.running():
            self.worker.cancel.set()
            self.worker.wait(5000)


class AssistantOverviewPage(QWidget):
    """Automation/AI > Assistant: the provider, the connection, what this month has cost here and everywhere, what it can see, and
    this organization's conversations with Open and Delete. In Global: every organization's month side by side, plus the total."""
    open_requested = Signal(int, int)               # conversation id, organization
    settings_requested = Signal()

    def __init__(self):
        super().__init__()
        self.provider = QLabel("")
        self.connection = QLabel("")
        self.here = QLabel("")
        self.everywhere = QLabel("")
        self.sees = QLabel("")
        for lab in (self.provider, self.connection, self.here, self.everywhere, self.sees):
            lab.setWordWrap(True)
            lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.orgs_table = QTableWidget(0, 5)
        self.orgs_table.setHorizontalHeaderLabels(["Organization", "Conversations", "Tokens in", "Tokens out", "Cost (USD)"])
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Conversation", "Started", "Turns", "Tokens", "Cost (USD)"])
        for t in (self.orgs_table, self.table):
            t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            t.verticalHeader().setVisible(False)
            t.setShowGrid(False)
            t.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.hint = EmptyHint(self.table, "No conversations yet", "Open the Assistant from the round button at the right edge of the window", wrap=True)
        self.open_btn, self.delete_btn, self.settings_btn = QPushButton("Open"), QPushButton("Delete"), QPushButton("AI settings")
        self.open_btn.setProperty("primary", True)
        lay = QVBoxLayout(self)
        lay.addWidget(self.provider)
        lay.addWidget(self.connection)
        lay.addWidget(self.here)
        lay.addWidget(self.everywhere)
        lay.addWidget(self.orgs_table)
        lay.addWidget(self.sees)
        bar = QHBoxLayout()
        bar.addWidget(self.settings_btn)
        bar.addStretch(1)
        bar.addWidget(self.delete_btn)
        bar.addWidget(self.open_btn)
        lay.addLayout(bar)
        lay.addWidget(self.table, 1)
        self.rows = []
        self.open_btn.clicked.connect(self._open)
        self.delete_btn.clicked.connect(self.delete)
        self.settings_btn.clicked.connect(self.settings_requested.emit)
        self.table.itemDoubleClicked.connect(lambda *_: self._open())
        self.table.itemSelectionChanged.connect(self._buttons)
        self.ask = lambda n: QMessageBox.question(self, "Delete conversation", f"Delete {'this conversation' if n == 1 else f'these {n} conversations'}?") == QMessageBox.StandardButton.Yes
        self.refresh()

    def refresh(self):
        provider = AI.provider_id()
        s = AI.state()
        self.provider.setText(f"<b>Provider:</b> {AI.PROVIDERS[provider]['label']}  ·  <b>Model:</b> {s.get('model') or AI.model_for(provider)}")
        if s.get("connected") is True:
            self.connection.setText("<b>Connection:</b> connected")
        elif s.get("connected") is False:
            self.connection.setText(f"<b>Connection:</b> not connected  ·  {s.get('text', '')}")
        elif not AI.has_key(provider):
            self.connection.setText("<b>Connection:</b> no API key yet. Add one under Settings > AI.")
        else:
            self.connection.setText(f"<b>Connection:</b> checking…")
        every = store.every_org_totals()
        total = store.all_totals()
        limit = AI.spend_limit()
        here = store.month_totals()
        self.here.setText(f"<b>This organization this month:</b> {here['conversations']} conversation{'s' if here['conversations'] != 1 else ''}, "
                          f"{fmt_tokens(here['tokens'])} tokens, USD {AI.money(here['cost'])}")
        self.everywhere.setText(f"<b>All organizations this month:</b> {fmt_tokens(total['tokens'])} tokens, "
                                f"USD {AI.money(total['cost'])} of {AI.money(limit)} across all organizations" if limit > 0 else
                                f"<b>All organizations this month:</b> {fmt_tokens(total['tokens'])} tokens, USD {AI.money(total['cost'])} across all organizations (no limit set)")
        in_global = db.everything()
        self.here.setVisible(not in_global)
        self.orgs_table.setVisible(in_global)
        if in_global:
            with filling(self.orgs_table):
                self.orgs_table.setRowCount(len(every) + 1)
                for i, (_org, name, t) in enumerate(every):
                    for j, v in enumerate([name, t["conversations"], fmt_tokens(t["tokens_in"]), fmt_tokens(t["tokens_out"]), AI.money(t["cost"])]):
                        self.orgs_table.setItem(i, j, QTableWidgetItem(str(v)))
                for j, v in enumerate(["Total", total["conversations"], fmt_tokens(total["tokens_in"]), fmt_tokens(total["tokens_out"]), AI.money(total["cost"])]):
                    it = QTableWidgetItem(str(v))
                    f = it.font()
                    f.setBold(True)
                    it.setFont(f)
                    self.orgs_table.setItem(len(every), j, it)
            self.orgs_table.resizeColumnsToContents()
        n = len(db.list_devices())
        name = "Global (every organization)" if in_global else db.org_name(db.home())
        self.sees.setText(f"<b>What it can see:</b> {name}, {n} device{'s' if n != 1 else ''}. It reads " + "; ".join(T.what_it_sees()) +
                          ". Passwords are masked everywhere. " + ("It changes nothing." if AI.commands_allowed() else "It only reads."))
        self.rows = store.list_conversations()
        with filling(self.table):
            self.table.setColumnHidden(0, False)
            self.table.setRowCount(len(self.rows))
            for i, r in enumerate(self.rows):
                title = r["title"] or "(untitled)"
                if in_global and db.several():
                    title += f"  ({db.org_name(r['org'])})"
                for j, v in enumerate([title, r["started"], r["turns"], fmt_tokens(r["tokens_in"] + r["tokens_out"]), AI.money(r["cost"]) if r["cost"] >= 0.005 or not r["cost"] else f"{r['cost']:.4f}"]):
                    self.table.setItem(i, j, QTableWidgetItem(str(v)))
        self.table.resizeColumnsToContents()
        self.hint.setVisible(not self.rows)
        self._buttons()

    def selected(self):
        rows = {i.row() for i in self.table.selectedItems()}
        return self.rows[rows.pop()] if len(rows) == 1 and self.rows else None

    def _buttons(self):
        on = self.selected() is not None
        self.open_btn.setEnabled(on)
        self.delete_btn.setEnabled(on)

    def _open(self):
        r = self.selected()
        if r:
            self.open_requested.emit(r["id"], r["org"])

    def delete(self):
        r = self.selected()
        if r and self.ask(1):
            store.delete(r["id"], r["org"])
            self.refresh()
