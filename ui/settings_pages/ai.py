"""Settings > AI: which provider and model the Assistant uses, its API key (kept in the vault), how deeply it thinks, the
monthly spend limit across every organization, whether it may run show commands on devices and whether it may search the
internet. Test reaches the provider with the key and fills the model list."""
import threading

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QCheckBox, QComboBox, QLabel, QLineEdit, QPushButton

from core import assistant as AI
from ui.settings_base import Page, TrimSpin, compact_row, note

INTRO = ("The Assistant answers questions about the organization you are looking at from Toner's own data: devices, check results, "
         "configuration backups (passwords masked), logs and what is on screen. It only reads, and runs show commands on devices only "
         "when you allow that below. It can search the internet for public information unless you switch that off below. One provider "
         "and key serve the whole installation; conversations and their cost are kept per organization.")
RUN_NOTE = ("Off by default. When on, the Assistant may send commands that only look (show, display, get, dir, ping, traceroute; "
            "Get-… in PowerShell) to the devices the Command Runner can command, with the Command Runner's read-only block and no way "
            "past it. Every command is written to the audit log and to a session log under Tools > Session logs.")
SEARCH_NOTE = ("When on, the Assistant may search the web through the provider's own search (Claude, OpenAI or Gemini; with Claude it can "
               "also read the pages it finds) for public information: security advisories and CVEs, release notes, end-of-life dates, "
               "documentation. It is told never to put anything from your network in a search: no device, organization or people's names, "
               "addresses, serial numbers or configuration lines; product names, versions and advisory ids only. Each search is written to "
               "the audit log, costs about USD 0.01 to 0.035 on top of tokens, and counts toward the monthly spend limit.")
KEY_SAVED = "saved; leave blank to keep"
TESTING = "Testing…"


class AiPage(Page):
    title = "AI"
    tested = Signal(object)                              # the test's result, from the thread that ran it

    def __init__(self):
        super().__init__()
        self.lay.insertWidget(0, note(INTRO))
        self.provider = QComboBox()
        for pid, info in AI.PROVIDERS.items():
            self.provider.addItem(info["label"], pid)
        self.key = QLineEdit()
        self.key.setEchoMode(QLineEdit.EchoMode.Password)
        self.key.setMinimumWidth(360)
        self.model = QComboBox()
        self.model.setEditable(True)
        self.model.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.model.setMinimumWidth(300)
        self.depth = QComboBox()
        for key, label in AI.DEPTHS:
            self.depth.addItem(label, key)
        self.limit = TrimSpin(2)
        self.limit.setRange(0, 1_000_000)
        self.limit.setSingleStep(5)
        self.test_btn = QPushButton("Test")
        self.test_btn.setProperty("notSetting", True)
        self.test_btn.setAutoDefault(False)
        self.result = QLabel("")
        self.result.setWordWrap(True)
        self.result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.run_cmds = QCheckBox("Let the Assistant run show commands on devices")
        self.run_cmds.setToolTip(RUN_NOTE)
        self.search = QCheckBox("Let the Assistant search the internet")
        self.search.setToolTip(SEARCH_NOTE)
        self.form.addRow("Provider", self.provider)
        self.form.addRow("API key", self.key)
        self.form.addRow("Model", self.model)
        self.form.addRow("Depth", self.depth)
        self.form.addRow("Monthly spend limit (USD)", self.limit)
        self.form.addRow("", compact_row(self.test_btn))
        self.form.addRow("", self.result)
        self.form.addRow("", self.run_cmds)
        self.form.addRow("", note(RUN_NOTE))
        self.form.addRow("", self.search)
        self.form.addRow("", note(SEARCH_NOTE))
        self.provider.currentIndexChanged.connect(self._provider_changed)
        self.test_btn.clicked.connect(self.test)
        self.tested.connect(self._tested)
        self._models = {}                                   # provider -> [(id, display)] from the last Test
        self._testing = False

    # ---------- Settings' own calls
    def load(self):
        pid = AI.provider_id()
        self.provider.blockSignals(True)
        self.provider.setCurrentIndex(max(0, self.provider.findData(pid)))
        self.provider.blockSignals(False)
        self._fill_models(pid)
        self.depth.setCurrentIndex(max(0, self.depth.findData(AI.depth())))
        self.limit.setValue(AI.spend_limit())
        self.run_cmds.setChecked(AI.commands_allowed())
        self.search.setChecked(AI.search_allowed())
        self.key.clear()
        self.key.setPlaceholderText(KEY_SAVED if AI.has_key(pid) else "")
        s = AI.state()
        self.result.setText(s.get("text") or "")

    def validate(self):
        problems = []
        if not self.chosen_model():
            problems.append("AI: choose or type a model.")
        if self.key.text().strip() == "" and not AI.has_key(self.chosen_provider()):
            problems.append(f"AI: enter the {AI.PROVIDERS[self.chosen_provider()]['label']} API key (or leave the provider as it was).") if self._provider_changed_from_saved() else None
        return [p for p in problems if p]

    def _provider_changed_from_saved(self):
        return self.chosen_provider() != AI.provider_id()

    def save(self):
        from core import db
        pid = self.chosen_provider()
        db.set_setting("ai_provider", pid)
        AI.set_model(pid, self.chosen_model())
        db.set_setting("ai_depth", self.depth.currentData())
        db.set_setting("ai_spend_limit", float(self.limit.value()))
        db.set_setting("ai_run_commands", self.run_cmds.isChecked())
        db.set_setting("ai_search", self.search.isChecked())
        typed = self.key.text().strip()
        if typed:
            AI.set_key(pid, typed)
        self.key.clear()
        self.key.setPlaceholderText(KEY_SAVED if AI.has_key(pid) else "")
        AI.check_in_background()                          # the strip and the side button follow

    # ---------- the fields
    def chosen_provider(self):
        return self.provider.currentData() or "claude"

    def chosen_model(self):
        return (self.model.currentData() if self.model.currentIndex() >= 0 and self.model.currentText() == self.model.itemText(self.model.currentIndex())
                else self.model.currentText()).strip() if self.model.currentText().strip() else ""

    def _fill_models(self, pid, keep=None):
        want = keep or AI.model_for(pid)
        self.model.blockSignals(True)
        self.model.clear()
        listed = self._models.get(pid) or []
        for mid, display in listed:
            self.model.addItem(f"{display}  ({mid})" if display and display != mid else mid, mid)
        if want and self.model.findData(want) < 0:
            self.model.insertItem(0, want, want)
        self.model.setCurrentIndex(max(0, self.model.findData(want)))
        self.model.blockSignals(False)

    def _provider_changed(self, *_):
        pid = self.chosen_provider()
        self._fill_models(pid)
        self.key.clear()
        self.key.setPlaceholderText(KEY_SAVED if AI.has_key(pid) else "")
        self.result.setText("")

    # ---------- Test
    def test(self):
        if self._testing:
            return
        pid, key, model = self.chosen_provider(), self.key.text().strip() or AI.get_key(self.chosen_provider()), self.chosen_model()
        if not key:
            self.result.setText(f"Enter the {AI.PROVIDERS[pid]['label']} API key first.")
            return
        self._testing = True
        self.test_btn.setEnabled(False)
        self.result.setText(TESTING)
        threading.Thread(target=lambda: self.tested.emit((pid, AI.test_connection(pid, key, model))), daemon=True).start()

    def _tested(self, payload):
        pid, result = payload
        self._testing = False
        self.test_btn.setEnabled(True)
        self.result.setText(result["text"])
        if result["ok"] and result["models"]:
            self._models[pid] = result["models"]
            if pid == self.chosen_provider():
                self._fill_models(pid, keep=self.chosen_model())
