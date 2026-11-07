"""WHOIS Lookup: who an address belongs to (the registry's RDAP record) and, when an API key is saved, where it is. Opened
from the right-click menu on any selected IP address (ui/ipmenu.py)."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QVBoxLayout

from core import iplookup, rdap, subnets
from ui.tools import Call


def _esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;")


def _table(rows):
    return "<table cellpadding='3'>" + "".join(f"<tr><td><b>{_esc(k)}</b></td><td>{_esc(v)}</td></tr>" for k, v in rows) + "</table>"


def gather(ip):
    """Both look-ups, for the window (off the window thread): {'rdap': rows or error text, 'ipstack': rows, error text or None}."""
    out = {}
    try:
        out["rdap"] = rdap.summary(rdap.lookup(ip)) or "The registry sent a record with nothing Toner shows."
    except Exception as e:
        out["rdap"] = f"Registry: {e}"
    if iplookup.has_key():
        try:
            out["ipstack"] = iplookup.fields(iplookup.lookup(ip))
        except Exception as e:
            out["ipstack"] = f"{iplookup.host()}: {e}"
    else:
        out["ipstack"] = None
    return out


class WhoisDialog(QDialog):
    def __init__(self, ip, parent=None):
        super().__init__(parent)
        self.ip = str(ip).strip()
        self.setWindowTitle(f"WHOIS Lookup – {self.ip}")
        self.resize(560, 420)
        self.head = QLabel(f"<b>{_esc(self.ip)}</b>")
        self.registry = QLabel("Asking the registry...")
        self.where = QLabel("")
        for lab in (self.registry, self.where):
            lab.setTextFormat(Qt.TextFormat.RichText)
            lab.setWordWrap(True)
            lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            lab.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        self.buttons.rejected.connect(self.reject)
        self.buttons.accepted.connect(self.accept)
        lay = QVBoxLayout(self)
        lay.addWidget(self.head)
        lay.addWidget(QLabel("<b>Registry</b>"))
        lay.addWidget(self.registry)
        self.where_title = QLabel("<b>Location</b>")
        lay.addWidget(self.where_title)
        lay.addWidget(self.where)
        lay.addStretch(1)
        lay.addWidget(self.buttons)
        self.worker = None
        try:
            public = subnets.is_public(subnets.parse(self.ip).ip)
        except ValueError:
            public = False
        if not public:
            self.registry.setText("A private or reserved address: no registry holds a record for it, and it has no location to look up.")
            self.where_title.hide()
            self.where.hide()
            return
        if not iplookup.has_key():
            self.where.setText("<span style='color:gray'>Add an API key under Settings &gt; Connections to see where it is.</span>")
        else:
            self.where.setText(f"Asking {_esc(iplookup.host())}...")
        self.worker = Call(lambda: gather(self.ip))
        self.worker.done.connect(self._show)
        self.worker.start()

    def _show(self, res):
        if isinstance(res, Exception):
            self.registry.setText(f"<span style='color:gray'>{_esc(res)}</span>")
            return
        r = res.get("rdap")
        self.registry.setText(_table(r) if isinstance(r, list) else f"<span style='color:gray'>{_esc(r)}</span>")
        w = res.get("ipstack")
        if isinstance(w, list):
            self.where.setText(_table(w))
        elif w:
            self.where.setText(f"<span style='color:gray'>{_esc(w)}</span>")

    def closeEvent(self, e):
        if self.worker is not None:
            self.worker.wait(2000)
        super().closeEvent(e)


def whois_popup(parent, ip):
    dlg = WhoisDialog(ip, parent)
    dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
    dlg.show()
    return dlg
