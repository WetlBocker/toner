"""The prompt an admin answers when a directory server's certificate isn't trusted by this computer (External Identities): it shows
the certificate, and Trust pins that exact certificate as the directory's CA file (directory.py, tls_pinned). The words are the
owner's, approved 2026-11-08."""
from PySide6.QtWidgets import QDialog, QFormLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout
from PySide6.QtCore import Qt

from core import certpeek, paths

TITLE = "Trust this certificate?"
TEXT = "{host} presented a certificate this computer doesn't trust. Trust it only if it's your directory server's."
EXPIRED = "This certificate expired on {date}."


class TrustDialog(QDialog):
    def __init__(self, host, der, parent=None):
        super().__init__(parent)
        self.setWindowTitle(TITLE)
        info = certpeek.describe(der)
        lay = QVBoxLayout(self)
        text = QLabel(TEXT.format(host=host))
        text.setWordWrap(True)
        lay.addWidget(text)
        form = QFormLayout()
        for label, value in (("Made out to", ", ".join(info["names"])), ("Issued by", info["issuer"]),
                             ("Valid", f"{info['valid_from']} to {info['valid_to']}"), ("SHA-256", info["sha256"])):
            shown = QLabel(value)
            shown.setWordWrap(True)
            shown.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)    # the fingerprint can be copied to compare
            form.addRow(QLabel(label), shown)
        lay.addLayout(form)
        if info["expired"]:
            lay.addWidget(QLabel(EXPIRED.format(date=info["valid_to"])))
        row = QHBoxLayout()
        row.addStretch(1)
        self.cancel_btn, self.trust_btn = QPushButton("Cancel"), QPushButton("Trust")
        self.cancel_btn.setDefault(True)                  # Enter doesn't trust a certificate by accident
        self.cancel_btn.clicked.connect(self.reject)
        self.trust_btn.clicked.connect(self.accept)
        row.addWidget(self.cancel_btn)
        row.addWidget(self.trust_btn)
        lay.addLayout(row)
        self.setMinimumWidth(520)


def ask(parent, host, der):
    """True when the admin trusts the certificate."""
    return TrustDialog(host, der, parent).exec() == QDialog.DialogCode.Accepted


def save(der):
    """The trusted certificate as a PEM file in Toner's data folder; its path, for the directory's CA file."""
    folder = paths.data_dir() / "certs"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (certpeek.describe(der)["sha256"].replace(":", "")[:16].lower() + ".pem")
    path.write_bytes(certpeek.pem(der))
    return str(path)
