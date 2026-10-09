"""The SNMP version / community / v3 fields, shared by the device dialog and the credential-profile dialog."""
from PySide6.QtWidgets import (QComboBox, QFormLayout, QLabel, QLineEdit, QSpinBox, QVBoxLayout, QWidget)
from core import snmp


class SnmpFields(QWidget):
    """Edits one SNMP configuration. Secrets are never shown: leave a box blank to keep what is stored."""

    def __init__(self):
        super().__init__()
        self.version = QComboBox()
        for label, v in snmp.VERSIONS:
            self.version.addItem(label, v)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(161)
        self.community = QLineEdit()
        self.user = QLineEdit()
        self.level = QComboBox()
        self.level.addItems(snmp.LEVELS)
        self.auth_proto, self.priv_proto = QComboBox(), QComboBox()
        self.auth_proto.addItems(snmp.AUTH_PROTOCOLS)
        self.priv_proto.addItems(snmp.PRIV_PROTOCOLS)
        self.auth_key, self.priv_key = QLineEdit(), QLineEdit()
        self.boxes = (self.community, self.auth_key, self.priv_key)
        for e in self.boxes:
            e.setEchoMode(QLineEdit.EchoMode.Password)
        self.form = QFormLayout()
        self.form.setContentsMargins(0, 0, 0, 0)
        for label, w in (("SNMP version", self.version), ("SNMP port", self.port), ("Community", self.community),
                         ("v3 user", self.user), ("Security level", self.level), ("Authentication", self.auth_proto),
                         ("Auth password", self.auth_key), ("Privacy", self.priv_proto), ("Privacy password", self.priv_key)):
            self.form.addRow(label, w)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(self.form)
        self.version.currentIndexChanged.connect(self._adapt)
        self.level.currentIndexChanged.connect(self._adapt)
        self._adapt()

    def _adapt(self, *_):
        v3 = self.version.currentData() == "3"
        lvl = self.level.currentText()
        show = self.form.setRowVisible
        show(self.community, not v3)
        for w in (self.user, self.level):
            show(w, v3)
        show(self.auth_proto, v3 and lvl != "noAuthNoPriv")
        show(self.auth_key, v3 and lvl != "noAuthNoPriv")
        show(self.priv_proto, v3 and lvl == "authPriv")
        show(self.priv_key, v3 and lvl == "authPriv")

    def set_stored(self, have):
        """Say which secrets already exist, as {'snmp': bool, 'snmp_auth': bool, 'snmp_priv': bool}."""
        for box, key in zip(self.boxes, ("snmp", "snmp_auth", "snmp_priv")):
            box.setPlaceholderText("leave blank to keep the stored value" if have.get(key) else "")

    def load(self, settings):
        s = {**{"version": "2c", "port": 161, "user": "", "level": "noAuthNoPriv", "auth_protocol": "SHA",
                "priv_protocol": "AES-128"}, **(settings or {})}
        self.version.setCurrentIndex(max(0, self.version.findData(str(s["version"]))))
        self.port.setValue(int(s["port"] or 161))
        self.user.setText(s["user"])
        self.level.setCurrentText(s["level"])
        self.auth_proto.setCurrentText(s["auth_protocol"])
        self.priv_proto.setCurrentText(s["priv_protocol"])
        for b in self.boxes:
            b.clear()
        self._adapt()

    def settings(self):
        return {"version": self.version.currentData(), "port": self.port.value(), "user": self.user.text().strip(),
                "level": self.level.currentText(), "auth_protocol": self.auth_proto.currentText(),
                "priv_protocol": self.priv_proto.currentText()}

    def secrets(self):
        return {"snmp": self.community.text(), "snmp_auth": self.auth_key.text(), "snmp_priv": self.priv_key.text()}
