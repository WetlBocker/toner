"""Tools > OpenSSL: keys, CSRs and certificates, reading and converting them, hashes, and a real openssl.exe if there is one."""
import os

from PySide6.QtCore import QProcess, QThread, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                               QPlainTextEdit, QPushButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget)
from core import audit, db, openssl
from ui.tools import OutputBox, Runner, _row
from ui.tools2 import _muted, _primary


class _Work(QThread):
    """Runs one function off the window thread (a 4096-bit key takes seconds); done carries the result or the exception."""
    done = Signal(object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn())
        except Exception as e:
            self.done.emit(e)


def _text(placeholder="", height=110):
    t = QPlainTextEdit()
    t.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
    t.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    t.setPlaceholderText(placeholder)
    t.setMinimumHeight(height)
    return t


def _secret(placeholder):
    e = QLineEdit()
    e.setEchoMode(QLineEdit.EchoMode.Password)
    e.setPlaceholderText(placeholder)
    e.setMaximumWidth(220)
    return e


def _save_text(parent, text, name):
    path, _ = QFileDialog.getSaveFileName(parent, "Save", name)
    if path:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    return path


class _Base(QWidget):
    def __init__(self):
        super().__init__()
        self.job = None

    def _run(self, fn, done):
        """Work in the background; `done` gets the result, and errors are shown in the status line."""
        if self.job and self.job.isRunning():
            return
        self.job = _Work(fn)

        def finished(result):
            if isinstance(result, Exception):
                self.status.setText(str(result) if isinstance(result, ValueError) else f"{type(result).__name__}: {result}")
            else:
                done(result)
        self.job.done.connect(finished)
        self.job.start()

    def wait(self):
        if self.job:
            self.job.wait(30000)

    def shutdown(self):
        self.wait()


# =============================================================================== make keys, CSRs, certificates
class GenerateTab(_Base):
    MODES = [("csr", "Private key and certificate request (CSR)"), ("self", "Self-signed certificate (with its key)"),
             ("key", "Private key only")]

    def __init__(self):
        super().__init__()
        self.mode = QComboBox()
        for k, label in self.MODES:
            self.mode.addItem(label, k)
        self.kind = QComboBox()
        for k, label in openssl.KEY_TYPES:
            self.kind.addItem(label, k)
        self.cn, self.sans = QLineEdit(), QLineEdit()
        self.cn.setPlaceholderText("www.example.com")
        self.sans.setPlaceholderText("other names: www.example.com, example.com, 10.0.0.5")
        self.org, self.unit, self.country, self.state, self.city, self.email = (QLineEdit() for _ in range(6))
        for w, tip in ((self.org, "Organization"), (self.unit, "Department"), (self.country, "US"), (self.state, "State or province"),
                       (self.city, "City"), (self.email, "Email")):
            w.setPlaceholderText(tip)
        self.country.setMaximumWidth(60)
        self.country.setMaxLength(2)
        self.days = QSpinBox()
        self.days.setRange(1, 36500)
        self.days.setValue(365)
        self.days.setSuffix(" days")
        self.ca = QCheckBox("Make it a certificate authority (can sign other certificates)")
        self.pass_ = _secret("passphrase for the key (optional)")
        self.existing = _text("Optional: paste an existing private key (PEM) to use it instead of making a new one", 60)
        self.existing_pass = _secret("its passphrase, if it has one")
        self.go = _primary("Create")
        self.status = _muted("")
        self.key_out, self.cert_out = _text("The private key appears here. Keep it secret.", 140), _text("The request or certificate appears here.", 140)
        self.copy_key, self.save_key = QPushButton("Copy key"), QPushButton("Save key...")
        self.copy_cert, self.save_cert = QPushButton("Copy"), QPushButton("Save...")
        for b in (self.copy_key, self.save_key, self.copy_cert, self.save_cert):
            b.setAutoDefault(False)
        self.cert_label = QLabel("<b>Certificate request</b>")
        lay = QVBoxLayout(self)
        lay.addWidget(_muted("Made on this computer with OpenSSL's own code. Nothing is stored or sent anywhere: copy or save what you need, "
                             "and keep private keys private."))
        lay.addLayout(_row("Create", self.mode, "Key", self.kind, self.pass_))
        lay.addLayout(_row("Common name", self.cn, "Alt names", self.sans))
        lay.addLayout(_row(self.org, self.unit, "Country", self.country, self.state, self.city, self.email))
        lay.addLayout(_row("Valid for", self.days, self.ca))
        lay.addWidget(self.existing)
        lay.addLayout(_row(self.existing_pass))
        lay.addLayout(_row(self.go))
        lay.addWidget(self.status)
        lay.addWidget(QLabel("<b>Private key</b>"))
        lay.addWidget(self.key_out)
        lay.addLayout(_row(self.copy_key, self.save_key))
        lay.addWidget(self.cert_label)
        lay.addWidget(self.cert_out)
        lay.addLayout(_row(self.copy_cert, self.save_cert))
        self.mode.currentIndexChanged.connect(self.adapt)
        self.go.clicked.connect(self.create)
        self.copy_key.clicked.connect(lambda: QApplication.clipboard().setText(self.key_out.toPlainText()))
        self.copy_cert.clicked.connect(lambda: QApplication.clipboard().setText(self.cert_out.toPlainText()))
        self.save_key.clicked.connect(lambda: _save_text(self, self.key_out.toPlainText(), "private.key"))
        self.save_cert.clicked.connect(lambda: _save_text(self, self.cert_out.toPlainText(), "request.csr" if self.mode.currentData() == "csr" else "certificate.crt"))
        self.adapt()

    def adapt(self, *_):
        mode = self.mode.currentData()
        self.days.setEnabled(mode == "self")
        self.ca.setEnabled(mode == "self")
        self.cert_label.setText("<b>Certificate request (CSR)</b>" if mode == "csr" else "<b>Certificate</b>")
        for w in (self.cert_out, self.copy_cert, self.save_cert, self.cert_label):
            w.setVisible(mode != "key")

    def subject(self):
        return {"CN": self.cn.text(), "O": self.org.text(), "OU": self.unit.text(), "C": self.country.text(), "ST": self.state.text(),
                "L": self.city.text(), "emailAddress": self.email.text()}

    def create(self):
        mode, kind = self.mode.currentData(), self.kind.currentData()
        sub, sans, pw = self.subject(), self.sans.text(), self.pass_.text()
        ex, ex_pw, days, ca = self.existing.toPlainText(), self.existing_pass.text(), self.days.value(), self.ca.isChecked()

        def work():
            if mode == "key":
                return (openssl.generate_key(kind, pw), "")
            if mode == "csr":
                return openssl.make_csr(sub, sans, kind, pw, ex, ex_pw)
            return openssl.make_self_signed(sub, sans, kind, days, pw, ca, ex, ex_pw)
        self.go.setEnabled(False)
        self.status.setText("Working...")
        self._run(work, self._done)
        self.job.finished.connect(lambda: self.go.setEnabled(True))

    def _done(self, result):
        key, cert = result
        self.key_out.setPlainText(key or ("(you supplied the key, so no new one was made)" if self.existing.toPlainText().strip() else ""))
        self.cert_out.setPlainText(cert)
        self.status.setText("Done. Copy or save the results: Toner does not keep them.")
        audit.log("openssl: created " + {"csr": "a key and CSR", "self": "a self-signed certificate", "key": "a private key"}[self.mode.currentData()],
                  self.cn.text().strip())


# =============================================================================== read things
class InspectTab(_Base):
    def __init__(self):
        super().__init__()
        self.blob = None                                       # a file that is not text (DER, .pfx)
        self.source = _text("Paste a certificate, request or key (PEM), or open a file. Paste a certificate and its key together to check "
                            "that they match.", 150)
        self.open_btn = QPushButton("Open file...")
        self.server = QLineEdit()
        self.server.setPlaceholderText("host or host:port")
        self.fetch = QPushButton("Get from server")
        self.pass_ = _secret("passphrase or .pfx password")
        self.go = _primary("Read")
        self.status = _muted("")
        self.out = OutputBox()
        self.source.textChanged.connect(self._typed)
        lay = QVBoxLayout(self)
        lay.addWidget(_muted("Reads PEM, DER, .pfx/.p12, certificate requests and keys, and says what is in them: who, until when, "
                             "which names, what key, fingerprints, and whether a key matches its certificate."))
        lay.addWidget(self.source)
        lay.addLayout(_row(self.open_btn, "Server", self.server, self.fetch, self.pass_, self.go))
        lay.addWidget(self.status)
        lay.addWidget(self.out, 1)
        self.open_btn.clicked.connect(self.open_file)
        self.fetch.clicked.connect(self.get_server)
        self.go.clicked.connect(self.read)

    def _typed(self):
        if self.source.toPlainText() != getattr(self, "_shown", None):
            self.blob = None                                   # the box was edited: it is text again

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open", "", "Certificates and keys (*.pem *.crt *.cer *.der *.key *.csr *.pfx *.p12);;All files (*)")
        if path:
            self.load_file(path)

    def load_file(self, path):
        with open(path, "rb") as f:
            data = f.read()
        if b"-----BEGIN" in data[:4000]:
            self.blob = None
            self.source.setPlainText(data.decode("utf-8", "replace"))
        else:
            self._shown = f"[binary file: {os.path.basename(path)}, {len(data)} bytes]"
            self.source.setPlainText(self._shown)
            self.blob = data
        self.read()

    def get_server(self):
        host, _, port = self.server.text().strip().partition(":")
        if not host:
            self.status.setText("Enter the server's name, or name:port.")
            return
        self.status.setText(f"Connecting to {host}...")
        self.fetch.setEnabled(False)
        self._run(lambda: openssl.fetch_chain(host, int(port or 443)), self._fetched)
        self.job.finished.connect(lambda: self.fetch.setEnabled(True))

    def _fetched(self, result):
        pem, info = result
        self.blob = None
        self.source.setPlainText(pem)
        self.read()
        self.status.setText(info + ". The chain is shown as sent and is not validated.")

    def read(self):
        data = self.blob if self.blob is not None else self.source.toPlainText().encode()
        if not data.strip():
            self.status.setText("Paste something to read, or open a file.")
            return
        try:
            text = openssl.inspect(data, self.pass_.text())
        except Exception as e:
            self.out.clear()
            self.status.setText(str(e) if isinstance(e, ValueError) else f"{type(e).__name__}: {e}")
            return
        self.out.clear()
        self.out.add(text + "\n")
        self.out.moveCursor(self.out.textCursor().MoveOperation.Start)
        self.status.setText("")


# =============================================================================== convert
class ConvertTab(_Base):
    ACTIONS = [("der", "PEM to DER (certificate, request or key)"), ("pem", "DER to PEM (certificate or request)"),
               ("pfx", "Certificate and key (PEM) to .pfx / PKCS#12"), ("unpfx", ".pfx / PKCS#12 to PEM"),
               ("pass", "Add, change or remove a key's passphrase")]

    def __init__(self):
        super().__init__()
        self.blob = None
        self.result = None                                     # (bytes, suggested file name) of the last conversion
        self.action = QComboBox()
        for k, label in self.ACTIONS:
            self.action.addItem(label, k)
        self.source = _text("Paste PEM here, or open a file (DER and .pfx files need Open file)", 130)
        self.open_btn = QPushButton("Open file...")
        self.old = _secret("current passphrase / .pfx password")
        self.new = _secret("new passphrase / export password")
        self.go = _primary("Convert")
        self.status = _muted("")
        self.out = _text("The result appears here", 130)
        self.copy = QPushButton("Copy")
        self.save = QPushButton("Save result...")
        self.out.setReadOnly(True)
        self.source.textChanged.connect(lambda: setattr(self, "blob", None) if self.source.toPlainText() != getattr(self, "_shown", None) else None)
        lay = QVBoxLayout(self)
        lay.addWidget(_muted("Change the format of a certificate, request or key. A .pfx bundles a certificate, its chain and its key "
                             "for Windows, IIS and many appliances."))
        lay.addLayout(_row("Convert", self.action))
        lay.addWidget(self.source)
        lay.addLayout(_row(self.open_btn, self.old, self.new, self.go))
        lay.addWidget(self.status)
        lay.addWidget(self.out, 1)
        lay.addLayout(_row(self.copy, self.save))
        self.open_btn.clicked.connect(self.open_file)
        self.go.clicked.connect(self.convert)
        self.copy.clicked.connect(lambda: QApplication.clipboard().setText(self.out.toPlainText()))
        self.save.clicked.connect(self.save_result)
        self.save.setEnabled(False)
        self.copy.setEnabled(False)

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open", "", "Certificates and keys (*.pem *.crt *.cer *.der *.key *.csr *.pfx *.p12);;All files (*)")
        if path:
            self.load_file(path)

    def load_file(self, path):
        with open(path, "rb") as f:
            data = f.read()
        if b"-----BEGIN" in data[:4000]:
            self.blob = None
            self.source.setPlainText(data.decode("utf-8", "replace"))
        else:
            self._shown = f"[binary file: {os.path.basename(path)}, {len(data)} bytes]"
            self.source.setPlainText(self._shown)
            self.blob = data

    def _input(self):
        return self.blob if self.blob is not None else self.source.toPlainText().encode()

    def convert(self):
        action, data, old, new = self.action.currentData(), self._input(), self.old.text(), self.new.text()
        try:
            if not data.strip():
                raise ValueError("paste something to convert, or open a file")
            if action == "der":
                raw = openssl.to_der(data, old)
                self._binary(raw, "converted.der")
            elif action == "pem":
                self._text(openssl.to_pem(data), "converted.pem")
            elif action == "pfx":
                raw = openssl.to_pfx(data, old, new)
                self._binary(raw, "bundle.pfx", " (export password set)" if new else " (no export password)")
            elif action == "unpfx":
                self._text(openssl.from_pfx(data, old, new), "bundle.pem")
            else:
                self._text(openssl.change_passphrase(data, old, new), "key.pem")
        except Exception as e:
            self.out.clear()
            self.result = None
            self.save.setEnabled(False)
            self.copy.setEnabled(False)
            self.status.setText(str(e) if isinstance(e, ValueError) else f"{type(e).__name__}: {e}")
            return
        self.save.setEnabled(True)
        self.copy.setEnabled(True)

    def _text(self, text, name):
        self.result = (text.encode(), name)
        self.out.setPlainText(text)
        self.status.setText("Done.")

    def _binary(self, raw, name, extra=""):
        import base64
        self.result = (raw, name)
        self.out.setPlainText(f"[{len(raw)} bytes of binary data{extra}: use Save result]\n\n" + base64.b64encode(raw).decode())
        self.status.setText("Done. This is a binary file: save it, or copy its base64.")

    def save_result(self):
        if not self.result:
            return
        raw, name = self.result
        path, _ = QFileDialog.getSaveFileName(self, "Save result", name)
        if path:
            with open(path, "wb") as f:
                f.write(raw)
            self.status.setText(f"Saved {path}")


# =============================================================================== hashes and random
class HashTab(_Base):
    def __init__(self):
        super().__init__()
        self.blob = None
        self.source = _text("Type or paste text, or open a file", 110)
        self.open_btn = QPushButton("Open file...")
        self.alg = QComboBox()
        self.alg.addItems(openssl.DIGESTS)
        self.go = _primary("Hash")
        self.b64e, self.b64d = QPushButton("Base64 encode"), QPushButton("Base64 decode")
        self.count = QSpinBox()
        self.count.setRange(1, 1_000_000)
        self.count.setValue(32)
        self.count.setSuffix(" bytes")
        self.fmt = QComboBox()
        self.fmt.addItems(["hex", "base64"])
        self.rand = QPushButton("Random")
        self.status = _muted("")
        self.out = OutputBox()
        lay = QVBoxLayout(self)
        lay.addWidget(_muted("Hash text or a file, encode and decode base64, or make random bytes (for keys, secrets and test data)."))
        lay.addWidget(self.source)
        lay.addLayout(_row(self.open_btn, "Digest", self.alg, self.go, self.b64e, self.b64d))
        lay.addLayout(_row(self.count, self.fmt, self.rand))
        lay.addWidget(self.status)
        lay.addWidget(self.out, 1)
        self.open_btn.clicked.connect(self.open_file)
        self.source.textChanged.connect(lambda: setattr(self, "blob", None) if self.source.toPlainText() != getattr(self, "_shown", None) else None)
        self.go.clicked.connect(self.hash)
        self.b64e.clicked.connect(lambda: self._try(lambda: openssl.base64_encode(self._input())))
        self.b64d.clicked.connect(self.decode)
        self.rand.clicked.connect(lambda: self._try(lambda: openssl.random_bytes(self.count.value(), self.fmt.currentText())))

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open")
        if path:
            self.load_file(path)

    def load_file(self, path):
        with open(path, "rb") as f:
            data = f.read()
        self._shown = f"[file: {os.path.basename(path)}, {len(data)} bytes]"
        self.source.setPlainText(self._shown)
        self.blob = data

    def _input(self):
        return self.blob if self.blob is not None else self.source.toPlainText().encode()

    def _show(self, text):
        self.out.clear()
        self.out.add(text + "\n")
        self.status.setText("")

    def _try(self, fn):
        try:
            self._show(fn())
        except Exception as e:
            self.status.setText(str(e) if isinstance(e, ValueError) else f"{type(e).__name__}: {e}")

    def hash(self):
        self._try(lambda: f"{self.alg.currentText().upper()}  {openssl.digest(self._input(), self.alg.currentText())}")

    def decode(self):
        def run():
            raw = openssl.base64_decode(self.source.toPlainText())
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return f"[{len(raw)} bytes of binary data]\n" + raw.hex()
        self._try(run)


# =============================================================================== the real openssl.exe
class CommandTab(_Base):
    def __init__(self):
        super().__init__()
        self.exe = openssl.find_openssl(db.get_setting("openssl_path"))
        self.where = _muted("")
        self.choose = QPushButton("Choose openssl.exe...")
        self.preset = QComboBox()
        self.preset.addItem("(examples)", "")
        for label, args in openssl.PRESETS:
            self.preset.addItem(label, args)
        self.args = QLineEdit()
        self.args.setPlaceholderText("version -a")
        self.folder = QLineEdit(os.path.expanduser("~"))
        self.folder.setToolTip("Files named in the command are read from and written to this folder.")
        self.stdin = QLineEdit()
        self.stdin.setPlaceholderText("text to send to the program (optional)")
        self.go = _primary("Run")
        self.stop = QPushButton("Stop")
        self.stop.setEnabled(False)
        self.out = OutputBox()
        self.runner = Runner(self)
        self.runner.output.connect(self.out.add)
        self.runner.finished.connect(lambda: (self.go.setEnabled(True), self.stop.setEnabled(False)))
        lay = QVBoxLayout(self)
        lay.addWidget(_muted("The other tabs need nothing installed. For anything else OpenSSL can do, run the real openssl.exe here: "
                             "it is not part of Toner, and Git for Windows and the OpenSSL installers both include one."))
        lay.addWidget(self.where)
        lay.addLayout(_row(self.choose, self.preset))
        lay.addLayout(_row("openssl", self.args, "In folder", self.folder))
        lay.addLayout(_row(self.stdin, self.go, self.stop))
        lay.addWidget(self.out, 1)
        self.choose.clicked.connect(self.pick)
        self.preset.currentIndexChanged.connect(lambda: self.preset.currentData() and self.args.setText(self.preset.currentData()))
        self.go.clicked.connect(self.run)
        self.args.returnPressed.connect(self.run)
        self.stop.clicked.connect(self.runner.stop)
        self._show_exe()

    def _show_exe(self):
        self.where.setText(f"Using {self.exe}" if self.exe else "No openssl.exe was found on this computer. Install Git for Windows or OpenSSL, "
                                                                   "or choose one.")
        self.go.setEnabled(bool(self.exe))

    def pick(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose openssl.exe", "", "openssl.exe (openssl.exe);;Programs (*.exe)")
        if path:
            self.exe = path
            db.set_setting("openssl_path", path)
            self._show_exe()

    def run(self):
        if not self.exe or self.runner.running():
            return
        args = QProcess.splitCommand(self.args.text())
        if not args:
            self.out.line("Enter the arguments, for example:  version -a")
            return
        folder = self.folder.text().strip()
        if folder and not os.path.isdir(folder):
            self.out.line(f"The folder {folder} does not exist.")
            return
        self.out.line(f"> openssl {self.args.text()}")
        if folder:
            self.runner.proc.setWorkingDirectory(folder)
        self.go.setEnabled(False)
        self.stop.setEnabled(True)
        self.runner.start(self.exe, args)
        data = (self.stdin.text() + "\n").encode() if self.stdin.text() else b""
        if data:
            self.runner.proc.write(data)
        self.runner.proc.closeWriteChannel()                 # s_client and friends otherwise wait for input forever
        audit.log("openssl command run", self.args.text()[:200])

    def shutdown(self):
        self.runner.stop()


# =============================================================================== the page
class OpensslTab(QWidget):
    def __init__(self):
        super().__init__()
        self.generate, self.inspect_, self.convert = GenerateTab(), InspectTab(), ConvertTab()
        self.hash, self.command = HashTab(), CommandTab()
        self.tabs = QTabWidget()
        for w, label in ((self.generate, "Create"), (self.inspect_, "Read"), (self.convert, "Convert"),
                         (self.hash, "Hash and random"), (self.command, "openssl.exe")):
            self.tabs.addTab(w, label)
        lay = QVBoxLayout(self)
        lay.addWidget(self.tabs)

    def refresh(self):
        pass

    def shutdown(self):
        for w in (self.generate, self.inspect_, self.convert, self.hash, self.command):
            w.shutdown()
