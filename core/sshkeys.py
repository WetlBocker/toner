"""SSH key pairs, made and read on this computer (Tools > SSH Keys).

Keys are written in OpenSSH's own file format (what ssh-keygen writes, comment included) and, for PuTTY and WinSCP, as a .ppk
file (version 2, which every PuTTY and WinSCP reads). Nothing here needs ssh-keygen to be installed. add_to_device() puts a
public key in a device's ~/.ssh/authorized_keys over an SSH connection, as ssh-copy-id does."""
import base64
import getpass
import hashlib
import hmac
import os
import socket
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TYPES = [("ed25519", "Ed25519 (recommended)", []), ("rsa", "RSA", [2048, 3072, 4096]), ("ecdsa", "ECDSA", [256, 384, 521])]
DEFAULT_BITS = {"rsa": 3072, "ecdsa": 256}
CURVES = {256: (ec.SECP256R1, "nistp256"), 384: (ec.SECP384R1, "nistp384"), 521: (ec.SECP521R1, "nistp521")}
FILE_NAMES = {"ed25519": "id_ed25519", "rsa": "id_rsa", "ecdsa": "id_ecdsa"}
KDF_ROUNDS = 16                                  # what ssh-keygen uses


class NeedsPassphrase(ValueError):
    pass


class WrongPassphrase(ValueError):
    pass


def default_comment():
    """you@thiscomputer, as ssh-keygen does."""
    try:
        user = getpass.getuser()
    except Exception:
        user = "user"
    return f"{user}@{socket.gethostname()}"


def generate(kind, bits=None):
    """A new private key: kind 'ed25519', 'rsa' or 'ecdsa' (bits: RSA 2048/3072/4096, ECDSA 256/384/521)."""
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=int(bits or DEFAULT_BITS["rsa"]))
    if kind == "ecdsa":
        return ec.generate_private_key(CURVES[int(bits or DEFAULT_BITS["ecdsa"])][0]())
    raise ValueError(f"unknown key type {kind!r}")


def kind_of(key):
    """('ed25519' | 'rsa' | 'ecdsa', bits) for a private or public key."""
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "ed25519", 256
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "rsa", key.key_size
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return "ecdsa", key.curve.key_size
    raise ValueError("Toner reads Ed25519, RSA and ECDSA keys; this is another kind")


def label_of(kind):
    return {"ed25519": "Ed25519", "rsa": "RSA", "ecdsa": "ECDSA"}.get(kind, kind)


def _public(key):
    return key.public_key() if hasattr(key, "public_key") else key


def public_blob(key):
    """The public key in SSH's wire form (what fingerprints and authorized_keys are made of)."""
    line = _public(key).public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return base64.b64decode(line.split()[1])


def algorithm(key):
    """'ssh-ed25519', 'ssh-rsa' or 'ecdsa-sha2-nistp256' (and so on)."""
    return _public(key).public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).split()[0].decode()


def public_line(key, comment=""):
    """The one line that goes in authorized_keys: 'ssh-ed25519 AAAA... comment'."""
    line = f"{algorithm(key)} {base64.b64encode(public_blob(key)).decode()}"
    comment = " ".join(str(comment or "").split())
    return f"{line} {comment}" if comment else line


def fingerprint(key_or_blob):
    """'SHA256:...' as ssh-keygen -l shows it."""
    blob = key_or_blob if isinstance(key_or_blob, bytes) else public_blob(key_or_blob)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


# ------------------------------------------------------------------ SSH's wire encoding
def _s(b):
    return struct.pack(">I", len(b)) + b


def _mp(n):
    return _s(n.to_bytes((n.bit_length() + 8) // 8, "big") if n else b"")


class _Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("the key is cut short")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def string(self):
        return self.take(self.u32())


def _seed(key):
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _openssh_fields(key):
    """The private key as OpenSSH lists it inside its file (type first)."""
    kind, bits = kind_of(key)
    alg = algorithm(key).encode()
    if kind == "ed25519":
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return _s(alg) + _s(pub) + _s(_seed(key) + pub)
    if kind == "rsa":
        p = key.private_numbers()
        return _s(alg) + _mp(p.public_numbers.n) + _mp(p.public_numbers.e) + _mp(p.d) + _mp(p.iqmp) + _mp(p.p) + _mp(p.q)
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return _s(alg) + _s(CURVES[bits][1].encode()) + _s(point) + _mp(key.private_numbers().private_value)


def _wrap(blob, begin, end, width=70):
    b64 = base64.b64encode(blob).decode()
    return f"{begin}\n" + "\n".join(b64[i:i + width] for i in range(0, len(b64), width)) + f"\n{end}\n"


def openssh_private(key, comment="", passphrase=""):
    """The private key file ssh-keygen would write: OpenSSH format, the comment inside, locked with the passphrase
    (bcrypt and AES-256, as ssh-keygen does) when there is one."""
    check = os.urandom(4)
    body = check + check + _openssh_fields(key) + _s(" ".join(str(comment or "").split()).encode())
    if passphrase:
        salt = os.urandom(16)
        cipher, kdf, kdfopts, block = b"aes256-ctr", b"bcrypt", _s(salt) + struct.pack(">I", KDF_ROUNDS), 16
    else:
        cipher, kdf, kdfopts, block = b"none", b"none", b"", 8
    i = 1
    while len(body) % block:
        body += bytes([i])
        i += 1
    if passphrase:
        import bcrypt
        km = bcrypt.kdf(passphrase.encode(), salt, 48, KDF_ROUNDS, ignore_few_rounds=True)
        enc = Cipher(algorithms.AES(km[:32]), modes.CTR(km[32:])).encryptor()
        body = enc.update(body) + enc.finalize()
    blob = (b"openssh-key-v1\0" + _s(cipher) + _s(kdf) + _s(kdfopts) + struct.pack(">I", 1) + _s(public_blob(key)) + _s(body))
    return _wrap(blob, "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----")


_CIPHERS = {b"aes256-ctr": (32, "ctr"), b"aes192-ctr": (24, "ctr"), b"aes128-ctr": (16, "ctr"),
            b"aes256-cbc": (32, "cbc"), b"aes192-cbc": (24, "cbc"), b"aes128-cbc": (16, "cbc")}
_FIELDS = {"ssh-ed25519": 2, "ssh-rsa": 6}       # ECDSA: 3 (curve, point, private value)


def _openssh_comment(text, passphrase):
    """The comment kept inside an OpenSSH private key file ('' when it cannot be read)."""
    try:
        pem = "".join(line for line in text.strip().splitlines()[1:-1])
        r = _Reader(base64.b64decode(pem))
        if r.take(15) != b"openssh-key-v1\0":
            return ""
        cipher, kdf, kdfopts = r.string(), r.string(), r.string()
        r.u32()
        r.string()
        body = r.string()
        if cipher != b"none":
            if kdf != b"bcrypt" or cipher not in _CIPHERS:
                return ""
            import bcrypt
            ko = _Reader(kdfopts)
            salt, rounds = ko.string(), ko.u32()
            size, mode = _CIPHERS[cipher]
            km = bcrypt.kdf(passphrase.encode(), salt, size + 16, rounds, ignore_few_rounds=True)
            dec = Cipher(algorithms.AES(km[:size]), modes.CTR(km[size:]) if mode == "ctr" else modes.CBC(km[size:])).decryptor()
            body = dec.update(body) + dec.finalize()
        b = _Reader(body)
        b.take(8)
        alg = b.string().decode()
        for _ in range(_FIELDS.get(alg, 3 if alg.startswith("ecdsa-") else -1)):
            b.string()
        if alg not in _FIELDS and not alg.startswith("ecdsa-"):
            return ""
        return b.string().decode("utf-8", "replace")
    except Exception:
        return ""


# ------------------------------------------------------------------ PuTTY (.ppk)
def _ppk_private(key):
    kind, _bits = kind_of(key)
    if kind == "ed25519":
        return _s(_seed(key))
    if kind == "rsa":
        p = key.private_numbers()
        return _mp(p.d) + _mp(p.p) + _mp(p.q) + _mp(p.iqmp)
    return _mp(key.private_numbers().private_value)


def _ppk_mac(alg, encryption, comment, pub, priv, passphrase):
    mac_key = hashlib.sha1(b"putty-private-key-file-mac-key" + passphrase.encode()).digest()
    data = _s(alg.encode()) + _s(encryption.encode()) + _s(comment.encode()) + _s(pub) + _s(priv)
    return hmac.new(mac_key, data, hashlib.sha1).hexdigest()


def _ppk_cipher_key(passphrase):
    p = passphrase.encode()
    return (hashlib.sha1(b"\0\0\0\0" + p).digest() + hashlib.sha1(b"\0\0\0\1" + p).digest())[:32]


def ppk(key, comment="", passphrase=""):
    """The private key as PuTTY and WinSCP keep it (.ppk, version 2), locked with the passphrase when there is one."""
    alg, pub, priv = algorithm(key), public_blob(key), _ppk_private(key)
    comment = " ".join(str(comment or "").split())
    encryption = "aes256-cbc" if passphrase else "none"
    if passphrase:                                # padded to the cipher's block, with a hash of the key (as PuTTY does)
        n = -(-len(priv) // 16) * 16
        priv += hashlib.sha1(priv).digest()[:n - len(priv)]
    mac = _ppk_mac(alg, encryption, comment, pub, priv, passphrase)
    if passphrase:
        enc = Cipher(algorithms.AES(_ppk_cipher_key(passphrase)), modes.CBC(b"\0" * 16)).encryptor()
        stored = enc.update(priv) + enc.finalize()
    else:
        stored = priv

    def lines(blob):
        b64 = base64.b64encode(blob).decode()
        return [b64[i:i + 64] for i in range(0, len(b64), 64)]
    pub_lines, priv_lines = lines(pub), lines(stored)
    out = [f"PuTTY-User-Key-File-2: {alg}", f"Encryption: {encryption}", f"Comment: {comment}",
           f"Public-Lines: {len(pub_lines)}", *pub_lines, f"Private-Lines: {len(priv_lines)}", *priv_lines, f"Private-MAC: {mac}"]
    return "\n".join(out) + "\n"


def _read_ppk(text):
    """(public key, comment, encrypted) from a .ppk file (its public half; PuTTYgen changes its passphrase)."""
    fields, lines = {}, text.strip().splitlines()
    i = 0
    pub = b""
    while i < len(lines):
        name, _, value = lines[i].partition(":")
        value = value.strip()
        if name == "Public-Lines":
            n = int(value)
            pub = base64.b64decode("".join(lines[i + 1:i + 1 + n]))
            i += n
        else:
            fields[name] = value
        i += 1
    key = serialization.load_ssh_public_key(f"{_Reader(pub).string().decode()} {base64.b64encode(pub).decode()}".encode())
    return key, fields.get("Comment", ""), fields.get("Encryption", "none") != "none"


# ------------------------------------------------------------------ reading any key
def read(text, passphrase=""):
    """What a pasted or opened key is. Returns a dict: key (the private key, or None for a public one), public, kind, bits,
    comment, encrypted, form ('OpenSSH private key', 'PEM private key', 'PuTTY private key', 'Public key').
    Raises NeedsPassphrase when it is locked and no passphrase was given, WrongPassphrase when the one given is wrong,
    ValueError when it is not a key Toner can read."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Paste a key or open a key file first.")
    data = text.encode()
    private, comment, encrypted, form = None, "", False, ""
    if text.startswith("PuTTY-User-Key-File-"):
        public, comment, encrypted = _read_ppk(text)
        form = "PuTTY private key"
    elif text.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"):
        form = "OpenSSH private key"
        try:
            private = serialization.load_ssh_private_key(data, None)
        except TypeError:
            encrypted = True
            if not passphrase:
                raise NeedsPassphrase("This key is locked with a passphrase. Enter it to read the key.") from None
            try:
                private = serialization.load_ssh_private_key(data, passphrase.encode())
            except ValueError:
                raise WrongPassphrase("That passphrase isn't right for this key.") from None
        comment = _openssh_comment(text, passphrase)
        public = private.public_key()
    elif text.startswith("-----BEGIN") and "PRIVATE KEY-----" in text.splitlines()[0]:
        form = "PEM private key"
        try:
            private = serialization.load_pem_private_key(data, None)
        except TypeError:
            encrypted = True
            if not passphrase:
                raise NeedsPassphrase("This key is locked with a passphrase. Enter it to read the key.") from None
            try:
                private = serialization.load_pem_private_key(data, passphrase.encode())
            except ValueError:
                raise WrongPassphrase("That passphrase isn't right for this key.") from None
        public = private.public_key()
    elif text.startswith("---- BEGIN SSH2 PUBLIC KEY ----"):
        form = "Public key"
        body, more = [], False
        for line in text.splitlines()[1:-1]:
            if more or ":" in line and not body:
                name, _, value = line.partition(":")
                if name.strip().lower() == "comment":
                    comment = value.strip().strip('"')
                more = line.endswith("\\")
                continue
            body.append(line.strip())
        blob = base64.b64decode("".join(body))
        public = serialization.load_ssh_public_key(f"{_Reader(blob).string().decode()} {base64.b64encode(blob).decode()}".encode())
    else:
        form = "Public key"
        parts = text.split(None, 2)
        try:
            public = serialization.load_ssh_public_key(" ".join(parts[:2]).encode())
        except Exception:
            raise ValueError("This isn't an SSH key Toner can read: paste a private key, a .ppk file or a public key line.") from None
        comment = parts[2].strip() if len(parts) > 2 else ""
    kind, bits = kind_of(public)
    return dict(key=private, public=public, kind=kind, bits=bits, comment=comment, encrypted=encrypted, form=form)


# ------------------------------------------------------------------ files
def write_private(path, text):
    """A private key file only this user can read (OpenSSH refuses keys others can read)."""
    if os.path.exists(path):
        os.chmod(path, 0o600)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if os.name == "nt":
        _owner_only(path)


def _owner_only(path):
    """Windows: drop the entries the file inherits from its folder and give this user full control, as Windows' OpenSSH asks
    ('Bad permissions' otherwise, in folders that let others read)."""
    import subprocess
    from core.platforms import NO_WINDOW
    user = os.environ.get("USERNAME") or getpass.getuser()
    who = f"{os.environ['USERDOMAIN']}\\{user}" if os.environ.get("USERDOMAIN") else user
    try:
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", f"{who}:F"], capture_output=True, timeout=30,
                       creationflags=NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        pass


def write_public(path, line):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(line.rstrip("\n") + "\n")


def ssh_folder():
    """~/.ssh when it exists, else the home folder (where the save dialog opens)."""
    d = os.path.join(os.path.expanduser("~"), ".ssh")
    return d if os.path.isdir(d) else os.path.expanduser("~")


# ------------------------------------------------------------------ onto a device
ADDED, PRESENT = "TONER-KEY-ADDED", "TONER-KEY-PRESENT"


def _q(s):
    return "'" + s.replace("'", "'\\''") + "'"


def authorized_keys_command(line):
    """The shell command that adds `line` to ~/.ssh/authorized_keys once (as ssh-copy-id does: a new folder and file are made
    readable only by the user; an existing key, whatever its comment, is left alone)."""
    line = " ".join(line.split())
    parts = line.split(None, 2)
    if len(parts) < 2:
        raise ValueError("That isn't a public key line ('ssh-ed25519 AAAA... comment').")
    try:
        serialization.load_ssh_public_key(" ".join(parts[:2]).encode())
    except Exception:
        raise ValueError("That isn't a public key line ('ssh-ed25519 AAAA... comment').") from None
    f = "~/.ssh/authorized_keys"
    return ("umask 077; mkdir -p ~/.ssh && touch " + f + " && "
            f"if grep -qF {_q(parts[0] + ' ' + parts[1])} {f}; then echo {PRESENT}; else "
            f"{{ [ -s {f} ] && [ -n \"$(tail -c1 {f})\" ] && echo >> {f}; }}; "
            f"printf '%s\\n' {_q(line)} >> {f} && echo {ADDED}; fi")


def add_to_device(client, line, timeout=30):
    """Add the public key line over an open paramiko connection. Returns 'added' or 'present'; raises ValueError with what the
    device said when it could not."""
    chan = client.get_transport().open_session(timeout=timeout)
    chan.settimeout(timeout)
    chan.exec_command(authorized_keys_command(line))
    out, err = b"", b""
    while True:
        if chan.recv_ready():
            out += chan.recv(4096)
        elif chan.recv_stderr_ready():
            err += chan.recv_stderr(4096)
        elif chan.exit_status_ready():
            while chan.recv_ready():
                out += chan.recv(4096)
            while chan.recv_stderr_ready():
                err += chan.recv_stderr(4096)
            break
        else:
            import time
            time.sleep(0.05)
    chan.close()
    text = out.decode("utf-8", "replace")
    if PRESENT in text:
        return "present"
    if ADDED in text:
        return "added"
    why = " ".join((err or out).decode("utf-8", "replace").split())
    raise ValueError(why or "the device did not run the command. It may not have a Unix shell (most network devices take "
                            "keys on their own admin page).")
