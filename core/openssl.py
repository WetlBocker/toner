"""An OpenSSL toolbox that needs no openssl.exe: make keys, CSRs and self-signed certificates, read any certificate, request
or key, convert between PEM, DER and PKCS#12 (.pfx), hash, encode and make random bytes, and fetch a server's chain.

It uses the `cryptography` package, which is built on OpenSSL, so the results are the same as the command-line tool's. For the
rest of the command line, find_openssl() locates a real openssl.exe if the computer has one (Git for Windows ships one).
"""
import base64
import hashlib
import ipaddress
import os
import re
import secrets
import shutil
import socket
import ssl
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

KEY_TYPES = [("rsa2048", "RSA 2048"), ("rsa3072", "RSA 3072"), ("rsa4096", "RSA 4096"), ("p256", "ECDSA P-256"),
             ("p384", "ECDSA P-384"), ("ed25519", "Ed25519")]
DIGESTS = ["sha256", "sha1", "sha384", "sha512", "sha224", "md5", "sha3_256", "sha3_512", "blake2b"]
_PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)
_ATTRS = [("CN", NameOID.COMMON_NAME), ("O", NameOID.ORGANIZATION_NAME), ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
          ("C", NameOID.COUNTRY_NAME), ("ST", NameOID.STATE_OR_PROVINCE_NAME), ("L", NameOID.LOCALITY_NAME),
          ("emailAddress", NameOID.EMAIL_ADDRESS)]


def _pw(text):
    return text.encode() if text else None


# ---------------------------------------------------------------- making things
def generate_key(kind="rsa2048", passphrase=""):
    """A new private key as PEM text (PKCS#8, encrypted when a passphrase is given)."""
    return _key_pem(_new_key(kind), passphrase)


def _new_key(kind):
    if kind.startswith("rsa"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(kind[3:]))
    if kind == "p256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "p384":
        return ec.generate_private_key(ec.SECP384R1())
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(f"unknown key type '{kind}'")


def _key_pem(key, passphrase=""):
    enc = serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc).decode()


def load_key(pem, passphrase=""):
    """A private key from PEM text (any of the usual PEM key types)."""
    data = pem.encode() if isinstance(pem, str) else pem
    try:
        try:
            return serialization.load_pem_private_key(data, _pw(passphrase))
        except TypeError:
            if passphrase:                                     # a passphrase was typed but the key has none: that is fine
                return serialization.load_pem_private_key(data, None)
            raise
    except TypeError:
        raise ValueError("the key is encrypted: enter its passphrase") from None
    except ValueError as e:
        if "password" in str(e).lower() or "decrypt" in str(e).lower() or "bad" in str(e).lower():
            raise ValueError("wrong passphrase for the key") from None
        raise ValueError(f"not a readable private key ({e})") from None


def subject_name(fields):
    """x509 Name from {'CN': ..., 'O': ..., 'C': ...} (empty values are left out)."""
    parts = []
    for key, oid in _ATTRS:
        value = (fields.get(key) or "").strip()
        if value:
            if key == "C" and len(value) != 2:
                raise ValueError("the country must be a two-letter code, e.g. US")
            parts.append(x509.NameAttribute(oid, value.upper() if key == "C" else value))
    return x509.Name(parts)


def parse_sans(text):
    """'a.example.com, 10.0.0.1, IP:10.0.0.2, DNS:b.example.com, email:me@x.org' -> general names."""
    names = []
    for item in re.split(r"[,\s;]+", (text or "").strip()):
        if not item:
            continue
        kind, sep, value = item.partition(":")
        if not sep or kind.lower() not in ("dns", "ip", "email", "uri"):
            kind, value = "", item
        kind = kind.lower()
        if kind == "email":
            names.append(x509.RFC822Name(value))
        elif kind == "uri":
            names.append(x509.UniformResourceIdentifier(value))
        else:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(value)))
            except ValueError:
                if kind == "ip":
                    raise ValueError(f"'{value}' is not an IP address") from None
                names.append(x509.DNSName(value))
    return names


def _hash_for(key):
    return None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()


def make_csr(subject, sans="", kind="rsa2048", passphrase="", existing_key="", existing_passphrase=""):
    """(private key PEM, CSR PEM). Pass existing_key to request a certificate for a key you already have."""
    name = subject_name(subject)
    names = parse_sans(sans)
    if not len(name) and not names:
        raise ValueError("enter a common name or at least one subject alternative name")
    key = load_key(existing_key, existing_passphrase) if existing_key.strip() else _new_key(kind)
    b = x509.CertificateSigningRequestBuilder().subject_name(name)
    if names:
        b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
    csr = b.sign(key, _hash_for(key))
    return (_key_pem(key, passphrase) if not existing_key.strip() else ""), csr.public_bytes(serialization.Encoding.PEM).decode()


def make_self_signed(subject, sans="", kind="rsa2048", days=365, passphrase="", ca=False, existing_key="", existing_passphrase=""):
    """(private key PEM, certificate PEM) for a self-signed certificate (a root CA when ca=True)."""
    name = subject_name(subject)
    names = parse_sans(sans)
    if not len(name) and not names:
        raise ValueError("enter a common name or at least one subject alternative name")
    days = int(days)
    if not 1 <= days <= 36500:
        raise ValueError("days must be between 1 and 36500")
    key = load_key(existing_key, existing_passphrase) if existing_key.strip() else _new_key(kind)
    if not len(name):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(names[0].value))])
    now = datetime.now(timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
         .not_valid_after(now + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                          key_encipherment=False, data_encipherment=False, key_agreement=False,
                                          encipher_only=False, decipher_only=False), critical=True)
    else:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    if names:
        b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
    cert = b.sign(key, _hash_for(key))
    return (_key_pem(key, passphrase) if not existing_key.strip() else ""), cert.public_bytes(serialization.Encoding.PEM).decode()


# ---------------------------------------------------------------- reading things
def _blocks(data):
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else data
    return [(label, m) for m in [x.group(0) for x in _PEM.finditer(text)] for label in [_PEM.match(m).group(1)]]


def _spki(public_key):
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _key_text(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA, {public_key.key_size} bit"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC, curve {public_key.curve.name}"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return type(public_key).__name__


def _colon(raw):
    return ":".join(f"{b:02X}" for b in raw)


def _name_text(name):
    return ", ".join(f"{a.rfc4514_attribute_name}={a.value}" for a in name) or "(empty)"


def _general(names):
    out = []
    for n in names:
        if isinstance(n, x509.DNSName):
            out.append(f"DNS:{n.value}")
        elif isinstance(n, x509.IPAddress):
            out.append(f"IP:{n.value}")
        elif isinstance(n, x509.RFC822Name):
            out.append(f"email:{n.value}")
        elif isinstance(n, x509.UniformResourceIdentifier):
            out.append(f"URI:{n.value}")
        else:
            out.append(str(n.value))
    return out


def _extensions(exts):
    lines = []
    for e in exts:
        v, crit = e.value, " (critical)" if e.critical else ""
        if isinstance(v, x509.SubjectAlternativeName):
            lines.append(f"    Subject Alternative Name{crit}: " + ", ".join(_general(v)))
        elif isinstance(v, x509.BasicConstraints):
            lines.append(f"    Basic Constraints{crit}: CA={'TRUE' if v.ca else 'FALSE'}" + (f", pathlen={v.path_length}" if v.path_length is not None else ""))
        elif isinstance(v, x509.KeyUsage):
            on = [n.replace("_", " ") for n in ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment", "key_agreement",
                                                "key_cert_sign", "crl_sign") if getattr(v, n)]
            lines.append(f"    Key Usage{crit}: " + ", ".join(on))
        elif isinstance(v, x509.ExtendedKeyUsage):
            lines.append(f"    Extended Key Usage{crit}: " + ", ".join(o._name if o._name != "Unknown OID" else o.dotted_string for o in v))
        elif isinstance(v, x509.SubjectKeyIdentifier):
            lines.append(f"    Subject Key Identifier: {_colon(v.digest)}")
        elif isinstance(v, x509.AuthorityKeyIdentifier) and v.key_identifier:
            lines.append(f"    Authority Key Identifier: {_colon(v.key_identifier)}")
        elif isinstance(v, x509.AuthorityInformationAccess):
            for d in v:
                lines.append(f"    {d.access_method._name}: {d.access_location.value}")
        elif isinstance(v, x509.CRLDistributionPoints):
            for d in v:
                lines.extend(f"    CRL Distribution Point: {u}" for u in _general(d.full_name or []))
        else:
            lines.append(f"    {e.oid._name if e.oid._name != 'Unknown OID' else e.oid.dotted_string}{crit}")
    return lines


def describe_cert(cert):
    now = datetime.now(timezone.utc)
    left = (cert.not_valid_after_utc - now).days
    state = "EXPIRED" if left < 0 else f"{left} days left"
    lines = ["Certificate",
             f"  Subject:      {_name_text(cert.subject)}", f"  Issuer:       {_name_text(cert.issuer)}",
             "  Self-signed:  " + ("yes" if cert.subject == cert.issuer else "no"),
             f"  Serial:       {_colon(cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8 or 1, 'big'))}",
             f"  Not before:   {cert.not_valid_before_utc:%Y-%m-%d %H:%M:%S} UTC",
             f"  Not after:    {cert.not_valid_after_utc:%Y-%m-%d %H:%M:%S} UTC  ({state})",
             f"  Public key:   {_key_text(cert.public_key())}",
             f"  Signature:    {cert.signature_algorithm_oid._name}", "  Extensions:"]
    lines += _extensions(cert.extensions) or ["    (none)"]
    lines += [f"  SHA-256:      {_colon(cert.fingerprint(hashes.SHA256()))}", f"  SHA-1:        {_colon(cert.fingerprint(hashes.SHA1()))}"]
    return "\n".join(lines)


def describe_csr(csr):
    lines = ["Certificate request (CSR)", f"  Subject:      {_name_text(csr.subject)}", f"  Public key:   {_key_text(csr.public_key())}",
             f"  Signature:    {csr.signature_algorithm_oid._name}  ({'valid' if csr.is_signature_valid else 'INVALID'})", "  Requested extensions:"]
    lines += _extensions(csr.extensions) or ["    (none)"]
    return "\n".join(lines)


def describe_key(key, encrypted=False):
    return "\n".join(["Private key", "  Type:         " + _key_text(key.public_key()), "  Protected:    " + ("yes (encrypted)" if encrypted else "no (not encrypted)")])


def inspect(data, passphrase=""):
    """Plain-text description of whatever is in data: PEM certificates, requests and keys, a DER certificate or request,
    or a .pfx/.p12 bundle. When it holds more than one thing, says whether the keys match."""
    if isinstance(data, str):
        data = data.encode()
    parts, keys = [], []                                   # keys: (label, SPKI bytes)
    blocks = _blocks(data)
    if blocks:
        for label, text in blocks:
            if label in ("CERTIFICATE", "TRUSTED CERTIFICATE"):
                c = x509.load_pem_x509_certificate(text.encode())
                parts.append(describe_cert(c)); keys.append(("certificate " + _name_text(c.subject)[:40], _spki(c.public_key())))
            elif label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
                r = x509.load_pem_x509_csr(text.encode())
                parts.append(describe_csr(r)); keys.append(("request " + _name_text(r.subject)[:40], _spki(r.public_key())))
            elif "PRIVATE KEY" in label:
                protected = label == "ENCRYPTED PRIVATE KEY" or "Proc-Type: 4,ENCRYPTED" in text
                if protected:
                    if not passphrase:
                        parts.append("Private key\n  Protected:    yes (encrypted): enter its passphrase to read it"); continue
                k = load_key(text, passphrase)
                parts.append(describe_key(k, encrypted=protected)); keys.append(("private key", _spki(k.public_key())))
            elif label == "PUBLIC KEY":
                k = serialization.load_pem_public_key(text.encode())
                parts.append("Public key\n  Type:         " + _key_text(k)); keys.append(("public key", _spki(k)))
            else:
                parts.append(f"({label.title()}: not described)")
    else:
        try:
            c = x509.load_der_x509_certificate(data)
            parts.append("(DER certificate)\n" + describe_cert(c)); keys.append(("certificate", _spki(c.public_key())))
        except ValueError:
            try:
                r = x509.load_der_x509_csr(data)
                parts.append("(DER request)\n" + describe_csr(r)); keys.append(("request", _spki(r.public_key())))
            except ValueError:
                try:
                    key, cert, extra = pkcs12.load_key_and_certificates(data, _pw(passphrase))
                except ValueError as e:
                    if "password" in str(e).lower() or "mac" in str(e).lower():
                        raise ValueError("this looks like a .pfx/.p12 file: enter its password") from None
                    raise ValueError("not recognised as a PEM, DER or PKCS#12 file") from None
                parts.append("(PKCS#12 bundle)")
                if key is not None:
                    parts.append(describe_key(key)); keys.append(("private key", _spki(key.public_key())))
                if cert is not None:
                    parts.append(describe_cert(cert)); keys.append(("certificate", _spki(cert.public_key())))
                parts += [describe_cert(c) for c in extra or []]
    if not parts:
        raise ValueError("nothing readable was found")
    if len(keys) > 1:
        first = keys[0][1]
        same = [k[0] for k in keys[1:] if k[1] == first]
        diff = [k[0] for k in keys[1:] if k[1] != first]
        lines = []
        if same:
            lines.append(f"Same key pair as the first item ({keys[0][0]}): {', '.join(same)}.")
        if diff:
            lines.append(f"NOT the same key pair as the first item: {', '.join(diff)}.")
        if not diff:
            lines.append("They match.")
        parts.append("Key check\n  " + "\n  ".join(lines))
    return "\n\n".join(parts)


# ---------------------------------------------------------------- converting
def to_der(data, passphrase=""):
    """PEM certificate, request or key -> DER bytes (the first item)."""
    blocks = _blocks(data)
    if not blocks:
        raise ValueError("paste a PEM certificate, request or key")
    label, text = blocks[0]
    if "CERTIFICATE REQUEST" in label:
        return x509.load_pem_x509_csr(text.encode()).public_bytes(serialization.Encoding.DER)
    if "CERTIFICATE" in label:
        return x509.load_pem_x509_certificate(text.encode()).public_bytes(serialization.Encoding.DER)
    if "PRIVATE KEY" in label:
        return load_key(text, passphrase).private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    raise ValueError(f"cannot convert a {label.title()}")


def to_pem(der):
    """DER certificate or request -> PEM text."""
    for loader in (x509.load_der_x509_certificate, x509.load_der_x509_csr):
        try:
            return loader(der).public_bytes(serialization.Encoding.PEM).decode()
        except ValueError:
            pass
    raise ValueError("not a DER certificate or request")


def to_pfx(data, key_passphrase="", export_password="", name=""):
    """PEM certificate(s) and a private key -> a PKCS#12 file (bytes). The certificate that matches the key is the leaf."""
    certs = [x509.load_pem_x509_certificate(t.encode()) for l, t in _blocks(data) if l == "CERTIFICATE"]
    keys = [t for l, t in _blocks(data) if "PRIVATE KEY" in l]
    if not certs or not keys:
        raise ValueError("a .pfx needs a certificate and its private key: paste both")
    key = load_key(keys[0], key_passphrase)
    spki = _spki(key.public_key())
    leaf = next((c for c in certs if _spki(c.public_key()) == spki), None)
    if leaf is None:
        raise ValueError("none of the certificates matches the private key")
    chain = [c for c in certs if c is not leaf]
    enc = serialization.BestAvailableEncryption(export_password.encode()) if export_password else serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates((name or "").encode() or None, key, leaf, chain or None, enc)


def from_pfx(data, password="", out_passphrase=""):
    """A .pfx/.p12 file -> PEM text: certificate, chain, then the private key."""
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(data, _pw(password))
    except ValueError:
        raise ValueError("could not open the file: wrong password, or it is not a PKCS#12 file") from None
    out = []
    if cert is not None:
        out.append(cert.public_bytes(serialization.Encoding.PEM).decode())
    out += [c.public_bytes(serialization.Encoding.PEM).decode() for c in extra or []]
    if key is not None:
        out.append(_key_pem(key, out_passphrase))
    return "".join(out)


def change_passphrase(pem, old="", new=""):
    """Add, change or remove (new = '') the passphrase on a private key."""
    if not _blocks(pem) or not any("PRIVATE KEY" in l for l, _ in _blocks(pem)):
        raise ValueError("paste a PEM private key")
    return _key_pem(load_key(pem, old), new)


# ---------------------------------------------------------------- hashes, encodings, random
def digest(data, algorithm="sha256"):
    if algorithm not in DIGESTS:
        raise ValueError(f"unknown digest '{algorithm}'")
    h = hashlib.new(algorithm) if algorithm != "blake2b" else hashlib.blake2b()
    h.update(data if isinstance(data, bytes) else data.encode())
    return h.hexdigest()


def base64_encode(data, wrap=True):
    raw = base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()
    return "\n".join(raw[i:i + 64] for i in range(0, len(raw), 64)) if wrap else raw


def base64_decode(text):
    try:
        return base64.b64decode("".join(text.split()), validate=True)
    except Exception:
        raise ValueError("that is not valid base64") from None


def random_bytes(count, fmt="hex"):
    count = int(count)
    if not 1 <= count <= 1_000_000:
        raise ValueError("choose between 1 and 1,000,000 bytes")
    raw = secrets.token_bytes(count)
    return raw.hex() if fmt == "hex" else base64.b64encode(raw).decode()


# ---------------------------------------------------------------- a server's certificates
def fetch_chain(host, port=443, servername="", timeout=8):
    """(PEM text of every certificate the server sent, a line about the connection). The chain is NOT validated:
    this is for looking at what a server presents, including expired or self-signed ones."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, int(port)), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=servername or host) as t:
            chain = t.get_unverified_chain() if hasattr(t, "get_unverified_chain") else [t.getpeercert(binary_form=True)]
            info = f"{t.version()}, {t.cipher()[0]}"
    pem = "".join(x509.load_der_x509_certificate(c if isinstance(c, bytes) else c.public_bytes(serialization.Encoding.DER))
                  .public_bytes(serialization.Encoding.PEM).decode() for c in chain)
    return pem, f"{host}:{port} answered with {len(chain)} certificate(s) over {info}"


# ---------------------------------------------------------------- a real openssl.exe, if there is one
CANDIDATES = (r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe", r"C:\Program Files\OpenSSL\bin\openssl.exe",
              r"C:\Program Files\Git\usr\bin\openssl.exe", r"C:\Program Files\Git\mingw64\bin\openssl.exe",
              r"C:\Program Files (x86)\Git\usr\bin\openssl.exe", r"C:\msys64\usr\bin\openssl.exe")


def find_openssl(configured=""):
    """Path to openssl.exe: the one chosen in the tool, else PATH, else the usual install folders. '' if none."""
    if configured and os.path.isfile(configured):
        return configured
    return shutil.which("openssl") or next((p for p in CANDIDATES if os.path.isfile(p)), "")


PRESETS = [("Version and build details", "version -a"),
           ("Look at a server's certificate", "s_client -connect example.com:443 -servername example.com -showcerts"),
           ("Read a certificate file", "x509 -in certificate.pem -noout -text"),
           ("Check when a certificate expires", "x509 -in certificate.pem -noout -dates"),
           ("New key and CSR", "req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr"),
           ("Self-signed certificate (1 year)", "req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365"),
           ("Verify a chain", "verify -CAfile ca.pem certificate.pem"),
           ("Test a TLS 1.2 handshake", "s_client -connect example.com:443 -tls1_2"),
           ("List ciphers", "ciphers -v")]
