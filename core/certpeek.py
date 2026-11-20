"""A directory server's certificate, read so an admin can see it and choose to trust it (External Identities). Only the TLS
handshake is done (after LDAP's StartTLS request where that is the security): no user name, password or search is sent, and the
certificate is not trusted here. Trusting it pins that exact certificate (directory.py, tls_pinned)."""
import hashlib, socket, ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

TIMEOUT = 8
# LDAPMessage { messageID 1, extendedReq { requestName "1.3.6.1.4.1.1466.20037" } }: RFC 4511's StartTLS request
START_TLS = bytes.fromhex("301d02010177188016") + b"1.3.6.1.4.1.1466.20037"


def fetch(host, port, security, timeout=TIMEOUT):
    """The server's certificate (DER). Raises OSError when there is none to read (closed, not TLS, StartTLS refused)."""
    raw = socket.create_connection((host, int(port)), timeout)
    try:
        if security == "starttls":
            raw.sendall(START_TLS)
            reply = raw.recv(4096)
            at = reply.find(b"\x0a\x01")                  # extendedResp's resultCode, an ENUMERATED: 0 is success
            if at < 0 or at + 2 >= len(reply) or reply[at + 2] != 0:
                raise OSError("StartTLS was refused")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False                       # read only, to be shown: nothing is trusted or sent over it
        ctx.verify_mode = ssl.VerifyMode(0)
        with ctx.wrap_socket(raw, server_hostname=host if not _is_ip(host) else None) as t:
            der = t.getpeercert(binary_form=True)
        if not der:
            raise OSError("no certificate")
        return der
    finally:
        raw.close()


def _is_ip(host):
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        return True
    except OSError:
        return False


def _cn(name):
    got = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return got[0].value if got else name.rfc4514_string()


def _serial_span(der):
    """Where the serial number's bytes are in a DER certificate (start, end): Certificate > tbsCertificate > [version] > serial."""
    def head(i):                                       # the element at i: its tag, where its content starts and ends
        n, j = der[i + 1], i + 2
        if n & 0x80:
            j += n & 0x7F
            n = int.from_bytes(der[i + 2:j], "big")
        return der[i], j, j + n
    _, i, _ = head(0)
    _, i, _ = head(i)
    tag, start, end = head(i)
    if tag == 0xA0:                                    # the version, which a v1 certificate leaves out
        tag, start, end = head(end)
    if tag != 0x02 or not start < end <= len(der):
        raise ValueError("no serial number")
    return start, end


def positive_serial(der):
    """The certificate for cryptography to load, and its real serial number when that differs (else None). A serial number that
    is zero or negative (RFC 5280 forbids both, devices issue them anyway) makes cryptography warn on every load and every read
    of it, and a later release is to refuse the certificate. So the serial is read from the bytes and cryptography is handed a
    copy with a positive one of the same length. Only for reading: a fingerprint or a pin is of the bytes the server sent."""
    try:
        start, end = _serial_span(der)
        n = int.from_bytes(der[start:end], "big", signed=True)
        if n <= 0:
            return der[:start] + b"\x01" * (end - start) + der[end:], n
    except (IndexError, ValueError):
        pass                                           # not laid out like a certificate: cryptography says what is wrong with it
    return der, None


def describe(der):
    """What the trust prompt shows: names (made out to), issuer, valid_from, valid_to (dates), expired, sha256 (AA:BB:...)."""
    c = x509.load_der_x509_certificate(positive_serial(der)[0])
    try:
        names = [n for n in c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        names = []
    cn = _cn(c.subject)
    if not names:
        names = [cn]
    end = c.not_valid_after_utc
    return {"names": names, "issuer": _cn(c.issuer), "valid_from": c.not_valid_before_utc.date().isoformat(), "valid_to": end.date().isoformat(),
            "expired": end < datetime.now(timezone.utc), "sha256": ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())}


def pem(der):
    return ssl.DER_cert_to_PEM_cert(der).encode("ascii")
