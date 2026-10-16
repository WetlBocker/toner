"""Which certificate authorities Toner's web requests trust: its own list of public ones, and what Windows trusts.

Toner carries the public list (certifi), so it works the same on every computer. On a network that inspects HTTPS (a
firewall with SSL inspection, or antivirus that scans HTTPS) the traffic is re-signed with a certificate that only the
computer's own store trusts, and a browser is fine while Toner is not. So at start Toner writes one file with both: the
public list and the authorities in the Windows store (Trusted Root and Intermediate, for server authentication), and
points its web requests at it. Connections that are set not to check certificates are unchanged.
"""
import hashlib
import os
import ssl
import warnings

from core import db

SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
MARK = "# ---- trusted by Windows on this computer (added by Toner)"


def bundle_path():
    return db.db_path().parent / "ca-bundle.pem"


def windows_pems():
    """PEM text of each certificate authority Windows trusts for server authentication. Certificates that cannot be read
    are left out, so one odd entry in the store cannot spoil the file."""
    from cryptography import x509
    out, seen = [], set()
    for store in ("ROOT", "CA"):
        try:
            items = ssl.enum_certificates(store)
        except (AttributeError, OSError):                 # not Windows, or the store cannot be opened
            continue
        for der, encoding, usage in items:
            if encoding != "x509_asn" or not (usage is True or SERVER_AUTH in usage):
                continue
            digest = hashlib.sha256(der).digest()
            if digest in seen:
                continue
            try:
                with warnings.catch_warnings():               # old store entries (a negative serial number) only warn
                    warnings.simplefilter("ignore")
                    x509.load_der_x509_certificate(der)
            except Exception:
                continue
            seen.add(digest)
            out.append(ssl.DER_cert_to_PEM_cert(der))
    return out


def install():
    """Write the combined file and make web requests use it. Returns its path, or None when nothing was changed: someone
    already chose a file (REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE), Windows added nothing, or the file would not load."""
    if os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE"):
        return None
    try:
        import certifi
        extra = windows_pems()
        if not extra:
            return None
        with open(certifi.where(), encoding="utf-8") as f:
            text = f.read().rstrip() + "\n\n" + MARK + "\n" + "".join(extra)
        path = bundle_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            same = path.read_text(encoding="utf-8") == text
        except OSError:
            same = False
        if not same:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, path)
        ssl.create_default_context(cafile=str(path))        # it must load, or it is not used
    except Exception:
        return None
    os.environ["REQUESTS_CA_BUNDLE"] = str(path)
    return path


SSL_HINT = ("If this network inspects HTTPS (a firewall with SSL inspection, or antivirus that scans HTTPS), the inspecting "
            "certificate must be in the Windows certificate store (Trusted Root Certification Authorities); Toner trusts what "
            "Windows trusts. Restart Toner after adding it.")
