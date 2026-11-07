"""What the External Identities flow (ui/identitywizard.py) shares: the approved messages, what to say for a failure, the CA file
read once with its hash, the vault name of a directory's service password, and the small helpers for the typed settings. The
service password goes to the vault only; it is never in netcheck.keys, a log, the audit or a message."""
import hashlib

from core import directory

FAILED = "Toner couldn't connect: {reason}"
NO_STORE = "This computer has no protected store, so Duo can't be turned on here."
TAKEN = "Another directory already uses {value}."
CA_UNREADABLE = "Toner can't read that CA file."
CA_CHANGED = "The directory's CA file changed. An admin needs to save the directory again."
KINDS = (("Active Directory", "ad"), ("LDAP", "ldap"))
SECURITY = (("LDAPS", "ldaps", 636), ("StartTLS", "starttls", 389))


class Said(Exception):
    """Already in the approved words."""


def service_key(directory_id):
    return f"service:directory-{directory_id}"


def words(e):
    """What to show for a failed connection (step 3, a search) or Save. Never a secret: directory's messages hold none."""
    if isinstance(e, Said):
        return str(e)
    if isinstance(e, directory.CaChanged):
        return CA_CHANGED
    known = (directory.InsecureConfig, directory.Unreachable, directory.BadCredentials)
    return FAILED.format(reason=str(e) if isinstance(e, known) else type(e).__name__)


def with_ca(cfg, signed=None):
    """`cfg` ready to connect (on the Job's thread: a CA path may be slow to open). A CA file is read here, and its SHA-256 is
    `signed` (the hash in the signed list, so a changed file is caught) or else the file's own (one just chosen, or a Save)."""
    if cfg.get("ca_file"):
        try:
            with open(cfg["ca_file"], "rb") as f:
                data = f.read()
        except OSError:
            raise Said(CA_UNREADABLE) from None
        cfg["ca_sha256"] = signed or hashlib.sha256(data).hexdigest()
    return cfg


def _netbios(cfg, pw):
    """[the domain's NetBIOS name] read from the directory when an Active Directory has none typed, else []."""
    return [directory.netbios(cfg, pw)] if cfg["kind"] == "ad" and not cfg["netbios"] else []


def _split(text):
    """Comma-separated values, trimmed, each once (case aside)."""
    out = {}
    for v in (x.strip() for x in text.split(",")):
        if v:
            out.setdefault(v.casefold(), v)
    return list(out.values())


def _taken(dirs, directory_id, cfg):
    """A NetBIOS name or suffix another directory already has (as typed), else None."""
    others = [d for d in dirs if d.get("id") != directory_id]
    for field in ("netbios", "suffixes"):
        vals = lambda d: [d.get(field)] if field == "netbios" else list(d.get(field) or [])
        used = {str(v).casefold() for d in others for v in vals(d) if v}
        hit = next((v for v in vals(cfg) if v and v.casefold() in used), None)
        if hit:
            return hit
    return None
