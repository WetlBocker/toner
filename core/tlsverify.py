"""Whether a device's HTTPS connections check its certificate, in one place.

Every API driver, the API config backup, the topology reader and the key bootstraps used to read the device's `verify_ssl` flag
themselves and call `urllib3.disable_warnings()` when it was off. That call silences every urllib3 warning for the rest of the
process (not only the one about unverified HTTPS), so one FortiGate with a self-signed certificate hid warnings about
anything else too. `verify(dev)` gives the flag, and when it is off it hides only the "unverified HTTPS request" warning,
once. New devices follow Settings > General > "Verify SSL certificates on new devices" (`default_for_new`), which is on
unless it has been turned off; devices that are already stored keep the flag they were saved with."""
import threading
import warnings

_lock = threading.Lock()
_silenced = False


def verify(dev):
    """True when `dev`'s HTTPS connections must present a trusted certificate. False hides the unverified-request warning
    (that one warning, for the process) because the person chose this knowingly in the device's dialog."""
    on = bool(dev.get("verify_ssl")) if dev else True
    if not on:
        _silence_insecure_warning()
    return on


def default_for_new():
    """The `verify_ssl` value for a device being added without an explicit choice: by import, discovery, an agent signing
    itself up or a session import. Follows the setting; True when the setting cannot be read."""
    try:
        from core import db
        return 1 if db.get_setting("default_verify_ssl") else 0
    except Exception:
        return 1


def _silence_insecure_warning():
    global _silenced
    if _silenced:
        return
    with _lock:
        if _silenced:
            return
        try:
            from urllib3.exceptions import InsecureRequestWarning
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)
        except Exception:                 # urllib3 missing or renamed: nothing to silence
            pass
        _silenced = True
