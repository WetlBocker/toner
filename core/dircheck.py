"""The background check of a directory account: every 15 minutes, off the UI thread, ask the directory (as the service account)
whether the signed-in person is still found, enabled and in a Toner group. If not, Toner locks and won't unlock until a new sign-in."""
import logging
import threading
import time

from core import audit, datakey, directory, passvault, quiet, roles, session

INTERVAL = 15 * 60
FIRST = 5                      # seconds after start before the first check
log = logging.getLogger(__name__)
_lock = threading.Lock()
_thread = _stop = None


def _refuse():
    try:
        session.lock(reason="refused")
    except RuntimeError:       # signed out or in the recovery key meanwhile: nothing to lock
        return
    audit.log("locked: the directory refused the account")


def run_once():
    """"ok", "refused", "offline" (nothing changed) or "skipped"."""
    name = session.user()
    if session.kind() != "directory" or session.state() not in ("open", "locked") or name is None:
        return "skipped"
    doc = roles.verified() if roles.state() == "ok" else None      # a hand-edited list never receives the service password
    if doc is None:
        return "skipped"
    rec = datakey.directory_account(name)
    cfg = next((d for d in doc.get("directories") or [] if rec and d.get("id") == rec.get("directory")), None)
    if cfg is None:
        _refuse()
        return "refused"
    try:
        password = passvault.get(f"service:directory-{cfg['id']}")
    except Exception:
        password = None
    if not password:
        return "offline"
    try:
        user = directory.look_up(cfg, rec["guid"], password)
    except directory.NotFound:
        user = None
    except Exception as e:     # unreachable, a refused service bind, a config problem: never a reason to lock anyone out
        log.info("directory check failed: %s", type(e).__name__)
        return "offline"
    role = directory.role_for(cfg, user.groups) if user is not None and user.enabled else None
    if role is None:
        _refuse()
        return "refused"
    datakey.set_online(name, time.time())
    datakey.set_groups_role(name, role)
    return "ok"


def _loop(stop, interval, first):
    wait = first
    while not stop.wait(wait):
        try:
            run_once()
        except Exception:
            quiet.ignored()
        wait = interval


def start(interval=INTERVAL, first=FIRST):
    global _thread, _stop
    with _lock:
        if _thread is not None and _thread.is_alive():
            return
        _stop = threading.Event()
        _thread = threading.Thread(target=_loop, args=(_stop, interval, first), name="dircheck", daemon=True)
        _thread.start()


def stop():
    global _thread, _stop
    with _lock:
        t, ev, _thread, _stop = _thread, _stop, None, None
    if ev is not None:
        ev.set()
    if t is not None and t is not threading.current_thread():
        t.join(5)
