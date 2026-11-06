"""The background check of a directory account: every 15 minutes, off the UI thread, ask the directory (as the service account)
whether the signed-in person is still found, enabled and in a Toner group. If not, Toner locks and won't unlock until a new sign-in.
The directory, the account's guid and its directory id come from what an Admin last signed (roles.last_signed), never from the
file, so an edit can neither switch the check off nor send the service password anywhere else."""
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
    last = roles.last_signed()          # what an Admin last signed, kept in the encrypted database: a file edit can't change it
    if last is None:
        return "skipped"
    acct = (last.get("accounts") or {}).get(name) or {}
    cfg = next((d for d in last.get("directories") or []
                if isinstance(d, dict) and acct.get("directory") is not None and d.get("id") == acct["directory"]), None)
    if cfg is None or not acct.get("guid"):
        _refuse()
        return "refused"
    try:
        password = passvault.get(f"service:directory-{cfg['id']}")
    except Exception:
        password = None
    if not password:
        return "offline"
    try:
        user = directory.look_up(cfg, acct["guid"], password)
    except directory.NotFound:
        user = None
    except Exception as e:     # unreachable, a refused service bind, a config problem: never a reason to lock anyone out
        log.info("directory check failed: %s", type(e).__name__)
        return "offline"
    role = directory.role_for(cfg, user.groups, user.dn) if user is not None and user.enabled else None
    if role is None:
        _refuse()
        return "refused"
    before = (datakey.directory_account(name) or {}).get("groups_role")
    datakey.set_online(name, time.time())
    datakey.set_groups_role(name, role)
    if role != before:
        roles.groups_changed()          # a demotion lets go of role keys now, not at the next sign-in
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
