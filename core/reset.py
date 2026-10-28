"""Reset Toner to factory settings: delete everything Toner keeps on this computer (ui/factoryreset.py asks first and quits after).

What goes: the whole data folder (core/paths.py data_dir(): the Global database and every organization's, the vault and its
remembered key, logs, session logs, saved host keys, the agent certificate, downloaded updates, Ansible files, the Demarc queue and
the lock files), what the system keeps for Toner outside it (the vault key in the keyring on Linux and macOS; the entries an older
Toner left in Windows Credential Manager under the service name 'netcheck') and, on Linux, the autostart entry. Nothing on other
systems is touched: Windows agents keep their tokens and Demarc keeps this Toner enrolled, and both stop working until enrolled again.

The folder is renamed first, in one step. Windows refuses that while any file inside is open (another Toner window, the service, a
program holding a log), so nothing is deleted until nothing holds a file; and if deleting what was renamed stops half-way, what is
left sits in the renamed folder, where no Toner mistakes it for a whole install."""
import gc
import logging
import os
import shutil
import stat
import sys
from pathlib import Path

from core import db, paths

LEGACY_SERVICE = db.SERVICE                 # 'netcheck': what Toner before the vault stored passwords under in Credential Manager
IN_USE = ("Toner could not reset. {path} is still in use, probably by another Toner window, the Toner service or a program that has "
          "the file open. Nothing was deleted. Close it and try again.")
LEFT = "Toner's data was deleted except {path}: {reason}. Delete the folder {folder} yourself. Toner will quit now."
CRED_LEFT = ("Toner's data was deleted, but its entry in Windows Credential Manager could not be removed: {reason}. Remove the entry "
             "named {name} in Credential Manager > Windows Credentials yourself. Toner will quit now.")
NATIVE_LEFT = ("Toner's data was deleted, but its entry Toner vault in the system keyring could not be removed: {reason}. Remove it "
               "yourself. Toner will quit now.")
NOT_ONE_FOLDER = ("Toner could not reset. Its database is not in its data folder ({db} is used instead of {folder}), so there is no "
                  "one folder to delete. Nothing was deleted.")


class ResetError(Exception):
    """What went wrong, in the words shown to the person. `deleted`: Toner's data is already gone (so Toner must still quit)."""

    def __init__(self, text, deleted=False):
        super().__init__(text)
        self.deleted = deleted


# ---------------------------------------------------------------- the system's own stores (the tests put fakes here)
def _cred_enumerate():
    """Windows Credential Manager: the target name of every credential of this user. Only the names are looked at."""
    if sys.platform != "win32":
        return []
    from win32ctypes.pywin32 import win32cred
    try:
        rows = win32cred.CredEnumerate(None, 0)
    except Exception:                                   # no credentials at all, or no Credential Manager (a service account)
        return []
    return [r["TargetName"] for r in rows or ()]


def _cred_delete(target):
    from win32ctypes.pywin32 import win32cred
    win32cred.CredDelete(Type=win32cred.CRED_TYPE_GENERIC, TargetName=target)


def _native_delete(service, username):
    from core import passvault
    passvault._native_keyring().delete_password(service, username)


def legacy_targets(names=None):
    """Which Credential Manager entries are Toner's: the service name itself, and 'user@netcheck' (how keyring names them)."""
    names = _cred_enumerate() if names is None else names
    return [t for t in names if t == LEGACY_SERVICE or t.endswith("@" + LEGACY_SERVICE)]


# ---------------------------------------------------------------- the pieces
def folder():
    """The data folder (a portable copy's `data` folder beside the program). Raises ResetError when the database is kept
    elsewhere (NETCHECK_DB): then there is no one folder that holds everything."""
    f = Path(paths.data_dir())
    base = Path(db.base_path())
    if base.parent.resolve() != f.resolve():
        raise ResetError(NOT_ONE_FOLDER.format(db=base, folder=f))
    return f


def stop_background():
    """Everything in this process that runs on its own and could hold or write a file."""
    from core import agents, demarc, extstore, service
    demarc.stop()
    agents.stop()
    extstore.stop()
    service.release_schedule()


def close_logs(f):
    """Close every log file open inside the folder (Windows will not rename or delete an open file)."""
    root = str(Path(f).resolve()).lower()
    loggers = [logging.getLogger()] + [x for x in logging.Logger.manager.loggerDict.values() if isinstance(x, logging.Logger)]
    for lg in loggers:
        for h in list(lg.handlers):
            base = getattr(h, "baseFilename", None)
            if base and str(Path(base).resolve()).lower().startswith(root):
                lg.removeHandler(h)
                h.close()


def in_use(f):
    """The first file in the folder some program still holds open (renaming it is refused), or None."""
    for root, _dirs, files in os.walk(f):
        for name in files:
            p = Path(root) / name
            probe = p.with_name(p.name + ".inuse")
            try:
                os.replace(p, probe)
            except OSError:
                return p
            os.replace(probe, p)
    return None


def _delete_tree(folder_):
    """Delete the renamed folder. Returns [(path, reason)] of what could not be deleted (read-only files are made writable first)."""
    left = []

    def onexc(fn, path, exc):
        try:
            os.chmod(path, stat.S_IWRITE)
            fn(path)
        except OSError as e:
            left.append((Path(path), e.strerror or str(e)))
    shutil.rmtree(folder_, onexc=onexc)
    return left


# ---------------------------------------------------------------- the reset itself
def wipe():
    """Delete it all. Raises ResetError with what to tell the person (deleted=True when the data is gone anyway); otherwise
    everything is gone and Toner must quit now without writing anything."""
    from core import passvault
    f = folder()
    vault_path = str(passvault.path())
    try:
        native = passvault.key_path().read_bytes().startswith(passvault.KEYRING_MARK)   # the vault key is in the system's keyring
    except OSError:
        native = False
    stop_background()
    close_logs(f)
    db._forget_settings()
    db.forget_orgs()
    db.forget_history()
    db.release()
    gc.collect()                                   # a connection waiting to be collected keeps its file open on Windows
    renamed = f.with_name(f"{f.name}.reset-{os.getpid()}")
    try:
        os.rename(f, renamed)
    except OSError:
        raise ResetError(IN_USE.format(path=in_use(f) or f)) from None
    passvault.lock()                               # from here on nothing reads or writes a password
    problems = []
    if native:
        try:
            _native_delete(passvault.NATIVE_SERVICE, vault_path)
        except Exception as e:
            problems.append(NATIVE_LEFT.format(reason=e))
    for target in legacy_targets():
        try:
            _cred_delete(target)
        except Exception as e:
            problems.append(CRED_LEFT.format(reason=e, name=target))
    if sys.platform.startswith("linux"):
        from core import autostart
        try:
            autostart.set_enabled(False)
        except OSError:
            pass
    left = _delete_tree(renamed)
    if left:
        problems.insert(0, LEFT.format(path=left[0][0], reason=left[0][1], folder=renamed))
    if problems:
        raise ResetError("\n\n".join(problems), deleted=True)
