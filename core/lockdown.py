"""Encrypting a copy Toner kept before sign-in: every database and side file under the data key, one file at a time.

Each step stands on its own if Toner stops halfway (sqldb.encrypt_file swaps a database in whole, sealedfile a side file), and
what is left is worked out from the files themselves, so running again after a crash carries on where it stopped.
"""
import os
import shutil

from core import agents, datakey, db, demarc, nettools, platforms, sealedfile, service, sessionlog, sqldb


class Busy(RuntimeError):
    """Another Toner process (the command-line service) has the data open."""


def _has_data(p):
    try:
        return p.is_file() and p.stat().st_size > 0      # an empty file holds nothing, and is written encrypted from now on
    except OSError:
        return False


def _steps():
    """[(path, what encrypts it)] for everything still plain."""
    base = db.base_path()
    databases = sorted(base.with_name(base.stem + ".orgs").glob("*.db")) + [base, demarc.queue_path()]
    steps = [(p, lambda p: sqldb.encrypt_file(p, sqldb.current_key())) for p in databases if _has_data(p) and not sqldb.is_encrypted(p)]
    side = sorted(sessionlog.log_dir().iterdir()) + [nettools.known_hosts_path()]
    steps += [(p, sealedfile.seal_existing) for p in side if _has_data(p) and not sealedfile.is_sealed(p)]
    key_file = agents.cert_dir() / "toner-agent.key"
    if key_file.exists() and not agents.key_is_encrypted(key_file):
        steps.append((key_file, agents.encrypt_key))
    rdp = base.parent / "rdp"                             # where Toner used to leave .rdp files
    if rdp.exists():
        steps.append((rdp, shutil.rmtree))
    return steps


def pending():
    """The files still to encrypt (and rdp/, still to delete)."""
    return [p for p, _ in _steps()]


def run(progress=None):
    """Encrypt everything pending, calling progress(done, total) after each file. Safe to run again after a crash."""
    if not datakey.is_open() or sqldb.current_key() is None:
        raise datakey.Locked("Sign in first.")
    if not service.owns_schedule():
        raise Busy("Toner's service is using the data. Stop it, then try again.")
    db.release()                                          # this process's kept connections would hold the files open
    keys = datakey.path()                                 # what's encrypted below is lost if the keys file isn't on disk
    fd = os.open(keys, os.O_RDWR)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    platforms.fsync_dir(keys.parent)
    writing = sessionlog.in_use()                         # sealing a log under an open session would cut it off: next run
    steps = [s for s in _steps() if s[0] not in writing]
    for done, (path, encrypt) in enumerate(steps, 1):
        encrypt(path)
        if progress:
            progress(done, len(steps))
    db.forget_wal()                                       # the swapped files are set to WAL again on their next connection
