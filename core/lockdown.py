"""Encrypting a copy Toner kept before sign-in: every database and side file under the data key, one file at a time.

Each step stands on its own if Toner stops halfway (sqldb.encrypt_file swaps a database in whole, sealedfile a side file), and
what is left is worked out from the files themselves, so running again after a crash carries on where it stopped.
"""
import json
import os
import shutil
from pathlib import Path

from core import agents, datakey, db, demarc, fileserver, nettools, platforms, quiet, sealedfile, service, sessionlog, sqldb


class Busy(RuntimeError):
    """Another Toner process (the command-line service) has the data open."""


def _has_data(p):
    try:
        return p.is_file() and p.stat().st_size > 0      # an empty file holds nothing, and is written encrypted from now on
    except OSError:
        return False


def _index_path():
    return db.base_path().with_suffix(".sealed")


def _plain_side_files():
    """The session logs (and known_hosts) with data that aren't sealed. One seen sealed before and unchanged since (the same size
    and modified time) isn't opened again: thousands of logs, opened at every start, cost seconds. The index is only a cache
    of what was seen, so a missing, damaged or stale one just means opening the files."""
    try:
        known = json.loads(_index_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        known = {}
    if not isinstance(known, dict):
        known = {}
    files = []
    with os.scandir(sessionlog.log_dir()) as it:
        for e in it:
            if e.is_file():
                files.append((Path(e.path), e.stat()))   # (on Windows the listing carries the stat: no file is opened)
    hosts = nettools.known_hosts_path()
    if hosts.is_file():
        files.append((hosts, hosts.stat()))
    seen, plain = {}, []
    for p, st in files:
        if not st.st_size:
            continue                                     # an empty file holds nothing, and is written encrypted from now on
        sig = [st.st_size, st.st_mtime_ns]
        if known.get(str(p)) == sig or sealedfile.is_sealed(p):
            seen[str(p)] = sig
        else:
            plain.append(p)
    if seen != known:
        try:
            sealedfile.replace_bytes(_index_path(), json.dumps(seen).encode("utf-8"))
        except OSError:
            quiet.ignored()                              # the next look opens them again
    return sorted(plain)


def _encrypt_db(p):
    sqldb.encrypt_file(p, sqldb.current_key())


def _encrypt_foreign(p):
    """A database someone left in the data folder. One SQLite can't read would stop Toner starting, every time: seal it whole."""
    try:
        _encrypt_db(p)
    except sqldb.sqlite3.OperationalError:
        raise                                            # in use: the person is asked to try again
    except sqldb.sqlite3.DatabaseError:
        sealedfile.seal_existing(p)


def _steps():
    """[(path, what encrypts it)] for everything still plain."""
    base = db.base_path()
    databases = sorted(base.with_name(base.stem + ".orgs").glob("*.db")) + [base, demarc.queue_path()]
    own = list(databases)
    databases += [p for p in sorted(base.parent.glob("*.db")) if p not in databases]   # backups an older Toner saved here, and the like
    steps = [(p, _encrypt_db if p in own else _encrypt_foreign) for p in databases if _has_data(p) and not sqldb.is_encrypted(p)]
    steps += [(p, sealedfile.seal_existing) for p in _plain_side_files()]
    key_file = agents.cert_dir() / "toner-agent.key"
    if key_file.exists() and not agents.key_is_encrypted(key_file):
        steps.append((key_file, agents.encrypt_key))
    for sftp in (base.parent / "sftp_host_key", base.with_name(base.stem + ".orgs") / "sftp_host_key"):   # Global's, the organizations'
        if _has_data(sftp) and not fileserver.host_key_is_encrypted(sftp):
            steps.append((sftp, fileserver.encrypt_host_key))
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
    fd = os.open(keys, os.O_RDWR | getattr(os, "O_BINARY", 0))
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
