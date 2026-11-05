"""Config backups kept with their passwords (before sign-in, or by masking turned off) move behind the backups key: each such body
becomes the masked text and the text it held goes to `secret`, encrypted to the backups key (core/backup.py reads it back).

`secret` says where a version stands: NULL not looked at yet, '' looked at (the body is masked, nothing kept), else the encrypted
text. Only the NULL ones are looked at, through a partial index, so a copy already done costs one lookup per file at each sign-in.
Runs right after sign-in, once core/roles.py has a backups key. One transaction per database, so a run that stops halfway leaves
each file moved or as it was, and running again carries on.
"""
import zlib

from core import backup, db, envelope, quiet, roles, sqldb


def databases():
    """Global's file and every organization's: the ones lockdown encrypts."""
    base = db.base_path()
    return [p for p in [base] + sorted(base.with_name(base.stem + ".orgs").glob("*.db")) if p.exists()]


def _open(path):
    c = sqldb.connect(path, timeout=15)
    c.row_factory = sqldb.sqlite3.Row
    return c


def _unchecked(c):
    """True when the file has a version not looked at yet."""
    try:
        return c.execute("SELECT 1 FROM config_backups WHERE secret IS NULL LIMIT 1").fetchone() is not None
    except sqldb.sqlite3.OperationalError as e:
        if "no such column" in str(e):                  # a file from before secrets: every version is still to look at
            return c.execute("SELECT 1 FROM config_backups LIMIT 1").fetchone() is not None
        if "no such table" in str(e):
            return False
        raise


def locked(e):
    """True for SQLite's "database is locked" or "busy": another Toner has the file open. Any other error is not a lock."""
    return isinstance(e, sqldb.sqlite3.OperationalError) and any(w in str(e).lower() for w in ("locked", "busy"))


def pending():
    """The databases with a version not looked at yet (it may hold passwords in its body). A file that can't be read is left out
    (it never stops Toner starting); a locked one raises."""
    out = []
    for p in databases():
        try:
            c = _open(p)
            try:
                if _unchecked(c):
                    out.append(p)
            finally:
                c.close()
        except Exception as e:
            if locked(e):
                raise
            quiet.ignored()
    return out


def run(progress=None):
    """Look at every version not looked at yet: an unmasked body goes behind the backups key, a masked one is marked ''. Calls
    progress(done, total) per database. A version or a file that fails is skipped and stays NULL, looked at again next time: never
    a reason not to start. Raises only when a file is locked. True when everything was done (or there is no backups key)."""
    pub = roles.backups_public()
    if pub is None:
        return True
    todo = pending()
    if progress:
        progress(0, len(todo))
    whole = True
    for done, p in enumerate(todo, 1):
        try:
            whole = _split(p, pub) and whole
        except Exception as e:
            if locked(e):
                raise
            quiet.ignored()                              # a damaged or unreadable file: skipped
            whole = False
        if progress:
            progress(done, len(todo))
    return whole


def _split(path, pub):
    """One database, in one transaction: the whole file moves, or none of it. False when a version was skipped."""
    c = _open(path)
    try:
        db._m13_backup_secrets(c)                        # a file the window hasn't brought up to date yet (db.init runs after this)
        moved, clean, whole = [], [], True
        for r in c.execute("SELECT id, sha, body FROM config_backups WHERE secret IS NULL").fetchall():
            try:
                text = zlib.decompress(r["body"]).decode("utf-8", "replace")
                masked = backup.mask_secrets(text)
                if masked == text:
                    clean.append((r["id"],))
                else:
                    moved.append((envelope.wrap(pub, backup._pack(text), backup.aad(r["sha"])), backup._pack(masked), len(masked), r["id"]))
            except Exception:
                quiet.ignored()                          # a damaged version: stays NULL
                whole = False
        with c:                                          # (secret IS NULL: an id deleted and used again meanwhile is another version)
            c.executemany("UPDATE config_backups SET secret='' WHERE id=? AND secret IS NULL", clean)
            c.executemany("UPDATE config_backups SET secret=?, body=?, size=? WHERE id=? AND secret IS NULL", moved)
        return whole
    finally:
        c.close()


def secrets_kept():
    """True when any database has a backup looked at under a backups key (roles' tripwire): a secret kept, or '' (looked at,
    nothing to keep), as only a signed copy writes. Files not set up for it yet don't; a file that can't be read is passed over (it
    never stops sign-in); a locked one raises."""
    for p in databases():
        try:
            c = _open(p)
            try:
                if c.execute("SELECT 1 FROM config_backups WHERE secret IS NOT NULL LIMIT 1").fetchone():
                    return True
            finally:
                c.close()
        except Exception as e:
            if locked(e):
                raise
            quiet.ignored()                              # no such table / column (an older file), or not a database at all
    return False
