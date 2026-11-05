"""Config backups kept with their passwords (before sign-in, or by masking turned off) move behind the backups key: each such body
becomes the masked text and the text it held goes to `secret`, encrypted to the backups key (core/backup.py reads it back).

`secret` says where a version stands: NULL not looked at yet, '' looked at (the body is masked, nothing kept), else the encrypted
text. Only the NULL ones are looked at, through a partial index, so a copy already done costs one lookup per file at each sign-in.
Runs right after sign-in, once core/roles.py has a backups key. One transaction per database, so a run that stops halfway leaves
each file moved or as it was, and running again carries on.
"""
import zlib

from core import backup, db, envelope, roles, sqldb


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


def pending():
    """The databases with a version not looked at yet (it may hold passwords in its body)."""
    out = []
    for p in databases():
        c = _open(p)
        try:
            if _unchecked(c):
                out.append(p)
        finally:
            c.close()
    return out


def run(progress=None):
    """Look at every version not looked at yet: an unmasked body goes behind the backups key, a masked one is marked ''. Calls
    progress(done, total) per database. Nothing to do without the backups key."""
    pub = roles.backups_public()
    if pub is None:
        return
    todo = pending()
    if progress:
        progress(0, len(todo))
    for done, p in enumerate(todo, 1):
        c = _open(p)
        try:
            db._m13_backup_secrets(c)                    # a file the window hasn't brought up to date yet (db.init runs after this)
            moved, clean = [], []
            for r in c.execute("SELECT id, sha, body FROM config_backups WHERE secret IS NULL").fetchall():
                text = zlib.decompress(r["body"]).decode("utf-8", "replace")
                masked = backup.mask_secrets(text)
                if masked == text:
                    clean.append((r["id"],))
                else:
                    moved.append((envelope.wrap(pub, backup._pack(text), backup.aad(r["sha"])), backup._pack(masked), len(masked), r["id"]))
            with c:                                      # one transaction: the whole file moves, or none of it
                c.executemany("UPDATE config_backups SET secret='' WHERE id=?", clean)
                c.executemany("UPDATE config_backups SET secret=?, body=?, size=? WHERE id=?", moved)
        finally:
            c.close()
        if progress:
            progress(done, len(todo))


def secrets_kept():
    """True when any database keeps a backup's passwords under a backups key (roles' tripwire). Files not set up for it yet don't."""
    for p in databases():
        c = _open(p)
        try:
            if c.execute("SELECT 1 FROM config_backups WHERE secret <> '' LIMIT 1").fetchone():
                return True
        except sqldb.sqlite3.OperationalError as e:
            if "no such" not in str(e):                  # no such table / column: an older file
                raise
        finally:
            c.close()
    return False
