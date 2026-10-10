"""A tree of named folders stored in the database, with things (devices, sessions) that live in them.
The same rules as the inventory's folders: names are unique among siblings, a folder cannot go inside itself, and deleting
a folder moves what was in it up one level, so nothing is ever deleted by accident."""
from core import db


class FolderTree:
    def __init__(self, folder_table, member_table, member_col="folder_id"):
        self.t, self.m, self.col = folder_table, member_table, member_col       # fixed names from code, never user input

    def list(self):
        with db.connect() as c:
            return [dict(r) for r in c.execute(f"SELECT id, name, parent_id FROM {self.t} ORDER BY name COLLATE NOCASE")]

    def paths(self):
        """{folder id: 'Parent/Child'}"""
        rows = {f["id"]: f for f in self.list()}
        out = {}
        for fid in rows:
            parts, cur, seen = [], fid, set()
            while cur in rows and cur not in seen:                  # 'seen' guards against a corrupt parent loop
                seen.add(cur)
                parts.append(rows[cur]["name"])
                cur = rows[cur]["parent_id"]
            out[fid] = "/".join(reversed(parts))
        return out

    def descendants(self, fid):
        """The folder's own id plus every folder below it."""
        kids, out, todo = {}, set(), [fid]
        for f in self.list():
            kids.setdefault(f["parent_id"], []).append(f["id"])
        while todo:
            cur = todo.pop()
            if cur not in out:
                out.add(cur)
                todo.extend(kids.get(cur, []))
        return out

    def _check_sibling(self, c, name, parent_id, ignore_id=None):
        if c.execute(f"SELECT id FROM {self.t} WHERE name=? COLLATE NOCASE AND parent_id IS ? AND id IS NOT ?",
                     (name, parent_id, ignore_id)).fetchone():
            raise ValueError(f"A folder named '{name}' already exists there.")

    def create(self, name, parent_id=None):
        name = db.clean_folder_name(name)
        with db.connect() as c:
            if parent_id is not None and not c.execute(f"SELECT 1 FROM {self.t} WHERE id=?", (parent_id,)).fetchone():
                raise ValueError("The folder to put it in no longer exists.")
            self._check_sibling(c, name, parent_id)
            return c.execute(f"INSERT INTO {self.t}(name, parent_id) VALUES(?,?)", (name, parent_id)).lastrowid

    def rename(self, fid, name):
        name = db.clean_folder_name(name)
        with db.connect() as c:
            parent = c.execute(f"SELECT parent_id FROM {self.t} WHERE id=?", (fid,)).fetchone()["parent_id"]
            self._check_sibling(c, name, parent, fid)
            c.execute(f"UPDATE {self.t} SET name=? WHERE id=?", (name, fid))

    def move(self, fid, parent_id):
        if parent_id is not None and parent_id in self.descendants(fid):
            raise ValueError("A folder cannot be moved into itself or one of its own subfolders.")
        with db.connect() as c:
            name = c.execute(f"SELECT name FROM {self.t} WHERE id=?", (fid,)).fetchone()["name"]
            self._check_sibling(c, name, parent_id, fid)
            c.execute(f"UPDATE {self.t} SET parent_id=? WHERE id=?", (parent_id, fid))

    def delete(self, fid):
        """Delete a folder; its subfolders and members move up one level."""
        with db.connect() as c:
            parent = c.execute(f"SELECT parent_id FROM {self.t} WHERE id=?", (fid,)).fetchone()["parent_id"]
            clash = [r["name"] for r in c.execute(f"SELECT name FROM {self.t} WHERE parent_id=?", (fid,))
                     if c.execute(f"SELECT 1 FROM {self.t} WHERE name=? COLLATE NOCASE AND parent_id IS ? AND id!=?",
                                  (r["name"], parent, fid)).fetchone()]
            if clash:
                raise ValueError("Moving the contents up would clash with existing folders named: "
                                 f"{', '.join(clash)}. Rename one first.")
            c.execute(f"UPDATE {self.t} SET parent_id=? WHERE parent_id=?", (parent, fid))
            c.execute(f"UPDATE {self.m} SET {self.col}=? WHERE {self.col}=?", (parent, fid))
            c.execute(f"DELETE FROM {self.t} WHERE id=?", (fid,))

    def move_members(self, ids, folder_id):
        if ids:
            with db.connect() as c:
                c.executemany(f"UPDATE {self.m} SET {self.col}=? WHERE id=?", [(folder_id, i) for i in ids])

    def ensure_path(self, path):
        """Id of the folder at 'A/B/C', creating any missing levels. '' means top level (None)."""
        parts = [p.strip() for p in (path or "").replace("\\", "/").split("/") if p.strip()]
        if len(parts) > 10:
            raise ValueError("Folder paths can be at most 10 levels deep.")
        parent = None
        for name in parts:
            name = db.clean_folder_name(name)
            with db.connect() as c:
                row = c.execute(f"SELECT id FROM {self.t} WHERE name=? COLLATE NOCASE AND parent_id IS ?", (name, parent)).fetchone()
            parent = row["id"] if row else self.create(name, parent)
        return parent
