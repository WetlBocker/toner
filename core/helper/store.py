"""The helper's one record on disk: {owner, keys_path, rules_pub (b64), spare, duo {conn_id: skey}, enrolled_at}. The spare
(data key then rules private key) and the Duo secret keys go through `protect` before they are written (b64 of the result) and
`unprotect` when read: in memory they are bytes."""
import base64
import json
import os


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _unb64(s):
    return base64.b64decode(s.encode("ascii"), validate=True)


class Store:
    def __init__(self, path, protect, unprotect):
        self.path, self.protect, self.unprotect = path, protect, unprotect

    def load(self):
        """The record, or None when there is none."""
        try:
            with open(self.path, encoding="utf-8") as f:
                rec = json.load(f)
        except FileNotFoundError:
            return None
        rec["spare"] = self.unprotect(_unb64(rec["spare"]))
        rec["duo"] = {k: self.unprotect(_unb64(v)) for k, v in rec["duo"].items()}
        return rec

    def save(self, rec):
        """Replaces the file in one step (a crash leaves the old record or the new one), readable by its owner only."""
        out = {**rec, "spare": _b64(self.protect(rec["spare"])), "duo": {k: _b64(self.protect(v)) for k, v in rec["duo"].items()}}
        tmp = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(out, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def clear(self):
        self.path.unlink(missing_ok=True)
