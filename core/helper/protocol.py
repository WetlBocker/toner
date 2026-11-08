"""The helper's messages: UTF-8 JSON objects of at most MAX bytes, never pickles. Requests are {"op": str, "v": PROTOCOL, ...};
answers {"ok": bool, "error": one of ERRORS} plus fields."""
import json

PROTOCOL = 1
MAX = 65536
COPY_FAILED = 3                         # --install's exit code when it couldn't copy its files
ERRORS = ("not_owner", "not_enrolled", "rules_changed", "refused", "not_fresh", "bad_answer", "unreachable", "not_in_group",
          "throttled", "bad_request", "other_user", "duo_denied")


class CopyFailed(OSError):
    """--install couldn't copy the helper's files into place."""


def encode(obj):
    b = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(b) > MAX:
        raise ValueError("message too big")
    return b


def _no_constant(name):
    raise ValueError("not JSON")       # NaN and Infinity, which json would otherwise take


def decode(b):
    """The message as a dict; ValueError when it is too big, not UTF-8 JSON, or not an object."""
    if len(b) > MAX:
        raise ValueError("message too big")
    obj = json.loads(bytes(b).decode("utf-8"), parse_constant=_no_constant)    # UnicodeDecodeError and JSONDecodeError are ValueErrors
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    return obj
