"""For the places where an error is expected and harmless (closing a socket that is already gone, a best-effort lookup): the
error is not shown, but it is not thrown away either. It goes to toner.log at debug level, so when something behaves
oddly there is a trail. Start Toner with the TONER_DEBUG environment variable set to see it."""
import logging
import sys

_log = logging.getLogger("toner")


def ignored(note=""):
    """Call inside an `except` block instead of `pass`."""
    if not _log.isEnabledFor(logging.DEBUG):
        return
    kind, value, _ = sys.exc_info()
    where = ""
    try:
        frame = sys._getframe(1)
        where = f"{frame.f_code.co_filename.rsplit(chr(92), 1)[-1]}:{frame.f_lineno} "
    except Exception:                 # no stack to show: just the message
        pass
    _log.debug("%signored %s: %s %s", where, getattr(kind, "__name__", "error"), value, note)
