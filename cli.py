"""Toner from the command line: for scripts, Task Scheduler and servers without a desktop.

    python cli.py run [--group "Vendor: Cisco"] [--json] [--fail-on warn|fail|error|never] [--no-notify]
    python cli.py backup [--group ...] [--json]
    python cli.py status [--json]
    python cli.py service [--metrics-port 9108]      keep running: scheduled checks, backups and alerts
    python cli.py metrics --port 9108                serve /metrics from the stored results

Exit codes for `run` follow --fail-on (default: fail): 0 all good, 1 something at or above that level, 2 nothing to check.
"""
import argparse
import getpass
import json
import signal
import sys
import threading

from core import backupsplit, datakey, db, directory, dirsignin, duo, fidokey, lockdown, oidc, passvault, pinslot, quiet, service, session
from drivers.base import SEVERITY

SERVICE_OFF = ("Toner's background service is off while sign-in is turned on. "
               "Scheduled checks and backups run while someone is signed in to Toner's window.")
UNFINISHED = "Toner's data hasn't finished encrypting. Open Toner's window to finish, then try again."
BUSY = "Toner's service is using the data. Stop it, then try again."
DUO_LINE = "Approve the sign-in on your phone. (Press Ctrl+C to enter a code instead.)"
APPROVAL = "Sign in to Toner's window once first, so an admin can approve this computer."
LEVEL = {"warn": 1, "fail": 2, "error": 3, "never": 99}


def _print_table(results):
    if not results:
        print("No results.")
        return
    w = max(len(r.device) for r in results)
    c = max(len(r.check) for r in results)
    for r in results:
        print(f"{r.status:<5} {r.device:<{w}}  {r.check:<{c}}  {r.value}  {r.message}".rstrip())
    n = lambda s: sum(r.status == s for r in results)
    print(f"\nOK {n('OK')}  WARN {n('WARN')}  FAIL {n('FAIL')}  ERROR {n('ERROR')}")


def _as_json(results):
    return json.dumps([{"device": r.device, "check": r.check, "status": r.status, "value": r.value,
                        "message": r.message, "numeric": r.numeric} for r in results], indent=2)


def main(argv=None, ready=None):
    ap = argparse.ArgumentParser(prog="toner", description="Toner without a window.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("run", "backup"):
        p = sub.add_parser(name, help=f"{name} the enabled devices")
        p.add_argument("--group", action="append", default=[], help="limit to a group such as 'Vendor: Cisco', "
                       "'Folder: HQ/Core' or 'Tag: core' (repeatable)")
        p.add_argument("--json", action="store_true", help="print JSON instead of a table")
        p.add_argument("--no-notify", action="store_true", help="do not send notifications")
        if name == "run":
            p.add_argument("--fail-on", choices=list(LEVEL), default="fail")
    st = sub.add_parser("status", help="show the latest stored results")
    st.add_argument("--json", action="store_true")
    sv = sub.add_parser("service", help="keep running scheduled checks and backups")
    sv.add_argument("--metrics-port", type=int, default=0, help="also serve Prometheus metrics on this port")
    sv.add_argument("--metrics-bind", default="127.0.0.1")
    mt = sub.add_parser("metrics", help="serve /metrics from the stored results")
    mt.add_argument("--port", type=int, default=9108)
    mt.add_argument("--bind", default="127.0.0.1")
    for p in sub.choices.values():
        if p is not sv:
            p.add_argument("--user", help="the Toner account to sign in with (asked for if left out)")
    a = ap.parse_args(argv)
    if datakey.missing():
        print(datakey.MISSING, file=sys.stderr)
        return 3
    if not datakey.exists():
        return _run(a)
    if a.cmd == "service":
        print(SERVICE_OFF, file=sys.stderr)
        return 3
    try:
        failed = _sign_in(a)
        return failed if failed else _run(a, ready)
    finally:
        session.sign_out()


def _sign_in(a):
    """None when signed in and ready to read; otherwise the exit code (3) after saying why on stderr."""
    try:
        if sys.stdin is None or not sys.stdin.isatty():   # Toner.exe (a window program) has no stdin; piped or redirected
            raise EOFError                                # input has no one typing, and getpass would wait on the console
        user = a.user or input("Username: ")
        kind = dirsignin.classify(user)
        sso = kind[0] == "directory" and kind[1].get("kind") == "oidc"     # the browser instead of a password
        password = None if sso else getpass.getpass("Password: ")
    except (EOFError, RuntimeError):           # Task Scheduler, redirected input, or input() that "lost sys.stdin": nobody to ask
        print("Sign in needs a terminal.", file=sys.stderr)
        return 3
    except dirsignin.Paused as e:
        print(e, file=sys.stderr)
        return 3
    except (ValueError, KeyError, AttributeError):          # a damaged keys file
        print("This file is damaged or was changed outside Toner.", file=sys.stderr)
        return 3
    try:
        if sso:
            if not _sso_sign_in(kind[1], user):
                print(APPROVAL, file=sys.stderr)
                return 3
        elif kind[0] == "directory":
            if not _directory_sign_in(user, password):
                print(APPROVAL, file=sys.stderr)       # approval needs an admin at the window; nothing was written for it
                return 3
        else:
            session.sign_in(user, password, _key)
        if lockdown.pending():                 # Toner's window finishes the upgrade; the command line never encrypts
            print(UNFINISHED, file=sys.stderr)
            return 3
        try:
            backupsplit.run()                  # passwords in old backups go behind the backups key, as the window does
        except Exception as e:                 # never stops the command, unless another Toner has a file locked
            if backupsplit.locked(e):
                print(BUSY, file=sys.stderr)
                return 3
            quiet.ignored()
    except passvault.Locked:                   # the old vault hasn't moved over yet: the window's first start does that
        print(UNFINISHED, file=sys.stderr)
        return 3
    except directory.Unreachable:
        print(dirsignin.SSO_UNREACHABLE.format(provider=kind[1]["name"]) if sso else dirsignin.UNREACHABLE, file=sys.stderr)
        return 3
    except oidc.OidcError as e:                # its own text names the provider's host: the approved sentence instead
        print(dirsignin.sso_said(kind[1], e), file=sys.stderr)
        return 3
    except (datakey.WrongPassword, datakey.Throttled, dirsignin.NotInGroup, dirsignin.CaChanged, duo.Unavailable, duo.Denied,
            pinslot.WrongPin, pinslot.PinLocked, fidokey.Failed) as e:      # WrongPin is a ValueError: keep it ahead of the damaged-file case
        print(e, file=sys.stderr)
        return 3
    except (ValueError, KeyError, AttributeError):          # includes JSONDecodeError: a damaged keys file
        print("This file is damaged or was changed outside Toner.", file=sys.stderr)
        return 3


def _directory_sign_in(login, password):
    """True when signed in; False when it needs an admin's approval, which never happens at a terminal."""
    at = dirsignin.begin(login, password)
    if at.stage == "password":                 # (offline, begin has gone straight to the PIN)
        dirsignin.after_password(at)
    if at.stage == "duo":
        _duo(at)
    if at.stage == "pin":
        dirsignin.finish(at, getpass.getpass("PIN: "), key=_key)
    if at.stage == "duo":                      # the Duo skip wasn't earned (no keys in the seal): Duo, then the PIN once more. Once only:
        _duo(at)                               # a second return is left as it is, which reads as the approval sentence
        if at.stage == "pin":
            dirsignin.finish(at, getpass.getpass("PIN: "), key=_key)
    return at.stage == "done"


def _key(creds):
    """The security key's touch; its own PIN (off Windows, where the system asks itself) is read without echo."""
    print("Touch your security key")
    return fidokey.value(creds, ask_pin=lambda: getpass.getpass("Enter your security key's PIN: "))


def _sso_sign_in(cfg, login):
    """The browser sign-in, then the PIN. True when signed in; False when it needs an admin's approval (a first sign-in, or a
    new PIN). Ctrl+C stops the wait for the browser."""
    at = dirsignin.sso_start(cfg, login)
    if at.stage == "browser":                  # (offline, sso_start has gone straight to the PIN)
        print(dirsignin.SSO_TEXT.format(provider=cfg["name"]))
        cancel, failed = threading.Event(), []

        def wait():
            try:
                dirsignin.sso_wait(at, cancel)
            except Exception as e:
                failed.append(e)
        worker = threading.Thread(target=wait, daemon=True)
        worker.start()
        try:
            while worker.is_alive():
                worker.join(0.2)
        except KeyboardInterrupt:
            cancel.set()                        # the wait ends within a second, as Cancelled
            worker.join()
        if failed:
            raise failed[0]
    if at.stage == "pin":
        dirsignin.finish(at, getpass.getpass("PIN: "))
    return at.stage == "done"


def _duo(at):
    """The push on a worker thread; Ctrl+C cancels it and asks for a code (a second Ctrl+C at that prompt ends as usual)."""
    print(DUO_LINE)
    cancel, failed = threading.Event(), []

    def push():
        try:
            dirsignin.duo_push(at, cancel)
        except Exception as e:
            failed.append(e)
    worker = threading.Thread(target=push, daemon=True)
    worker.start()
    try:
        while worker.is_alive():
            worker.join(0.2)
    except KeyboardInterrupt:
        cancel.set()
        worker.join()
        failed.clear()                          # a cancelled push's end (denied or cut off) isn't the answer
    if failed:
        raise failed[0]
    if at.stage == "duo":                       # still: the person chose a code
        dirsignin.duo_code(at, getpass.getpass("Duo code: "))


def _run(a, ready=None):
    if ready:
        ready()                                # the caller's own database work, which needs the vault open
    db.init()

    if a.cmd in ("run", "backup"):
        known = set(db.group_labels())
        bad = [g for g in a.group if g not in known]
        if bad:
            print("Unknown group(s): " + ", ".join(bad) + "\nAvailable: " + ", ".join(sorted(known - {db.ALL_DEVICES})), file=sys.stderr)
            return 2
        fn = service.run_checks if a.cmd == "run" else service.run_backups
        results = fn(a.group, do_notify=not a.no_notify, scheduled=False)
        if a.json:
            print(_as_json(results))
        else:
            _print_table(results)
        if not results:
            return 2
        if a.cmd == "run":
            worst = max(SEVERITY[r.status] for r in results)
            return 1 if worst >= LEVEL[a.fail_on] else 0
        return 1 if any(r.status == "ERROR" for r in results) else 0

    if a.cmd == "status":
        rows = [{"device": db.label_org(n), "status": v["status"], "checks": v["checks"], "checked": v["at"],
                 "problems": [{"check": c, "status": s, "message": m} for c, s, m in v["problems"]]}
                for n, v in sorted(db.device_health().items())]
        if a.json:
            print(json.dumps(rows, indent=2))
        else:
            for r in rows:
                print(f"{r['status']:<5} {r['device']}  ({r['checks']} checks, {r['checked']})")
                for p in r["problems"]:
                    print(f"        {p['status']:<5} {p['check']}  {p['message']}")
            if not rows:
                print("No results yet. Run: python cli.py run")
        return 0 if all(r["status"] in ("OK", "WARN") for r in rows) else 1

    if a.cmd == "metrics":
        srv = service.MetricsServer(a.port, a.bind)
        srv.start()
        print(f"Serving http://{a.bind}:{srv.port}/metrics  (Ctrl+C to stop)")
        try:
            signal.pause() if hasattr(signal, "pause") else __import__("time").sleep(10 ** 9)
        except KeyboardInterrupt:
            pass
        srv.stop()
        return 0

    if a.cmd == "service":
        daemon = service.Daemon(log=lambda m: print(m, flush=True))
        srv = None
        port = a.metrics_port or int(db.get_setting("metrics_port"))
        if port:
            srv = service.MetricsServer(port, a.metrics_bind)
            srv.start()
            print(f"Metrics on http://{a.metrics_bind}:{srv.port}/metrics", flush=True)
        try:
            daemon.run()
        except KeyboardInterrupt:
            pass
        daemon.stop()
        if srv:
            srv.stop()
        print("Stopped.")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
