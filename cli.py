"""Toner from the command line: for scripts, Task Scheduler and servers without a desktop.

    python cli.py run [--group "Vendor: Cisco"] [--json] [--fail-on warn|fail|error|never] [--no-notify]
    python cli.py backup [--group ...] [--json]
    python cli.py status [--json]
    python cli.py service [--metrics-port 9108]      keep running: scheduled checks, backups and alerts
    python cli.py metrics --port 9108                serve /metrics from the stored results

Exit codes for `run` follow --fail-on (default: fail): 0 all good, 1 something at or above that level, 2 nothing to check.
"""
import argparse
import json
import signal
import sys

from core import db, service
from drivers.base import SEVERITY

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


def main(argv=None):
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
    a = ap.parse_args(argv)
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
        rows = [{"device": n, "status": v["status"], "checks": v["checks"], "checked": v["at"],
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
