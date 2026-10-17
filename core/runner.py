import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core import checks, custom, db, profiles, reach, support, vendors, winmon
from core.nettools import resolve_host
from drivers import DRIVERS
from drivers.base import AuthRejected, Driver, Result, ERROR, WARN
from core import quiet


def _transient(e):
    """Network hiccups worth another try. A rejected login is NOT retried: repeating bad
    credentials is how accounts get locked out."""
    try:
        from netmiko.exceptions import NetmikoTimeoutException
        netmiko_timeout = (NetmikoTimeoutException,)
    except ImportError:
        netmiko_timeout = ()
    return isinstance(e, (TimeoutError, socket.timeout, ConnectionError, requests.exceptions.ConnectionError,
                          requests.exceptions.Timeout) + netmiko_timeout)


def sweepable(dev):
    """Devices whose address answers from here: not this computer's Wi-Fi, a status page, or a Windows agent that reports by itself."""
    kind = vendors.get(dev["vendor"]).get("kind")
    if dev["vendor"] == "unifi_cloud":
        return False                                   # that is api.ui.com, not a device of yours
    return kind in ("ssh", "api", "snmp") or (kind == "windows" and winmon.transport(dev) == "winrm")


def reachability(dev, opts):
    """The Reachable row (a TCP connection to the management port, through the proxy when there is one), before the login."""
    if dev["vendor"] not in reach.VENDORS or checks.key(dev["vendor"], "reachability") in opts.get("disabled", ()):
        return []
    try:
        return [reach.row(dev, timeout=min(5, int(opts.get("ssh_timeout", 5)) or 5))]
    except Exception:
        quiet.ignored()
        return []


def stored_copy_note(dev):
    """A 'credentials' WARN row when the device's password is linked to a password manager item that could not be read, so the
    check used Toner's stored copy (core/extstore.py); [] otherwise."""
    try:
        from core import extstore
        if extstore.active() == "toner":
            return []
        names = [db.secret_name(dev["name"])]
        if dev.get("profile_id"):
            p = profiles.of(dev)
            if p:
                names.append(db.secret_name(f"profile:{p['name']}"))
        note = extstore.fallback_note(dev["name"], names)
    except Exception:
        return []
    return [Result(dev["name"], "credentials", WARN, "stored copy", note)] if note else []


def run_one(dev, thresholds, opts=None):
    opts = opts or db.runtime_options()
    opts = {**opts, "disabled": db.disabled_for(dev, opts.get("disabled", ()))}      # the device's own list of checks, if it has one
    pre = reachability(dev, opts) + stored_copy_note(dev)
    attempts = 1 + max(0, int(opts.get("retries", 0)))
    for attempt in range(1, attempts + 1):
        try:
            dev = profiles.resolve(dev)      # username from the device's credential profile, if it has one
            if vendors.get(dev["vendor"]).get("kind") != "windows" or winmon.needs_dns(dev):
                resolve_host(dev["host"])    # a clear DNS error beats a cryptic socket one (an agent reports by itself)
            drv = DRIVERS[dev["vendor"]](dev, thresholds, opts)
            drv.custom = custom.for_device(dev, opts.get("custom"))        # user-defined checks that apply here
            res = drv.run()
            res += custom.run_network(dev, drv.custom)                       # web, port, certificate, ping, SNMP
            if "all:support" not in opts.get("disabled", ()):
                res += support.rows(dev, thresholds)                         # support, warranty and licence dates kept in the device's fields
            if opts.get("tls_sweep") and sweepable(dev):
                res += custom.sweep(dev, thresholds, opts.get("tls_sweep_ports", "443"))
            drv.flush_baselines()            # only after a complete run
            return pre + res
        except Exception as e:
            if attempt < attempts and _transient(e):
                time.sleep(max(0, int(opts.get("retry_delay", 0))))
                continue
            tail = f" (after {attempt} attempts)" if attempt > 1 else ""
            said = str(e) if isinstance(e, AuthRejected) else Driver.explain(e)          # a rejected key already says so in words; an HTTP error names its code, not the long address
            rows = pre + [Result(dev["name"], "connection", ERROR, "", f"{said}{tail}")]
            try:                                   # web, port, certificate and ping checks do not need the login
                rows += custom.run_network(dev, [c for c in custom.for_device(dev, opts.get("custom"))
                                                 if c["kind"] in ("http", "tcp", "tls", "ping", "iperf")])
            except Exception:
                quiet.ignored()
            return rows


def run_all(devices, thresholds, on_results=None, workers=10, opts=None):
    """Run every device in parallel; call on_results(list) as each one finishes.
    `thresholds` is one dict for everyone, or a function dev -> dict (per-device overrides)."""
    for_dev = thresholds if callable(thresholds) else (lambda _d: thresholds)
    here, per_org = db.target(), {}

    def setup(d):
        """A device from another organization's file (Global listing everything, or a Shared device) is checked with that
        organization's thresholds, checks and timeouts."""
        org = d.get("org")
        if org is None or org == here:
            return for_dev(d), opts
        with db.within(org):
            if org not in per_org:
                per_org[org] = (db.get_thresholds(), db.get_setting("threshold_overrides"), db.runtime_options())
            base, rules, own = per_org[org]
            return db.thresholds_for(d, base, rules), own

    def one(d, th, o):
        with db.within(d.get("org")):                     # its baselines, secrets and history are in its own file
            res = run_one(d, th, o)
        for r in res:
            r.org = d.get("org")
        return res

    allres = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(one, d, *setup(d)) for d in devices]
        for f in as_completed(futs):
            res = f.result()
            allres.extend(res)
            if on_results:
                on_results(res)
    return allres
