import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core import custom, db, profiles, vendors, winmon
from core.nettools import resolve_host
from drivers import DRIVERS
from drivers.base import Result, ERROR
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


def run_one(dev, thresholds, opts=None):
    opts = opts or db.runtime_options()
    opts = {**opts, "disabled": db.disabled_for(dev, opts.get("disabled", ()))}      # the device's own list of checks, if it has one
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
            if opts.get("tls_sweep") and sweepable(dev):
                res += custom.sweep(dev, thresholds, opts.get("tls_sweep_ports", "443"))
            drv.flush_baselines()            # only after a complete run
            return res
        except Exception as e:
            if attempt < attempts and _transient(e):
                time.sleep(max(0, int(opts.get("retry_delay", 0))))
                continue
            tail = f" (after {attempt} attempts)" if attempt > 1 else ""
            rows = [Result(dev["name"], "connection", ERROR, "", f"{type(e).__name__}: {e}{tail}")]
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
    allres = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(run_one, d, for_dev(d), opts) for d in devices]
        for f in as_completed(futs):
            res = f.result()
            allres.extend(res)
            if on_results:
                on_results(res)
    return allres
