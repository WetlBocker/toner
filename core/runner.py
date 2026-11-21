import dataclasses
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core import checks, custom, db, ifaces, nettools, profiles, reach, support, vendors, winmon, winsettings
from core.nettools import resolve_host
from drivers import DRIVERS
from drivers.base import AuthRejected, Driver, Result, ERROR, FAIL, NA, OK, WARN
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
    if dev["vendor"] and dev["vendor"] not in reach.VENDORS or checks.key(dev["vendor"], "reachability") in opts.get("disabled", ()):     # no vendor yet: its SSH port
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


def keep_software(dev, drv):
    """The software version the driver read during its run goes on the device record (db.set_software), so the Inventory and the
    Assistant know it without the Firmware Transfer wizard; a Windows computer's settings snapshot is kept the same way
    (db.set_device_settings). Never raises: a failure here must not spoil the results."""
    facts = getattr(drv, "facts", None) or {}
    try:
        snap = winsettings.clean(facts.get("windows_settings"))
        if snap:
            db.set_device_settings(dev, snap)
    except Exception:
        quiet.ignored()
    sw = facts.get("software")
    if not sw:
        return
    try:
        db.set_software(dev, sw)
    except Exception:
        quiet.ignored()


NO_VENDOR = "No vendor chosen. Edit the device to choose one. Until then only its ping and port checks run."
SNMP_EXTRA_CHECKS = ("cpu", "memory", "storage", "uptime", "interfaces", "interface errors")


def snmp_extras(dev, thresholds, opts, have, on_check=None, only=None):
    """A manager checked through its API that also answers SNMP once that is set up on it and in the device's SNMP tab (ISE, FMC,
    the SD-WAN Manager, vCenter, SonicWall): CPU, memory, storage, uptime and interfaces by SNMP, for whatever the API did not give.
    With `only` (subjects, for fill_gaps) exactly those are read, whatever `have` holds, without asking their tick boxes (the caller has).
    An SNMP failure is one ERROR row, never the loss of the API's rows."""
    from drivers.snmpdev import SnmpDriver
    done = {r.check for r in have if r.device == dev["name"]}

    class Extras(SnmpDriver):
        def check_list(self):
            own = dict([("cpu", self.cpu), ("memory", self.memory), ("storage", self.storage), ("uptime", self.uptime),
                        ("interfaces", self.interfaces), ("interface errors", self.errors)])
            return [(k, own[k]) for k in SNMP_EXTRA_CHECKS if (k in only if only is not None else k not in done)]

        def enabled(self, check_key):
            return (only is not None and check_key in only) or super().enabled(check_key)
    try:
        drv = Extras(dev, thresholds, opts)
        drv.on_check = on_check
        rows = drv.run()
    except Exception as e:
        return [Result(dev["name"], "snmp", ERROR, "", "SNMP: " + Driver.explain(e))]
    drv.flush_baselines()
    return [r for r in rows if r.check != "reachability"]


SSH_FILL = {"fortinet": ("cpu", "memory", "uptime"), "paloalto": ("cpu", "memory", "uptime", "firmware")}
FG_COMMANDS = {"cpu": 'get system performance status | grep "CPU states"', "memory": "get system performance status | grep Memory",
               "uptime": "get system performance status | grep Uptime"}       # one line each, so the pager never starts


def ssh_extras(dev, thresholds, opts, wanted, on_check=None):
    """A FortiGate's or Palo Alto's CPU, memory, uptime (and Palo Alto's version) from its command line, with the SSH login stored on
    it, for the `wanted` subjects: a row for each it could read. A failed session is one ssh ERROR row."""
    from core import cmdrun
    from drivers import fortinet, paloalto, sshbase
    vendor, rows = dev["vendor"], []
    try:
        drv = DRIVERS[vendor](dev, thresholds, opts)           # makes the rows; never run
        drv.on_check = on_check
        if vendor == "fortinet":
            # shortcut: FortiGates with VDOMs are not filled over SSH, upgrade when one is available to test against
            text = "\n".join(o for _c, o in cmdrun.run_cli(dev, [FG_COMMANDS[s] for s in SSH_FILL[vendor] if s in wanted], opts,
                                                           device_type="fortinet_readonly", before=lambda c: not c._vdoms))
            cpu, mem, up = fortinet.cli_cpu(text), fortinet.cli_memory(text), re.search(r"^Uptime:.*$", text, re.M)
            read = {"cpu": lambda: cpu is not None and drv.level_check("cpu", cpu),
                    "memory": lambda: mem is not None and drv.level_check("memory", mem),
                    "uptime": lambda: up and drv.uptime_row(sshbase.uptime_hours(up.group(0)))}
        else:
            text = "\n".join(o for _c, o in cmdrun.run_cli(dev, (["show system info"] if {"uptime", "firmware"} & set(wanted) else [])
                                                           + (["show system resources"] if {"cpu", "memory"} & set(wanted) else []), opts))
            sw = paloalto.cli_field(text, "sw-version")
            read = {"cpu": lambda: drv.level_check("cpu", paloalto.cpu_memory(text)[0]),
                    "memory": lambda: drv.level_check("memory", paloalto.cpu_memory(text)[1]),
                    "uptime": lambda: drv.uptime_row(paloalto.uptime_hours(paloalto.cli_field(text, "uptime"))),
                    "firmware": lambda: sw and drv.result("firmware", OK, sw, paloalto.cli_field(text, "model"))}
    except Exception as e:
        return [Result(dev["name"], "ssh", ERROR, "", "SSH: " + Driver.explain(e))]
    for s in SSH_FILL[vendor]:
        try:
            r = s in wanted and read[s]()
        except ValueError:                                     # not in the output: no row
            r = None
        if r:
            rows.append(r)
    return rows


def tagged(row, source, failed="", main="API"):
    """A copy of a row another method filled in, its message saying so."""
    msg = f"{row.message}, via {source}" if row.message else f"via {source}"
    return dataclasses.replace(row, message=f"{msg}; the {main} check failed: {failed}" if failed else msg)


def fill_gaps(dev, thresholds, opts, res, on_check=None, signed_in=True):
    """After a device's own driver: the CPU, memory, storage, uptime and interfaces it did not give, or failed at, by SNMP once that
    is set up, each filled row saying so; then, on a FortiGate or Palo Alto, what is still missing over SSH (SSH_FILL) with the SSH
    login stored on it. A main ERROR row goes once all it covers is filled. signed_in=False: the run raised."""
    vendor, name = dev["vendor"], dev["name"]
    if not vendors.fills(vendor):
        return res
    by_ssh = SSH_FILL.get(vendor, ())
    subjects = checks.SUBJECTS + (("firmware",) if by_ssh else ())
    gov = {s: checks.governs(vendor, s) for s in subjects}
    on = [s for s in subjects if checks.key(vendor, gov[s]) not in opts["disabled"]]
    mine = [r for r in res if r.device == name] if signed_in else []
    about = {s: [r for r in mine if r.check in (s, gov[s])] for s in on}
    failed = {s: rows[0].message for s, rows in about.items() if rows and all(r.status == ERROR for r in rows)}
    wanted = [s for s in on if s in failed or not about[s] and (s != "firmware" or not signed_in)]
    snmp_on = profiles.snmp_configured(dev)
    ssh_on = bool(set(wanted) & set(by_ssh)) and bool((dev.get("username") or "").strip()) and bool(profiles.ssh_secret(dev))
    if not wanted or not (snmp_on or ssh_on):
        return res
    by_snmp = [s for s in wanted if s in checks.SUBJECTS]
    got = snmp_extras(dev, thresholds, opts, res, on_check, only=by_snmp) if snmp_on and by_snmp else []
    main = "SSH" if vendors.get(vendor).get("kind") == "ssh" else "API"
    filled = [(r, "SNMP") for r in got if r.check in by_snmp and r.status != ERROR]
    done = {r.check for r, _src in filled}
    errors = [r for r in got if r.status == ERROR and r.check not in failed]     # SNMP's own failure stays only where the main method said nothing
    left = [s for s in wanted if s in by_ssh and s not in done]
    if ssh_on and left:
        more = ssh_extras(dev, thresholds, opts, left, on_check)
        filled += [(r, "SSH") for r in more if r.check in left and r.status != ERROR]
        done = {r.check for r, _src in filled}
        errors = [r for r in errors if r.check not in done] + [r for r in more if r.status == ERROR]     # the ssh row is kept
    filled.sort(key=lambda f: subjects.index(f[0].check))

    def dropped(r):
        covers = [s for s in on if r.check in (s, gov[s])]
        return r.device == name and r.status == ERROR and covers and all(s in done for s in covers)
    return [r for r in res if not dropped(r)] + [tagged(r, src, failed.get(r.check, ""), main) for r, src in filled] + errors


def _no_login(dev, opts):
    """The device's own web, port, certificate, ping and throughput checks: they need no sign-in."""
    return custom.run_network(dev, [c for c in custom.for_device(dev, opts.get("custom")) if c["kind"] in ("http", "tcp", "tls", "ping", "iperf")])


def run_one(dev, thresholds, opts=None, on_check=None):
    """One device's results. on_check(device name, check) is called as each check's row is made (a progress line)."""
    opts = opts or db.runtime_options()
    opts = {**opts, "disabled": db.disabled_for(dev, opts.get("disabled", ()), opts.get("profiles"))}      # its monitoring profile's list of checks, or its own
    pre = reachability(dev, opts) + stored_copy_note(dev)
    if not dev.get("vendor"):                # imported without one: nothing knows how to sign in, so only what needs no sign-in
        return pre + [Result(dev["name"], "vendor", NA, "", NO_VENDOR)] + _no_login(dev, opts)
    dead = next((r for r in pre if r.check == "reachability" and r.status == FAIL), None)
    if dead and not dev.get("jump"):         # its port did not answer: a login would only wait out its timeout (and retry);
        try:                                 # (a jump host is not probed)
            resolve_host(dev["host"])
            said = dead.message
        except Exception as e:               # a name that does not resolve says so plainly
            said = Driver.explain(e)
        return pre + [Result(dev["name"], "connection", ERROR, "", said)] + _no_login(dev, opts)
    attempts = 1 + max(0, int(opts.get("retries", 0)))
    for attempt in range(1, attempts + 1):
        try:
            dev = profiles.resolve(dev)      # username from the device's credential profile, if it has one
            if vendors.get(dev["vendor"]).get("kind") != "windows" or winmon.needs_dns(dev):
                resolve_host(dev["host"])    # a clear DNS error beats a cryptic socket one (an agent reports by itself)
            drv = DRIVERS[dev["vendor"]](dev, thresholds, opts)
            drv.on_check = on_check
            drv.custom = custom.for_device(dev, opts.get("custom"))        # user-defined checks that apply here
            res = drv.run()
            keep_software(dev, drv)
            if not getattr(drv, "wan_in_run", True) and ifaces.wan_capable(dev["vendor"]) and drv.enabled("wan usage"):
                drv.safe(res, "wan usage", drv.wan_usage)                  # by SNMP once it is set up (Driver.interface_counters)
            if dev["vendor"] in vendors.SNMP_EXTRAS and profiles.snmp_configured(dev):
                res += snmp_extras(dev, thresholds, opts, res, on_check)     # the managers: CPU, memory, storage, uptime, interfaces by SNMP, beside the API
            elif vendors.fills(dev["vendor"]):
                try:                                                         # what the device's own checks lacked or failed at, by SNMP or SSH;
                    res = fill_gaps(dev, thresholds, opts, res, on_check)    # a failure here never costs the device its own rows
                except Exception:
                    quiet.ignored()
            res += custom.run_network(dev, drv.custom)                       # web, port, certificate, ping, SNMP
            if "all:support" not in opts.get("disabled", ()):
                res += support.rows(dev, thresholds)                         # support, warranty and licence dates kept in the device's fields
            if opts.get("tls_sweep") and sweepable(dev):
                res += custom.sweep(dev, thresholds, opts.get("tls_sweep_ports", "443"))
            drv.flush_baselines()            # only after a complete run
            return pre + res
        except Exception as e:
            key_problem = nettools.host_key_problem(e)           # the device's SSH host key: changed, or unknown while rejected
            if attempt < attempts and _transient(e) and not key_problem:
                time.sleep(max(0, int(opts.get("retry_delay", 0))))
                continue
            tail = f" (after {attempt} attempts)" if attempt > 1 else ""
            said = str(e) if isinstance(e, AuthRejected) else Driver.explain(e)          # a rejected key already says so in words; an HTTP error names its code, not the long address
            if key_problem == "changed":
                rows = pre + [Result(dev["name"], "host key", FAIL, "", nettools.HOSTKEY_CHANGED)]
            elif key_problem == "unknown":
                rows = pre + [Result(dev["name"], "host key", ERROR, "", nettools.HOSTKEY_UNKNOWN)]
            else:
                rows = pre + [Result(dev["name"], "connection", ERROR, "", f"{said}{tail}")]
            try:                                   # web, port, certificate and ping checks do not need the login
                rows += _no_login(dev, opts)
                rows += fill_gaps(dev, thresholds, opts, [], on_check, signed_in=False)    # nor does SNMP
            except Exception:
                quiet.ignored()
            return rows


def run_all(devices, thresholds, on_results=None, workers=10, opts=None, on_check=None):
    """Run every device in parallel; call on_results(list) as each one finishes, and on_check(device name, check) as each
    check's row is made. `thresholds` is one dict for everyone, or a function dev -> dict (per-device overrides)."""
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
            res = run_one(d, th, o, on_check) if on_check is not None else run_one(d, th, o)      # (tests stand in a two-argument run_one)
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
