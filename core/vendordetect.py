"""Working out what an imported device is, for Detect Vendors in the vendor window of a MobaXterm, PuTTY or SecureCRT import.

First what the device shows without signing in (core/discovery: its SSH banner, its HTTPS certificate, WinRM answering).
Then, for one still unknown, or a vendor with several platforms (Cisco IOS, IOS XE, NX-OS, ASA), signing in over SSH with
the entry's user name and password and asking it (netmiko's SSHDetect, connecting the way the checks do). Anything not
worked out stays without a vendor, to be chosen by hand or later.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed

from core import discovery, nettools, vendors

# what netmiko's detector answers -> (Toner's vendor, its platform); anything else is not a device Toner monitors over SSH
NETMIKO = {"cisco_ios": ("cisco", "cisco_ios"), "cisco_xe": ("cisco", "cisco_xe"), "cisco_nxos": ("cisco", "cisco_nxos"),
           "cisco_asa": ("cisco", "cisco_asa"), "juniper_junos": ("juniper", "juniper_junos"), "arista_eos": ("arista", "arista_eos"),
           "aruba_aoscx": ("hpe", "aruba_aoscx"), "hp_procurve": ("hpe", "aruba_osswitch"), "fortinet": ("fortinet", ""),
           "paloalto_panos": ("paloalto", "")}
LOOK_PORTS = (22, 443, 5985, 5986)       # SSH banner, HTTPS certificate, WinRM


def without_sign_in(host, timeout=2.0):
    """(vendor, platform) from what the device shows to anyone, or ('', '')."""
    try:
        ip = nettools.resolve_host(host)
        found = discovery.probe(ip, communities=(), ports=LOOK_PORTS, timeout=timeout)
    except Exception:
        return "", ""
    if not found or found["vendor"] not in vendors.VENDORS:
        return "", ""
    return found["vendor"], found["platform"]


def signing_in(host, port, username, password, timeout=20):
    """(vendor, platform) from what the device says once signed in over SSH, or ('', '')."""
    from netmiko import SSHDetect
    guesser = None
    try:
        guesser = SSHDetect(device_type="autodetect", host=host, port=int(port or 22), username=username, password=password,
                            timeout=timeout, conn_timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)
        best = guesser.autodetect()
    except Exception:
        return "", ""
    finally:
        try:
            if guesser is not None:
                guesser.connection.disconnect()
        except Exception:
            pass
    return NETMIKO.get(best or "", ("", ""))


def detect(entry, password="", timeout=20):
    """(vendor, platform) for one entry ({'kind', 'host', 'port', 'username'}), or ('', '') when it can't be told."""
    vendor, platform = without_sign_in(entry["host"])
    known = vendor and len(vendors.platform_keys(vendor)) <= 1
    if not known and entry.get("username") and password and entry["kind"] in ("ssh", "telnet"):
        port = entry.get("port") if entry["kind"] == "ssh" else 22          # Telnet entries: their SSH port, as the checks use
        got = signing_in(entry["host"], port, entry["username"], password, timeout)
        if got[0]:
            return got
    return vendor, platform


def detect_all(entries, passwords, on_done=None, cancel=None, workers=16, timeout=20):
    """detect() for many entries at once. entries: {key: entry}; passwords: {key: password}. Calls on_done(key, vendor, platform)
    as each finishes. Stops starting new ones once cancel (a threading.Event) is set. Returns {key: (vendor, platform)}."""
    out = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(detect, e, passwords.get(k, ""), timeout): k for k, e in entries.items()}
        for f in as_completed(futs):
            if cancel is not None and cancel.is_set():
                for g in futs:
                    g.cancel()
                break
            k = futs[f]
            try:
                out[k] = f.result()
            except Exception:
                out[k] = ("", "")
            if on_done:
                on_done(k, *out[k])
    return out
