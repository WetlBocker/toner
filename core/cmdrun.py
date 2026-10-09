"""Run the same command(s) on many devices over SSH and collect the output."""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core import db, profiles, vendors

# first words of commands that only read; everything else needs the operator's explicit say-so
READ_ONLY = ("show", "display", "get", "ping", "traceroute", "tracert", "dir", "more", "list", "monitor", "diagnose",
             "diag", "/system resource print", "/interface print", "/ip address print", "/export", "/ping", "/tool")
DANGEROUS = ("reload", "reboot", "restart", "erase", "format", "delete", "write erase", "factory", "reset", "shutdown",
             "no ", "clear", "configure", "conf t", "commit", "copy ", "request system", "/system reset", "/system reboot",
             "/system shutdown", "execute", "set ", "unset", "config ")


def read_only(command):
    c = (command or "").strip().lower()
    if not c:
        return True
    return c.startswith(READ_ONLY) and not any(c.startswith(d) for d in DANGEROUS)


def split_commands(text):
    return [l.strip() for l in (text or "").splitlines() if l.strip() and not l.strip().startswith("#")]


def run_on_device(dev, commands, opts=None, read_timeout=60):
    """Run the commands in one SSH session. Returns {'device','ok','outputs':[(command, text)],'error','seconds'}."""
    from drivers import DRIVERS
    start = time.time()
    dev = profiles.resolve(dev)
    out = {"device": dev["name"], "ok": False, "outputs": [], "error": "", "seconds": 0.0}
    cls = DRIVERS.get(dev["vendor"])
    if not cls or not hasattr(cls, "connect") or vendors.get(dev["vendor"]).get("kind") != "ssh":
        out["error"] = "not an SSH-managed device (commands run over SSH on Cisco, Juniper, Arista, HPE and MikroTik)"
        return out
    try:
        drv = cls(dev, {}, opts or db.runtime_options())
        drv.plat = dev.get("platform") or cls.DEFAULT_PLATFORM
        with drv.connect() as c:
            try:
                c.enable()
            except Exception:
                pass
            for cmd in commands:
                out["outputs"].append((cmd, c.send_command(cmd, read_timeout=read_timeout)))
        out["ok"] = True
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    out["seconds"] = time.time() - start
    return out


def run_many(devices, commands, workers=8, on_result=None, opts=None, cancel=None):
    results = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = [pool.submit(run_on_device, d, commands, opts) for d in devices]
        for f in as_completed(futs):
            r = f.result()
            results.append(r)
            if on_result:
                on_result(r)
            if cancel is not None and cancel.is_set():
                for g in futs:
                    g.cancel()
                break
    return sorted(results, key=lambda r: r["device"].lower())
