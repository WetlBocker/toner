"""User-defined checks: a command, an SNMP object, a web page, a TCP port, a certificate or a ping, plus a rule
for turning the answer into OK / WARN / FAIL. They run alongside the built-in checks of every device they apply to.

kind    ssh    run `target` on the device (SSH-managed vendors) and read the output
        snmp   read the OID in `target` (needs SNMP settings on the device or its profile)
        http   GET the URL in `target` ({host} is replaced by the device's host)
        tcp    connect to `port` on the device
        tls    read the certificate served on `port` and count the days left
        ping   ping the device
        iperf  an iperf3 throughput test to the device (it must run `iperf3 -s`); the result is Mbit/s, lower is worse
mode    number   the first number in the answer (or capture group 1 of `parse`) is compared with warn / fail
        match    `parse` (a regular expression) must match the answer, else FAIL
        nomatch  `parse` must NOT match the answer, else FAIL
Rules for http/tcp/tls/ping use the same warn / fail thresholds on their own measurement (milliseconds, days, %).
"""
import json
import re
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone

from core import db, proxy
from drivers.base import Result, OK, WARN, FAIL, ERROR

KINDS = [("ssh", "SSH command"), ("snmp", "SNMP object"), ("http", "Web page (HTTP/HTTPS)"),
         ("tcp", "TCP port"), ("tls", "TLS certificate"), ("ping", "Ping"),
         ("iperf", "Throughput (iperf3)")]
MODES = [("number", "A number, compared with the limits"), ("match", "Output must match"),
         ("nomatch", "Output must not match")]
FIELDS = ["name", "kind", "target", "parse", "mode", "warn", "fail", "higher_worse", "expect", "unit", "scope",
          "enabled", "port", "options"]


def list_checks():
    with db.connect() as c:
        out = [dict(r) for r in c.execute("SELECT * FROM custom_checks ORDER BY name COLLATE NOCASE")]
    for r in out:
        try:
            r["scope"] = json.loads(r["scope"] or "[]")
        except ValueError:
            r["scope"] = []
        try:
            r["options"] = json.loads(r.get("options") or "{}")
        except ValueError:
            r["options"] = {}
    return out


def validate(chk):
    name = (chk.get("name") or "").strip()
    if not name:
        raise ValueError("The check needs a name.")
    kind = chk.get("kind")
    if kind not in dict(KINDS):
        raise ValueError("Choose what kind of check this is.")
    if kind in ("ssh", "snmp", "http") and not (chk.get("target") or "").strip():
        raise ValueError({"ssh": "Enter the command to run.", "snmp": "Enter the OID to read.",
                          "http": "Enter the URL."}[kind])
    if kind in ("tcp",) and not int(chk.get("port") or 0):
        raise ValueError("Enter the TCP port.")
    if kind == "iperf":
        from core import iperf
        o = chk.get("options") or {}
        iperf.client_args("x", chk.get("port") or 5201, o.get("seconds", 10), o.get("streams", 1), False,
                          bool(o.get("udp")), o.get("bandwidth", ""))
    if kind == "snmp":
        from core import snmp
        snmp.parse_oid(chk["target"])
    if chk.get("mode") in ("match", "nomatch") or chk.get("parse"):
        try:
            re.compile(chk.get("parse") or "")
        except re.error as e:
            raise ValueError(f"The pattern is not a valid regular expression: {e}") from None
        if chk.get("mode") in ("match", "nomatch") and not chk.get("parse"):
            raise ValueError("Enter the pattern to look for.")
    w, f = chk.get("warn"), chk.get("fail")
    higher = 0 if kind == "iperf" else chk.get("higher_worse", 1)           # a slow link is the problem
    if w is not None and f is not None:
        bad = (w > f) if higher else (w < f)
        if bad:
            raise ValueError("WARN must be reached before FAIL: " + ("WARN <= FAIL." if higher
                                                                  else "WARN >= FAIL for 'lower is worse'."))
    return name


def save_check(chk):
    name = validate(chk)
    row = {k: chk.get(k) for k in FIELDS}
    row["name"] = name
    row["scope"] = json.dumps(chk.get("scope") or [])
    row["higher_worse"] = int(bool(chk.get("higher_worse", 1)))
    row["enabled"] = int(bool(chk.get("enabled", 1)))
    row["port"] = int(chk.get("port") or 0)
    row["options"] = json.dumps(chk.get("options") or {})
    if row["kind"] == "iperf":
        row["higher_worse"] = 0                            # a slow link is the problem
    with db.connect() as c:
        clash = c.execute("SELECT id FROM custom_checks WHERE name=? COLLATE NOCASE AND id IS NOT ?",
                          (name, chk.get("id"))).fetchone()
        if clash:
            raise ValueError(f"A check named '{name}' already exists.")
        if chk.get("id"):
            c.execute("UPDATE custom_checks SET " + ", ".join(f"{k}=?" for k in FIELDS) + " WHERE id=?",
                      [row[k] for k in FIELDS] + [chk["id"]])
            return chk["id"]
        return c.execute(f"INSERT INTO custom_checks ({','.join(FIELDS)}) VALUES ({','.join('?' * len(FIELDS))})",
                         [row[k] for k in FIELDS]).lastrowid


def delete_check(cid):
    with db.connect() as c:
        c.execute("DELETE FROM custom_checks WHERE id=?", (cid,))


def for_device(dev, checks=None):
    """The enabled custom checks whose scope includes this device."""
    checks = list_checks() if checks is None else checks
    return [c for c in checks if c.get("enabled", 1) and db.in_groups(dev, c.get("scope") or [])]


# ---------------------------------------------------------------- turning an answer into a status
def _threshold_status(chk, value):
    w, f = chk.get("warn"), chk.get("fail")
    if chk.get("higher_worse", 1):
        return FAIL if f is not None and value >= f else WARN if w is not None and value >= w else OK
    return FAIL if f is not None and value <= f else WARN if w is not None and value <= w else OK


def _fmt(value, unit):
    return (f"{value:,.2f}".rstrip("0").rstrip(".") if abs(value) < 1e6 else f"{value:.3g}") + (unit or "")


def evaluate(chk, device, text):
    """Judge an answer (command output, SNMP value, page body) by the check's mode."""
    name, unit, mode = chk["name"], chk.get("unit") or "", chk.get("mode") or "number"
    if mode in ("match", "nomatch"):
        found = re.search(chk["parse"], text or "", re.M | re.S) is not None
        good = found if mode == "match" else not found
        snippet = " ".join((text or "").split())[:80]
        return Result(device, name, OK if good else FAIL, "ok" if good else ("not found" if mode == "match" else "found"),
                      "" if good else (f"pattern {chk['parse']!r} " + ("did not match" if mode == "match" else "matched")
                                       + (f": {snippet}" if snippet else "")))
    pattern = chk.get("parse") or r"(-?\d+(?:\.\d+)?)"
    m = re.search(pattern, text or "", re.M | re.S)
    if not m:
        return Result(device, name, ERROR, "", "no number found in the answer: " + " ".join((text or "").split())[:80])
    try:
        value = float((m.group(1) if m.groups() else m.group(0)).replace(",", ""))
    except ValueError:
        return Result(device, name, ERROR, "", f"'{m.group(0)}' is not a number")
    status = _threshold_status(chk, value)
    return Result(device, name, status, _fmt(value, unit), "", numeric=value)


def _measured(chk, device, value, what):
    """A measurement taken by the app itself (latency, days left, packet loss) judged by warn / fail."""
    status = _threshold_status(chk, value)
    return Result(device, chk["name"], status, _fmt(value, chk.get("unit") or what), "", numeric=value)


# ---------------------------------------------------------------- the kinds
def run_tcp(chk, dev, timeout=5):
    port = int(chk.get("port") or 0)
    t0 = time.time()
    try:
        with proxy.create_connection(dev, (dev["host"], port), timeout):
            pass
    except OSError as e:
        return Result(dev["name"], chk["name"], FAIL, "closed", f"port {port}: {e.strerror or e}")
    ms = (time.time() - t0) * 1000
    r = _measured({**chk, "higher_worse": 1}, dev["name"], ms, " ms")
    r.message = f"port {port} open"
    return r


def run_http(chk, dev, timeout=10):
    import requests
    import urllib3
    url = (chk["target"] or "").replace("{host}", dev["host"])
    if "://" not in url:
        url = "https://" + url
    verify = bool(dev.get("verify_ssl"))
    if not verify:
        urllib3.disable_warnings()
    t0 = time.time()
    try:
        from urllib.parse import urlparse
        r = requests.get(url, timeout=timeout, verify=verify, allow_redirects=True,
                         **proxy.requests_kwargs(dev, urlparse(url).hostname))
    except requests.exceptions.SSLError as e:
        return Result(dev["name"], chk["name"], FAIL, "TLS error", str(e)[:120])
    except requests.RequestException as e:
        return Result(dev["name"], chk["name"], FAIL, "unreachable", f"{type(e).__name__}: {str(e)[:100]}")
    ms = (time.time() - t0) * 1000
    expect = (chk.get("expect") or "2xx").replace(" ", "")
    wanted = [w for w in expect.split(",") if w]
    good = any(str(r.status_code).startswith(w[0]) if w.endswith("xx") else str(r.status_code) == w for w in wanted)
    if not good:
        return Result(dev["name"], chk["name"], FAIL, str(r.status_code), f"expected {expect}")
    if chk.get("mode") in ("match", "nomatch") and chk.get("parse"):
        res = evaluate(chk, dev["name"], r.text[:200000])
        if res.status != OK:
            res.value = f"{r.status_code}, " + res.value
            return res
    res = _measured({**chk, "higher_worse": 1}, dev["name"], ms, " ms")
    res.message = f"HTTP {r.status_code}"
    return res


def run_tls(chk, dev, timeout=8):
    port = int(chk.get("port") or 443)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE                    # we read the certificate, whoever signed it
    try:
        with proxy.create_connection(dev, (dev["host"], port), timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=chk.get("target") or dev["host"]) as s:
                der = s.getpeercert(binary_form=True)
    except OSError as e:
        return Result(dev["name"], chk["name"], FAIL, "no certificate", f"port {port}: {e}")
    info = cert_info(der)
    days = info["days_left"]
    c2 = {**chk, "higher_worse": 0}
    if c2.get("warn") is None:
        c2["warn"] = 30
    if c2.get("fail") is None:
        c2["fail"] = 7
    status = _threshold_status(c2, days)
    msg = f"{info['subject']}, expires {info['not_after']:%Y-%m-%d}" + (" (EXPIRED)" if days < 0 else "")
    return Result(dev["name"], chk["name"], status, f"{days} days", msg, numeric=float(days))


def sweep_ports(text):
    """'443, 8443' -> [443, 8443] (bad entries are dropped)."""
    out = []
    for part in re.split(r"[,\s;]+", text or ""):
        if part.isdigit() and 0 < int(part) < 65536 and int(part) not in out:
            out.append(int(part))
    return out or [443]


def sweep(dev, thresholds, ports="443", timeout=3):
    """The certificate sweep: for each port, if the device answers TLS there, how long its certificate has left. A port that does
    not answer is not a problem (not every device has a web page), so it adds no row."""
    t = thresholds.get("cert_days", {"warn": 30, "fail": 7})
    out = []
    for port in sweep_ports(ports):
        name = "certificate" if port == 443 else f"certificate :{port}"
        r = run_tls({"name": name, "port": port, "warn": t["warn"], "fail": t["fail"]}, dev, timeout=timeout)
        if r.value != "no certificate":
            out.append(r)
    return out


def cert_info(der):
    """Subject, issuer, validity, SANs and days left for a DER certificate."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    cert = x509.load_der_x509_certificate(der)
    after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {"subject": cn[0].value if cn else cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_before": before, "not_after": after, "days_left": (after - datetime.now(timezone.utc)).days,
            "sans": list(sans), "serial": format(cert.serial_number, "x")}


def run_ping(chk, dev, timeout=8):
    r = subprocess.run(["ping", "-n", "4", "-w", "1500", dev["host"]], capture_output=True, text=True,
                       timeout=timeout + 8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    out = r.stdout or ""
    m = re.search(r"\((\d+)% loss\)", out)
    loss = int(m.group(1)) if m else 100
    avg = re.search(r"Average = (\d+)ms", out)
    if loss >= 100:
        return Result(dev["name"], chk["name"], FAIL, "no reply", "100% packet loss")
    ms = float(avg.group(1)) if avg else 0.0
    res = _measured({**chk, "higher_worse": 1}, dev["name"], ms, " ms")
    if loss and res.status == OK:
        res.status = WARN
    res.message = f"{loss}% loss" if loss else ""
    return res


def run_iperf(chk, dev, timeout=0):
    """Throughput from this computer to an iperf3 server on the device (or the address in `target`)."""
    from core import iperf
    exe = iperf.find_iperf3(db.get_setting("iperf_path"))
    if not exe:
        return Result(dev["name"], chk["name"], ERROR, "", "iperf3 was not found (see Tools > Throughput)")
    o = chk.get("options") or {}
    host = (chk.get("target") or "").replace("{host}", dev["host"]).strip() or dev["host"]
    seconds = int(o.get("seconds", 10))
    args = iperf.client_args(host, chk.get("port") or 5201, seconds, o.get("streams", 1), bool(o.get("reverse")),
                             bool(o.get("udp")), o.get("bandwidth", ""))
    try:
        sm, out = iperf.run_test(exe, args, seconds)
    except subprocess.TimeoutExpired:
        return Result(dev["name"], chk["name"], FAIL, "timed out", "iperf3 did not finish")
    got = sm.receiver or sm.sender
    if not got:
        return Result(dev["name"], chk["name"], FAIL, "no result", iperf.failure_reason(out))
    mbps = got["mbps"]
    status = _threshold_status({**chk, "higher_worse": 0}, mbps)
    res = Result(dev["name"], chk["name"], status, _fmt(mbps, chk.get("unit") or " Mbit/s"), sm.text(), numeric=mbps)
    if sm.sender and sm.sender.get("retransmits"):
        res.message = f"{sm.sender['retransmits']} retransmits"
    return res


def run_snmp(chk, dev, opts=None):
    from core import profiles, snmp
    if not (profiles.snmp_configured(dev) or dev.get("vendor") == "snmp"):
        return None                                    # the device has no SNMP settings: not applicable
    creds, port = snmp.credentials_for(dev)
    try:
        with snmp.Client(dev["host"], port, creds, timeout=5, retries=1) as c:
            got = c.get(snmp.parse_oid(chk["target"]))
    except (snmp.SnmpError, ValueError) as e:
        return Result(dev["name"], chk["name"], ERROR, "", str(e))
    if not got:
        return Result(dev["name"], chk["name"], ERROR, "", "the device has no such object")
    raw = next(iter(got.values()))
    text = snmp.text_of(raw)
    if (chk.get("mode") or "number") == "number" and not chk.get("parse"):
        v = snmp.number_of(raw)
        if v is not None:
            return Result(dev["name"], chk["name"], _threshold_status(chk, v), _fmt(v, chk.get("unit")), "", numeric=v)
    return evaluate(chk, dev["name"], text)


def run_ssh(driver, conn, checks=None):
    """Run the SSH custom checks inside an open session of an SSH driver. Returns Results."""
    out = []
    for chk in (checks if checks is not None else getattr(driver, "custom", [])):
        if chk["kind"] != "ssh":
            continue
        try:
            text = conn.send_command(chk["target"])
            out.append(evaluate(chk, driver.name, text))
        except Exception as e:
            out.append(Result(driver.name, chk["name"], ERROR, "", f"{type(e).__name__}: {e}"))
    return out


def run_network(dev, checks):
    """The kinds that need no session on the device. Returns Results."""
    out = []
    for chk in checks:
        try:
            fn = {"tcp": run_tcp, "http": run_http, "tls": run_tls, "ping": run_ping, "snmp": run_snmp,
                  "iperf": run_iperf}.get(chk["kind"])
            if not fn:
                continue
            r = fn(chk, dev)
            if r is not None:
                out.append(r)
        except Exception as e:
            out.append(Result(dev["name"], chk["name"], ERROR, "", f"{type(e).__name__}: {e}"))
    return out


def test_check(chk, dev, opts=None):
    """Run one check on one device now (for the editor's Test button). Returns a Result or an error message."""
    from core import profiles
    dev = profiles.resolve(dev)
    if chk["kind"] == "ssh":
        from drivers import DRIVERS
        drv = DRIVERS.get(dev["vendor"])
        if not drv or not hasattr(drv, "connect"):
            return Result(dev["name"], chk["name"], ERROR, "", "SSH checks need an SSH-managed vendor "
                                                                "(Cisco, Juniper, Arista, HPE, MikroTik).")
        d = drv(dev, db.thresholds_for(dev), {**db.runtime_options()})
        d.plat = dev.get("platform") or d.DEFAULT_PLATFORM
        with d.connect() as c:
            return run_ssh(d, c, [chk])[0]
    res = run_network(dev, [chk])
    return res[0] if res else Result(dev["name"], chk["name"], ERROR, "",
                                     "this device has no SNMP settings" if chk["kind"] == "snmp" else "nothing to run")
