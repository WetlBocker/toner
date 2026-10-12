"""Windows monitoring: one PowerShell collector, three ways to run it.

  agent   a small script on the Windows computer runs it and sends the result to Toner (core/agents.py)
  winrm   Toner runs it remotely over WinRM / PowerShell remoting (pypsrp): nothing to install on the server
  local   Toner runs it on the computer it is running on

All three give the same JSON document, and evaluate() turns it into check results, so the checks are identical.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

# ---------------------------------------------------------------- the collector (Windows PowerShell 5.1 and later)
COLLECTOR = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$o = [ordered]@{ v = 1; at = (Get-Date).ToUniversalTime().ToString('o') }
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$o.computer = $env:COMPUTERNAME
$o.domain = [string]$cs.Domain
$o.joined = [bool]$cs.PartOfDomain
$o.os = [string]$os.Caption
$o.build = [string]$os.BuildNumber
$o.boot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
$o.uptime_h = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 5)
$o.mem_total_mb = [math]::Round($os.TotalVisibleMemorySize / 1024)
$o.mem_free_mb = [math]::Round($os.FreePhysicalMemory / 1024)
$o.ips = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { $_.IPAddress } | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
$load = @()
1..3 | ForEach-Object { $load += [double](Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average; if ($_ -lt 3) { Start-Sleep -Milliseconds 600 } }
$o.cpu = [math]::Round(($load | Measure-Object -Average).Average, 1)
$o.disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [ordered]@{ drive = $_.DeviceID; size = [int64]$_.Size; free = [int64]$_.FreeSpace } })
$reb = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reb += 'component servicing' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reb += 'Windows Update' }
$a = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName').ComputerName
$b = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName').ComputerName
if ($a -and $b -and $a -ne $b) { $reb += 'computer rename' }
$o.reboot = @($reb)
$svc = @(Get-CimInstance Win32_Service)
$o.service_states = [ordered]@{}
foreach ($s in $svc) { $o.service_states[[string]$s.Name] = $(if ($s.State -eq 'Running') { 'R' } else { 'S' }) }
$o.auto_stopped = @($svc | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } | ForEach-Object {
    [ordered]@{ name = [string]$_.Name; display = [string]$_.DisplayName; exit = [int]$_.ExitCode; delayed = [bool]$_.DelayedAutoStart
                trigger = [bool](Test-Path ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $_.Name + '\TriggerInfo')) } })
$evOk = $true
try { $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System', 'Application'; Level = 1, 2; StartTime = (Get-Date).AddHours(-24) } -MaxEvents 1000 -ErrorAction Stop) }
catch { $ev = @(); if ($_.Exception.Message -notmatch 'No events were found') { $evOk = $false } }
if ($evOk) {
    $o.events = [ordered]@{ count = $ev.Count; capped = ($ev.Count -ge 1000)
        top = @($ev | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { [ordered]@{ source = $_.Name; count = $_.Count } }) }
}
$now = Get-Date
$o.certs = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.NotAfter -lt $now.AddDays(90) -and $_.NotAfter -gt $now.AddDays(-30) -and $_.Subject -ne ('CN=' + $env:COMPUTERNAME) } | ForEach-Object {
    [ordered]@{ subject = [string]$_.Subject; days = [math]::Floor(($_.NotAfter - $now).TotalDays); thumb = [string]$_.Thumbprint } })
$last = $null
$t = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install').LastSuccessTime
if ($t) { try { $last = [datetime]::SpecifyKind([datetime]::Parse($t), 'Utc') } catch {} }
if (-not $last) { $h = Get-CimInstance Win32_QuickFixEngineering | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($h) { $last = $h.InstalledOn.ToUniversalTime() } }
if ($last) { $o.patched = $last.ToString('o') }
# what is installed, who may administer the computer, what is listening: compared from one run to the next
$sw = [ordered]@{}
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
    Get-ItemProperty $k | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } | ForEach-Object { $sw[[string]$_.DisplayName] = [string]$_.DisplayVersion }
}
$o.software = $sw
try { $o.admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch {}
try {
    $names = @{}
    Get-Process | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
    $o.ports = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Sort-Object LocalPort -Unique | ForEach-Object { ([string]$_.LocalPort) + '/' + $names[[int]$_.OwningProcess] })
} catch {}
$o | ConvertTo-Json -Depth 6 -Compress
"""

# Automatic services that legitimately stop on their own are not reported: ones that start on a trigger, ones that
# are still starting after boot, per-user services, and a few well-known updaters.
BUILTIN_IGNORE = ("gupdate", "gupdatem", "edgeupdate", "edgeupdatem", "sppsvc", "clr_optimization_*", "MapsBroker",
                  "RemoteRegistry", "TrustedInstaller", "wuauserv", "UsoSvc", "WbioSrvc", "BITS", "ShellHWDetection",
                  "tiledatamodelsvc", "CDPUserSvc*", "OneSyncSvc*", "edgeupdate*", "GoogleUpdater*", "MicrosoftEdgeElevationService")
_PER_USER = re.compile(r"_[0-9a-f]{4,}$", re.I)

AUTHS = (("negotiate", "Windows sign-in (Kerberos or NTLM)"), ("ntlm", "NTLM"), ("kerberos", "Kerberos only"),
         ("basic", "Basic (local account, use HTTPS)"), ("credssp", "CredSSP"))


def transport(dev):
    return dev.get("platform") if dev.get("platform") in ("agent", "winrm", "local") else "agent"


def needs_dns(dev):
    """An agent reports by itself and a laptop away from the office may not resolve: only WinRM needs the name to work."""
    return transport(dev) == "winrm"


def options(dev):
    """The device's Windows settings, with defaults."""
    try:
        raw = json.loads(dev.get("winopts") or "{}")
    except ValueError:
        raw = {}
    raw = raw if isinstance(raw, dict) else {}
    return {"https": bool(raw.get("https")), "auth": raw.get("auth") if raw.get("auth") in dict(AUTHS) else "negotiate",
            "watch": _names(raw.get("watch")), "ignore": _names(raw.get("ignore"))}


def _names(value):
    if isinstance(value, str):
        value = re.split(r"[,;\n]+", value)
    return [x.strip() for x in (value or []) if isinstance(x, str) and x.strip()]


def names_text(names):
    return ", ".join(names)


# ---------------------------------------------------------------- running the collector
def _parse(text):
    """The JSON document inside whatever PowerShell printed."""
    text = text or ""
    start = text.find("{")
    if start < 0:
        raise ValueError("the collector returned no data" + (f": {text.strip()[:200]}" if text.strip() else ""))
    data = json.loads(text[start:text.rfind("}") + 1])
    if not isinstance(data, dict) or "computer" not in data:
        raise ValueError("the collector's answer was not understood")
    return data


def parse_report(text):
    return _parse(text)


LIST_SERVICES = r"""
$ErrorActionPreference = 'Stop'
$list = @(Get-CimInstance Win32_Service | ForEach-Object {
    [ordered]@{ name = [string]$_.Name; display = [string]$_.DisplayName; state = [string]$_.State; start = [string]$_.StartMode } })
[ordered]@{ services = $list } | ConvertTo-Json -Depth 4 -Compress
"""


def parse_services(text):
    """The services a computer has, [{'name', 'display', 'state', 'start'}], by display name."""
    text = text or ""
    start = text.find("{")
    if start < 0:
        raise ValueError("the computer returned no list of services" + (f": {text.strip()[:200]}" if text.strip() else ""))
    data = json.loads(text[start:text.rfind("}") + 1])
    rows = data.get("services") if isinstance(data, dict) else None
    if isinstance(rows, dict):
        rows = [rows]                                   # PowerShell 5.1 turns a list of one into the item itself
    if not isinstance(rows, list):
        raise ValueError("the list of services was not understood")
    out = [{"name": str(r.get("name") or ""), "display": str(r.get("display") or ""), "state": str(r.get("state") or ""),
            "start": str(r.get("start") or "")} for r in rows if isinstance(r, dict) and r.get("name")]
    return sorted(out, key=lambda r: (r["display"] or r["name"]).lower())


def list_services(dev, password=None, timeout=30):
    """(services, note): what to choose from when naming services to watch. A computer that reports by agent is not asked anything;
    the last report it sent is used, which has each service's name and whether it was running."""
    how = transport(dev)
    if how == "agent":
        from core import agents
        report, age = agents.latest(dev.get("name", ""))
        if report is None:
            raise RuntimeError("this computer's agent has not reported yet, so there is no list to choose from. Install the agent, "
                               "wait for its first report, and open this again. (You can also type service names.)")
        states = report.get("service_states") or {}
        shown = {s.get("name"): s.get("display", "") for s in report.get("auto_stopped") or []}
        rows = [{"name": n, "display": shown.get(n, ""), "state": "Running" if v == "R" else "Stopped", "start": ""}
                for n, v in states.items()]
        when = "" if age is None else f" ({age:.0f} min ago)" if age < 120 else f" ({age / 60:.1f} h ago)"
        return sorted(rows, key=lambda r: r["name"].lower()), f"From the agent's last report{when}."
    if how == "local":
        return collect_local(timeout=timeout, script=LIST_SERVICES, parser=parse_services), "From this computer."
    return collect_winrm(dev, password, timeout=timeout, script=LIST_SERVICES, parser=parse_services), "From the computer, just now."


def collect_local(timeout=90, script=None, parser=None):
    """Run the collector on this computer."""
    exe = shutil.which("powershell.exe") or "powershell.exe"
    folder = tempfile.mkdtemp(prefix="toner_ps_")
    try:
        path = os.path.join(folder, "collect.ps1")
        with open(path, "w", encoding="utf-8-sig") as f:
            f.write("[Console]::OutputEncoding = [Text.Encoding]::UTF8\n" + (script or COLLECTOR))
        r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path],
                           capture_output=True, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    out = r.stdout.decode("utf-8", "replace")
    if r.returncode and "{" not in out:
        raise RuntimeError(f"PowerShell failed: {r.stderr.decode('utf-8', 'replace').strip()[:300] or r.returncode}")
    return (parser or _parse)(out)


def collect_winrm(dev, password, timeout=30, factory=None, script=None, parser=None):
    """Run the collector on a remote computer through PowerShell remoting."""
    opts = options(dev)
    port = int(dev.get("port") or 0) or (5986 if opts["https"] else 5985)
    https = opts["https"] or port == 5986
    user = (dev.get("username") or "").strip() or None
    if factory is None:
        from pypsrp.client import Client as factory
    try:
        client = factory(dev["host"], username=user, password=(password or None) if user else None, ssl=https, port=port,
                         auth=opts["auth"], cert_validation=bool(dev.get("verify_ssl")), connection_timeout=timeout,
                         operation_timeout=max(10, timeout - 5), read_timeout=timeout + 60)
        out, streams, failed = client.execute_ps(script or COLLECTOR)
    except Exception as e:
        raise RuntimeError(explain(e, https, port)) from None
    if not str(out or "").strip():
        errs = "; ".join(str(x) for x in getattr(streams, "error", [])[:2])
        raise RuntimeError(f"the remote computer returned nothing{': ' + errs if errs else ''}")
    return (parser or _parse)(str(out))


def explain(e, https, port):
    """A reason an administrator can act on, instead of a library traceback."""
    text = " ".join(str(e).split())
    low = text.lower()
    if "401" in low or "credentials were rejected" in low or "logon failure" in low or "access is denied" in low:
        return ("the computer rejected the sign-in. Check the user name (DOMAIN\\user, user@domain or .\\user) and password, "
                "and that the account may use remote management (Remote Management Users)." + f" [{text[:120]}]")
    if "timed out" in low or "timeout" in low:
        return f"no answer on port {port}: WinRM is not enabled or a firewall blocks it (Enable-PSRemoting; allow TCP {port})."
    if "refused" in low or "actively refused" in low:
        return f"port {port} refused the connection: WinRM is not listening there ({'HTTPS' if https else 'HTTP'} listener)."
    if "certificate" in low or "ssl" in low:
        return f"the HTTPS certificate was not accepted ({text[:160]}). Turn off 'Verify the certificate' or install a trusted one."
    if "kerberos" in low or "spn" in low or "server not found in kerberos" in low:
        return f"Kerberos could not sign in ({text[:160]}). Use the computer's DNS name, or choose NTLM."
    return f"{type(e).__name__}: {text[:240]}"


# ---------------------------------------------------------------- reading a report
def _when(text):
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024


def _matches(name, patterns):
    low = name.lower()
    for p in patterns:
        p = p.lower()
        if (p.endswith("*") and low.startswith(p[:-1])) or low == p:
            return True
    return False


def stopped_services(report, ignore=(), uptime_h=None):
    """Automatic services that are not running and should be: not trigger-started, not just booting, not ignored."""
    up = report.get("uptime_h") if uptime_h is None else uptime_h
    out = []
    for s in report.get("auto_stopped") or []:
        name = s.get("name", "")
        if (s.get("trigger") or _PER_USER.search(name) or _matches(name, BUILTIN_IGNORE) or _matches(name, ignore)
                or (s.get("delayed") and up is not None and up < 0.25)):
            continue
        out.append(s)
    return out


def summary(report):
    """One line to say what the computer is."""
    bits = [report.get("os", ""), f"domain {report['domain']}" if report.get("joined") else "not in a domain"]
    return ", ".join(x for x in bits if x)
