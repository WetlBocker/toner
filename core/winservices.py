"""Windows services on a computer Toner can reach: list them, and start, stop or restart them.

Listing and control go through the same channels as the checks: PowerShell on this computer, or PowerShell remoting (WinRM) to another one.
A computer that reports through an agent cannot be controlled: the agent only sends, and takes no commands. For such a computer the list
is the last report's, and controlling needs a sign-in over WinRM (asked for when the window is opened, kept in memory only)."""
import json
import re

from core import winmon

ACTIONS = {"start": ("Start", "started"), "stop": ("Stop", "stopped"), "restart": ("Restart", "restarted")}

# stopping these can cut off the very connection being used, or take the computer's own services with it
RISKY = {
    "winrm": "Windows Remote Management is how Toner reaches this computer: stopping it ends this connection, and it cannot be started again from here.",
    "rpcss": "Remote Procedure Call is needed by almost everything on Windows. Stopping it can make the computer unusable until it restarts.",
    "dcomlaunch": "DCOM Server Process Launcher is needed by almost everything on Windows. Stopping it can make the computer unusable until it restarts.",
    "termservice": "Remote Desktop Services: stopping it disconnects everyone using Remote Desktop, you included if you are connected that way.",
    "lanmanserver": "Server (file and printer sharing): stopping it cuts off everyone using this computer's shares.",
    "netlogon": "Netlogon: on a domain controller, stopping it stops sign-ins for the domain.",
    "ntds": "Active Directory Domain Services: stopping it stops this domain controller.",
    "dns": "DNS Server: stopping it stops name resolution for everything that uses this server.",
    "dhcpserver": "DHCP Server: stopping it stops handing out addresses.",
    "eventlog": "Windows Event Log: other services depend on it and will stop too.",
}

# startup types: key -> (what a person reads, what sc.exe is told)
STARTUP = {"auto": ("Automatic", "auto"), "delayed": ("Automatic (Delayed Start)", "delayed-auto"), "manual": ("Manual", "demand"),
           "disabled": ("Disabled", "disabled")}

_BAD = re.compile(r"[\x00-\x1f\x7f]")


def check_name(name):
    """A service name that is safe to put in a script: not empty, not absurdly long, no control characters."""
    name = (name or "").strip()
    if not name or len(name) > 256 or _BAD.search(name):
        raise ValueError("that is not a service name")
    return name


def _q(name):
    """A PowerShell single-quoted string (the only character that needs care in one is the quote itself)."""
    return "'" + check_name(name).replace("'", "''").replace("‘", "''").replace("’", "''") + "'"


def warning(action, name):
    """What to say before stopping or restarting a service that matters, or '' for an ordinary one."""
    return RISKY.get((name or "").strip().lower(), "") if action in ("stop", "restart") else ""


def action_script(action, name):
    """The PowerShell that does one thing to one service and prints what became of it as one line of JSON."""
    if action not in ACTIONS:
        raise ValueError(f"unknown action '{action}'")
    verb = {"start": "Start-Service -InputObject $svc",
            "stop": "Stop-Service -InputObject $svc -Force",
            "restart": "Restart-Service -InputObject $svc -Force"}[action]
    return f"""
$ErrorActionPreference = 'Stop'
$n = {_q(name)}
$svc = Get-Service | Where-Object {{ $_.Name -eq $n }} | Select-Object -First 1
if (-not $svc) {{
    [ordered]@{{ ok = $false; name = $n; state = ''; display = ''; error = "there is no service called '$n' on this computer" }} | ConvertTo-Json -Compress
    return
}}
try {{
    {verb}
    $svc.Refresh()
    [ordered]@{{ ok = $true; name = $n; state = [string]$svc.Status; display = [string]$svc.DisplayName; error = '' }} | ConvertTo-Json -Compress
}} catch {{
    $svc.Refresh()
    [ordered]@{{ ok = $false; name = $n; state = [string]$svc.Status; display = [string]$svc.DisplayName; error = [string]$_.Exception.Message }} | ConvertTo-Json -Compress
}}
"""


def startup_script(mode, name):
    """The PowerShell that sets a service's startup type with sc.exe (the one tool that also knows 'delayed start') and prints what became of it."""
    if mode not in STARTUP:
        raise ValueError(f"unknown startup type '{mode}'")
    word = STARTUP[mode][1]
    return f"""
$ErrorActionPreference = 'Stop'
$n = {_q(name)}
$svc = Get-CimInstance Win32_Service | Where-Object {{ $_.Name -eq $n }} | Select-Object -First 1
if (-not $svc) {{
    [ordered]@{{ ok = $false; name = $n; state = ''; display = ''; start = ''; delayed = $false; error = "there is no service called '$n' on this computer" }} | ConvertTo-Json -Compress
    return
}}
$out = (& sc.exe config $n start= {word} 2>&1 | Out-String).Trim()
$code = $LASTEXITCODE
$now = Get-CimInstance Win32_Service | Where-Object {{ $_.Name -eq $n }} | Select-Object -First 1
[ordered]@{{ ok = ($code -eq 0); name = $n; state = [string]$now.State; display = [string]$now.DisplayName; start = [string]$now.StartMode;
            delayed = ([bool]$now.DelayedAutoStart -and [string]$now.StartMode -eq 'Auto'); error = $(if ($code -eq 0) {{ '' }} else {{ $out }}) }} | ConvertTo-Json -Compress
"""


def parse_action(text):
    """{'ok', 'name', 'state', 'display', 'error'} from what the script printed."""
    text = text or ""
    start = text.find("{")
    if start < 0:
        raise ValueError("the computer returned no answer" + (f": {text.strip()[:200]}" if text.strip() else ""))
    data = json.loads(text[start:text.rfind("}") + 1])
    if not isinstance(data, dict) or "ok" not in data:
        raise ValueError("the answer was not understood")
    return {"ok": bool(data.get("ok")), "name": str(data.get("name") or ""), "state": _state(data.get("state")),
            "display": str(data.get("display") or ""), "error": friendly(str(data.get("error") or "")),
            "start": str(data.get("start") or ""), "delayed": bool(data.get("delayed"))}


def _state(raw):
    """Get-Service says Running, Stopped, StartPending...; the service list says the same words: keep them."""
    raw = str(raw or "")
    return {"StartPending": "Start Pending", "StopPending": "Stop Pending", "ContinuePending": "Continue Pending",
            "PausePending": "Pause Pending"}.get(raw, raw)


def friendly(message):
    """A reason a person can act on, in place of the raw PowerShell error."""
    low = message.lower()
    if not message:
        return ""
    if "cannot open" in low and "service" in low or "access is denied" in low or "requested registry access is not allowed" in low:
        return "access denied: the account used here may not control services on this computer (it needs to be an administrator)"
    if "openservice failed 5" in low or "changeserviceconfig failed 5" in low:
        return "access denied: the account used here may not control services on this computer (it needs to be an administrator)"
    if "does not exist as an installed service" in low:
        return "there is no such service on this computer"
    if "cannot be started" in low and "disabled" in low:
        return "the service is disabled, so it cannot be started (change its startup type first)"
    if "cannot be started" in low and "dependent" in low or "dependency" in low and "failed to start" in low:
        return "a service this one depends on is not running"
    if "has not started" in low or "did not respond" in low or "timeout" in low or "time-out" in low or "time out" in low:
        return "the service did not answer in time: it may still be starting or stopping, so refresh the list"
    if "cannot be stopped" in low:
        return "the service cannot be stopped (it does not accept stop requests)"
    return " ".join(message.split())[:300]


# ---------------------------------------------------------------- reaching the computer
def can_control(dev):
    """True when this computer can be commanded: this PC, or a computer reached over WinRM. (An agent only reports.)"""
    return winmon.transport(dev) in ("local", "winrm")


def with_signin(dev, username):
    """The device as seen through a WinRM sign-in typed for this window (a computer that reports by agent has none of its own)."""
    own = winmon.options(dev)
    opts = {"https": own["https"], "auth": own["auth"], "watch": [], "ignore": []}
    return {**dev, "platform": "winrm", "username": username, "winopts": json.dumps(opts)}


def listing(dev, password=None, timeout=45):
    """(services, note): every service with its name, display name, state and startup type. Live for this PC and WinRM computers;
    the last report's for one that reports by agent."""
    return winmon.list_services(dev, password, timeout=timeout)


def startup_label(row):
    """What the Startup column says for a row of the list: Auto, Auto (Delayed), Manual, Disabled."""
    start = row.get("start") or ""
    return "Auto (Delayed)" if start == "Auto" and row.get("delayed") else start


def set_startup(dev, mode, name, password=None, timeout=60):
    """Change a service's startup type to `mode` (a key of STARTUP). Returns {'ok', 'name', 'state', 'display', 'error', 'start', 'delayed'}."""
    how = winmon.transport(dev)
    script = startup_script(mode, name)
    if how == "local":
        return winmon.collect_local(timeout=timeout, script=script, parser=parse_action)
    if how == "winrm":
        return winmon.collect_winrm(dev, password, timeout=timeout, script=script, parser=parse_action)
    raise RuntimeError("this computer reports through an agent, which takes no commands. Sign in with a Windows account to manage its services.")


def control(dev, action, name, password=None, timeout=120):
    """Do `action` ('start', 'stop' or 'restart') to the service called `name`. Returns the answer: {'ok', 'name', 'state', 'display', 'error'}.
    Raises RuntimeError when the computer cannot be reached or commanded."""
    how = winmon.transport(dev)
    script = action_script(action, name)
    if how == "local":
        return winmon.collect_local(timeout=timeout, script=script, parser=parse_action)
    if how == "winrm":
        return winmon.collect_winrm(dev, password, timeout=timeout, script=script, parser=parse_action)
    raise RuntimeError("this computer reports through an agent, which takes no commands. Sign in with a Windows account to manage its services.")
