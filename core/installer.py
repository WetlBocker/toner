"""Installing a missing tool from Toner (Linux): iperf3, nmap, FreeRDP, a VNC viewer, NetworkManager, Ansible, the Bitwarden CLI.

Each tool lists the installers it can come from (apt, pip, npm). Only those present on this computer are offered. apt (and npm
when its global folder is not this user's) needs administrator rights: Toner asks the system for them through pkexec, so the
password goes to the system's own window and never to Toner. Without pkexec the person is given the command to run in a
terminal instead.

Ubuntu 23.04 and later refuse `pip install --user` for the system's Python (PEP 668), so pip's option uses pipx when it is
there and is offered as plain pip only where the system allows it."""
import os
import shutil
import subprocess
import sys

from core.platforms import WINDOWS

TOOLS = {
    "iperf3": {"label": "iperf3", "apt": "iperf3", "find": "iperf3"},
    "nmap": {"label": "nmap", "apt": "nmap", "find": "nmap"},
    "freerdp": {"label": "FreeRDP", "apt": "freerdp3-x11", "find": "xfreerdp3"},
    "vnc": {"label": "TigerVNC", "apt": "tigervnc-viewer", "find": "vncviewer"},
    "nmcli": {"label": "NetworkManager", "apt": "network-manager", "find": "nmcli"},
    "rsync": {"label": "rsync", "apt": "rsync", "find": "rsync"},
    "ansible": {"label": "Ansible", "apt": "ansible", "pip": "ansible-core", "find": "ansible-playbook"},
    "bw": {"label": "the Bitwarden CLI", "npm": "@bitwarden/cli", "find": "bw"},
}


class Method:
    """One way to install a tool: what to show ('apt: sudo apt install iperf3'), what to run, and whether it needs root."""

    def __init__(self, kind, shown, argv, root):
        self.kind, self.shown, self.argv, self.root = kind, shown, argv, root

    @property
    def text(self):
        return f"{self.kind}: {self.shown}"


def _pip_allowed():
    """True unless the system's Python is marked externally managed (PEP 668)."""
    import sysconfig
    stdlib = sysconfig.get_paths().get("stdlib") or ""
    return not os.path.exists(os.path.join(stdlib, "EXTERNALLY-MANAGED"))


def _npm_global_writable():
    try:
        prefix = subprocess.run(["npm", "prefix", "-g"], capture_output=True, text=True, timeout=20).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(prefix) and os.access(os.path.join(prefix, "lib") if os.path.isdir(os.path.join(prefix, "lib")) else prefix, os.W_OK)


def methods(tool):
    """The ways `tool` can be installed on this computer, in the order apt, pip, npm. [] on Windows."""
    if WINDOWS or tool not in TOOLS:
        return []
    t, out = TOOLS[tool], []
    if t.get("apt") and shutil.which("apt-get"):
        out.append(Method("apt", f"sudo apt install {t['apt']}", ["apt-get", "install", "-y", t["apt"]], True))
    if t.get("pip"):
        if shutil.which("pipx"):
            out.append(Method("pip", f"pipx install {t['pip']}", ["pipx", "install", t["pip"]], False))
        elif _pip_allowed() and (shutil.which("pip3") or shutil.which("pip")):
            out.append(Method("pip", f"pip install --user {t['pip']}", [sys.executable if not getattr(sys, "frozen", False) else "python3",
                                                                       "-m", "pip", "install", "--user", t["pip"]], False))
    if t.get("npm") and shutil.which("npm"):
        root = not _npm_global_writable()
        out.append(Method("npm", f"npm install -g {t['npm']}", ["npm", "install", "-g", t["npm"]], root))
    return out


def can_elevate():
    """True when the system can ask for the administrator password itself (pkexec, with a desktop's polkit agent)."""
    return bool(shutil.which("pkexec"))


def command(method):
    """What is run: the method's command, through pkexec when it needs root."""
    return (["pkexec"] + method.argv) if method.root else list(method.argv)


def installed(tool):
    """True when the tool can now be found (after an install, PATH as it is now)."""
    t = TOOLS.get(tool) or {}
    return bool(shutil.which(t.get("find") or tool) or shutil.which(t.get("find") or tool,
                                                                     path=os.pathsep.join([os.environ.get("PATH", ""),
                                                                                           os.path.expanduser("~/.local/bin")])))


NO_AGENT = ("no authentication agent", "not authorized", "polkit")


def needs_terminal(output):
    """True when pkexec could not ask for the password (no polkit agent, as under WSL): the command goes to a terminal instead."""
    low = (output or "").lower()
    return any(w in low for w in NO_AGENT)
