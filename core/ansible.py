"""Ansible from inside Toner: a library of playbooks, an inventory made from Toner's own, and runs on a machine that has Ansible.

Ansible does not run on Windows, so a run happens somewhere else and Toner does the rest:
- WSL on this PC (a Linux distribution with ansible installed), or
- a Linux server reached over SSH (an existing Ansible control node).
Toner writes the inventory (groups from vendors, folders, locations and tags; connection settings by kind of device), puts the devices' logins in a second,
private inventory that exists only for the length of the run, starts `ansible-playbook`, streams what it prints and keeps the result."""
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import zlib
from datetime import datetime
from pathlib import Path

import yaml

from core import db, paths, profiles, vendors, winmon

SERVER_SECRET = "service:ansible-server"          # the password of the control-node server typed in Settings > Ansible (also in core/vault.py)
DEFAULT_COMMAND = "ansible-playbook"
SKIP_DIRS = {".git", ".svn", "__pycache__", "node_modules", ".venv", "venv", "collections", ".cache"}
NOT_PLAYBOOKS = {"roles", "group_vars", "host_vars", "vars", "templates", "files", "handlers", "tasks", "defaults", "meta", "inventory", "inventories",
                 "library", "filter_plugins", "plugins", "molecule"}
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_UPLOAD_FILES = 2000


# ---------------------------------------------------------------- the library of playbooks
def default_dir():
    return paths.data_dir() / "ansible" / "playbooks"


def playbook_dir(create=True):
    """The folder the playbooks live in: the one chosen in Settings, or a folder in Toner's data folder."""
    chosen = (db.get_setting("ansible_playbooks") or "").strip()
    d = Path(chosen) if chosen else default_dir()
    if create:
        d.mkdir(parents=True, exist_ok=True)
    return d


def _clean_name(name):
    """A playbook name relative to the library: a/b.yml. No drive, no '..', no hidden or reserved parts, .yml or .yaml."""
    name = (name or "").strip().replace("\\", "/")
    if name.startswith("/"):
        raise ValueError("that is not a playbook name")
    name = name.strip("/")
    if not name or re.match(r"^[A-Za-z]:", name) or any(p in ("", ".", "..") or p.startswith(".") for p in name.split("/")):
        raise ValueError("that is not a playbook name")
    if not name.lower().endswith((".yml", ".yaml")):
        name += ".yml"
    if len(name) > 200 or re.search(r'[<>:"|?*\x00-\x1f]', name):
        raise ValueError("a playbook name cannot contain  < > : \" | ? *  and must be short")
    if re.match(r"^(con|prn|aux|nul|com\d|lpt\d)(\.|/|$)", name.lower()):
        raise ValueError("that name is reserved by Windows")
    return name


def resolve(name):
    """The file for a playbook name, always inside the library."""
    root = playbook_dir().resolve()
    p = (root / _clean_name(name)).resolve()
    if root != p and root not in p.parents:
        raise ValueError("a playbook must be inside the playbook folder")
    return p


def list_playbooks():
    """[{'name': 'site/backup.yml', 'path', 'size', 'mtime'}] for every playbook in the library, by name. Role, variable and template files are not playbooks."""
    root, out = playbook_dir(), []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and d not in NOT_PLAYBOOKS and not d.startswith("."))
        for f in sorted(files):
            if f.lower().endswith((".yml", ".yaml")) and not f.startswith("."):
                full = Path(dirpath) / f
                rel = full.relative_to(root).as_posix()
                st = full.stat()
                out.append({"name": rel, "path": str(full), "size": st.st_size, "mtime": st.st_mtime})
    return sorted(out, key=lambda p: p["name"].lower())


def read(name):
    return resolve(name).read_text(encoding="utf-8-sig", errors="replace")


def write(name, text):
    """Save a playbook (UTF-8, Unix line endings, a final newline), through a temporary file so a failure never leaves half of one."""
    p = resolve(name)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    if body and not body.endswith("\n"):
        body += "\n"
    tmp = p.with_name(p.name + ".toner-tmp")
    tmp.write_text(body, encoding="utf-8", newline="\n")
    os.replace(tmp, p)
    return p


def create(name, template="blank"):
    p = resolve(name)
    if p.exists():
        raise ValueError(f"'{p.name}' already exists")
    return write(name, TEMPLATES.get(template, TEMPLATES["blank"])[1])


def delete(name):
    p = resolve(name)
    if p.exists():
        p.unlink()
    return True


def rename(old, new):
    src, dst = resolve(old), resolve(new)
    if dst.exists():
        raise ValueError(f"'{dst.name}' already exists")
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.rename(dst)
    return dst


TEMPLATES = {
    "blank": ("Blank playbook", """---
- name: Describe what this playbook does
  hosts: all
  gather_facts: false
  tasks:
    - name: Say hello
      ansible.builtin.debug:
        msg: "Hello from {{ inventory_hostname }}"
"""),
    "ping": ("Ping every device (connection test)", """---
# Checks that Ansible can reach and log in to the devices. Run it in check mode first; it changes nothing.
- name: Test the connection
  hosts: all
  gather_facts: false
  tasks:
    - name: Ping
      ansible.builtin.ping:
"""),
    "ios_show": ("Cisco IOS: run a show command", """---
# Needs the cisco.ios collection:  ansible-galaxy collection install cisco.ios
- name: Show the version of Cisco IOS devices
  hosts: cisco
  gather_facts: false
  tasks:
    - name: show version
      cisco.ios.ios_command:
        commands:
          - show version
      register: out

    - name: Print it
      ansible.builtin.debug:
        var: out.stdout_lines
"""),
    "win_service": ("Windows: make sure a service is running", """---
# Windows computers reached over WinRM (set up in Toner: Edit device > Windows). Needs ansible.windows.
- name: Keep a service running
  hosts: windows
  gather_facts: false
  vars:
    service_name: Spooler
  tasks:
    - name: "{{ service_name }} is started and starts automatically"
      ansible.windows.win_service:
        name: "{{ service_name }}"
        state: started
        start_mode: auto
"""),
    "win_updates": ("Windows: install security updates", """---
# Installs security updates and reboots if Windows asks for it. Try it on one computer first (Limit to).
- name: Windows updates
  hosts: windows
  gather_facts: false
  tasks:
    - name: Install security and critical updates
      ansible.windows.win_updates:
        category_names:
          - SecurityUpdates
          - CriticalUpdates
        reboot: true
"""),
    "ntp": ("Network devices: set an NTP server (Cisco IOS)", """---
# Adds an NTP server to Cisco IOS devices. Change the address first, and run it in check mode to see what would change.
- name: NTP on Cisco IOS
  hosts: cisco
  gather_facts: false
  vars:
    ntp_server: 10.0.0.1
  tasks:
    - name: NTP server {{ ntp_server }}
      cisco.ios.ios_config:
        lines:
          - ntp server {{ ntp_server }}
"""),
}


class _Loader(yaml.SafeLoader):
    """Reads what Ansible reads: the tags it adds (!vault, !unsafe) are accepted and set aside."""


_Loader.add_multi_constructor("!", lambda loader, suffix, node: None)


def check_yaml(text):
    """(True, '', 0) when the text is YAML Ansible can read, else (False, a message, the line number)."""
    try:
        data = list(yaml.load_all(text or "", Loader=_Loader))
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        line = (mark.line + 1) if mark is not None else 0
        what = getattr(e, "problem", None) or str(e).splitlines()[0]
        return False, f"line {line}: {what}" if line else what, line
    docs = [d for d in data if d is not None]
    if not docs:
        return False, "the playbook is empty", 0
    for d in docs:
        if not isinstance(d, list) or not all(isinstance(x, dict) for x in d):
            return False, "a playbook is a list of plays: each starts with '- name:' and 'hosts:'", 1
        for play in d:
            if not ({"hosts", "import_playbook", "ansible.builtin.import_playbook"} & set(play)):
                return False, "every play needs 'hosts:' (which devices it runs on)", 1
    return True, "", 0


# ---------------------------------------------------------------- the inventory
def _ident(text, prefix=""):
    s = re.sub(r"[^A-Za-z0-9_]+", "_", str(text or "")).strip("_")
    return (prefix + s) if s else ""


def host_name(dev):
    """The name Ansible knows a device by (letters, digits, _ . -); the Toner name stays in the variable toner_name."""
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", dev["name"])


NETWORK_OS = {
    ("cisco", "cisco_ios"): "cisco.ios.ios", ("cisco", "cisco_xe"): "cisco.ios.ios", ("cisco", "cisco_nxos"): "cisco.nxos.nxos", ("cisco", "cisco_asa"): "cisco.asa.asa",
    ("juniper", ""): "junipernetworks.junos.junos", ("arista", ""): "arista.eos.eos", ("mikrotik", ""): "community.routeros.routeros",
}


def _fields(dev):
    raw = dev.get("fields")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw) if raw.strip() else {}
        except ValueError:
            raw = {}
    return raw if isinstance(raw, dict) else {}


def device_vars(dev):
    """(variables for the inventory, variables for the private logins inventory) for a device. No password is ever in the first."""
    dev = profiles.resolve(dev)
    vendor = dev["vendor"]
    plain = {"ansible_host": dev["host"], "toner_name": dev["name"], "toner_vendor": vendor}
    if dev.get("location"):
        plain["toner_location"] = dev["location"]
    secret = {}
    user = (dev.get("username") or "").strip()
    password = profiles.secret(dev, "main")
    if vendor in ("cisco", "juniper", "arista", "mikrotik", "hpe"):
        platform = dev.get("platform") or vendors.default_platform(vendor)
        os_name = NETWORK_OS.get((vendor, platform)) or NETWORK_OS.get((vendor, ""))
        if vendor == "hpe":
            os_name = "arubanetworks.aoscx.aoscx" if platform == "aruba_aoscx" else None
        if os_name:
            plain["ansible_network_os"] = os_name
            plain["ansible_connection"] = "ansible.netcommon.httpapi" if vendor == "hpe" else "ansible.netcommon.network_cli"
        if user:
            plain["ansible_user"] = user
        if dev.get("port"):
            plain["ansible_port"] = int(dev["port"])
        if vendor in ("cisco", "arista") and os_name:
            plain["ansible_become"] = True
            plain["ansible_become_method"] = "enable"
        if password:
            secret["ansible_password"] = password
            if vendor in ("cisco", "arista"):
                secret["ansible_become_password"] = password
    elif vendor == "windows":
        o = winmon.options(dev)
        plain["ansible_connection"] = "winrm"
        plain["ansible_winrm_transport"] = {"negotiate": "ntlm", "ntlm": "ntlm", "kerberos": "kerberos", "basic": "basic", "credssp": "credssp"}.get(o["auth"], "ntlm")
        https = o["https"] or int(dev.get("port") or 0) == 5986
        plain["ansible_port"] = int(dev.get("port") or 0) or (5986 if https else 5985)
        plain["ansible_winrm_scheme"] = "https" if https else "http"
        plain["ansible_winrm_server_cert_validation"] = "validate" if dev.get("verify_ssl") else "ignore"
        if user:
            plain["ansible_user"] = user
        if password and winmon.transport(dev) == "winrm":
            secret["ansible_password"] = password
    elif vendor == "fortinet":
        plain.update({"ansible_network_os": "fortinet.fortios.fortios", "ansible_connection": "httpapi", "ansible_httpapi_use_ssl": True,
                      "ansible_httpapi_validate_certs": bool(dev.get("verify_ssl")), "ansible_httpapi_port": int(dev.get("port") or 443)})
        if password:
            secret["ansible_httpapi_session_key"] = {"access_token": password}
    elif vendor == "paloalto":
        plain.update({"ansible_connection": "local", "panos_ip_address": dev["host"], "panos_port": int(dev.get("port") or 443)})
        if password:
            secret["panos_api_key"] = password
    for key, value in _fields(dev).items():
        k = str(key).strip().lower().replace(".", "_")
        if k.startswith("ansible_") and isinstance(value, (str, int, float, bool)):
            plain[k] = value
    return plain, secret


def build_inventory(devices):
    """(inventory, logins, names): `inventory` has every device with its connection settings and the groups (each vendor, folder_<path>, location_<place>,
    tag_<tag>); `logins` (or None) holds only the passwords and tokens, for the length of one run; `names` maps the host names Ansible uses to Toner's."""
    hosts, logins, groups = {}, {}, {}
    names, keys = {}, {}
    for dev in devices:
        h = host_name(dev)
        key = dev.get("key") or dev["name"]
        if h in keys and keys[h] != key:                  # two devices with one name (in two organizations, from Global)
            code = (next((o["code"] for o in db.org_rows() if o["id"] == dev.get("org")), "") or str(dev.get("id") or len(names)))
            h = f"{h}_{code}"
        keys[h] = key
        names[h] = dev["name"]
        plain, secret = device_vars(dev)
        hosts[h] = plain
        if secret:
            logins[h] = secret
        member = lambda g: groups.setdefault(g, {}).__setitem__(h, None)
        member(_ident(dev["vendor"]) or "other")
        fp = db.path_of(dev)
        if fp:
            member(_ident(fp, "folder_"))
        if db.several() and dev.get("org") is not None:     # Global: a group per organization too
            member(_ident(db.org_name(dev["org"]), "org_"))
        if dev.get("location"):
            member(_ident(dev["location"], "location_"))
        for tag in db.split_tags(dev.get("tags")):
            member(_ident(tag.lower(), "tag_"))            # tags are compared without regard to case in Toner, so their groups are too
    inventory = {"all": {"hosts": hosts, "children": {g: {"hosts": members} for g, members in sorted(groups.items())}}}
    return inventory, ({"all": {"hosts": logins}} if logins else None), names


def dump_yaml(data):
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)


# ---------------------------------------------------------------- a run
class RunSpec:
    """What to run: a playbook, on which devices, how."""

    def __init__(self, playbook, devices, check=True, tags="", extra_vars=None, verbosity=0, syntax_only=False, text=None):
        self.playbook, self.devices = playbook, list(devices)
        self.check, self.tags, self.extra_vars, self.verbosity = bool(check), (tags or "").strip(), dict(extra_vars or {}), int(verbosity or 0)
        self.syntax_only = syntax_only
        self.text = text                              # the playbook as typed, when it has not been saved (syntax checks)


def parse_extra_vars(text):
    """'a=1 b="two words"' or a JSON object -> {'a': '1', 'b': 'two words'}. Raises ValueError with what is wrong."""
    text = (text or "").strip()
    if not text:
        return {}
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError as e:
            raise ValueError(f"the variables are not valid JSON: {e}") from None
        if not isinstance(data, dict):
            raise ValueError("variables as JSON must be an object: {\"name\": \"value\"}")
        return data
    out = {}
    try:
        parts = shlex.split(text)
    except ValueError as e:
        raise ValueError(f"the variables have an unclosed quote: {e}") from None
    for part in parts:
        key, sep, value = part.partition("=")
        if not sep or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            raise ValueError(f"'{part}' is not name=value")
        out[key] = value
    return out


def build_args(spec, files):
    """The arguments after the command: `files` says where the inventory, logins and limit are, on the machine the run happens on."""
    args = ["-i", files["inventory"]]
    if files.get("logins"):
        args += ["-i", files["logins"]]
    args.append(files["playbook"])
    if spec.syntax_only:
        return args + ["--syntax-check"]
    if files.get("limit"):
        args += ["--limit", "@" + files["limit"]]
    if spec.check:
        args += ["--check", "--diff"]
    if spec.tags:
        args += ["--tags", spec.tags]
    if spec.extra_vars:
        args += ["--extra-vars", json.dumps(spec.extra_vars)]
    if spec.verbosity:
        args.append("-" + "v" * min(4, spec.verbosity))
    return args


def environment():
    """What every run is told: plain output (no colour codes), no prompts, and the host-key policy chosen in Settings > Security."""
    return {"ANSIBLE_NOCOLOR": "1", "ANSIBLE_FORCE_COLOR": "0", "PYTHONUNBUFFERED": "1", "ANSIBLE_RETRY_FILES_ENABLED": "0",
            "ANSIBLE_HOST_KEY_CHECKING": "False" if db.get_setting("hostkey_mode") == "Always trust" else "True",
            "ANSIBLE_STDOUT_CALLBACK": "default", "ANSIBLE_DEPRECATION_WARNINGS": "False", "ANSIBLE_LOCALHOST_WARNING": "False"}


RECAP = re.compile(r"^(?P<host>\S+)\s*:\s*ok=(?P<ok>\d+)\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+failed=(?P<failed>\d+)"
                   r"(?:\s+skipped=(?P<skipped>\d+))?(?:\s+rescued=(?P<rescued>\d+))?(?:\s+ignored=(?P<ignored>\d+))?", re.M)


def parse_recap(output, names=None):
    """[{'host', 'ok', 'changed', 'unreachable', 'failed', 'skipped'}] from the PLAY RECAP at the end of a run, with Toner's names for the hosts."""
    tail = output.rsplit("PLAY RECAP", 1)[-1] if "PLAY RECAP" in output else ""
    rows = []
    for m in RECAP.finditer(tail):
        d = {k: (int(v) if v is not None else 0) for k, v in m.groupdict().items() if k != "host"}
        d["host"] = (names or {}).get(m.group("host"), m.group("host"))
        rows.append(d)
    return rows


def to_wsl_path(path):
    """C:\\Users\\me\\x -> /mnt/c/Users/me/x"""
    p = str(path).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/?(.*)$", p)
    return f"/mnt/{m.group(1).lower()}/{m.group(2)}" if m else p


def _kill_tree(proc):
    try:
        if os.name != "nt":                                   # Linux, macOS: the run is its own process group (stream_process)
            import signal
            os.killpg(proc.pid, signal.SIGTERM)
            return
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _decode_line(raw):
    """One line of a program's output. An older wsl.exe writes its own messages in UTF-16 whatever it is told (a NUL between letters, which
    shows as boxes), so those NULs and a byte order mark are dropped."""
    text = raw.decode("utf-8", "replace").replace("\x00", "")
    return text.lstrip("﻿").rstrip("\r\n")


def stream_process(argv, on_line, cancel=None, env=None, cwd=None, timeout=None):
    """Run a program, giving each line it prints to on_line as it comes. Returns the exit code (-1 when cancelled or out of time)."""
    env = dict(os.environ if env is None else env, WSL_UTF8="1")           # wsl.exe then speaks UTF-8 instead of UTF-16 for its own messages
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), start_new_session=os.name != "nt")
    started, stopped = time.time(), {"why": ""}

    def watch():
        while proc.poll() is None:
            if cancel is not None and cancel.is_set():
                stopped["why"] = "cancelled"
                _kill_tree(proc)
                return
            if timeout and time.time() - started > timeout:
                stopped["why"] = "timed out"
                _kill_tree(proc)
                return
            time.sleep(0.2)

    t = threading.Thread(target=watch, daemon=True)
    t.start()
    for raw in iter(proc.stdout.readline, b""):
        on_line(_decode_line(raw))
    proc.wait()
    t.join(1)
    if stopped["why"]:
        on_line(f"[Toner: the run was {stopped['why']}]")
        return -1
    return proc.returncode


class BackendError(Exception):
    pass


class Backend:
    name = ""

    def describe(self):
        return self.name

    def check(self):
        """(True, 'ansible-playbook [core 2.17.1]') when Ansible can be used here, else (False, what to do)."""
        raise NotImplementedError

    def run(self, spec, files_text, on_line, cancel=None):
        """Run a playbook. files_text: {'inventory', 'logins', 'limit'} contents. Returns the exit code."""
        raise NotImplementedError


def _version_line(text):
    for line in (text or "").splitlines():
        if "ansible" in line.lower() and ("core" in line.lower() or re.search(r"\d+\.\d+", line)):
            return line.strip()
    return (text or "").strip().splitlines()[0] if (text or "").strip() else ""


class WslBackend(Backend):
    """Ansible in a WSL distribution on this PC. Files go through a private folder in Windows' temp area; the playbooks stay where they are."""
    name = "WSL"

    def __init__(self, distro="", command=DEFAULT_COMMAND):
        self.distro, self.command = (distro or "").strip(), (command or DEFAULT_COMMAND).strip() or DEFAULT_COMMAND

    def describe(self):
        return "WSL" + (f" ({self.distro})" if self.distro else "")

    @staticmethod
    def wsl():
        return shutil.which("wsl.exe") or "wsl.exe"

    @staticmethod
    def distros():
        """The names of the WSL distributions on this PC, or [] when WSL is not installed."""
        try:
            r = subprocess.run([WslBackend.wsl(), "-l", "-q"], capture_output=True, timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError):
            return []
        text = r.stdout.decode("utf-16-le", "ignore") if b"\x00" in r.stdout else r.stdout.decode("utf-8", "ignore")
        return [x.strip().strip("\ufeff") for x in text.splitlines() if x.strip().strip("\ufeff") and "no installed" not in x.lower()] if r.returncode == 0 else []

    def _argv(self, shell_command, cwd=None):
        argv = [self.wsl()]
        if self.distro:
            argv += ["-d", self.distro]
        if cwd:
            argv += ["--cd", str(cwd)]
        return argv + ["--", "bash", "-lc", shell_command]

    def check(self):
        if not shutil.which("wsl.exe"):
            return False, "WSL is not installed on this PC. In an administrator PowerShell run  wsl --install -d Ubuntu , restart, and open Ubuntu once to finish."
        found = self.distros()
        if not found:
            return False, "WSL has no Linux distribution yet. In PowerShell run  wsl --install -d Ubuntu , then open Ubuntu once to finish setting it up."
        if self.distro and self.distro not in found:
            return False, f"There is no WSL distribution called '{self.distro}'. Installed: {', '.join(found)}."
        lines = []
        try:
            code = stream_process(self._argv(f"{shlex.quote(self.command)} --version"), lines.append, timeout=60)
        except OSError as e:
            return False, f"WSL could not be started: {e}"
        text = "\n".join(lines)
        if code != 0 or "command not found" in text.lower() or "not found" in text.lower() and "ansible" in text.lower():
            return False, ("Ansible is not installed in " + (self.distro or "the default WSL distribution") + ". Open it and run  sudo apt update && sudo apt install -y ansible  "
                           "(or  pipx install ansible-core ). " + (text[:200] if text else ""))
        return True, _version_line(text)

    def run(self, spec, files_text, on_line, cancel=None):
        stage = Path(tempfile.mkdtemp(prefix="toner_ansible_")).resolve()      # resolved: the temp folder may be given by its 8.3 short name
        try:
            files = {"playbook": to_wsl_path(spec.playbook_path)}
            for key, fname in (("inventory", "inventory.yml"), ("logins", "logins.yml"), ("limit", "limit.txt")):
                if files_text.get(key):
                    p = stage / fname
                    p.write_text(files_text[key], encoding="utf-8", newline="\n")
                    files[key] = to_wsl_path(p)
            args = build_args(spec, files)
            env = environment()
            cmd = shlex.join(["env"] + [f"{k}={v}" for k, v in env.items()] + [self.command] + args)
            return stream_process(self._argv(cmd, cwd=Path(spec.playbook_path).parent), on_line, cancel)
        finally:
            shutil.rmtree(stage, ignore_errors=True)


class LocalBackend(Backend):
    """Ansible on this computer itself (Linux and macOS): the command is run directly, with the files in a private temp folder."""
    name = "local"

    def __init__(self, command=DEFAULT_COMMAND):
        self.command = (command or DEFAULT_COMMAND).strip() or DEFAULT_COMMAND

    def describe(self):
        return "this computer"

    def check(self):
        exe = shutil.which(self.command)
        if not exe:
            return False, ("Ansible is not installed on this computer. Install it (for example: sudo apt install ansible, or "
                           "pipx install ansible-core), then try again.")
        lines = []
        try:
            code = stream_process([exe, "--version"], lines.append, timeout=60)
        except OSError as e:
            return False, f"Ansible could not be started: {e}"
        text = "\n".join(lines)
        return (True, _version_line(text)) if code == 0 else (False, text[:300])

    def run(self, spec, files_text, on_line, cancel=None):
        stage = Path(tempfile.mkdtemp(prefix="toner_ansible_")).resolve()
        try:
            os.chmod(stage, 0o700)                                   # the logins file holds passwords: this user only
            files = {"playbook": str(spec.playbook_path)}
            for key, fname in (("inventory", "inventory.yml"), ("logins", "logins.yml"), ("limit", "limit.txt")):
                if files_text.get(key):
                    p = stage / fname
                    p.write_text(files_text[key], encoding="utf-8", newline="\n")
                    files[key] = str(p)
            env = {**os.environ, **environment()}
            return stream_process([self.command] + build_args(spec, files), on_line, cancel, env=env, cwd=Path(spec.playbook_path).parent)
        finally:
            shutil.rmtree(stage, ignore_errors=True)


class ServerBackend(Backend):
    """Ansible on a Linux server reached over SSH. The playbook folder is copied to a private temporary folder there, run, and removed."""
    name = "server"

    def __init__(self, login, command=DEFAULT_COMMAND):
        self.login, self.command = login, (command or DEFAULT_COMMAND).strip() or DEFAULT_COMMAND

    def describe(self):
        return f"server {self.login.get('host', '')}"

    def _connect(self, timeout=20):
        import paramiko
        from core import nettools
        lg = self.login
        if not lg.get("host") or not lg.get("user"):
            raise BackendError("The Ansible server is not set up: Settings > Ansible needs its address and user name.")
        client = paramiko.SSHClient()
        nettools.configure_hostkeys(client, db.get_setting("hostkey_mode"))
        kw = dict(hostname=lg["host"], port=int(lg.get("port") or 22), username=lg["user"], timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                  allow_agent=False, look_for_keys=False)
        if lg.get("key_file"):
            kw["key_filename"] = lg["key_file"]
            if lg.get("password"):
                kw["passphrase"] = lg["password"]
        else:
            kw["password"] = lg.get("password") or ""
        try:
            client.connect(**kw)
        except Exception as e:
            raise BackendError(f"Could not sign in to {lg['host']}: {type(e).__name__}: {str(e)[:200]}") from None
        return client

    def check(self):
        try:
            client = self._connect()
        except BackendError as e:
            return False, str(e)
        try:
            _i, out, _e = client.exec_command(f"{shlex.quote(self.command)} --version 2>&1", timeout=30)
            text = out.read().decode("utf-8", "replace")
            code = out.channel.recv_exit_status()
        finally:
            client.close()
        if code != 0:
            return False, f"Ansible is not available on {self.login['host']} ({self.command}): {text.strip()[:200] or 'command not found'}"
        return True, _version_line(text)

    @staticmethod
    def _tree(root):
        files, total = [], 0
        for dirpath, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for n in names:
                if n.endswith((".pyc", ".toner-tmp")):
                    continue
                full = Path(dirpath) / n
                size = full.stat().st_size
                total += size
                files.append((full, full.relative_to(root).as_posix()))
        if len(files) > MAX_UPLOAD_FILES or total > MAX_UPLOAD_BYTES:
            raise BackendError(f"The playbook folder is too big to copy to the server ({len(files)} files, {total // 1024 // 1024} MB). Keep it under "
                               f"{MAX_UPLOAD_FILES} files and {MAX_UPLOAD_BYTES // 1024 // 1024} MB.")
        return files

    def run(self, spec, files_text, on_line, cancel=None):
        client = self._connect()
        remote = ""
        try:
            _i, out, _e = client.exec_command("mktemp -d /tmp/toner-ansible.XXXXXX", timeout=20)
            remote = out.read().decode().strip()
            if not remote.startswith("/tmp/toner-ansible."):
                raise BackendError("The server would not make a temporary folder in /tmp.")
            sftp = client.open_sftp()
            root = Path(spec.playbook_root)
            for full, rel in self._tree(root):
                target = f"{remote}/pb/{rel}"
                self._mkdirs(sftp, os.path.dirname(target))
                sftp.put(str(full), target)
            if getattr(spec, "text", None) is not None:                           # an unsaved playbook (syntax check)
                with sftp.open(f"{remote}/pb/{Path(spec.playbook_path).relative_to(root).as_posix()}", "w") as f:
                    f.write(spec.text.encode("utf-8"))
            files = {"playbook": f"{remote}/pb/{Path(spec.playbook_path).relative_to(root).as_posix()}"}
            for key, fname in (("inventory", "inventory.yml"), ("logins", "logins.yml"), ("limit", "limit.txt")):
                if files_text.get(key):
                    path = f"{remote}/{fname}"
                    with sftp.open(path, "w") as f:
                        f.write(files_text[key].encode("utf-8"))
                    sftp.chmod(path, 0o600)
                    files[key] = path
            sftp.close()
            args = build_args(spec, files)
            env = environment()
            cmd = "cd " + shlex.quote(os.path.dirname(files["playbook"])) + " && " + shlex.join(["env"] + [f"{k}={v}" for k, v in env.items()] + [self.command] + args) + " 2>&1"
            chan = client.get_transport().open_session()
            chan.exec_command(cmd)
            buf = b""
            while True:
                if cancel is not None and cancel.is_set():
                    chan.close()
                    on_line("[Toner: the run was cancelled]")
                    return -1
                if chan.recv_ready():
                    buf += chan.recv(65536)
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        on_line(line.decode("utf-8", "replace").rstrip("\r"))
                elif chan.exit_status_ready():
                    while chan.recv_ready():
                        buf += chan.recv(65536)
                    break
                else:
                    time.sleep(0.05)
            if buf:
                for line in buf.decode("utf-8", "replace").splitlines():
                    on_line(line)
            return chan.recv_exit_status()
        finally:
            try:
                if remote.startswith("/tmp/toner-ansible."):
                    client.exec_command("rm -rf " + shlex.quote(remote), timeout=20)[1].channel.recv_exit_status()
            except Exception:
                pass
            client.close()

    @staticmethod
    def _mkdirs(sftp, path):
        parts, cur = [p for p in path.split("/") if p], ""
        for p in parts:
            cur += "/" + p
            try:
                sftp.stat(cur)
            except IOError:
                sftp.mkdir(cur)


# ---------------------------------------------------------------- the backend chosen in Settings
def device_login(name):
    """The control-node login taken from an Inventory device: its address, SSH port, user name and stored password."""
    dev = next((d for d in db.list_devices() if d["name"] == name), None)
    if dev is None:
        raise BackendError(f"The Ansible server device '{name}' is not in the Inventory any more: choose another in Settings > Ansible.")
    dev = profiles.resolve(dev)
    return {"host": dev["host"], "port": int(dev.get("port") or 22) if vendors.get(dev["vendor"]).get("kind") == "ssh" else 22,
            "user": dev.get("username") or "", "password": profiles.secret(dev, "main") or "", "key_file": ""}


def server_login():
    """The control-node login: an Inventory device chosen in Settings, or the host and user typed there (password in the vault)."""
    name = (db.get_setting("ansible_server_device") or "").strip()
    if name:
        return device_login(name)
    s = dict(db.get_setting("ansible_server") or {})
    try:
        import keyring
        pw = keyring.get_password(db.SERVICE, SERVER_SECRET) or ""
    except Exception:
        pw = ""
    return {"host": (s.get("host") or "").strip(), "port": int(s.get("port") or 22), "user": (s.get("user") or "").strip(),
            "key_file": (s.get("key_file") or "").strip(), "password": pw}


def backend():
    """The backend Settings > Ansible chose."""
    cmd = db.get_setting("ansible_command") or DEFAULT_COMMAND
    if db.get_setting("ansible_backend") == "server":
        return ServerBackend(server_login(), cmd)
    if os.name != "nt":                                       # Linux and macOS run it themselves; WSL is Windows' way
        return LocalBackend(cmd)
    return WslBackend(db.get_setting("ansible_distro") or "", cmd)


def prepare(spec):
    """Fill in where the playbook is (its file and the library it sits in), and check it exists."""
    spec.playbook_root = playbook_dir().resolve()
    spec.playbook_path = resolve(spec.playbook)
    if spec.text is None and not spec.playbook_path.exists():
        raise ValueError(f"There is no playbook called '{spec.playbook}'.")
    return spec


def run(spec, on_line, cancel=None, back=None):
    """Run a playbook and keep the result. Returns {'exit_code', 'rows', 'output', 'mode', 'seconds', 'run_id'}."""
    prepare(spec)
    back = back or backend()
    inv, logins, names = build_inventory(spec.devices)
    files_text = {"inventory": dump_yaml(inv), "logins": dump_yaml(logins) if logins else "",
                  "limit": "\n".join(names) + "\n" if (names and not spec.syntax_only) else ""}
    if spec.syntax_only and not names:
        files_text["inventory"] = dump_yaml({"all": {"hosts": {"localhost": {"ansible_connection": "local"}}}})
    lines, started = [], time.time()

    def keep(line):
        lines.append(line)
        on_line(line)

    code = back.run(spec, files_text, keep, cancel)
    output = "\n".join(lines)
    rows = parse_recap(output, names)
    result = {"exit_code": code, "rows": rows, "output": output, "seconds": time.time() - started,
              "mode": "syntax" if spec.syntax_only else ("check" if spec.check else "run"), "backend": back.describe()}
    if not spec.syntax_only:
        result["run_id"] = record_run(spec, result)
    return result


# ---------------------------------------------------------------- history
def record_run(spec, result):
    rows = result["rows"]
    n = lambda k: sum(r[k] for r in rows)
    with db.connect() as c:
        rid = c.execute("INSERT INTO ansible_runs(started_at, playbook, mode, backend, targets, ok, changed, unreachable, failed, exit_code, seconds, output) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), spec.playbook, result["mode"], result["backend"],
                         json.dumps([d["name"] for d in spec.devices]), n("ok"), n("changed"), n("unreachable"), n("failed"), result["exit_code"],
                         round(result["seconds"], 1), zlib.compress(result["output"].encode("utf-8", "replace"), 6))).lastrowid
        keep = max(10, int(db.get_setting("ansible_keep_runs") or 200))
        c.execute("DELETE FROM ansible_runs WHERE id NOT IN (SELECT id FROM ansible_runs ORDER BY id DESC LIMIT ?)", (keep,))
    return rid


def list_runs(limit=200):
    with db.connect() as c:
        return [dict(r) for r in c.execute("SELECT id, started_at, playbook, mode, backend, targets, ok, changed, unreachable, failed, exit_code, seconds "
                                           "FROM ansible_runs ORDER BY id DESC LIMIT ?", (limit,))]


def get_run(run_id):
    with db.connect() as c:
        row = c.execute("SELECT * FROM ansible_runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["output"] = zlib.decompress(d["output"]).decode("utf-8", "replace") if d["output"] else ""
    d["targets"] = json.loads(d["targets"] or "[]")
    return d
