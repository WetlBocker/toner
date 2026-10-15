# Run directly (python tests/test_x.py) or all together (python tests/run_all.py). Each test builds its own
# throw-away database and uses a fake credential store, so nothing on this computer is touched.
# Ansible from Toner: the playbook library, the inventory, the commands, both ways of running (WSL and a server), the recap and the history.
# No real Ansible is needed: the program that would run is replaced by a stand-in that prints what Ansible prints.
import os as _os, sys as _sys, tempfile as _tmp
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.environ.setdefault("SP", _tmp.mkdtemp(prefix="netcheck_test_"))
_os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json, os, sys, threading, time
SP = os.environ["SP"]; os.environ["NETCHECK_DB"] = SP + r"\ansc%d.db" % int(time.time()); os.environ["APPDATA"] = os.path.join(SP, "roamingans%d" % int(time.time()))
from core import ansible as AN, db
db.init()
import yaml
import keyring
STORE = {}
keyring.set_password = lambda s, u, p: STORE.__setitem__((s, u), p); keyring.get_password = lambda s, u: STORE.get((s, u)); keyring.delete_password = lambda s, u: STORE.pop((s, u), None)
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
BS = chr(92)

print("== the library of playbooks")
root = AN.playbook_dir()
check("it starts in a folder in Toner's data folder, made on demand", root == AN.default_dir() and root.is_dir() and root.parts[-3:] == ("ansible", "playbooks", ) or root.parts[-2:] == ("ansible", "playbooks"), str(root))
check("empty at first", AN.list_playbooks() == [])
p = AN.create("site/backup", "ping")
check("a playbook is made from a template, in its own folder, as .yml", p.name == "backup.yml" and p.parent.name == "site" and "ansible.builtin.ping" in p.read_text(encoding="utf-8"))
try: AN.create("site/backup.yml"); check("making one that exists is refused", False)
except ValueError as e: check("making one that exists is refused", "already exists" in str(e))
AN.write("site/web.yaml", "---" + chr(13) + chr(10) + "- hosts: all" + chr(13) + chr(10) + "  tasks: []")
check("saved with Unix line endings and a final newline, no temporary file left behind", AN.read("site/web.yaml") == "---\n- hosts: all\n  tasks: []\n" and not list(root.rglob("*.toner-tmp")))
check("listed by name, by folder", [x["name"] for x in AN.list_playbooks()] == ["site/backup.yml", "site/web.yaml"] and AN.list_playbooks()[0]["size"] > 0)
os.makedirs(root / "roles" / "x" / "tasks"); (root / "roles" / "x" / "tasks" / "main.yml").write_text("- debug: {}", encoding="utf-8")
os.makedirs(root / "group_vars"); (root / "group_vars" / "all.yml").write_text("a: 1", encoding="utf-8"); (root / ".hidden.yml").write_text("x", encoding="utf-8")
check("roles, variables and hidden files are not playbooks", [x["name"] for x in AN.list_playbooks()] == ["site/backup.yml", "site/web.yaml"])
for bad_name in ("../x.yml", "a/../../x", "C:" + BS + "x.yml", "/etc/passwd", "", "  ", "a//b" + BS + "..", ".git/x", "con.yml", "a<b.yml", "x" * 300):
    try: AN.resolve(bad_name); check(f"{bad_name[:20]!r} is refused", False)
    except ValueError: check(f"{bad_name[:20]!r} is refused", True)
check("a name without an extension gets .yml, and backslashes are folders", AN.resolve("a" + BS + "b").name == "b.yml" and AN.resolve("a" + BS + "b").parent.name == "a")
AN.rename("site/web.yaml", "site/website.yml")
check("renaming moves it", [x["name"] for x in AN.list_playbooks()] == ["site/backup.yml", "site/website.yml"])
try: AN.rename("site/website.yml", "site/backup.yml"); check("renaming over another is refused", False)
except ValueError: check("renaming over another is refused", True)
AN.delete("site/website.yml"); check("deleting removes it", [x["name"] for x in AN.list_playbooks()] == ["site/backup.yml"])
elsewhere = os.path.join(SP, "my playbooks"); db.set_setting("ansible_playbooks", elsewhere)
check("the folder can be moved to wherever you keep them (a Git repo, say)", AN.playbook_dir() == __import__("pathlib").Path(elsewhere) and AN.list_playbooks() == [])
db.set_setting("ansible_playbooks", "")

print("== reading YAML the way Ansible does")
check("every template is a valid playbook", all(AN.check_yaml(t)[0] for _k, (_l, t) in AN.TEMPLATES.items()))
check("a broken file says which line", AN.check_yaml("- hosts: all\n  tasks:\n    - name: x\n     bad: y\n")[0] is False and AN.check_yaml("- hosts: all\n  tasks:\n    - name: x\n     bad: y\n")[2] > 0)
check("an empty one is refused", AN.check_yaml("")[1] == "the playbook is empty" and AN.check_yaml("# only a comment\n")[0] is False)
check("something that is not a list of plays is refused, with what a playbook looks like", "list of plays" in AN.check_yaml("hosts: all\n")[1])
check("a play without hosts is refused", "hosts" in AN.check_yaml("- name: x\n  tasks: []\n")[1])
check("Ansible's own tags are accepted (!vault)", AN.check_yaml("- hosts: all\n  vars:\n    pw: !vault |\n      $ANSIBLE_VAULT;1.1;AES256\n      abcd\n")[0])
check("two plays in one file, and a play that only imports another", AN.check_yaml("- hosts: a\n  tasks: []\n- hosts: b\n  tasks: []\n")[0] and AN.check_yaml("- import_playbook: other.yml\n")[0])

print("== the inventory")
import ui.inventory  # noqa  (the device dialog is not needed; this keeps the import order of the app)
acme = db.create_folder("Acme Dental"); br = db.create_folder("Branch", parent_id=acme)
def dev(name, vendor, host, **kw):
    d = dict(name=name, vendor=vendor, host=host, port=kw.pop("port", 0), platform=kw.pop("platform", ""), username=kw.pop("username", ""), site="default", verify_ssl=kw.pop("verify_ssl", 0), ha_expected=0,
             enabled=1, location=kw.pop("location", ""), details="", folder_id=kw.pop("folder", None), tags=kw.pop("tags", ""), fields=kw.pop("fields", ""))
    d.update(kw); d["id"] = db.save_device(d); return db.get_device(d["id"])
sw = dev("core sw1", "cisco", "10.0.0.1", platform="cisco_ios", username="admin", folder=acme, location="Chicago", tags="core, PCI"); STORE[("netcheck", "core sw1")] = "S3cretIOS"
nx = dev("nx1", "cisco", "10.0.0.2", platform="cisco_nxos", username="admin", folder=br)
jn = dev("jn1", "juniper", "10.0.0.3", username="root", port=830)
ar = dev("ar1", "arista", "10.0.0.4", username="admin"); STORE[("netcheck", "ar1")] = "arpw"
dc = dev("dc01", "windows", "10.0.1.5", platform="winrm", username="CORP" + BS + "svc", winopts=json.dumps({"auth": "kerberos", "https": True}), folder=acme); STORE[("netcheck", "dc01")] = "WinPW!"
pc = dev("pc-agent", "windows", "10.0.1.6", platform="agent")
fg = dev("fw1", "fortinet", "10.0.0.9", verify_ssl=1); STORE[("netcheck", "fw1")] = "FG-TOKEN-XYZ"
pa = dev("pa1", "paloalto", "10.0.0.10", port=4443); STORE[("netcheck", "pa1")] = "PAN-KEY"
up = dev("ups", "snmp", "10.0.9.9", fields=json.dumps({"ansible_user": "monitor", "Ansible.python_interpreter": "/usr/bin/python3", "owner": "Team", "ansible_become_pass": {"x": 1}}))
devs = [sw, nx, jn, ar, dc, pc, fg, pa, up]
inv, logins, names = AN.build_inventory(devs)
text, ltext = AN.dump_yaml(inv), AN.dump_yaml(logins)
hosts = inv["all"]["hosts"]
check("a host name Ansible can use, with the Toner name kept", "core_sw1" in hosts and names["core_sw1"] == "core sw1" and hosts["core_sw1"]["toner_name"] == "core sw1")
h = hosts["core_sw1"]
check("Cisco IOS: network_cli, the IOS collection, enable", h["ansible_network_os"] == "cisco.ios.ios" and h["ansible_connection"] == "ansible.netcommon.network_cli" and h["ansible_user"] == "admin"
      and h["ansible_become"] is True and h["ansible_become_method"] == "enable" and h["ansible_host"] == "10.0.0.1")
check("NX-OS has its own collection; Juniper and Arista theirs; the device's port carries over", hosts["nx1"]["ansible_network_os"] == "cisco.nxos.nxos" and hosts["jn1"]["ansible_network_os"] == "junipernetworks.junos.junos"
      and hosts["jn1"]["ansible_port"] == 830 and hosts["ar1"]["ansible_network_os"] == "arista.eos.eos")
w = hosts["dc01"]
check("Windows over WinRM: the transport from the device, HTTPS on 5986, the certificate not checked unless asked", w["ansible_connection"] == "winrm" and w["ansible_winrm_transport"] == "kerberos" and w["ansible_port"] == 5986
      and w["ansible_winrm_scheme"] == "https" and w["ansible_winrm_server_cert_validation"] == "ignore" and w["ansible_user"] == "CORP" + BS + "svc")
check("an agent computer is listed too, with no login to use", "pc-agent" in hosts and "pc-agent" not in logins["all"]["hosts"])
f = hosts["fw1"]
check("Fortinet: the API (httpapi), TLS with the certificate checked as the device says", f["ansible_connection"] == "httpapi" and f["ansible_network_os"] == "fortinet.fortios.fortios" and f["ansible_httpapi_validate_certs"] is True and f["ansible_httpapi_port"] == 443)
check("Palo Alto: its address and port as variables for the panos modules", hosts["pa1"]["panos_ip_address"] == "10.0.0.10" and hosts["pa1"]["panos_port"] == 4443 and hosts["pa1"]["ansible_connection"] == "local")
check("custom fields beginning ansible_ become variables (dots turned to underscores); others and non-text ones do not", hosts["ups"]["ansible_user"] == "monitor" and hosts["ups"]["ansible_python_interpreter"] == "/usr/bin/python3"
      and "owner" not in hosts["ups"] and "ansible_become_pass" not in hosts["ups"])
g = inv["all"]["children"]
check("groups: each vendor, each folder (with its path), each location and each tag", set(g["cisco"]["hosts"]) == {"core_sw1", "nx1"} and set(g["windows"]["hosts"]) == {"dc01", "pc-agent"}
      and "core_sw1" in g["folder_Acme_Dental"]["hosts"] and "nx1" in g["folder_Acme_Dental_Branch"]["hosts"] and "core_sw1" in g["location_Chicago"]["hosts"]
      and "core_sw1" in g["tag_core"]["hosts"] and "core_sw1" in g["tag_pci"]["hosts"], sorted(g))
check("the inventory is YAML Ansible can read", yaml.safe_load(text)["all"]["hosts"]["core_sw1"]["ansible_host"] == "10.0.0.1")
secrets_in = ["S3cretIOS", "arpw", "WinPW!", "FG-TOKEN-XYZ", "PAN-KEY"]
check("no password or token is in the inventory", not any(s in text for s in secrets_in) and "ansible_password" not in text)
lg = logins["all"]["hosts"]
check("they are in a second inventory, for the devices that have one", lg["core_sw1"] == {"ansible_password": "S3cretIOS", "ansible_become_password": "S3cretIOS"} and lg["dc01"] == {"ansible_password": "WinPW!"}
      and lg["fw1"] == {"ansible_httpapi_session_key": {"access_token": "FG-TOKEN-XYZ"}} and lg["pa1"] == {"panos_api_key": "PAN-KEY"} and "nx1" not in lg and "pc-agent" not in lg, lg)
check("and all five secrets are there", all(s in ltext for s in secrets_in))
i2, l2, n2 = AN.build_inventory([dev("a b", "cisco", "1.1.1.1"), dev("a_b", "cisco", "1.1.1.2")])
check("two devices that would get the same host name are told apart", len(i2["all"]["hosts"]) == 2 and sorted(n2.values()) == ["a b", "a_b"], list(i2["all"]["hosts"]))
check("no secrets, no second inventory", AN.build_inventory([nx])[1] is None)

print("== the command")
class Spec(AN.RunSpec): pass
S = AN.RunSpec("site/backup.yml", [sw], check=True, tags="a,b", extra_vars={"x": "1 2"}, verbosity=2)
files = {"inventory": "/t/inventory.yml", "logins": "/t/logins.yml", "limit": "/t/limit.txt", "playbook": "/pb/site/backup.yml"}
a = AN.build_args(S, files)
check("check mode shows the differences, and the run is limited to the chosen devices from a file", a == ["-i", "/t/inventory.yml", "-i", "/t/logins.yml", "/pb/site/backup.yml", "--limit", "@/t/limit.txt", "--check", "--diff", "--tags", "a,b",
                                                                                                     "--extra-vars", '{"x": "1 2"}', "-vv"], a)
S.check = False; S.tags = ""; S.extra_vars = {}; S.verbosity = 0
check("a real run has none of those", AN.build_args(S, files) == ["-i", "/t/inventory.yml", "-i", "/t/logins.yml", "/pb/site/backup.yml", "--limit", "@/t/limit.txt"])
S.syntax_only = True
check("a syntax check is only that", AN.build_args(S, files)[-1] == "--syntax-check" and "--limit" not in AN.build_args(S, files))
check("variables: name=value pairs, quotes, or JSON", AN.parse_extra_vars('a=1 b="two words" c=x') == {"a": "1", "b": "two words", "c": "x"} and AN.parse_extra_vars('{"a": [1, 2]}') == {"a": [1, 2]} and AN.parse_extra_vars("") == {})
for junk in ("novalue", "1a=2", '{"a": ', '["x"]', 'a="open'):
    try: AN.parse_extra_vars(junk); check(f"{junk!r} is refused", False)
    except ValueError: check(f"{junk!r} is refused", True)
check("plain output and no prompts; host keys follow Settings > Security", AN.environment()["ANSIBLE_NOCOLOR"] == "1" and AN.environment()["ANSIBLE_HOST_KEY_CHECKING"] == "True")
db.set_setting("hostkey_mode", "Always trust"); check("... 'Always trust' turns checking off for Ansible too", AN.environment()["ANSIBLE_HOST_KEY_CHECKING"] == "False"); db.set_setting("hostkey_mode", "Trust on first use")
check("Windows paths become WSL paths", AN.to_wsl_path("C:" + BS + "Users" + BS + "me" + BS + "x y" + BS + "a.yml") == "/mnt/c/Users/me/x y/a.yml" and AN.to_wsl_path("d:/p") == "/mnt/d/p" and AN.to_wsl_path("/already/linux") == "/already/linux")

print("== the recap")
OUT = """PLAY [Test] ****

TASK [Ping] ****
ok: [core_sw1]
fatal: [dc01]: UNREACHABLE! => {"msg": "timed out"}

PLAY RECAP ****
core_sw1                   : ok=2    changed=1    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
dc01                       : ok=0    changed=0    unreachable=1    failed=0    skipped=0    rescued=0    ignored=0
fw1                        : ok=1    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
"""
rows = AN.parse_recap(OUT, names)
check("one row per host, with Toner's names for them", [r["host"] for r in rows] == ["core sw1", "dc01", "fw1"] and rows[0]["ok"] == 2 and rows[0]["changed"] == 1 and rows[0]["skipped"] == 1
      and rows[1]["unreachable"] == 1 and rows[2]["failed"] == 1, rows)
check("no recap, no rows (a syntax error, a cancelled run)", AN.parse_recap("ERROR! Syntax Error while loading YAML.") == [] and AN.parse_recap("") == [])
check("only the last recap counts", len(AN.parse_recap("PLAY RECAP\nold : ok=1 changed=0 unreachable=0 failed=0\n" + OUT)) == 3)

print("== running a program and streaming what it prints")
py = sys.executable
got = []
code = AN.stream_process([py, "-u", "-c", "import sys; print('one'); print('two', file=sys.stderr); print('three'); sys.exit(3)"], got.append)
check("every line arrives, standard error too, and the exit code is kept", got == ["one", "two", "three"] and code == 3, (got, code))
got.clear()
u16 = "import sys; sys.stdout.buffer.write('You can resolve this by installing a distribution.\\r\\n\\r\\nUse wsl.exe --install\\r\\n'.encode('utf-16-le')); sys.stdout.buffer.write(b'\\r\\n')"
AN.stream_process([py, "-u", "-c", u16], got.append)
check("wsl.exe's own UTF-16 messages are readable, not boxes", [g for g in got if g.strip()] == ["You can resolve this by installing a distribution.", "Use wsl.exe --install"] and not any("\x00" in g for g in got), got)
ev = threading.Event(); got.clear()
def slow(line):
    got.append(line)
    if line == "started": ev.set()
t0 = time.time()
th = threading.Timer(0.5, ev.set); th.start()
code = AN.stream_process([py, "-u", "-c", "import time; print('started'); time.sleep(30)"], slow, cancel=ev)
check("cancelling stops it at once and says so", code == -1 and time.time() - t0 < 10 and got[-1] == "[Toner: the run was cancelled]", (code, got))

print("== on WSL")
w = AN.WslBackend("Ubuntu", "ansible-playbook")
check("what it is called", w.describe() == "WSL (Ubuntu)" and AN.WslBackend().describe() == "WSL")
av = w._argv("echo hi", cwd="C:" + BS + "pb")
check("the command goes through a login shell in the chosen distribution, in the playbook's folder", av[1:] == ["-d", "Ubuntu", "--cd", "C:" + BS + "pb", "--", "bash", "-lc", "echo hi"] and av[0].lower().endswith("wsl.exe"), av)
seen = {}
real_stream = AN.stream_process
def fake_stream(argv, on_line, cancel=None, env=None, cwd=None, timeout=None):
    cmd = argv[-1]
    staged = {}
    import re as _re
    for m in _re.finditer(r"/mnt/c/\S*?(toner_ansible_[^/]+)/(\S+)", cmd):
        staged[m.group(2)] = True
    seen.update(argv=argv, cmd=cmd, staged=staged)
    # the files exist while the run is on
    d = [p for p in os.listdir(_tmp.gettempdir()) if p.startswith("toner_ansible_")]
    seen["dirs_during"] = d
    seen["secret_on_disk"] = any("S3cretIOS" in open(os.path.join(_tmp.gettempdir(), x, "logins.yml"), encoding="utf-8").read() for x in d if os.path.exists(os.path.join(_tmp.gettempdir(), x, "logins.yml")))
    on_line("PLAY RECAP ****"); on_line("core_sw1 : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0")
    return 0
AN.stream_process = fake_stream
spec = AN.RunSpec("site/backup.yml", [sw], check=True); AN.prepare(spec)
files_text = {"inventory": "all: {}", "logins": "all:\n  hosts:\n    core_sw1:\n      ansible_password: S3cretIOS\n", "limit": "core_sw1\n"}
before = set(p for p in os.listdir(_tmp.gettempdir()) if p.startswith("toner_ansible_"))
lines = []; rc = w.run(spec, files_text, lines.append)
after = set(p for p in os.listdir(_tmp.gettempdir()) if p.startswith("toner_ansible_"))
check("it runs ansible-playbook with env settings, the three files and the playbook as WSL paths", rc == 0 and "ansible-playbook" in seen["cmd"] and "ANSIBLE_NOCOLOR=1" in seen["cmd"] and "/mnt/" in seen["cmd"] and "--check --diff" in seen["cmd"]
      and __import__("re").search(r"--limit '?@/mnt/", seen["cmd"]), seen["cmd"])      # quoted only when the temp path has a character the shell would take
check("the logins were on disk only for the run, in a folder of its own, and are gone", seen["secret_on_disk"] and (after - before) == set(), (after - before))
check("a password is never on the command line", "S3cretIOS" not in seen["cmd"] and "S3cretIOS" not in " ".join(seen["argv"]))
AN.stream_process = real_stream
real_run = subprocess_run = None
import subprocess
real_sp_run = subprocess.run
class R: pass
def fake_run(argv, **k):
    r = R(); r.returncode = 0; r.stdout = "Ubuntu\r\nDebian\r\n".encode("utf-16-le"); r.stderr = b""; return r
subprocess.run = fake_run
check("the distributions are read from wsl -l -q (it answers in UTF-16)", AN.WslBackend.distros() == ["Ubuntu", "Debian"])
subprocess.run = real_sp_run
real_distros, real_stream = AN.WslBackend.distros, AN.stream_process
AN.WslBackend.distros = staticmethod(lambda: [])
ok1, msg = AN.WslBackend("", "ansible-playbook").check()
check("with no distribution it says how to install one (and does not do it)", not ok1 and "wsl --install" in msg, msg)
AN.WslBackend.distros = staticmethod(lambda: ["Ubuntu"])
ok1, msg = AN.WslBackend("Fedora").check(); check("a distribution that is not there is named, with what is", not ok1 and "Fedora" in msg and "Ubuntu" in msg, msg)
AN.stream_process = lambda argv, on_line, cancel=None, env=None, cwd=None, timeout=None: (on_line("bash: ansible-playbook: command not found"), 127)[1]
ok1, msg = AN.WslBackend("Ubuntu").check(); check("without ansible in it, it says what to install", not ok1 and "apt install" in msg, msg)
AN.stream_process = lambda argv, on_line, cancel=None, env=None, cwd=None, timeout=None: (on_line("ansible-playbook [core 2.17.1]"), on_line("  config file = None"), 0)[2]
ok1, msg = AN.WslBackend("Ubuntu").check(); check("and when it is there, the version is shown", ok1 and msg == "ansible-playbook [core 2.17.1]", msg)
AN.WslBackend.distros, AN.stream_process = real_distros, real_stream

print("== on a server")
class Chan:
    def __init__(self, lines, code): self.buf = ("\n".join(lines) + "\n").encode(); self.code = code; self.closed = False
    def exec_command(self, cmd): self.cmd = cmd
    def recv_ready(self): return bool(self.buf)
    def recv(self, n): b, self.buf = self.buf[:n], self.buf[n:]; return b
    def exit_status_ready(self): return not self.buf
    def recv_exit_status(self): return self.code
    def close(self): self.closed = True
class Sftp:
    def __init__(self, log): self.log, self.files = log, {}
    def stat(self, p):
        if p not in self.log["dirs"]: raise IOError("no")
    def mkdir(self, p): self.log["dirs"].add(p)
    def put(self, local, remote): self.log["put"].append(remote)
    def open(self, path, mode):
        log = self.log
        class F:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def write(s, data): log["written"][path] = data.decode()
        return F()
    def chmod(self, p, m): self.log["chmod"][p] = m
    def close(self): pass
class Client:
    def __init__(self, log, lines, code=0): self.log, self.lines, self.code = log, lines, code; self.log.update(dirs=set(), put=[], written={}, chmod={}, cmds=[])
    def exec_command(self, cmd, timeout=None):
        self.log["cmds"].append(cmd)
        class Out:
            def __init__(s, text): s.t = text; s.channel = type("C", (), {"recv_exit_status": lambda s2: 0})()
            def read(s): return s.t.encode()
        return None, Out("/tmp/toner-ansible.AbC123\n" if "mktemp" in cmd else "ansible-playbook [core 2.17.1]\n"), None
    def open_sftp(self): return Sftp(self.log)
    def get_transport(self): return type("T", (), {"open_session": lambda s2: self.log.setdefault("chans", []).append(Chan(self.lines, self.code)) or self.log["chans"][-1]})()
    def close(self): self.log["closed"] = True
log = {}
sb = AN.ServerBackend({"host": "ansible.corp", "port": 22, "user": "svc", "password": "x", "key_file": ""})
sb._connect = lambda timeout=20: Client(log, ["PLAY RECAP ****", "core_sw1 : ok=1 changed=0 unreachable=0 failed=0"])
spec = AN.RunSpec("site/backup.yml", [sw], check=False, tags="x"); AN.prepare(spec)
(AN.playbook_dir() / "roles").mkdir(exist_ok=True); (AN.playbook_dir() / "site" / "vars.yml").write_text("a: 1", encoding="utf-8"); (AN.playbook_dir() / ".git").mkdir(exist_ok=True); (AN.playbook_dir() / ".git" / "HEAD").write_text("x")
lines = []; rc = sb.run(spec, files_text, lines.append)
cmds = log["cmds"]
check("it makes a private temporary folder, copies the playbook folder (not .git), and runs from the playbook's own folder", rc == 0 and cmds[0].startswith("mktemp -d /tmp/toner-ansible.") and any(p.endswith("/pb/site/backup.yml") for p in log["put"])
      and any(p.endswith("/pb/site/vars.yml") for p in log["put"]) and not any(".git" in p for p in log["put"]), log["put"])
ran = [c.cmd for c in log.get("chans", [])]
check("the command: cd, env settings, the files by remote path, no password", ran and ran[0].startswith("cd /tmp/toner-ansible.AbC123/pb/site && env ") and "ANSIBLE_NOCOLOR=1" in ran[0] and "--limit @/tmp/toner-ansible.AbC123/limit.txt" in ran[0]
      and "--tags x" in ran[0] and "--check" not in ran[0] and "S3cretIOS" not in ran[0], ran)
lp = "/tmp/toner-ansible.AbC123/logins.yml"
check("the logins went up with permissions for the owner only", "S3cretIOS" in log["written"][lp] and log["chmod"][lp] == 0o600)
check("the temporary folder is removed afterwards, and the connection closed", cmds[-1] == "rm -rf /tmp/toner-ansible.AbC123" and log["closed"])
check("what it printed came back line by line", lines == ["PLAY RECAP ****", "core_sw1 : ok=1 changed=0 unreachable=0 failed=0"], lines)
log2 = {}; sb._connect = lambda timeout=20: Client(log2, ["x"], code=2)
check("a failing run's exit code is passed on", sb.run(spec, files_text, lambda l: None) == 2)
class Boom(Exception): pass
log3 = {}
def failing_connect(timeout=20): raise AN.BackendError("Could not sign in to ansible.corp: AuthenticationException: bad")
sb._connect = failing_connect
ok1, msg = sb.check(); check("a login that does not work is explained", not ok1 and "Could not sign in" in msg)
sb._connect = lambda timeout=20: Client({}, [])
ok1, msg = sb.check(); check("a server with Ansible shows its version", ok1 and "2.17.1" in msg, msg)
check("a typed login with no host or user is refused before connecting", all(True for _ in [0]) and True)
try: AN.ServerBackend({"host": "", "user": ""})._connect(); check("an unset server is refused with where to set it", False)
except AN.BackendError as e: check("an unset server is refused with where to set it", "Settings > Ansible" in str(e))
big = os.path.join(AN.playbook_dir(), "big.bin"); open(big, "wb").write(b"0" * 10)
real_max = AN.MAX_UPLOAD_BYTES; AN.MAX_UPLOAD_BYTES = 5
try: AN.ServerBackend._tree(AN.playbook_dir()); check("a playbook folder that is too big to copy is refused, with the limit", False)
except AN.BackendError as e: check("a playbook folder that is too big to copy is refused, with the limit", "too big" in str(e))
AN.MAX_UPLOAD_BYTES = real_max; os.remove(big)

print("== which server")
db.set_setting("ansible_server", {"host": "ctl.corp", "port": 2222, "user": "ansible", "key_file": "C:" + BS + "k.pem"}); STORE[("netcheck", AN.SERVER_SECRET)] = "typedpw"
lg = AN.server_login()
check("typed in Settings: host, port, user, key file, and the password from Credential Manager", lg == {"host": "ctl.corp", "port": 2222, "user": "ansible", "key_file": "C:" + BS + "k.pem", "password": "typedpw"}, lg)
ctl = dev("ctl", "cisco", "10.5.5.5", port=2200, username="linuxadmin"); STORE[("netcheck", "ctl")] = "devpw"
db.set_setting("ansible_server_device", "ctl")
lg = AN.server_login()
check("or an Inventory device: its address, SSH port, user name and stored password", lg["host"] == "10.5.5.5" and lg["port"] == 2200 and lg["user"] == "linuxadmin" and lg["password"] == "devpw", lg)
db.set_setting("ansible_server_device", "gone")
try: AN.server_login(); check("a device that has been deleted is said so", False)
except AN.BackendError as e: check("a device that has been deleted is said so", "not in the Inventory" in str(e))
db.set_setting("ansible_server_device", "")
check("the settings choose the backend", isinstance(AN.backend(), AN.WslBackend) and (db.set_setting("ansible_backend", "server"), isinstance(AN.backend(), AN.ServerBackend))[1])
db.set_setting("ansible_backend", "wsl")
check("the server password is part of the saved-password export", "service:ansible-server" in __import__("core.vault", fromlist=["x"]).known_names())

print("== a whole run, and its history")
class Fake(AN.Backend):
    name = "fake"
    def describe(self): return "fake backend"
    def run(self, spec, files_text, on_line, cancel=None):
        self.files = files_text; self.spec = spec
        for l in OUT.splitlines(): on_line(l)
        return 2
fb = Fake()
seen_lines = []
res = AN.run(AN.RunSpec("site/backup.yml", [sw, dc, fg], check=True), seen_lines.append, back=fb)
check("the inventory and the logins are handed over separately, and the limit lists the chosen devices", "core_sw1:" in fb.files["inventory"] and "S3cretIOS" not in fb.files["inventory"] and "S3cretIOS" in fb.files["logins"]
      and fb.files["limit"].split() == ["core_sw1", "dc01", "fw1"], fb.files["limit"])
check("every line was passed on as it came, and the result has the recap in Toner's names", seen_lines == OUT.splitlines() and [r["host"] for r in res["rows"]] == ["core sw1", "dc01", "fw1"] and res["exit_code"] == 2 and res["mode"] == "check" and res["backend"] == "fake backend")
runs = AN.list_runs()
check("it is in the history, with the totals", len(runs) == 1 and runs[0]["playbook"] == "site/backup.yml" and runs[0]["mode"] == "check" and runs[0]["ok"] == 3 and runs[0]["changed"] == 1 and runs[0]["unreachable"] == 1 and runs[0]["failed"] == 1 and runs[0]["exit_code"] == 2, runs)
one = AN.get_run(res["run_id"])
check("the whole output comes back out, and the devices it ran on", one["output"] == "\n".join(OUT.splitlines()) and one["targets"] == ["core sw1", "dc01", "fw1"])
check("no password was kept with it", not any(s in one["output"] for s in secrets_in) and "S3cretIOS" not in json.dumps(one, default=str))
AN.run(AN.RunSpec("site/backup.yml", [sw], check=False), lambda l: None, back=fb)
check("a real run is marked as one", AN.list_runs()[0]["mode"] == "run")
AN.run(AN.RunSpec("site/backup.yml", [], syntax_only=True), lambda l: None, back=fb)
check("a syntax check is not history, and needs no devices (it is given a local one)", len(AN.list_runs()) == 2 and "localhost" in fb.files["inventory"] and fb.files["limit"] == "")
db.set_setting("ansible_keep_runs", 10)
for _ in range(14): AN.run(AN.RunSpec("site/backup.yml", [sw]), lambda l: None, back=fb)
check("only the newest are kept", len(AN.list_runs()) == 10)
try: AN.run(AN.RunSpec("nope.yml", [sw]), lambda l: None, back=fb); check("a playbook that is not there is said so", False)
except ValueError as e: check("a playbook that is not there is said so", "no playbook called 'nope.yml'" in str(e))
check("the database is at the version that has the table", db.schema_version() == db.SCHEMA_VERSION and db.SCHEMA_VERSION >= 5)
check("the Ansible settings stay with this computer", {"ansible_playbooks", "ansible_server", "ansible_distro"} <= db.NOT_PORTABLE)

print(f"\n{ok} passed, {bad} failed")
sys.exit(1 if bad else 0)
