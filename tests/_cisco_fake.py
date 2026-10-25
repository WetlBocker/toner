"""A fake Cisco device for the Firmware Transfer tests, on the test SSH server (tests/_ssh_shell.py): IOS, IOS XE (INSTALL or
BUNDLE mode, standalone or a stack), NX-OS or ASA. It answers the commands the wizard sends with the platform's own wording,
keeps one state for every SSH session to it (a second session sees a copy growing), and really fetches what `copy` asks for
from the URL it was given (FTP, SFTP, SCP or TFTP), so the URL the wizard builds is checked and sizes and MD5s are real.

What a real device does and this does not: exact timing, every line of Cisco's output, prompts that differ between releases.
The fake follows the forms in Cisco's documentation and is meant to catch mistakes in the wizard, not to stand in for a lab."""
import hashlib
import io
import ipaddress
import os
import re
import socket
import struct
import tempfile
import threading
import time

import paramiko

from _ssh_shell import ShellServer

PLATFORM_FS = {"cisco_ios": "flash:", "cisco_xe": "flash:", "cisco_nxos": "bootflash:", "cisco_asa": "disk0:"}


class LoopbackOnly(paramiko.MissingHostKeyPolicy):
    """The fake only ever pulls from the test's own servers on this computer, each with a key made for the test: a key from a
    loopback address is accepted for that one connection (and not saved anywhere); any other host is refused."""

    def missing_host_key(self, client, hostname, key):
        host = hostname[1:].split("]")[0] if hostname.startswith("[") else hostname      # '[127.0.0.1]:2222' -> '127.0.0.1'
        try:
            loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise paramiko.SSHException(f"the fake device only fetches from this computer, not {hostname}")


class Fs:
    """One file system (flash:, flash-2:, bootflash:, disk0:): {name: [size, md5]} and its total size."""

    def __init__(self, name, total, files=None):
        self.name, self.total = name, total
        self.files = {n: [size, md5] for n, (size, md5) in (files or {}).items()}

    def used(self):
        return sum(s for s, _m in self.files.values())

    def free(self):
        return self.total - self.used()


def fetch(url):
    """The bytes at an ftp://, sftp://, scp:// or tftp:// URL, as the device would get them. Raises OSError with the reason."""
    m = re.match(r"^(ftp|sftp|scp|tftp)://(?:([^:@/]*)(?::([^@/]*))?@)?([^/:]+)(?::(\d+))?(/.*)$", url)
    if not m:
        raise OSError("%Error parsing URL")
    proto, user, pw, host, port, path = m.groups()
    if proto == "ftp":
        import ftplib
        c = ftplib.FTP()
        c.connect(host, int(port or 21), timeout=10)
        c.login(user or "anonymous", pw or "")
        buf = io.BytesIO()
        c.retrbinary("RETR " + path.lstrip("/"), buf.write) if not path.startswith("//") else c.retrbinary("RETR " + path[1:], buf.write)
        c.quit()
        return buf.getvalue()
    if proto in ("sftp", "scp"):
        cl = paramiko.SSHClient()
        cl.set_missing_host_key_policy(LoopbackOnly())
        cl.connect(host, int(port or 22), user, pw, look_for_keys=False, allow_agent=False, timeout=10)
        try:
            if proto == "sftp":
                sf = cl.open_sftp()
                with sf.open(path, "rb") as fh:
                    return fh.read()
            from core.scp import Scp
            with tempfile.TemporaryDirectory(prefix="cisco_fake_") as folder:   # a private folder, removed afterwards
                target = os.path.join(folder, "image")
                Scp(cl).download(path, target)
                with open(target, "rb") as fh:
                    return fh.read()
        finally:
            cl.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            # tftp: a plain read request
    s.settimeout(5)
    try:
        s.sendto(struct.pack("!H", 1) + path.lstrip("/").encode() + b"\0octet\0", (host, int(port or 69)))
        out, block = b"", 1
        while True:
            pkt, addr = s.recvfrom(70000)
            op = struct.unpack("!H", pkt[:2])[0]
            if op == 5:
                raise OSError("%Error opening tftp: " + pkt[4:].rstrip(b"\0").decode(errors="replace"))
            out += pkt[4:]
            s.sendto(struct.pack("!HH", 4, block), addr)
            block += 1
            if len(pkt) < 516:
                return out
    finally:
        s.close()


class CiscoFake(ShellServer):
    def __init__(self, platform="cisco_xe", hostname="sw1", user="admin", password="pw", version=None, mode=None,
                 members=1, member_states=None, image=None, boot=None, fs_total=8 * 1024 ** 3, files=None, member_files=None,
                 reach=None, vrf=None, copy_seconds=1.0, install_files=None, enable_secret=None):
        """reach: {host: {"ping": bool, "ports": {21, ...}}} what the device can get to (anything else: nothing).
        vrf: NX-OS only: the VRF the source is reached through (ping and copy without it fail).
        enable_secret: the login lands in user mode (prompt '>'); `enable` asks for this password, and the privileged
        commands (dir, copy, delete, configure, install, verify, the boot lines) are refused until it is given."""
        super().__init__(user=user, password=password, banner="", prompt=f"{hostname}#")
        self.platform, self.hostname = platform, hostname
        self.enable_secret = enable_secret
        self.mode = mode if platform == "cisco_xe" else None
        self.version = version or {"cisco_ios": "15.2(7)E9", "cisco_xe": "17.06.05", "cisco_nxos": "10.2(5)", "cisco_asa": "9.16(4)"}[platform]
        fs = PLATFORM_FS[platform]
        self.members = [(n, "Active" if n == 1 else "Standby" if n == 2 else "Member", (member_states or {}).get(n, "Ready"))
                        for n in range(1, members + 1)] if platform in ("cisco_ios", "cisco_xe") and members > 1 else []
        self.fs = {fs: Fs(fs, fs_total, files)}
        for n, _r, _s in self.members[1:]:
            name = self.member_fs(n)
            self.fs[name] = Fs(name, fs_total, (member_files or {}).get(n, files))
        self.image = image or ("packages.conf" if self.mode == "INSTALL" else next(iter(files or {"image.bin": 0}), "image.bin"))
        self.boot = list(boot if boot is not None else [f"{fs}{self.image}"])     # what the boot statement / variable names
        self.saved_boot = list(self.boot)
        self.reach, self.vrf, self.copy_seconds = reach or {}, vrf, copy_seconds
        self.install_files = list(install_files or [])                           # what install remove inactive would remove
        self.corrupt = set()                                                      # copies of these files arrive damaged
        self.protect = set()                                                      # deleting these is refused
        self.install_fail = ""                                                    # install add answers FAILED with this
        self.ignore_boot = False                                                  # boot lines are accepted but change nothing
        self.config_saved = True
        self.added = []                                                           # install add file ... that succeeded
        self.commands = []                                                        # every line typed, in order (all sessions)
        self.lock = threading.Lock()

    # ---------------------------------------------------------------- naming
    def member_fs(self, n):
        """Stack member n's flash: flash-2: on IOS XE, flash2: on classic IOS."""
        return f"flash-{n}:" if self.platform == "cisco_xe" else f"flash{n}:"

    def split(self, path):
        """'flash:x.bin', 'flash:/x.bin', 'bootflash:///x.bin', 'disk0:/x.bin' -> (Fs, 'x.bin') or (None, name)."""
        m = re.match(r"^([\w-]+:)/*(.*)$", path)
        if not m or m.group(1) not in self.fs:
            return None, path
        return self.fs[m.group(1)], m.group(2)

    # ---------------------------------------------------------------- the shell
    def _shell(self, ch):
        sess = {"conf": False, "ask": None, "telnet": False, "esc": False, "priv": self.enable_secret is None}
        try:
            ch.send(self.banner + self.prompt_of(sess))
            buf = b""
            while True:
                d = ch.recv(1024)
                if not d:
                    break
                for b in d:
                    if sess["telnet"]:                        # typing goes to the far end until Ctrl-^ x
                        if b == 0x1e:
                            sess["esc"] = True
                        elif sess["esc"] and b in (ord("x"), ord("X")):
                            sess["telnet"] = sess["esc"] = False
                            ch.send("\r\n" + self.prompt_of(sess))
                        else:
                            sess["esc"] = False
                        continue
                    if b in (13, 10):
                        if b == 10 and not buf and sess.get("_cr"):
                            sess["_cr"] = False
                            continue
                        sess["_cr"] = b == 13
                        line = buf.decode(errors="replace")
                        buf = b""
                        ch.send("\r\n")
                        if line == "exit" and not sess["conf"]:
                            ch.close()
                            return
                        out, more = self.answer(line, sess)
                        if out:
                            ch.send(out.replace("\n", "\r\n"))
                        if not more:
                            ch.send(self.prompt_of(sess))
                    else:
                        sess["_cr"] = False
                        buf += bytes([b])
                        ch.send(bytes([b]))
        except (OSError, EOFError):
            pass

    def prompt_of(self, sess):
        if sess["conf"]:
            return f"{self.hostname}(config)#"
        return f"{self.hostname}#" if sess.get("priv", True) else f"{self.hostname}>"

    def answer(self, line, sess):
        """(output, waiting): waiting is True when the device asked a question and prints no prompt yet."""
        with self.lock:
            self.lines.append(line)
            self.commands.append(line)
        if sess["ask"] is not None:
            fn, sess["ask"] = sess["ask"], None
            return fn(line)
        cmd = line.strip()
        if not cmd:
            return "", False
        if sess["conf"]:
            return self.config(cmd, sess)
        low = cmd.lower()
        if low == "enable" and not sess.get("priv", True):
            def typed(pw):
                if pw == self.enable_secret:
                    sess["priv"] = True
                    return "", False
                return ("Invalid password.\n" if self.platform == "cisco_asa" else "% Access denied\n"), False
            sess["ask"] = typed
            return "Password: ", True
        if low in ("terminal length 0", "terminal width 511", "terminal pager 0", "enable"):
            return "", False
        if low == "show curpriv":
            level = 15 if sess.get("priv", True) else 1
            return f"Username : admin\nCurrent privilege level : {level}\nCurrent Mode/s : {'P_PRIV' if level == 15 else 'P_UNPR'}\n", False
        if not sess.get("priv", True) and low.startswith(("dir ", "copy ", "delete ", "install ", "verify ", "show running-config",
                                                          "show boot", "configure terminal", "conf t")):
            return ("ERROR: " if self.platform == "cisco_asa" else "") + "% Invalid input detected at '^' marker.\n", False
        if low in ("configure terminal", "conf t"):
            sess["conf"] = True
            return "Enter configuration commands, one per line.  End with CNTL/Z.\n", False
        if low == "show version":
            return self.show_version(), False
        if low == "show switch":
            return self.show_switch(), False
        if low.startswith("dir "):
            return self.dir(cmd[4:].strip()), False
        if low in ("show boot", "show bootvar", "show running-config boot", "show running-config | include ^boot"):
            return self.show_boot(), False
        if low.startswith("ping "):
            return self.ping(cmd), False
        if low.startswith("telnet "):
            return self.telnet(cmd, sess)
        if low == "disconnect" or low.startswith("disconnect "):
            sess["ask"] = lambda ans: ("", False)
            return "Closing connection to the far end [confirm]", True
        if low.startswith("delete "):
            return self.delete(cmd), False
        if low == "install remove inactive":
            return self.install_remove(sess)
        if low.startswith("install add file "):
            return self.install_add(cmd.split()[-1]), False
        if low.startswith("copy "):
            return self.copy(cmd, sess)
        if low.startswith("verify /md5 "):
            return self.verify(cmd), False
        if low.startswith("show file ") and low.endswith(" md5sum"):
            return self.md5sum(cmd.split()[2]), False
        if low in ("write memory", "wr mem", "write"):
            self.saved_boot, self.config_saved = list(self.boot), True
            return "Building configuration...\n[OK]\n", False
        if "reload" in low or low.startswith("install activate") or low.startswith("install commit"):
            return "THE FAKE DEVICE WAS ASKED TO RELOAD OR ACTIVATE\n", False
        return "% Invalid input detected at '^' marker.\n", False

    # ---------------------------------------------------------------- reading
    def show_version(self):
        img = self.image
        fs = PLATFORM_FS[self.platform]
        if self.platform == "cisco_ios":
            return (f"Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version {self.version}, RELEASE SOFTWARE (fc1)\n"
                    f"{self.hostname} uptime is 1 year, 2 weeks, 3 days, 4 hours, 5 minutes\n"
                    f'System image file is "{fs}/{img}"\n')
        if self.platform == "cisco_xe":
            return (f"Cisco IOS XE Software, Version {self.version}\n"
                    f"Cisco IOS Software [Bengaluru], Catalyst L3 Switch Software (CAT9K_IOSXE), Version {self.version}, RELEASE SOFTWARE (fc2)\n"
                    f"{self.hostname} uptime is 12 weeks, 3 days, 4 hours, 5 minutes\n"
                    f'System image file is "{fs}{img}"\n'
                    f"Installation mode is {self.mode}\n")
        if self.platform == "cisco_nxos":
            return (f"Cisco Nexus Operating System (NX-OS) Software\nSoftware\n  BIOS: version 05.45\n NXOS: version {self.version}\n"
                    f"  NXOS image file is: bootflash:///{img}\n")
        return (f"Cisco Adaptive Security Appliance Software Version {self.version}\nSSP Operating System Version 2.10(1.162)\n"
                f'System image file is "disk0:/{img}"\n{self.hostname} up 12 days 3 hours\n')

    def show_switch(self):
        if self.platform not in ("cisco_ios", "cisco_xe"):
            return "% Invalid input detected at '^' marker.\n"
        rows = self.members or [(1, "Active", "Ready")]
        out = ("Switch/Stack Mac Address : 0011.2233.4455 - Local Mac Address\nMac persistency wait time: Indefinite\n"
               "                                             H/W   Current\nSwitch#   Role    Mac Address     Priority Version  State\n"
               "-------------------------------------------------------------------------------------\n")
        for n, role, state in rows:
            out += f"{'*' if n == 1 else ' '}{n}       {role:<8} 0011.2233.44{n:02d}     {16 - n:<2}     V01     {state}\n"
        return out

    def dir(self, path):
        fs, rest = self.split(path)
        if fs is None or (rest and rest not in fs.files):
            return f"%Error opening {path} (No such file or directory)\n"
        with self.lock:
            files = {rest: list(fs.files[rest])} if rest else {n: list(v) for n, v in fs.files.items()}   # `dir flash:x.bin`: that file only
        if self.platform == "cisco_nxos":
            out = ""
            for name, (size, _m) in sorted(files.items()):
                out += f"{size:>12}    Oct 22 10:00:00 2026  {name}\n"
            return out + (f"\nUsage for {fs.name}//sup-local\n {fs.used()} bytes used\n {fs.free()} bytes free\n {fs.total} bytes total\n")
        out = f"\nDirectory of {fs.name}/\n\n"
        for i, (name, (size, _m)) in enumerate(sorted(files.items()), 2):
            if self.platform == "cisco_asa":
                out += f"{i:<6} -rwx  {size:<10} 10:00:00 Oct 22 2026  {name}\n"
            else:
                out += f"{i:>6}  -rw-  {size:>12}  Oct 22 2026 10:00:00 +00:00  {name}\n"
        if self.platform == "cisco_asa":                       # as an ASA 5515 prints it, percentage and all
            return out + f"\n{len(files)} file(s) total size: {fs.used()} bytes\n{fs.total} bytes total ({fs.free()} bytes free/{fs.free() * 100 // fs.total}% free)\n"
        return out + f"\n{fs.total} bytes total ({fs.free()} bytes free)\n"

    def show_boot(self):
        if self.platform == "cisco_xe":
            return "---------------------------\nSwitch 1\n---------------------------\nCurrent Boot Variables:\n" \
                   f"BOOT variable = {';'.join(self.boot)};\n\nBoot Variables on next reload:\nBOOT variable = {';'.join(self.saved_boot)};\n" \
                   "Manual Boot = no\nEnable Break = yes\n"
        if self.platform == "cisco_ios":
            return f"BOOT path-list      : {';'.join(self.boot)}\nConfig file         : flash:/config.text\nManual Boot         : no\n"
        if self.platform == "cisco_nxos":
            return "Current Boot Variables:\n\nsup-1\nNXOS variable = " + ";".join(self.boot) + "\nBoot POAP Disabled\n"
        return "".join(f"boot system {b}\n" for b in self.boot)

    # ---------------------------------------------------------------- reaching the source
    def _reach(self, host, cmd):
        r = self.reach.get(host, {})
        if self.platform == "cisco_nxos" and self.vrf and f"vrf {self.vrf}" not in cmd:
            return {}                                     # the source is only reachable through the management VRF
        return r

    def ping(self, cmd):
        host = cmd.split()[1]
        ok = self._reach(host, cmd).get("ping", False)
        if self.platform == "cisco_nxos":
            got = 5 if ok else 0
            return (f"PING {host} ({host}): 56 data bytes\n" + "".join(f"64 bytes from {host}: icmp_seq={i} ttl=63 time=1.1 ms\n" for i in range(got))
                    + f"\n--- {host} ping statistics ---\n5 packets transmitted, {got} packets received, {100 - got * 20:.2f}% packet loss\n")
        return (f"Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to {host}, timeout is 2 seconds:\n"
                + ("!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/1/2 ms\n" if ok else ".....\nSuccess rate is 0 percent (0/5)\n"))

    def telnet(self, cmd, sess):
        if self.platform not in ("cisco_ios", "cisco_xe"):
            return "% Invalid input detected at '^' marker.\n", False
        _t, host, port = (cmd.split() + ["23"])[:3]
        r = self._reach(host, cmd)
        if not r.get("ping"):
            time.sleep(0.3)
            return f"Trying {host}, {port} ... \n% Connection timed out; remote host not responding\n\n", False
        if int(port) not in r.get("ports", ()):
            return f"Trying {host}, {port} ... \n% Connection refused by remote host\n\n", False
        sess["telnet"] = True
        return f"Trying {host}, {port} ... Open\n220 Server ready.\n", True

    # ---------------------------------------------------------------- changing things
    def delete(self, cmd):
        words = cmd.split()
        path = next((w for w in words[1:] if not w.startswith("/") and w != "no-prompt"), "")
        fs, name = self.split(path)
        if fs is None or name not in fs.files:
            return f"%Error deleting {path} (No such file or directory)\n"
        quiet = "/force" in words or "/noconfirm" in words or "no-prompt" in words
        if not quiet:
            return "THE FAKE DEVICE WOULD HAVE ASKED: Delete filename? [confirm]\n"
        if name in self.protect:
            return f"%Error deleting {path} (Permission denied)\n"
        del fs.files[name]
        return ""

    def install_remove(self, sess):
        if self.mode != "INSTALL":
            return "FAILED: install_remove : Device is not in INSTALL mode\n", False
        out = "install_remove: START\nCleaning up unnecessary package files\nScanning boot directory for packages ... done.\n" \
              "Preparing packages list to delete ...\n"
        if not self.install_files:
            return out + "    No path specified, will use booted path flash:packages.conf\n" \
                         "SUCCESS: No extra package or provisioning files found on media. Nothing to clean.\n", False
        out += "".join(f"    {n}\n" for n in self.install_files) + "\nThe following files will be deleted:\n"
        out += "".join(f"[1]: {PLATFORM_FS['cisco_xe']}{n}\n" for n in self.install_files)
        out += "\nDo you want to remove the above files? [y/n]"

        def reply(ans):
            if ans.strip().lower() != "y":
                return "\nFAILED: install_remove : Operation aborted by user\n", False
            for n in self.install_files:
                for fs in self.fs.values():
                    fs.files.pop(n, None)
            self.install_files = []
            return "\nDeleting file flash:... done.\nSUCCESS: Files deleted.\nSUCCESS: install_remove\n", False
        sess["ask"] = reply
        return out, True

    def install_add(self, path):
        fs, name = self.split(path)
        if fs is None or name not in fs.files:
            return f"FAILED: install_add : {path} not found\n"
        if self.install_fail:
            return f"install_add: START\ninstall_add: Adding PACKAGE\nFAILED: install_add : {self.install_fail}\n"
        self.added.append(name)
        return (f"install_add: START\ninstall_add: Adding PACKAGE\nFinished initial file syncing\n--- Starting Add ---\n"
                f"Performing Add on all members\n  [1] Add package(s) on switch 1\n  [1] Finished Add on switch 1\nChecking status of Add on [1]\n"
                f"Add: Passed on [1]\nFinished Add\n\nImage added. Version: {name}\nSUCCESS: install_add\n")

    def copy(self, cmd, sess):
        words = cmd.split()
        args = [w for w in words[1:] if not w.startswith("/")]
        if len(args) < 2:
            return "% Incomplete command.\n", False
        src, dst = args[0], args[1]
        vrf = words[words.index("vrf") + 1] if "vrf" in words else None
        quiet = "/noconfirm" in words
        if src == "running-config" and dst == "startup-config":
            self.saved_boot = list(self.boot)
            return "[########################################] 100%\nCopy complete.\n", False
        if re.match(r"^(ftp|sftp|scp|tftp)://", src):
            name = src.rstrip("/").rsplit("/", 1)[-1]
            dfs, dname = self.split(dst)
            dname = dname or name
            if dfs is None:
                return f"%Error parsing filename ({dst})\n", False

            def go(_answer=""):
                host = re.match(r"^\w+://(?:[^@/]*@)?([^/:]+)", src).group(1)
                r = self.reach.get(host, {})
                if self.platform == "cisco_nxos" and self.vrf and vrf != self.vrf:
                    r = {}
                if not r.get("ping"):
                    return f"%Error opening {self._shown(src)} (Timed out)\n", False
                try:
                    data = fetch(src)
                except Exception as e:                     # noqa: BLE001
                    return f"%Error opening {self._shown(src)} ({e})\n", False
                if len(data) > dfs.free():
                    return f"%Error copying {self._shown(src)} (Not enough space on device)\n", False
                digest = hashlib.md5(data).hexdigest()
                if name in self.corrupt:
                    digest = hashlib.md5(data + b"damaged").hexdigest()
                steps = 10
                for i in range(1, steps + 1):              # the file grows on flash while the copy runs
                    with self.lock:
                        dfs.files[dname] = [len(data) * i // steps, ""]
                    time.sleep(self.copy_seconds / steps)
                with self.lock:
                    dfs.files[dname] = [len(data), digest]
                return (f"Accessing {self._shown(src)}...\nLoading {name} !!!!!!!!!!\n[OK - {len(data)}/4096 bytes]\n\n"
                        f"{len(data)} bytes copied in {self.copy_seconds:.3f} secs ({len(data)} bytes/sec)\n"), False
            if quiet or self.platform == "cisco_nxos":
                return go()
            sess["ask"] = go
            return f"Destination filename [{dname}]? ", True
        sfs, sname = self.split(src)
        dfs, dname = self.split(dst)
        if sfs is None or sname not in sfs.files:
            return f"%Error opening {src} (No such file or directory)\n", False
        if dfs is None:
            return f"%Error parsing filename ({dst})\n", False

        def local(_answer=""):
            size, digest = sfs.files[sname]
            if size > dfs.free():
                return f"%Error copying {src} (Not enough space on device)\n", False
            for i in range(1, 6):
                with self.lock:
                    dfs.files[dname or sname] = [size * i // 5, ""]
                time.sleep(self.copy_seconds / 5)
            with self.lock:
                dfs.files[dname or sname] = [size, hashlib.md5(b"damaged").hexdigest() if (dname or sname) in self.corrupt and dfs.name != sfs.name else digest]
            return f"Copy in progress...CCCCCCCCCC\n{size} bytes copied in {self.copy_seconds:.3f} secs ({size} bytes/sec)\n", False
        sess["ask"] = local
        return f"Destination filename [{dname or sname}]? ", True

    @staticmethod
    def _shown(url):
        """Cisco prints the URL with the password in it; the wizard must keep it out of its logs."""
        return url

    def _md5_of(self, path):
        fs, name = self.split(path)
        if fs is None or name not in fs.files:
            return None
        return fs.files[name][1]

    def verify(self, cmd):
        words = cmd.split()
        path, want = words[2], (words[3] if len(words) > 3 else "")
        got = self._md5_of(path)
        if got is None:
            return f"%Error opening {path} (No such file or directory)\n"
        if not want:
            return f"........Done!\nverify /md5 ({path}) = {got}\n"
        if got == want.lower():
            return f"........Done!\nVerified ({path}) = {got}\n"
        return f"........Done!\n%Error verifying {path}\nComputed signature   = {got}\nSubmitted signature  = {want}\n"

    def md5sum(self, path):
        got = self._md5_of(path)
        return f"{got}\n" if got else f"% Permission denied / No such file {path}\n"

    def config(self, cmd, sess):
        low = cmd.lower()
        if low in ("end", "exit"):
            sess["conf"] = False
            return "", False
        if low == "terminal width 511":
            return "", False
        if self.ignore_boot and ("boot " in low):
            return "", False
        if low == "no boot system":
            self.boot = []
            self.config_saved = False
            return "", False
        m = re.match(r"^no boot system (\S+)$", cmd)
        if m:
            self.boot = [b for b in self.boot if b != m.group(1)]
            self.config_saved = False
            return "", False
        m = re.match(r"^boot system (?:switch all )?(\S+)$", cmd)
        if m:
            if self.platform == "cisco_asa":
                if m.group(1) not in self.boot:
                    self.boot.append(m.group(1))        # an ASA adds the line at the end, and boots from the first one
            else:
                self.boot = [m.group(1)]
            self.config_saved = False
            return "", False
        m = re.match(r"^boot nxos (\S+)$", cmd)
        if m:
            self.boot = [m.group(1)]
            self.config_saved = False
            return "Performing image verification and compatibility check, please wait....\n", False
        return "% Invalid input detected at '^' marker.\n", False
