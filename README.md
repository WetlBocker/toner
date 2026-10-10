# Toner

A Windows desktop tool for checking, documenting and troubleshooting a multi-vendor network, from one window.

    pip install -r requirements.txt
    python app.py

Everything is stored on your computer: the database in `%APPDATA%\NetCheck\netcheck.db`, passwords, tokens and SNMP
communities in Windows Credential Manager (never in the database), logs next to the database.

## What it does

**Overview** shows how the network is doing from the stored results the moment it opens: healthy, warning and failing
devices, what needs attention, availability over 24 hours / 7 days / 30 days, configuration changes and recent runs.

**Results** runs the health checks. One row per device; open it to see its checks. Right-click a check that says
"unexpected output" to see what the device actually said (passwords masked), for a bug report.

**Inventory** is a tree of folders and devices (drag to organise), with tags, credential profiles, jump hosts,
bulk edit, import and export (CSV, JSON, YAML). Click a device's **Details** for one window with its checks, history,
configuration and quick actions (SSH, ping, SNMP, web page).

**Configs** backs up device configurations, keeps only versions that really differ, shows what changed (diff),
and searches every stored configuration. Passwords and keys are masked in stored copies by default.

**History** charts any checks over time; hover for the measured values. Checks on very different scales get their own
chart.

**Reports** exports CSV, HTML and PDF.

**Sessions** keeps your connections: SSH, Telnet, Remote Desktop and Serial (console cable). Create one with New session,
choose the type, and it is saved so a double-click connects later. Sessions live in a folder tree like the inventory's: make
folders and subfolders (New folder, or New folder... while creating a session), drag sessions and folders between them, rename
or delete a folder (what is in it moves up, nothing is lost), and search, edit and duplicate sessions. SSH, Telnet and Serial open in tabs inside Toner (several at once), follow the font and colours in
Settings > Terminal, and every one is logged (Session logs). An SSH session can keep its password in Credential Manager,
or use an inventory device's saved login, jump host and proxy; Telnet and SSH sessions follow the proxy settings. Serial
sessions have a Send break button for ROMMON. Remote Desktop starts Windows' own client with a generated .rdp file, and
Windows asks for the password. Inventory > Open SSH session and a device window's SSH button open a Sessions tab.

**Tools**: command runner (one command on many devices, read-only by default),
ping / traceroute / DNS, live ping graph, path monitor (MTR), port scanner, TLS certificate checker (also for the whole
inventory), subnet calculator, device discovery, topology map from LLDP / CDP, SNMP (v1, v2c, v3: get, walk, bulk walk,
interface table and rates, neighbours), syslog and trap receivers, MAC lookup and Wake-on-LAN, a TFTP server and an SFTP
server (see below), and an iperf3 throughput test.

**File servers.** TFTP and SFTP serve one folder you choose, nothing outside it, and are off until you start them.
They are read-only until you tick "Allow uploads", replacing or deleting files needs a second tick, you can limit them to
the devices you name, and they stop themselves after a time you set. Every transfer is listed on screen, and starts,
stops, uploads, deletions, refusals and logins go to the audit log. TFTP has no passwords by design, so name the devices
in "Allowed clients" whenever uploads are on. SFTP needs a user name and password (kept in Credential Manager), has no
shell, shows its fingerprint, and locks an address out for five minutes after five wrong passwords. Whole drives and
system folders are refused.

**SCP and xcopy** (Tools > File transfer). SCP copies files and folders to or from a device over SSH, using the device's saved login, jump host and proxy; the device must allow it (Cisco IOS: `ip scp server enable` and a privilege-15 user). Names a device sends are checked, so nothing can be written outside the folder you chose, and Stop leaves no half-written files. xcopy runs Windows xcopy to copy folders on this computer or to and from a network share, for example to move what the TFTP and SFTP servers received to a file server. Preview shows what would be copied without copying anything, and copying over existing files asks first.

**iperf3** is run, not bundled: download iperf3 for Windows (iperf.fr) and choose `iperf3.exe` on the page, or put it on
your PATH. The page can run a test against another iperf3 server (TCP or UDP, upload or download, several streams) or act
as the server, and shows the sent and received rates and retransmits, with a live graph of the speed during the test.

**Scheduled throughput.** Settings > Custom checks > Throughput (iperf3) runs a test from this computer to an iperf3
server (`iperf3 -s` on the device) on every scheduled run. The speed is kept for the History charts, and WARN / FAIL
fire when it drops below the limits you set.

**Proxy.** Settings > Proxy sends Toner's connections through an HTTP (CONNECT), SOCKS5 or SOCKS4 proxy, with an
optional user name and password (kept in Credential Manager) and a "do not use it for" list (names, `*.corp.example.com`,
addresses, networks such as `10.0.0.0/8`). The options are no proxy, the Windows proxy settings (web connections only,
as a browser would), or a proxy you enter. Any device can override it in its Access tab: use the global setting, connect
directly, or use its own proxy. SSH (checks, backups, the console and jump hosts), the Fortinet, Palo Alto, Meraki and
UniFi APIs, status pages, web, port and certificate checks and notifications all use it. SNMP, ping, traceroute, the
listeners and the file servers use UDP or ICMP or listen for connections, so they never go through a proxy. A **Test**
button on the page tries a connection through the proxy you have entered.

**Maintenance windows** (Settings > Maintenance) hold back alerts for planned work: a one-off window or a weekly one
(Saturday 22:00-02:00), for all devices or chosen groups. Checks still run and are recorded and the Overview marks the
devices; when the window ends, a problem that is still there is announced and a fixed one is reported as recovered.

**Wi-Fi.** Tools > Wi-Fi Scanner lists the networks this computer can hear (signal, channel, band, security, who made the
access point) and suggests the quietest 2.4 GHz channel; Windows needs Location access switched on for it. Add "This PC's
Wi-Fi" as a device (host `localhost`) to check a laptop's connection, signal strength and link speed on every run.

**Cloud status.** Add a "Cloud status page" device (GitHub, Cloudflare, Zoom, Meraki, Duo, Discord and any other status
page built on Atlassian Statuspage) to get its overall status, affected components and open incidents in the same
results, history and alerts as your own devices. Microsoft 365 is not included: its service health is only available
through an authenticated Microsoft Graph app registration.

**Settings**: thresholds (with per-vendor, folder, tag and device overrides), which checks run, custom checks, timeouts,
automation, config backups, notifications (email, Teams, Slack, Discord, ntfy, webhook, desktop), credential profiles,
appearance, terminal, reports, security (host keys), audit log, data and logs.

Press **Ctrl+K** anywhere to jump to a section, tool, device or action. Ctrl+1 to Ctrl+8 switch sections.

## Supported devices and checks

| Vendor | How | Checks |
|---|---|---|
| Cisco (IOS, IOS XE, NX-OS, ASA) | SSH | CPU, memory, uptime, interfaces and error counters, BGP, OSPF |
| Juniper (Junos) | SSH | CPU, memory, uptime, chassis alarms, interfaces, BGP, OSPF |
| Arista (EOS) | SSH | CPU, memory, uptime, temperature, interfaces, BGP, OSPF |
| HPE Aruba (AOS-CX, AOS-S) | SSH | CPU, memory, uptime, interfaces |
| MikroTik (RouterOS) | SSH | CPU, memory, uptime, version, interfaces, OSPF |
| Fortinet (FortiGate) | REST API | CPU, memory, firmware, WAN links, HA, IPsec tunnels |
| Palo Alto (PAN-OS) | XML API | CPU, memory, uptime, version, sessions, HA, interfaces |
| Cisco Meraki | Dashboard API | device status, appliance uplinks, licenses |
| UniFi OS | controller API | site health, per device state, uptime, CPU, memory, temperature, firmware, uplink, port errors, clients, channel utilisation |
| Generic SNMP (anything else) | SNMP v1/v2c/v3 | reachability, CPU, memory, storage, uptime, temperature, interfaces, errors, utilisation |
| Cloud status page | public Statuspage JSON, no login | overall status, components, open incidents |
| This PC's Wi-Fi | `netsh wlan`, no login | connection, signal strength, link speed |

Configuration backup: Cisco, Juniper, Arista, HPE, MikroTik (SSH), Fortinet and Palo Alto (API).

**Custom checks** need no code: run a command over SSH, read an SNMP object, fetch a web page, test a TCP port, count
the days left on a certificate, or ping, and turn the answer into OK / WARN / FAIL.

The parsers for Juniper, Arista, HPE, MikroTik and Palo Alto were written from the vendors' documented output and are
tested against sample text, not real hardware. If a check reports "unexpected output", the raw output is saved so it can
be fixed from a real sample.

## Without the window

    python cli.py run --group "Tag: core" --json --fail-on warn     checks; exit code 1 if anything is WARN or worse
    python cli.py backup                                            back up configurations
    python cli.py status                                            the latest stored results
    python cli.py service --metrics-port 9108                       keep running scheduled checks, backups and alerts
    python cli.py metrics --port 9108                               Prometheus /metrics from the stored results

`service` uses the schedules from Settings > Automation and Config backups, so it can run from Task Scheduler or any
service wrapper. In the desktop app, **Settings > General > Keep running in the system tray** does the same while the
window is closed.

## Tests

    python tests/run_all.py            every test file, one line each
    python tests/test_custom.py        a single file

The tests use fakes (simulated devices and APIs, a local SNMP agent, local TLS and SSH servers) and a throw-away
database; they never touch your inventory or credentials.

## About and updates

**About** (the last section) shows the version, how this copy was installed, the program, data, database and log
locations, the Python, Qt and Windows versions, the libraries Toner is built with and the license. **Copy details**
puts all of it on the clipboard for a bug report.

**Check for updates** looks at the newest GitHub release (once a day if "Check for updates automatically" is ticked,
or whenever you press the button). A newer version puts a dot next to About, and shows its release notes with
**Download and install**, **View release** and **Skip this version**. The installer is downloaded from GitHub over
HTTPS only, its SHA-256 checksum is compared with the one GitHub published for the file, and only then is it run (a
download that does not match, or a release with no checksum, is never run). Your inventory, history and saved passwords
are kept. **Install updates automatically** downloads and verifies a new version as soon as it is found and installs it
when you close Toner. Copies not set up with the installer (running from source, or unzipped) can check for updates but
not install them.

To publish a release for the update check to find: raise `VERSION` in `core\version.py`, run `packaging\build.ps1`, then
create a GitHub release tagged `v<version>` (for example `v1.2.0`) and attach `Toner-Setup-<version>.exe`. GitHub adds the
checksum itself.

## Install or portable

The installer's first page asks how to set Toner up:

- **Install on this computer** adds Start Menu and desktop shortcuts, an entry in Installed apps, an uninstaller and an
  optional start-with-Windows entry. Data is kept in `%APPDATA%\NetCheck`.
- **Portable** copies Toner into a folder you choose (a USB drive, a share) and nothing else: no shortcuts, no registry
  entries, no uninstaller. A `portable.flag` file beside `Toner.exe` makes Toner keep its database, settings, logs and
  downloaded updates in a `data` folder next to it, so copying the whole folder moves everything. Delete the folder to
  remove it. Saved passwords are the one thing that stays behind: they live in Windows Credential Manager on each computer.
  A portable copy still checks for updates and updates itself in place, keeping its data.

Both can also be chosen from a script: `Toner-Setup-1.1.0.exe /VERYSILENT /MODE=portable /DIR="E:\Toner"`.
## Build the installer

    powershell -File packaging\build.ps1

This builds the program folder with PyInstaller, then `build\installer\Toner-Setup-1.0.0.exe` with
[Inno Setup 6](https://jrsoftware.org/isinfo.php) (`winget install JRSoftware.InnoSetup`). The installer needs no
administrator rights, offers desktop and start-with-Windows shortcuts, and leaves your data and saved passwords alone
when you uninstall or upgrade. `Toner.exe --minimized` starts in the tray when background running is on.
