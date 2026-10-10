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

**Tools**: SSH console (every session logged), command runner (one command on many devices, read-only by default),
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

**iperf3** is run, not bundled: download iperf3 for Windows (iperf.fr) and choose `iperf3.exe` on the page, or put it on
your PATH. The page can run a test against another iperf3 server (TCP or UDP, upload or download, several streams) or act
as the server, and shows the sent and received rates and retransmits.

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

## Build the installer

    powershell -File packaging\build.ps1 -Version 1.0.0

This builds the program folder with PyInstaller, then `build\installer\Toner-Setup-1.0.0.exe` with
[Inno Setup 6](https://jrsoftware.org/isinfo.php) (`winget install JRSoftware.InnoSetup`). The installer needs no
administrator rights, offers desktop and start-with-Windows shortcuts, and leaves your data and saved passwords alone
when you uninstall or upgrade. `Toner.exe --minimized` starts in the tray when background running is on.
