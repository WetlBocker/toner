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

**OpenSSL** (Tools > Certificates) works without installing anything, using the same OpenSSL code as the command line.
*Create* makes a private key (RSA 2048/3072/4096, ECDSA P-256/P-384, Ed25519), a certificate request (CSR) with alternative
names, or a self-signed or CA certificate, and can reuse a key you already have. *Read* describes any certificate, request,
key, DER file or .pfx (names, dates, key, fingerprints), tells you whether a key belongs to a certificate, and can fetch what a
server presents. *Convert* goes between PEM, DER and .pfx and adds or removes a key's passphrase. *Hash and random* does
digests, base64 and random bytes. *openssl.exe* runs the real command-line program for anything else, if the computer has one
(Git for Windows includes it). Toner stores none of the keys or results: copy or save them.

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

**Windows monitoring.** Add a device with Vendor **Windows** and choose how to monitor it:

- **Agent**: a small program on the Windows computer reports to Toner over HTTPS every few minutes. Nothing connects to the
  computer, so it suits laptops, computers outside the domain and anything behind a firewall. In Settings > **Agents** turn on
  "Receive reports" (Toner listens on port 8750 while it is running, in the tray is fine) and "Let computers sign themselves up",
  save, then **Download agent package**. Copy the zip to the Windows computer, unzip it and double-click
  **Install-TonerAgent.cmd** (it asks for administrator permission). The computer signs itself up and appears in the Inventory
  under its own name. The same package works for every computer. It installs as a scheduled task running as SYSTEM in
  `C:\ProgramData\Toner Agent`, and only sends: it opens no port and takes no commands. Toner is identified by its certificate's
  fingerprint, built into the package (no certificate authority to set up), and each computer gets its own token. The package
  holds a sign-up key, so keep it private and turn sign-up off when you are done (a new key makes old packages useless).
  To set up one computer by hand instead: add a Windows device with How to monitor: Agent, then its Windows tab > Get agent
  script. A computer that stops reporting turns into a warning, then a failure ("last report 3.0 h ago").
  Inventory > **Agents** (a Devices | Agents switch above the device list) lists every computer that reports through an
  agent (system, last report, age, agent version, notes such as "silent" or "reboot pending"), and can **Revoke** an agent or
  **Remove** the computer. The receiver, package, sign-up key and certificate stay in Settings > Agents. A package agent **updates itself** when Toner is newer than it: the
  agent always has Toner's version number (Toner 1.3.4 means agent 1.3.4), and can be given a **new token every N days** (the old one keeps working for a week, so nothing is locked
  out). Toner tells your notification channels when a computer signs itself up that you did not add, and warns when the
  agent certificate is within 90 days of expiring. Each report is also stored as a point for the History charts.
- **WinRM**: Toner connects to the computer over PowerShell remoting and nothing is installed on it. Leave the user name empty
  to sign in as the Windows account Toner runs as (domain single sign-on), or give `DOMAIN\user`, `user@domain` or `.\user`
  and a password (saved in Credential Manager). HTTP (5985) is encrypted by the sign-in; HTTPS (5986) is also available. The
  server needs `Enable-PSRemoting`, the firewall open, and an account in Remote Management Users and Event Log Readers.
- **This computer**: reads the computer Toner is running on.

All three produce the same checks (plus **Changes**: what was installed or removed, who became or stopped being a local
administrator, and which ports started or stopped listening since the previous check, reported once each): CPU, memory, disk space (fullest volume, every volume in the details), uptime and recent
reboots, pending reboot, services (automatic services that are stopped, ignoring trigger-start and per-user services;
plus a list of services that must be running, which fail), Critical and Error events in the last 24 hours, certificates in
the machine store about to expire, and days since an update was installed. Limits are in Settings > Thresholds, and each check
can be switched off in Settings > Checks. Remote Desktop is one click from the device's menu and window. Proxies and jump
hosts do not apply to Windows devices. The 5985 and 5986 ports are in the default scan list, so discovery suggests Windows
computers.

**Certificates.** Settings > Automation > "Also check the HTTPS certificate of every device" adds a certificate row (days left)
to every run for each device that answers TLS on the ports you list; it warns at 30 days and fails at 7 (Settings >
Thresholds). Devices with nothing listening there are skipped. The Overview has a panel for Windows computers and any
certificate running out: computers not reporting, waiting for a reboot, with filling disks, behind on updates, or changed.

**Trend report.** Reports > Trend report (7, 30 or 90 days) compares the period with the one before: availability, worst
offenders, what keeps failing, what is still wrong, configuration changes, and the Windows computers' busiest CPUs and
growing disks. Save it as PDF, HTML or CSV. Settings > Reports can make one every week or month into the default folder
(a PDF from the window, HTML from the background service).

**Saved passwords.** Passwords live in Windows Credential Manager, which belongs to one computer. Settings > Data and logs >
Export saved passwords writes them all to one file encrypted with a password you choose (scrypt and AES-256-GCM);
Import saved passwords restores them on another computer, so a portable copy can have its passwords too.

**UniFi by API key**: add a device with the vendor *UniFi*, choose **How to monitor** (*Network API*, *Protect API* or *Site Manager in the cloud*), and paste an API key made
for that application (UniFi's documentation at developer.ui.com says to create keys at unifi.ui.com). Network and Protect talk to the console at its address
(`/proxy/network/integration/v1`, `/proxy/protect/integration/v1`); the Site field picks a Network site (`default`, a name, or `*` for all). Site Manager
reads every console and site on the account through api.ui.com, and its Site field can narrow that to one console or site. A console that runs both Network and
Protect gets two devices (same vendor, a different way to monitor). In import and export files that is `vendor: unifi` with `platform: login`, `network`, `protect` or `cloud`. The first choice, *Console login*, signs in with a user name and password and stays for the checks the API does not have yet (port errors, uplinks,
channel utilisation). Each type has its own checks (Settings > Checks, or per device) and its own limits (Settings > Thresholds).

**Per-device checks and thresholds**: Edit device > Checks lets one device run its own list of checks and use its own WARN/FAIL limits. A device with
nothing set there follows Settings > Checks and Settings > Thresholds, and its own limits beat the overrides in Settings. On a Windows device, **Choose...**
beside the service fields lists the computer's services (asked live over WinRM or on this PC; from the last report for an agent) so you tick the ones
that must be running or that may be stopped, instead of typing names.

**Settings**: thresholds (with per-vendor, folder, tag and device overrides), which checks run, custom checks, timeouts,
automation, config backups, notifications (email, Teams, Slack, Discord, ntfy, webhook, desktop; each with its service's mark in the list), credential profiles,
appearance, terminal, reports, security (host keys), audit log, data and logs.

Press **Ctrl+K** (or the Search button under the sections) anywhere to jump to a section, tool, device or action. Ctrl+1 to Ctrl+9 switch sections. **Ctrl+B** (or the button under the sections) folds the sidebar to a strip of icons and back; Toner remembers which you chose.

Interface details: right-click a heading in Inventory or Results to choose its columns (empty ones hide themselves until you choose); Status columns and marks
use different shapes as well as colours (circle OK, triangle WARN, square FAIL, diamond ERROR); the Overview says what changed since the previous run; Enter opens the
selected device; Ctrl+K also finds Settings pages, limits and checks; a device dialog asks before throwing away edits.

A few things that make the day-to-day quicker: the Inventory has a search box (Ctrl+F) and a dot beside each device for how its latest checks went; a finished run opens the
devices that need a look; Settings marks the pages with unsaved edits; small confirmations appear as a short note that fades instead of a box to click away; a new
installation shows a getting-started list on the Overview; and the window opens at the size and place you left it.

## Supported devices and checks

| Vendor | How | Checks |
|---|---|---|
| Cisco (IOS, IOS XE, NX-OS, ASA) | SSH | CPU, memory, uptime, interfaces and error counters, BGP, OSPF, fans / power / temperature, NTP, unsaved configuration, flash space, switch stack, HSRP / VRRP, port-channels, ASA failover |
| Juniper (Junos) | SSH | CPU, memory, uptime, chassis alarms, interfaces, BGP, OSPF, fans / power / temperature, NTP, uncommitted changes, core dumps, BFD, storage, virtual chassis |
| Arista (EOS) | SSH | CPU, memory, uptime, temperature, interfaces, BGP, OSPF, fans and power, MLAG, NTP, flash space |
| HPE Aruba (AOS-CX, AOS-S) | SSH | CPU, memory, uptime, interfaces, fans / power / temperature, NTP |
| MikroTik (RouterOS) | SSH | CPU, memory, uptime, version, interfaces, OSPF, temperature and voltage, flash space, RouterBOARD firmware, NTP |
| Fortinet (FortiGate) | REST API | CPU, memory, firmware, WAN links, HA, IPsec tunnels, FortiCare / FortiGuard subscriptions, certificates, interfaces and errors, HA configuration sync, FortiAPs and FortiSwitches, log disk |
| Palo Alto (PAN-OS) | XML API | CPU, memory, uptime, version, sessions, HA, interfaces, subscriptions, content update age, disk, Panorama connection, last commit |
| Cisco Meraki | Dashboard API | device status, appliance uplinks, licenses, dashboard alerts, configuration changes, site-to-site VPN, uplink loss and latency |
| Proxmox VE | REST API with an API token | cluster quorum and nodes, node CPU / memory / uptime, storage, virtual machines and containers, failed tasks, backup jobs |
| TrueNAS (CORE, SCALE) | REST API with an API key | pool health, errors and space, active alerts, load, uptime |
| OPNsense | REST API with a key and secret | updates waiting, memory, disk, uptime, each gateway's state, delay and loss |
| UniFi, console login | controller API | site health, per device state, uptime, CPU, memory, temperature, firmware, uplink, port errors, clients, channel utilisation |
| UniFi, Network API (key) | Integration API on the console | API version, per device state, uptime, CPU, memory, firmware, Wi-Fi transmit retries per radio, devices waiting to be adopted, client count |
| UniFi, Protect API (key) | Integration API on the console | NVR alarm state, cameras, lights, sensors, chimes and other devices connected or not, sensor batteries, recent leak / tamper / smoke alarms |
| UniFi, Site Manager (cloud) | api.ui.com, one key for the account | per console device status and firmware, per site health and WAN uptime, ISP latency and packet loss, SD-WAN status |
| Generic SNMP (anything else) | SNMP v1/v2c/v3 | reachability, CPU, memory, storage, uptime, temperature, interfaces, errors, utilisation, fans / power supplies / sensors, load average, UPS battery and load (UPS-MIB, APC), printer toner and paper, Synology and QNAP disks and volumes |
| Cloud status page | public Statuspage JSON, no login | overall status, components (or only the ones named in a `watch` field), open incidents, planned maintenance |
| This PC's Wi-Fi | `netsh wlan`, no login | connection, signal strength, link speed |
| Windows | agent, WinRM (PowerShell remoting) or this computer | CPU, memory, disks, uptime, pending reboot, services, event errors, certificate expiry, update age, physical disk health, BitLocker, antivirus, firewall, clock difference, failed sign-ins and lockouts, activation, Remote Desktop sessions, failed scheduled tasks, Active Directory replication, Hyper-V, backup age |

**Every device** can also have support, warranty and licence end dates checked: put `support=2027-06`, `warranty=2026-12-31`, `eol=...` or `licence_expires=...` in its custom fields (Edit device > Tags and fields) and the days left appear as a result, graded by Settings > Thresholds.

Configuration backup: Cisco, Juniper, Arista, HPE, MikroTik (SSH), Fortinet and Palo Alto (API).

**Custom checks** need no code: run a command over SSH, read an SNMP object, fetch a web page, test a TCP port, count
the days left on a certificate, or ping, and turn the answer into OK / WARN / FAIL.

The parsers for Juniper, Arista, HPE, MikroTik, Palo Alto, Fortinet, Meraki, Proxmox, TrueNAS and OPNsense, and the SNMP checks for UPS, printers and NAS boxes, were written from the vendors' documented output and are
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

The installed program does the same without Python: `Toner.exe cli service`, `Toner.exe cli run --json`, and so on (output
goes to the console that started it, or to `toner-service.log` in the data folder when there is none, as under Task
Scheduler). The service also runs the **agent receiver** when it is turned on in Settings > Agents, makes the scheduled
trend report, and watches the agent certificate, so a server can collect Windows reports with nobody logged in. It uses the
data folder and Credential Manager of the account it runs as, so run it as the same account you set Toner up with.

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
