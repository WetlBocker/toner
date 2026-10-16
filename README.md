# Toner

A Windows desktop tool for checking, documenting and troubleshooting a multi-vendor network, from one window.

## Contents

- [Get started](#get-started)
- [The sections](#the-sections)
- [Supported devices and checks](#supported-devices-and-checks)
- [Monitoring in detail](#monitoring-in-detail)
  - [Windows computers](#windows-computers)
  - [UniFi](#unifi)
  - [API keys from the device](#api-keys-from-the-device)
  - [Per-device checks and thresholds](#per-device-checks-and-thresholds)
  - [Interfaces](#interfaces)
  - [Custom checks and support dates](#custom-checks-and-support-dates)
  - [Certificates](#certificates)
  - [Maintenance windows](#maintenance-windows)
  - [Proxy](#proxy)
  - [Wi-Fi and cloud status pages](#wi-fi-and-cloud-status-pages)
- [Tools in detail](#tools-in-detail)
  - [OpenSSL](#openssl)
  - [File servers (TFTP and SFTP)](#file-servers-tftp-and-sftp)
  - [SCP and xcopy](#scp-and-xcopy)
  - [iperf3](#iperf3)
- [Automation (Ansible)](#automation-ansible)
- [Without the window](#without-the-window)
- [Updates and About](#updates-and-about)
- [Build and test](#build-and-test)

## Get started

Run from source:

    pip install -r requirements.txt
    python app.py

Or use the installer. Its first page asks how to set Toner up:

- **Install on this computer**: Start Menu and desktop shortcuts, an entry in Installed apps, an uninstaller and an optional
  start-with-Windows entry. Data is kept in `%APPDATA%\NetCheck`.
- **Portable**: copies Toner to a folder you choose (a USB drive, a share) and nothing else. A `portable.flag` beside
  `Toner.exe` keeps the database, settings, logs and updates in a `data` folder next to it, so copying the folder moves
  everything. Delete the folder to remove it. It still checks for updates and updates itself in place.

From a script: `Toner-Setup-1.1.0.exe /VERYSILENT /MODE=portable /DIR="E:\Toner"`.

**Your data stays on your computer.** The database is `%APPDATA%\NetCheck\netcheck.db` and the logs sit next to it. Passwords,
tokens and SNMP communities are in Windows Credential Manager, never in the database. Because Credential Manager belongs to one
computer, **Settings > Data and logs > Export saved passwords** writes them to one file encrypted with a password you choose
(scrypt and AES-256-GCM), and **Import saved passwords** restores them on another computer.

**Shortcuts:** **Ctrl+K** searches sections, tools, devices, Settings pages, limits, checks and actions. **Ctrl+1** to **Ctrl+9**
switch sections. **Ctrl+B** folds the sidebar to icons and back (remembered). **Ctrl+F** searches the Inventory.

## The sections

| Section | What it does |
|---|---|
| **Overview** | How the network is doing, from stored results: healthy, warning and failing devices (click a number to see them in Results), what needs attention, availability over 24 hours / 7 / 30 days, configuration changes, what changed since the last run, and a panel for Windows computers and certificates running out. Under **Needs attention**: open the device, run its checks, SSH or Remote Desktop to it, **Acknowledge** or **Snooze** (see below). A new installation shows a getting-started list. |
| **Results** | Runs the health checks, and opens on every device's latest stored results. One row per device; open it for its checks. Filter to problems, warnings, failures or healthy devices. Right-click a check that says "unexpected output" to see what the device said (passwords masked) for a bug report. |
| **Inventory** | Folders and devices (drag to organise), tags, credential profiles, jump hosts, bulk edit, import and export (CSV, JSON, YAML). Each device shows its status and when it was last checked. **Details** opens one window per device: checks, history, configuration, quick actions (SSH, ping, SNMP, web page). **Agents** lists Windows computers that report by agent. Right-click a heading to choose columns. |
| **Configs** | Backs up configurations (see below), keeps only versions that differ, shows diffs and searches every stored configuration. Passwords and keys are masked in stored copies by default. |
| **History** | Charts any checks over time; hover for values. Checks on very different scales get their own chart. Uptime shows restarts. |
| **Reports** | CSV, HTML and PDF. The **Trend report** (7, 30 or 90 days) compares with the period before: availability, worst offenders, repeat failures, what is still wrong, configuration changes, busiest CPUs and growing disks. Settings > Reports can make one every week or month. |
| **Tools** | Command runner (the same commands on many devices, read-only by default: Cisco, Juniper, Arista, HPE and MikroTik by SSH, Windows computers by PowerShell, Fortinet and Palo Alto firewalls by SSH with a login set on the device), ping, traceroute, DNS, live ping graph, path monitor (MTR), port scanner, TLS certificate checker, subnet calculator, device discovery, LLDP / CDP topology map, SNMP (v1, v2c, v3), syslog and trap receivers, MAC lookup, Wake-on-LAN, Wi-Fi scanner, file servers, SCP and xcopy, OpenSSL, iperf3, and the Ansible **Playbook Editor**. |
| **Sessions** | Saved connections in a folder tree (drag, rename, search, duplicate): SSH, Telnet and Serial open in tabs inside Toner, follow Settings > Terminal, and are logged. An SSH session can keep its password in Credential Manager or use an inventory device's login, jump host and proxy. Serial has a Send break button for ROMMON. **Remote Desktop** runs inside a Toner tab, using the Remote Desktop control Windows ships (the one `mstsc.exe` is built on): Windows asks for the password and Toner never stores it. Fill the window or use a fixed size; clipboard, drives, printers, the console session and a gateway are options. Settings > Terminal can send it to Windows' own window instead. |
| **Automation** | Runs **Ansible** playbooks on Inventory devices: pick a playbook and devices, check first (nothing changes), then run for real after a confirmation naming the playbook and devices. Output streams live, with a recap per device and a history. See [Automation (Ansible)](#automation-ansible). More will be added here. |
| **Settings** | Thresholds (overrides per vendor, folder, tag or device), which checks run and when (Checks has tabs for the list, the schedule and your own checks), timeouts, config backups, notifications (email, Teams, Slack, Discord, ntfy, webhook, desktop), credential profiles, proxy, agents, maintenance, appearance, terminal, reports, security (host keys, and older SSH algorithms: ssh-rsa and SHA-1 key exchange for devices such as older Cisco ASAs that offer nothing newer, tried last and on unless turned off), audit log, data and logs. Pages with unsaved edits are marked, and Save and Revert list exactly what changes. |
| **About** | Version, how this copy was installed, locations, library versions, license. **Copy details** puts it all on the clipboard for a bug report. |

Every section has the same header: its name and a line of context. The line along the bottom of the window shows the last run (or
the progress of the one going), the next scheduled run and backup, the agent receiver and notifications; click a part to go where it is
set. **Styles.** Settings > Appearance > *Style* switches between **Standard** (roomy rows, rounded pills) and **Ops console** (dense and flat: 22 px rows, monospace data, small tags, a narrower sidebar, teal accent by default) for watching many devices at once. Both follow the light or dark theme; **Ctrl+K** > *Style* switches at once. Status colours are one set everywhere (pills, text, dots, numbers), tuned per theme to stay readable, and marks use shapes as well
as colours (circle OK, triangle WARN, square FAIL, diamond ERROR).

**Clients.** The top-level folders of the Inventory are treated as clients. Pick one at the top of the sidebar and every section shows
only that client: the Overview, Results, Inventory, Configs, History and Reports, and the runs and backups you start by hand (scheduled
ones keep their own groups). The window title names the client.

**Acknowledge and snooze.** On the Overview, *Acknowledge* puts a device's problems aside while they stay the same or get better; a new
problem, or one getting worse, brings it back. *Snooze* puts them aside for 1 hour to 7 days (sooner if something gets worse). Put-aside
devices leave Needs attention (*Show put aside* lists them, marked) and are not announced by notifications, but their checks still run,
are recorded and count in the numbers. Each one is in the audit log.

## Supported devices and checks

| Vendor | How | Checks |
|---|---|---|
| Cisco (IOS, IOS XE, NX-OS, ASA) | SSH | CPU, memory, uptime, interfaces and error counters, BGP, OSPF, EIGRP, fans / power / temperature, NTP, unsaved configuration, flash, switch stack, HSRP / VRRP, port-channels, ASA failover |
| Juniper (Junos) | SSH | CPU, memory, uptime, chassis alarms, interfaces, BGP, OSPF, fans / power / temperature, NTP, uncommitted changes, core dumps, BFD, storage, virtual chassis |
| Arista (EOS) | SSH | CPU, memory, uptime, temperature, interfaces, BGP, OSPF, fans and power, MLAG, NTP, flash |
| HPE Aruba (AOS-CX, AOS-S) | SSH | CPU, memory, uptime, interfaces, fans / power / temperature, NTP |
| MikroTik (RouterOS) | SSH | CPU, memory, uptime, version, interfaces, OSPF, temperature and voltage, flash, RouterBOARD firmware, NTP |
| Fortinet (FortiGate) | REST API token | CPU, memory, firmware, WAN links, HA, IPsec, FortiCare / FortiGuard subscriptions, certificates, interfaces and errors, HA sync, FortiAPs and FortiSwitches, log disk |
| Palo Alto (PAN-OS) | XML API key | CPU, memory, uptime, version, sessions, HA, interfaces, subscriptions, content update age, disk, Panorama connection, last commit |
| Cisco Meraki | Dashboard API key | device status, appliance uplinks, licenses, alerts, configuration changes, site-to-site VPN, uplink loss and latency |
| Proxmox VE | API token | cluster quorum and nodes, node CPU / memory / uptime, storage, VMs and containers, failed tasks, backup jobs |
| TrueNAS (CORE, SCALE) | API key | pool health, errors and space, active alerts, load, uptime |
| OPNsense | API key and secret | updates waiting, memory, disk, uptime, each gateway's state, delay and loss |
| UniFi | console login, or API key (see [UniFi](#unifi)) | per type: site health, device state, uptime, CPU, memory, firmware, Wi-Fi retries, Protect cameras and sensors, WAN and ISP health |
| Windows | agent, WinRM or this computer | CPU, memory, disks, uptime, reboots, services, event errors, certificates, update age, disk health, BitLocker, antivirus, firewall, clock, sign-in failures, activation, RDP sessions, scheduled tasks, Active Directory, Hyper-V, backup age, changes |
| Generic SNMP (anything else) | SNMP v1/v2c/v3 | reachability, CPU, memory, storage, uptime, temperature, interfaces, errors, utilisation, fans / power / sensors, load, UPS battery and load, printer toner and paper, Synology and QNAP disks |
| Cloud status page | public Statuspage JSON | overall status, components, open incidents, planned maintenance |
| This PC's Wi-Fi | `netsh wlan` | connection, signal strength, link speed |

**Configuration backup** works for Cisco, Juniper, Arista, HPE, MikroTik (SSH), Fortinet and Palo Alto (API).

**N/A.** A chosen check that does not apply to a device still gets a grey **N/A** row, so it never just goes missing: BGP, OSPF or
EIGRP that is not configured, fans and sensors on a virtual appliance, ASA failover that is off. N/A is never a problem and never
alerts. A routing protocol that is configured but has no neighbors is a WARN. A Cisco ASA reads its own commands for CPU
(`show cpu usage`), memory (`show memory`), uptime, interfaces (`show interface`, with error counters), BGP, OSPF, EIGRP and disk
(`dir disk0:`). EIGRP lists only the neighbors that are up, so a drop in the count since the last run is a WARN.

The parsers for the SSH and API vendors, Proxmox, TrueNAS and OPNsense, and the SNMP checks for UPS, printers and NAS boxes, were
written from the vendors' documented output and tested against samples, not real hardware. If a check says "unexpected output",
the raw output is saved so it can be fixed from a real sample.

## Monitoring in detail

### Windows computers

Add a device with Vendor **Windows** and choose how to monitor it:

- **Agent**: a small program on the computer reports to Toner over HTTPS. Nothing connects to the computer, so it suits laptops,
  computers outside the domain and anything behind a firewall.
  1. In Settings > **Agents** turn on "Receive reports" (port 8750, while Toner runs; the tray is fine) and "Let computers sign
     themselves up", save, then **Download agent package**.
  2. Copy the zip to the computer, unzip it and double-click **Install-TonerAgent.cmd** (it asks for administrator permission).
     The computer signs itself up and appears in the Inventory. The same package works for every computer.

  The agent is a scheduled task running as SYSTEM in `C:\ProgramData\Toner Agent`. It only sends: no port, no commands. Toner is
  identified by its certificate fingerprint built into the package, and each computer gets its own token. The package holds a
  sign-up key, so keep it private and turn sign-up off when done (a new key makes old packages useless). For one computer by
  hand: add a device with How to monitor: Agent, then its Windows tab > Get agent script.

  A silent computer becomes a warning, then a failure. Inventory > **Agents** lists each one (system, last report, version, notes
  like "silent" or "reboot pending") and can **Revoke** an agent or **Remove** the computer. Agents **update themselves** when
  Toner is newer (the agent version is always Toner's version), can get **a new token every N days**, and can have their **reporting
  interval changed from Toner** (Settings > Agents > Report every N minutes > *Also change computers that already have the agent*).
  Toner warns when a computer signs itself up that you did not add, and when the agent certificate is within 90 days of expiring.
- **WinRM**: PowerShell remoting, nothing installed. Leave the user name empty to sign in as the account Toner runs as, or give
  `DOMAIN\user`, `user@domain` or `.\user` and a password. HTTP (5985) or HTTPS (5986). The server needs `Enable-PSRemoting`, the
  firewall open, and an account in Remote Management Users and Event Log Readers.
- **This computer**: reads the computer Toner runs on.

**Services.** A Windows computer's device window has a **Services** button: every service with its state and startup type, a search box,
and filters (running, stopped, automatic but not running). Select one or more and **Start**, **Stop** or **Restart** them (Restart only for running ones), or right-click
for the same plus **Startup type** (Automatic, Automatic (Delayed Start), Manual, Disabled) and copying names; Toner asks
first, warns about services that matter (Remote Management, Remote Desktop, Netlogon, Active Directory, DNS...), says what a restart
stops along with it, shows the reason when Windows refuses, and logs each change in the audit log. It works on this PC and over WinRM.
A computer that reports by agent is listed from its last report, because an agent only sends and takes no commands; **Sign in to manage...**
lists it live and controls it over WinRM with an administrator account typed for that window only (never saved).

All three give the same checks, including **Changes** (software installed or removed, local administrators added or removed, ports
that started or stopped listening). Services: automatic services that are stopped (trigger-start and per-user services ignored),
plus a list that must be running. Limits are in Settings > Thresholds and each check can be switched off in Settings > Checks.
Proxies and jump hosts do not apply to Windows devices.

### UniFi

Add a device with vendor *UniFi* and pick **How to monitor**:

- **Console login**: user name and password; also covers port errors, uplinks and channel utilisation.
- **Network API**, **Protect API**: an API key made on the console (developer.ui.com says to create keys at unifi.ui.com). The Site
  field picks a Network site (`default`, a name, or `*` for all). A console running both gets two devices.
- **Site Manager in the cloud**: one key reads every console and site on the account through api.ui.com; the Site field can narrow it.

In import files that is `vendor: unifi` with `platform: login`, `network`, `protect` or `cloud`. Each type has its own checks and limits.

### API keys from the device

For **Palo Alto** and **Proxmox**, the **Get API key / token** button on the device's Access tab signs in once with an
administrator's user name and password, asks the device for a key and fills it in. The password is sent over HTTPS in the request
body and never kept; only the key is saved. Proxmox gets a read-only token called `toner` (PVEAuditor on `/`), and an account with
two-factor sign-in cannot be used. For other products paste a key made in their own interface.

**Command line on firewalls.** Fortinet and Palo Alto are checked through their API, so for the Command Runner their device dialog also has an
**SSH user name** and **SSH password** (Access tab; separate from the API key, kept in Credential Manager). Without them the firewall is listed greyed.
Each SSH device's last Command Runner session is written to `ssh-logs\command-runner-<device>.log` next to Toner's data (passwords
left out), and a failure says where it is; a failed SSH config backup leaves `ssh-logs\backup-<device>.log`, masked like a stored
backup. A Cisco ASA is given time to show its prompt before the first command, since one that
authorises the shell over TACACS+ or RADIUS drops what is typed before then.
Config changes can be sent as plain lines (`conf t`, the changes, `end`, `wr`): each line waits for the device's prompt in whatever mode
it is in, such as `fw1(config)#` or `[edit]` `user@srx#`.
On Windows, the Command Runner works for this PC and for computers reached over WinRM; one that reports by agent is listed greyed, because an agent takes no
commands. Read-only mode lets PowerShell *look* (Get-..., Where-Object on `$_`, hostname, ipconfig, netstat ...) and asks before anything that could change a computer. A rejected key is reported once,
in words, instead of once per check.

### Per-device checks and thresholds

Edit device > **Checks** lets one device run its own list of checks and use its own WARN / FAIL limits. A device with nothing set
follows Settings > Checks and Settings > Thresholds; its own limits beat the overrides in Settings. On a Windows device,
**Choose...** beside the service fields lists the computer's services (live over WinRM or on this PC; from the last report for an
agent) so you tick them instead of typing names.

### Interfaces

The *interfaces* row is a **FAIL** when any interface that should be up is down (ports an administrator switched off are not
counted; an err-disabled port is a WARN). Edit device > Checks > **Check only some of this device's interfaces** > **Choose
interfaces...** asks the device for its list (using the address and login typed in the dialog, saved or not) and you tick the
ones that matter. Only those are read, for the interfaces row and for error and utilisation checks. A chosen port that is
switched off counts as down; one the device no longer has is a WARN, so a rename is noticed.

### Custom checks and support dates

**Custom checks** (Settings > Checks > Custom) need no code: run a command over SSH, read an SNMP object, fetch a web page, test a
TCP port, count the days left on a certificate, ping, or run an **iperf3** throughput test on every scheduled run (the speed is kept
for History, and WARN / FAIL fire below your limits). Each turns the answer into OK / WARN / FAIL.

**Support dates**: put `support=2027-06`, `warranty=2026-12-31`, `eol=...` or `licence_expires=...` in a device's custom fields (Edit
device > Tags and fields) and the days left appear as a result, graded by Settings > Thresholds.

### Certificates

Settings > Checks > Schedule > "Also check the HTTPS certificate of every device" adds a days-left row for each device that answers TLS on
the ports you list. It warns at 30 days and fails at 7; devices with nothing listening are skipped.

### Maintenance windows

Settings > Maintenance holds back alerts for planned work: one-off or weekly (e.g. Saturday 22:00-02:00), for all devices or chosen
groups. Checks still run and are recorded and the Overview marks the devices. When the window ends, a problem still there is
announced and a fixed one is reported as recovered.

### Proxy

Settings > Proxy has two sections.

**Proxy** sends Toner's connections through an HTTP (CONNECT), SOCKS5 or SOCKS4 proxy, with an optional user name and password
and a "do not use it for" list (names, `*.corp.example.com`, addresses, networks). Choose no proxy, the Windows proxy settings
(web connections only), or one you enter; a **Test** button tries it. Any device can override it on its Access tab. SSH, the
vendor APIs, status pages, web / port / certificate checks and notifications use it; SNMP, ping, traceroute, the listeners and the
file servers use UDP or ICMP or listen for connections, so they never do.

**SSH Tunnel** does what PuTTY's Dynamic port forwarding (`ssh -D`) does, with no PuTTY needed: Toner signs in to an SSH server
and opens a SOCKS5 port on this computer (**Local SOCKS Port**, 1080 by default). Point the proxy at it (SOCKS5, `127.0.0.1`,
port 1080; **Use it for the proxy above** fills that in), or only the devices that need it. Use the same server, user name and
password as with PuTTY. When the server asks for a Duo option (type `1` for a push, then approve it), a one-time code or a
YubiKey touch, a box appears; the saved password answers its "Password:" question. It can also sign in with a **key file**
(OpenSSH or PEM: RSA, ECDSA, Ed25519); the Password box is then the key's passphrase, and Toner asks for it when the key is
protected and none is saved (a PuTTY `.ppk` key must be exported to OpenSSH format in PuTTYgen first). **Connect** and
**Disconnect** open and close it, **Connect when Toner starts** opens it at start, and a connection through its port while it
is closed signs in first. The status strip shows it as connected or disconnected; click it when it is disconnected to sign in.
Like PuTTY's, the port is on this computer only and asks for no sign-in of its own. Each sign-in is written step by step to
`ssh-tunnel.log` next to Toner's data (the algorithms agreed, the methods the server offered, the questions it asked; never a
password, passphrase or code), and a failed sign-in says where it stopped. A tunnel signed in with a Duo push or a YubiKey
cannot sign in again by itself, so checks that run by themselves use it while it is open.

For a proxy with two-step sign-in, set **One-time code**: Toner adds the current code to the end of the password (or sends it alone
when there is no password). **Ask me for it when connecting** shows a box for the code; **Make it from a secret key** works the
code out itself from the authenticator's secret key (kept in Credential Manager), which is what checks that run by themselves
need. When a proxy answers in a way Toner does not understand, the error says what it sent (for example an SSH banner or a sign-in
method Toner cannot do) instead of "invalid response".

### Wi-Fi and cloud status pages

- **Wi-Fi**: Tools > Wi-Fi Scanner lists the networks this computer can hear (signal, channel, band, security, maker) and suggests the
  quietest 2.4 GHz channel (Windows needs Location access on). Add "This PC's Wi-Fi" (host `localhost`) to check a laptop's connection,
  signal and link speed on every run.
- **Cloud status**: add a "Cloud status page" device (GitHub, Cloudflare, Zoom, Meraki, Duo, Discord and any other Atlassian
  Statuspage) for its overall status, affected components and open incidents. Microsoft 365 is not included: its health is only
  available through an authenticated Microsoft Graph app.

## Tools in detail

### OpenSSL

Tools > Certificates works without installing anything. *Create* makes a private key (RSA 2048/3072/4096, ECDSA P-256/P-384,
Ed25519), a CSR with alternative names, or a self-signed or CA certificate. *Read* describes any certificate, request, key, DER
file or .pfx, says whether a key belongs to a certificate, and can fetch what a server presents. *Convert* goes between PEM, DER and
.pfx and adds or removes a passphrase. *Hash and random* does digests, base64 and random bytes. *openssl.exe* runs the real
program if the computer has one (Git for Windows includes it). Toner stores none of the keys or results.

### File servers (TFTP and SFTP)

Each serves one folder you choose, nothing outside it, and is off until you start it. Read-only until you tick "Allow uploads";
replacing or deleting needs a second tick; you can limit them to named devices; they stop after a time you set. Every transfer is
listed, and starts, stops, uploads, deletions, refusals and logins go to the audit log. TFTP has no passwords by design, so name
the devices in "Allowed clients" whenever uploads are on. SFTP needs a user name and password (in Credential Manager), has no
shell, shows its fingerprint and locks an address out for five minutes after five wrong passwords. Whole drives and system folders
are refused.

### SCP and xcopy

Tools > File transfer. **SCP** copies files and folders to or from a device over SSH using its saved login, jump host and proxy
(the device must allow it; Cisco IOS: `ip scp server enable` and a privilege-15 user). Names a device sends are checked so nothing
is written outside your folder, and Stop leaves no half-written files. **xcopy** runs Windows xcopy between this computer and a
network share, for example to move what the TFTP and SFTP servers received. Preview shows what would be copied, and overwriting
asks first.

### iperf3

Run, not bundled: download iperf3 for Windows (iperf.fr) and choose `iperf3.exe` on the page, or put it on your PATH. Test against
another iperf3 server (TCP or UDP, upload or download, several streams) or act as the server; it shows sent and received rates and
retransmits with a live graph.

## Automation (Ansible)

Ansible does not run on Windows, so Toner runs it somewhere that does and shows you the result. Choose where in **Settings > Ansible**:

- **This PC, through WSL.** Needs WSL with a Linux distribution that has Ansible (`wsl --install -d Ubuntu`, then
  `sudo apt install ansible` inside it). Toner never installs anything for you; **Test** says what is missing.
- **A Linux server, over SSH.** Use an Inventory device as the server (its address, SSH port, user and saved password), or type the
  address, user, key file and password (the password goes to Credential Manager). Toner copies the playbook folder to a private
  temporary folder on the server, runs it and removes the folder.

**Playbooks** are ordinary `.yml` files in a folder you can change (default: a `ansible\playbooks` folder in Toner's data folder; point
it at a Git checkout if you like). **Tools > Playbook Editor** lists them, makes new ones from templates (ping, show commands on Cisco IOS,
restart a Windows service, install Windows updates, set NTP on Cisco IOS), highlights YAML, checks it as you type, and can run Ansible's own
`--syntax-check`.

**The inventory is made for you** from Toner's Inventory: every device with its address and connection settings for its kind
(network devices over `network_cli`, Windows over WinRM, Fortinet and Palo Alto through their APIs), plus groups for each vendor, folder
(`folder_Acme_Branch`), location and tag (`tag_core`). Add your own variables as custom fields named `ansible_...`. Passwords and tokens
are never in the inventory or any playbook: they go in a second file that exists only for the run and is deleted afterwards.

**Running.** Automation > Playbooks starts in **check mode** (`--check --diff`: shows what would change, changes nothing). Turn it off for
a real run, which asks first and names the playbook and the devices. You can add tags and variables (`ntp=10.0.0.1`), raise verbosity, and
stop a run. Every check and run is kept (newest 200 by default) under Automation > Run history, with its output and totals, and in the
audit log.

## Without the window

    python cli.py run --group "Tag: core" --json --fail-on warn     checks; exit code 1 if anything is WARN or worse
    python cli.py backup                                            back up configurations
    python cli.py status                                            the latest stored results
    python cli.py service --metrics-port 9108                       keep running scheduled checks, backups and alerts
    python cli.py metrics --port 9108                               Prometheus /metrics from the stored results

`service` uses the schedules from Settings > Checks > Schedule and Config backups, so it can run from Task Scheduler or any service
wrapper. **Settings > General > Keep running in the system tray** does the same while the window is closed. The installed program
does it without Python: `Toner.exe cli service`, `Toner.exe cli run --json` (output goes to the console, or to `toner-service.log`
in the data folder when there is none). The service also runs the agent receiver when it is on, makes the scheduled trend report and
watches the agent certificate. It uses the data folder and Credential Manager of the account it runs as, so run it as the account you
set Toner up with.

## Updates and About

**Check for updates** looks at the newest GitHub release (daily if "Check for updates automatically" is ticked, or when you press the
button). A newer version puts a dot next to About with its release notes and **Download and install**, **View release** and **Skip
this version**. The installer comes from GitHub over HTTPS only, its SHA-256 is compared with the one GitHub published, and only
then is it run (a mismatch, or a release with no checksum, is never run). Your inventory, history and saved passwords are kept.
**Install updates automatically** installs a verified update when you close Toner. Copies run from source or unzipped can check but
not install.

**Earlier versions.** The installers of the 3 newest versions stay in the `updates` folder of Toner's data (older ones are deleted
when an update starts and when Toner starts), and About > **Earlier versions** has a **Revert to** button for each one older than
the running version. The installer is checked again first: against the checksum recorded when it was downloaded or, for one
downloaded before 1.5.12, against the one its GitHub release publishes (if GitHub cannot be reached, it is not run). Toner then
closes, installs that version over the same copy (a portable copy stays portable) and opens again. The version you left is
skipped, so automatic updating does not put it straight back; newer versions are still offered.

Toner's web requests (updates, notifications, status pages, vendor APIs that check certificates) trust the public certificate
authorities Toner carries **and** the ones in the Windows certificate store. So on a network that inspects HTTPS (a firewall with
SSL inspection, or antivirus that scans HTTPS), Toner works once the inspecting certificate is trusted by Windows, as a browser
does. A certificate error during an update says so and points to the release page.

## Build and test

    python tests/run_all.py            every test file, one line each
    python tests/test_custom.py        a single file

The tests use fakes (simulated devices and APIs, a local SNMP agent, local TLS and SSH servers) and a throw-away database, so they
never touch your inventory or credentials.

    powershell -File packaging\build.ps1

builds the program folder with PyInstaller, then `build\installer\Toner-Setup-<version>.exe` with
[Inno Setup 6](https://jrsoftware.org/isinfo.php) (`winget install JRSoftware.InnoSetup`). The installer needs no administrator
rights and leaves your data and saved passwords alone on uninstall or upgrade. `Toner.exe --minimized` starts in the tray.
To publish: raise `VERSION` in `core\version.py`, build, then create a GitHub release tagged `v<version>` with
`Toner-Setup-<version>.exe` attached (GitHub adds the checksum).
