# Checking Toner against your own equipment

Toner's tests run against sample output and local stand-ins, not real network gear, a real domain or a real WinRM server. This
checklist is a quick way to confirm each part works on **your** equipment before you rely on it. Run it on a few devices of each
kind; it takes about ten minutes per kind.

Nothing here changes a device: Toner only reads. Where a step asks you to change something (stop a service, add a test
administrator), do it on a lab machine.

## Any device

1. Inventory > Add the device (or Tools > Find Devices). Open it and press **Test connection**. Expect "Connected ... N check results".
2. Overview > **Run checks**. Open the device in Results. Every check should be OK, WARN or FAIL with a sensible value. **ERROR** with
   "unexpected output" means a parser did not recognise something: open Settings > Data and logs, and send the saved raw output
   (it is kept in the diagnostics list and masked) so the parser can be fixed from a real sample.
3. Compare three numbers with the device's own display: CPU, memory, uptime. They should agree to within a few percent.
4. History: run the checks twice, ten minutes apart. The chart should show two points for each numeric check.
5. Make one check fail on purpose (unplug a link, lower a threshold in Settings > Thresholds below the current value). Confirm the
   status changes, the Overview shows it, and a notification arrives on a test channel.

## Network devices (SSH or API)

| Vendor | Confirm |
|---|---|
| Cisco IOS / IOS XE / NX-OS / ASA | CPU, memory, uptime; interface list and error counters; BGP and OSPF neighbour counts match `show ip bgp summary` / `show ip ospf neighbor` |
| Juniper | chassis alarms match `show chassis alarms`; routing-engine CPU and memory |
| Arista | temperature and CPU; BGP and OSPF |
| HPE Aruba (AOS-CX, AOS-S) | CPU, memory, uptime, interface up/down count |
| MikroTik | resource figures match `/system resource print`; RouterOS version |
| Fortinet | CPU, memory, firmware, WAN link states, HA members, IPsec tunnels against the GUI |
| Palo Alto | sessions used against the maximum, HA state, uptime |
| Meraki, UniFi | device status counts agree with the dashboard; firmware update flags |
| Anything else | Generic SNMP: reachability, storage, interface table; try v2c then v3 |

Also check **Configs**: back up the device, change one line, back up again. Toner should show a diff of exactly that line.

## Windows computers

Do each way you plan to use.

**Agent**

1. Settings > Agents: turn on the receiver and sign-up, save, **Download agent package**.
2. On a test PC, unzip and run **Install-TonerAgent.cmd**. Allow the administrator prompt. The PC appears in Inventory within a minute.
3. In Task Scheduler there is a task named **Toner Agent** (SYSTEM, every N minutes). `C:\ProgramData\Toner Agent` is readable only by
   SYSTEM and Administrators.
4. Disconnect the PC from the network for longer than the "agent silent" limits (Settings > Thresholds). Results show the late then silent states.
5. Bump `AGENT_VERSION` in a test build, or wait for a release: the agent should update itself on its next report.
6. Settings > Agents > **Revoke**: the agent is turned away. **Uninstall-TonerAgent.cmd** removes the task and folder.

**WinRM**

1. On the server: `Enable-PSRemoting -Force`, allow TCP 5985 (or 5986 for HTTPS). Use an account in *Remote Management Users* and *Event Log Readers*.
2. Domain: leave the user name empty to sign in as the account Toner runs as, or give `DOMAIN\user`. Not in a domain: `.\user` with a
   password (and, for a local administrator account other than the built-in one, `LocalAccountTokenFilterPolicy`).
3. Press **Test connection**. A refused or rejected sign-in gives a plain-language reason; note it if it does not.

**Both**

- CPU, memory and per-disk figures agree with Task Manager. Stopped automatic services are the ones you expect (Services.msc).
- Add a service name under *Services to require*, stop that service on the test machine: the check goes FAIL.
- **Changes** reports a newly installed program, a user added to Administrators, and a newly listening port (on the check after the first one).
- Event errors match Event Viewer (System and Application, Critical and Error, last 24 hours).
- A certificate in *Local Machine > Personal* that expires within 90 days is listed.

## Notifications, updates, installer

- Settings > Notifications: send a test to each channel you use.
- About > Check for updates, from an older installed version, installs the newest release and reopens Toner. (Not covered by automated tests.)
- Install on a clean Windows PC; run once; uninstall. Data stays in `%APPDATA%\NetCheck` unless you delete it.
- Portable: copy the folder to a USB drive, run on another PC, then **Settings > Data and logs > Export / Import saved passwords** to carry the passwords.

If anything above does not behave, note the device, the vendor/OS version and the check name, and (for parser problems) the saved raw output.
