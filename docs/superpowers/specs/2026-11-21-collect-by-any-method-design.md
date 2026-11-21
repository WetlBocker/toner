# Collecting a check by any available method: design

**Status:** every decision in section 7 is settled by the owner (2026-11-21). The build plan is `docs/superpowers/plans/2026-11-21-collect-by-any-method.md`; the owner approved the plan, the wording and the rulings in section 8 on 2026-11-21.

**Request (owner, 2026-11-21):** "Uptime data and any data for that matter should be able to be collected from any available method, SSH, SNMP, or API."

**Owner decisions so far (2026-11-21):** start with the full SNMP set; the vendor's main method first, the others fill gaps; show where a value came from; SSH as a second method for Fortinet and Palo Alto first; the five vendors that already have SNMP fill-in stay as they are; Storage and Interface errors are on as soon as SNMP is set up; the wording says "via", not "from" or "by"; a failed row is replaced by the filled one, which carries the reason; all six Settings > Checks labels change to "via SNMP".

**Basis:** a read of the code on `main` at `8af095b`. Line numbers are that commit's.

## 1. How it works today

- **One method per vendor.** `drivers/__init__.py:31-35` maps each vendor to one driver, and that driver uses one method for its checks: SSH (Cisco, Juniper, Arista, HPE, MikroTik, Dell, Extreme), the vendor's API (Fortinet, Palo Alto, Meraki, Proxmox, TrueNAS, OPNsense, ISE, FMC, SD-WAN, vCenter, SonicWall, Mist, UniFi), or SNMP (generic SNMP, ESXi, Sophos).
- **A device can already hold three sets of credentials:** its main secret (API key or password), a separate SSH login for the vendors in `vendors.CLI_TYPES` (`core/vendors.py:152`), and SNMP settings once "This device also answers SNMP" is ticked (`ui/inventory.py:173`). For Fortinet and Palo Alto the SSH login is used only by Command Runner and config backups.
- **SNMP already fills gaps for five vendors.** `core/runner.py:87-105` (`snmp_extras`) runs for ISE, FMC, SD-WAN, vCenter and SonicWall (`vendors.SNMP_EXTRAS`) when SNMP is set up. It adds CPU, memory, storage, uptime, interfaces and interface errors by SNMP for any of those names the API did not produce, honours the tick boxes, and turns an SNMP failure into one `snmp` ERROR row.
- **It only fills what is absent.** A check the main method attempted and failed stays an ERROR row; SNMP is not tried for it.
- **Uptime parsers exist:** `sshbase.uptime_hours` reads the FortiGate CLI line "31 days,  4 hours,  0 minutes" as 748 hours; `drivers/snmpdev.py:125-132` reads `sysUpTime`.

## 2. What changes

**A. SNMP fills gaps on every vendor that has a login.** The existing mechanism applies to any device with SNMP set up, not five vendors (which vendors exactly: section 8).

**B. A gap is a subject, not a name.** Fortinet and Palo Alto report CPU and memory in one check, `resources`; SNMP's are `cpu` and `memory`. So that SNMP does not repeat what the main method already gave:

| Subject | Main-method checks that cover it |
|---|---|
| CPU | `cpu`, `resources` |
| Memory | `memory`, `resources` |
| Uptime | `uptime` |
| Interfaces | `interfaces` |
| Interface errors | `interface errors`, and `interfaces` where the vendor's check includes error counters (Cisco) |
| Storage | `storage` where the vendor has its own (Juniper, Proxmox); otherwise none, and it is SNMP's own |

**C. A failed check is a gap too.** When the main method's row for a subject is an ERROR, or the main method could not sign in at all, the next method supplies that subject and the row says why (section 6). The main method's sign-in failure keeps its own ERROR row, as today.

**D. SSH as a second method for Fortinet and Palo Alto,** with the SSH login already stored on the device. It is tried only for subjects still missing after the API and SNMP, because an SSH login is slow.
- Fortinet: `get system performance status` gives CPU, memory and uptime (the owner's sample of 2026-11-21 is the test fixture). The firmware version over SSH waits for a real `get system status` sample.
- Palo Alto: `show system info` (uptime, version) and `show system resources` (CPU, memory). The owner's session of 2026-11-21 (PA-VM, PAN-OS 11.1.4) shows the same text the API returns, so the API's existing parsing serves both.

**E. Order:** the vendor's main method, then SNMP, then SSH. No per-device choice of preferred method.

**F. Every filled row says its source** (section 6). Rows from the main method are unchanged.

## 3. What does not change

- Checks only the main method can give (HA, VPN, licences, BGP and so on) stay with it. "Any data" by SSH for those is later work, one vendor and one command at a time.
- SSH-first vendors do not gain an API method in this change.
- Tick boxes keep their meaning: a check's own tick decides whether it runs, whichever method ends up supplying it.

## 4. Where the code changes

- `core/runner.py`: `snmp_extras` becomes the general gap filler (subjects from the table above; errors count as gaps; each filled row tagged with its source); a new SSH filler for the two vendors.
- `core/vendors.py`: `SNMP_EXTRAS` stays for the five vendors, whose code path is untouched; a new rule says which other vendors gain fill-in (section 8).
- `core/checks.py`: which tick box governs each subject per vendor; the subjects a vendor has no check of its own for are listed with the labels the five vendors already have (reworded per section 6).
- The parsers are pure functions over text, beside each vendor's driver (`drivers/fortinet.py`, `drivers/paloalto.py`); Palo Alto's are the API's existing ones, lifted out.
- `core/netconn.py`: a FortiGate login for checks that changes nothing on the firewall (section 8).
- Grading for uptime is written out in a dozen drivers today; the fillers reuse one helper rather than adding a thirteenth copy. The existing copies are left alone.

## 5. Tests

- A fake API, a fake SNMP agent and fake SSH output per case; no real device.
- Per subject: main gives it (nothing filled); main lacks it (SNMP fills, tagged); main errors (SNMP fills, tagged with the reason); SNMP lacks it too (SSH fills, tagged); nothing has it (no row, no error).
- Fortinet's `resources` suppresses SNMP's `cpu` and `memory`; unticking `resources` suppresses them from every method.
- The owner's FortiGate CLI sample parses to CPU 0%, memory 58.1%, uptime 31 days 4 hours.
- The five vendors that have SNMP fill-in today produce the same rows as before.
- An SSH login is not attempted when nothing is missing.

## 6. Wording to approve

The owner's rule (2026-11-21): "via", not "from" or "by".

- A row filled by another method, in its message: "via SNMP" or "via SSH". Where the row also has a message of its own: "recent reboot, via SNMP".
- A row filled because the main method failed: "via SNMP; the API check failed: {reason}" (or "via SSH; ...").
- Settings > Checks: the six labels in `checks.SNMP_EXTRA` change from "(by SNMP)" to "(via SNMP)", for the five vendors that show them today as well, since the list is shared: "CPU (via SNMP, when set up)", "Memory (via SNMP)", "Disk and storage (via SNMP)", "Uptime and recent reboots (via SNMP)", "Interface status (via SNMP)", "Interface errors (via SNMP)". Only the labels change; the check names and their history do not.

Found while planning, approved by the owner 2026-11-21:

- For a vendor whose main method is SSH (Cisco, Juniper and the other switches): "via SNMP; the SSH check failed: {reason}".
- When the SSH fill-in cannot sign in or run, one row named `ssh`: "SSH: {reason}", as today's `snmp` row says "SNMP: {reason}".

## 7. Decided (owner, 2026-11-21)

- **The five vendors that already have SNMP fill-in** (ISE, FMC, SD-WAN, vCenter, SonicWall) keep exactly the rows they have today. The subject rule applies to the vendors gaining fill-in.
- **Storage and Interface errors via SNMP** are on as soon as SNMP is set up. Devices that already have SNMP ticked gain rows after the update, and Interface errors can raise new warnings; the release notes say so.
- **A failed row is replaced by the filled one,** which carries the reason: `uptime  OK  31:04:24:20  via SNMP; the API check failed: HTTP 403`. The fault is in the message and raises no alert. A sign-in the device refuses keeps its own ERROR row.
- **All six labels** change to "via SNMP". Other sentences that say "by SNMP" (the WAN interface hint, the README) are not part of this change.
- **Palo Alto's parser** is built from the owner's readable session log of 2026-11-21.

## 8. Rulings made while planning (approved by the owner 2026-11-21)

1. **Who gains fill-in:** vendors reached by SSH or by an API on the device itself. Not the three whose address is the vendor's cloud (Meraki, Mist, UniFi Site Manager), and not Windows computers, status pages or SNMP-only devices.
2. **A device whose management port does not answer is not filled.** It is most likely down, and trying SNMP would add a time-out and a second error row to every down device. A refused sign-in, or any other failed run, is filled.
3. **Checks never change a FortiGate's configuration.** The SSH library's FortiGate login runs `config system console` / `set output standard` / `end` and restores it on exit, which is two configuration changes per run. The login used for checks skips both and sends only commands whose output is one line (`get system performance status | grep Uptime` and the like). The Command Runner and config backups keep their present login.
4. **A FortiGate with VDOMs is not filled over SSH** until one is available to test against.
5. **Interface errors via SNMP never reported a change** in the "since last run" counter mode, on the five existing vendors: the counters were not kept between runs. Fixed as part of this work, since the check is now on for every vendor; found by reading the code, to be proven by a failing test first.
6. **The owner's FortiGate has not been asked the three `| grep` commands.** One run of each in the Command Runner before release confirms they print one line each.
