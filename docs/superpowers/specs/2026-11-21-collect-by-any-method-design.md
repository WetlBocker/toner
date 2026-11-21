# Collecting a check by any available method: design

**Status:** draft for the owner's approval (2026-11-21). No code is written from this until it is approved, including the wording in section 6.

**Request (owner, 2026-11-21):** "Uptime data and any data for that matter should be able to be collected from any available method, SSH, SNMP, or API."

**Owner decisions so far (2026-11-21):** start with the full SNMP set; the vendor's main method first, the others fill gaps; show where a value came from; SSH as a second method for Fortinet and Palo Alto first; the five vendors that already have SNMP fill-in stay as they are; Storage and Interface errors are on as soon as SNMP is set up; the wording says "via", not "from" or "by". Still open: section 7.

**Basis:** a read of the code on `main` at `8af095b`. Line numbers are that commit's.

## 1. How it works today

- **One method per vendor.** `drivers/__init__.py:31-35` maps each vendor to one driver, and that driver uses one method for its checks: SSH (Cisco, Juniper, Arista, HPE, MikroTik, Dell, Extreme), the vendor's API (Fortinet, Palo Alto, Meraki, Proxmox, TrueNAS, OPNsense, ISE, FMC, SD-WAN, vCenter, SonicWall, Mist, UniFi), or SNMP (generic SNMP, ESXi, Sophos).
- **A device can already hold three sets of credentials:** its main secret (API key or password), a separate SSH login for the vendors in `vendors.CLI_TYPES` (`core/vendors.py:152`), and SNMP settings once "This device also answers SNMP" is ticked (`ui/inventory.py:173`). For Fortinet and Palo Alto the SSH login is used only by Command Runner and config backups.
- **SNMP already fills gaps for five vendors.** `core/runner.py:87-105` (`snmp_extras`) runs for ISE, FMC, SD-WAN, vCenter and SonicWall (`vendors.SNMP_EXTRAS`) when SNMP is set up. It adds CPU, memory, storage, uptime, interfaces and interface errors by SNMP for any of those names the API did not produce, honours the tick boxes, and turns an SNMP failure into one `snmp` ERROR row.
- **It only fills what is absent.** A check the main method attempted and failed stays an ERROR row; SNMP is not tried for it.
- **Uptime parsers exist:** `sshbase.uptime_hours` reads the FortiGate CLI line "31 days,  4 hours,  0 minutes" as 748 hours; `drivers/snmpdev.py:125-132` reads `sysUpTime`.

## 2. What changes

**A. SNMP fills gaps on every vendor that has a login.** The existing mechanism applies to any device with SNMP set up, not five vendors.

**B. A gap is a subject, not a name.** Fortinet and Palo Alto report CPU and memory in one check, `resources`; SNMP's are `cpu` and `memory`. So that SNMP does not repeat what the main method already gave:

| Subject | Main-method checks that cover it |
|---|---|
| CPU | `cpu`, `resources` |
| Memory | `memory`, `resources` |
| Uptime | `uptime` |
| Interfaces | `interfaces` |
| Interface errors | `interface errors`, and `interfaces` where the vendor's check includes error counters (Cisco) |
| Storage | none (always SNMP's own) |

**C. A failed check is a gap too.** When the main method's row for a subject is an ERROR, or the main method could not sign in at all, the next method supplies that subject and the row says why (section 6). The main method's sign-in failure keeps its own ERROR row, as today.

**D. SSH as a second method for Fortinet and Palo Alto,** with the SSH login already stored on the device. It is tried only for subjects still missing after the API and SNMP, because an SSH login is slow.
- Fortinet: `get system performance status` gives CPU, memory and uptime (the owner's sample of 2026-11-21 is the test fixture); `get system status` gives the firmware version.
- Palo Alto: `show system info` (uptime, version) and `show system resources` (CPU, memory). Not built until the parser can be written from the owner's real output (section 7).

**E. Order:** the vendor's main method, then SNMP, then SSH. No per-device choice of preferred method.

**F. Every filled row says its source** (section 6). Rows from the main method are unchanged.

## 3. What does not change

- Checks only the main method can give (HA, VPN, licences, BGP and so on) stay with it. "Any data" by SSH for those is later work, one vendor and one command at a time.
- SSH-first vendors do not gain an API method in this change.
- Tick boxes keep their meaning: a check's own tick decides whether it runs, whichever method ends up supplying it.

## 4. Where the code changes

- `core/runner.py`: `snmp_extras` becomes the general gap filler (subjects from the table above; errors count as gaps; each filled row tagged with its source); a new SSH filler for the two vendors.
- `core/vendors.py`: `SNMP_EXTRAS` goes; the rule is "has a login and SNMP is set up".
- `core/checks.py`: the two SNMP-only subjects (storage, interface errors) are listed for every vendor with a login, with the labels the five vendors already have (reworded per section 6).
- New `drivers/fortinet_cli.py` and `drivers/paloalto_cli.py`: the parsers, each a pure function over text.
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
- A row filled because the main method failed: "via SNMP; the API check failed: {reason}" (or "via SSH; ..."). Depends on decision 2 in section 7.
- Settings > Checks: the six labels in `checks.SNMP_EXTRA` change from "(by SNMP)" to "(via SNMP)", for the five vendors that show them today as well, since the list is shared: "CPU (via SNMP, when set up)", "Memory (via SNMP)", "Disk and storage (via SNMP)", "Uptime and recent reboots (via SNMP)", "Interface status (via SNMP)", "Interface errors (via SNMP)". Only the labels change; the check names and their history do not. To be confirmed by the owner (decision 3).

## 7. Decided, and still open

Decided (owner, 2026-11-21):

- **The five vendors that already have SNMP fill-in** (ISE, FMC, SD-WAN, vCenter, SonicWall) keep exactly the rows they have today. The subject rule applies to the vendors gaining fill-in.
- **Storage and Interface errors via SNMP** are on as soon as SNMP is set up, on every vendor with a login. Devices that already have SNMP ticked gain two rows after the update, and Interface errors can raise new warnings; the release notes say so.

Still open:

1. **Palo Alto's CLI output.** The owner's session log `2026-11-21_021656_PaloVM.log` is sealed with the data key and cannot be read outside Toner. A readable copy (Tools > Logs > "Save a readable copy...") or the pasted output of `show system info` and `show system resources` is needed before its parser is written.
2. **A failed row replaced by a filled one.** Example: the FortiGate's API uptime call fails with "HTTP 403" and SNMP has the uptime. Either (a) one row, `uptime  OK  31:04:24:20  via SNMP; the API check failed: HTTP 403`, so the value is there and the API fault is in the message but raises no alert; or (b) two rows, the API's ERROR row as today plus the OK row "via SNMP", so the fault still alerts every run although the value is known. Recommended: (a).
3. **The label change above** reaches the five existing vendors' Settings > Checks labels. Other sentences that say "by SNMP" (the WAN interface hint, the README) are not part of this change unless the owner asks.
