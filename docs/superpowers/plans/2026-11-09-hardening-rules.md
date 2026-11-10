# New hardening rules, for the owner's approval

Task 6 of the vulnerability sources and hardening plan. Nothing here is built yet. Tasks 7 to 11 wait for your approval or edits.

## How to read this

- Each row is one rule: `(key, label, severity, test)`, as in `core/hardening.py`. The "Finding message" is the exact text a finding shows, with `{x}` filled in from the configuration.
- Every message names the setting to change. Backup rows end `(backup of {date})`, as they do today.
- N/A wording reuses text that already exists, so it needs no new approval:
  - `{what}, the stored backup masks it (Settings > Config backups)` (Cisco's existing masked wording, `hardening.MASKED`)
  - `Does not apply to this platform.` (`hardening.NOT_HERE`)
  - `Toner could not read this setting on this computer.` (`hardening.UNREAD_SETTING`, already approved)
- A setting that is missing from a backup reads as the vendor's default. The "Reads" column gives that default where it matters.
- Password length is 15 for network devices and 14 for Windows, the STIG figures.
- Rules are written in Toner's own words. Nothing is copied from a STIG or a vendor guide, and no CIS Benchmark content was used.

## Sources

| Group | Source | How far it was confirmed |
|---|---|---|
| FortiGate | DISA Fortinet FortiGate Firewall NDM STIG V1R4 (FGFW-ND ids); Fortinet's Best Practices guide | Ids and check settings read on cyber.trackr.live and Tenable's audit of the STIG |
| Palo Alto | DISA Palo Alto Networks NDM STIG V3R4 (PANW-NM ids) | Read on cyber.trackr.live |
| Juniper | DISA Juniper SRX Services Gateway NDM STIG (JUSX-DM ids) | Ids from Tenable's V3R3 audit (first 50 of 68 items). Config statements from the older V1R3 text. The STIG is written for SRX; the same statements apply to all Junos |
| Arista | DISA Arista MLS EOS 4.X NDM STIG V2R2 (ARST-ND ids) | Read on cyber.trackr.live |
| HPE | No STIG for AOS-CX or ArubaOS-Switch. DISA's "HPE Aruba Networking AOS NDM" STIG reads as the wireless and gateway line, so it is not used. Vendor guides instead: AOS-CX 10.x Hardening Guide, ArubaOS-Switch 16.x Hardening Guide | Commands read through summaries of those guides (Tenable, G5 Cyber Security), not the guides themselves |
| MikroTik | No STIG. MikroTik's "Securing your router" (RouterOS 7.25 manual) | Read directly |
| Windows | DISA Windows Server 2022 STIG V2R9 (WN22 ids); Microsoft's security baselines; Microsoft Learn | Ids read on stigaview.com. V2R9 is archived there, so a newer release may exist. Audit GUIDs read from `auditpol /list` on a Windows machine |

stigviewer.com refused automated requests, so the STIG text came from the mirrors above.

"General practice" in a Source column means no STIG or vendor id could be confirmed for that rule. It does not mean the rule is weak.

## FortiGate (11 new rules)

Reads `show full-configuration`, or the API export, which can leave out defaults. `core/hardening_fortinet.py`'s parser already reads a missing line as the default.

| Key | Label | Severity | Finding message | Reads | Source |
|---|---|---|---|---|---|
| `fg lockout` | Admin lockout too short | WARN | `admin-lockout-threshold {t}, admin-lockout-duration {d}: set them to 3 and 900 under config system global` | `system global`: `admin-lockout-threshold` (default 3), `admin-lockout-duration` (default 60). Finding when threshold is over 3 or duration is under 900 | FGFW-ND-000045 |
| `fg password length` | Admin password minimum under 15 | WARN | `minimum-length {n}: set minimum-length 15 under config system password-policy` | `system password-policy`: `minimum-length` (default 8) | FGFW-ND-000220 |
| `fg password complexity` | Password character rules off | WARN | `{settings} 0: set min-upper-case-letter, min-lower-case-letter, min-number and min-non-alphanumeric to 1 under config system password-policy` | `system password-policy`: those four (default 0) | FGFW-ND-000225 to 000240 |
| `fg banner` | No pre-login banner | WARN | `pre-login-banner is not enabled: set pre-login-banner enable under config system global` | `system global`: `pre-login-banner` (default disable) | FGFW-ND-000050 |
| `fg snmp public` | SNMP community public or private | FAIL | `community {name}: rename it under config system snmp community` | `system snmp community`: each entry's `set name`, where `status` is not disable. Not masked in stored backups | FGFW-ND-000200 (non-secure services); general practice |
| `fg snmp v3` | SNMPv3 user without authentication | WARN | `user {name}: security-level {v}: set security-level auth-priv under config system snmp user` | `system snmp user`: `security-level` (default no-auth-no-priv). Finding on no-auth-no-priv | FGFW-ND-000210 |
| `fg ntp auth` | NTP servers without authentication | WARN | `{n} of {m} NTP servers without authentication: set authentication enable under config ntpserver` | `system ntp` with `type custom`: `ntpserver` entries. Passes on FortiGuard NTP | FGFW-ND-000215 |
| `fg ntp servers` | Only one NTP server | WARN | `one NTP server: add a second under config system ntp, config ntpserver` | `system ntp` with `type custom`: `ntpserver` entries | FGFW-ND-000120 |
| `fg event log` | Event logging off | WARN | `{settings} disable: set event, system and user enable under config log eventfilter` | `log eventfilter`: `event`, `system`, `user` (default enable) | FGFW-ND-000010 and related audit rules |
| `fg tls version` | Old TLS on the web UI | WARN | `admin-https-ssl-versions {v}: set admin-https-ssl-versions tlsv1-2 tlsv1-3 under config system global` | `system global`: `admin-https-ssl-versions`. Finding when it lists tlsv1-0 or tlsv1-1 | Fortinet Best Practices (strong ciphers); general practice |
| `fg ldap` | LDAP without TLS | WARN | `{name}: set secure ldaps under config user ldap` | `user ldap`: each entry's `secure` (default disable). Finding unless ldaps or starttls | FGFW-ND-000245 |

Left out: two-factor for admins (`set two-factor`; admins can get it through remote sign-in, which the backup does not show), the maintainer account (Fortinet calls disabling it optional, and it matters only with physical access), SNMP host limits (the parser does not keep hosts per community).

## Palo Alto (10 new rules)

Reads PAN-OS XML. Only set values appear in the XML, so a missing element reads as the default.

| Key | Label | Severity | Finding message | Reads | Source |
|---|---|---|---|---|---|
| `pa idle long` | Idle timeout over 10 minutes | WARN | `idle-timeout {n}: set Idle Timeout to 10 or fewer (Device > Setup > Management > Authentication Settings)` | `deviceconfig/setting/management/idle-timeout` (default 60). 0 is left to the existing "Idle timeout never" rule | PANW-NM-000069 |
| `pa password length` | Password minimum under 15 | WARN | `minimum-length {n}: set Minimum Length to 15 (Device > Setup > Management > Minimum Password Complexity)` | `mgt-config/password-complexity/minimum-length`, when complexity is enabled | PANW-NM-000053 |
| `pa password chars` | Password character rules off | WARN | `{settings} 0: set Minimum Uppercase, Lowercase, Numeric and Special to 1 (Device > Setup > Management > Minimum Password Complexity)` | `mgt-config/password-complexity/`: `minimum-uppercase-letters`, `minimum-lowercase-letters`, `minimum-numeric-letters`, `minimum-special-characters` | PANW-NM-000055 to 000058 |
| `pa banner` | No login banner | WARN | `no login-banner: set Login Banner (Device > Setup > Management > General Settings)` | `deviceconfig/system/login-banner` | PANW-NM-000016 |
| `pa ntp auth` | NTP not authenticated | WARN | `{servers} authentication-type none: set Symmetric Key or Autokey (Device > Setup > Services)` | `deviceconfig/system/ntp-servers/{primary,secondary}-ntp-server/authentication-type` for each server with an address | PANW-NM-000145 |
| `pa ntp second` | Only one NTP server | WARN | `no secondary-ntp-server: set Secondary NTP Server (Device > Setup > Services)` | `deviceconfig/system/ntp-servers/secondary-ntp-server/ntp-server-address` | PANW-NM-000100 |
| `pa config log` | Config logs not forwarded | WARN | `config logs: no syslog server profile: set one (Device > Log Settings > Configuration)` | `log-settings/config//send-syslog/member`. Passes when a Panorama server is set, as `pa log forwarding` does | PANW-NM-000128 |
| `pa snmp trap` | SNMP traps on v2c | WARN | `trap profile {name}: version v2c: set Version to V3 (Device > Server Profiles > SNMP Trap)` | `log-settings/snmptrap/entry/version/v2c` | PANW-NM-000118 |
| `pa ldap ssl` | LDAP without SSL | WARN | `LDAP profile {name}: ssl no: tick Require SSL/TLS (Device > Server Profiles > LDAP)` | `server-profile/ldap/entry/ssl`. Finding only on an explicit no | PANW-NM-000051 |
| `pa syslog udp` | Syslog over UDP | WARN | `syslog profile {name}: transport UDP: set Transport to SSL (Device > Server Profiles > Syslog)` | `log-settings/syslog/entry/server/entry/transport` (default UDP) | General practice, matching `fg syslog` |

Left out: a local-admin count (noisy on small sites), UTC time zone (a choice), the high data-plane load log (minor), admin access on an untrust zone (the zone name is a guess).

## Juniper (14 rules)

Reads `show configuration | no-more`, a brace hierarchy. Two points for the parser, not the wording:

- Settings can sit in `groups { }` and arrive through `apply-groups`. `show configuration` does not merge them, so rules must read applied groups too, or a device configured that way gets false findings.
- Lines prefixed `inactive:` do not count.

| Key | Label | Severity | Finding message | Reads | Source |
|---|---|---|---|---|---|
| `jn telnet http` | Telnet or HTTP management on | FAIL | `{found}: delete system services {found}` | `system services`: `telnet`, `web-management http` | JUSX-DM-000109; JUSX-DM-000167 (J-Web, Toner checks plain HTTP only) |
| `jn services` | Legacy services on | WARN | `{found}: delete system services {found}` | `system services`: `ftp`, `finger`, `rlogin`, `rsh`, `xnm-clear-text` | JUSX-DM-000108, 000109 |
| `jn ssh root` | Root login over SSH allowed | WARN | `root-login deny is not set: set system services ssh root-login deny` | `system services ssh root-login`. Missing reads as allowed | JUSX-DM-000112 |
| `jn lockout` | No lockout after failed logins | WARN | `retry-options lockout-period is not set: set system login retry-options lockout-period 15` | `system login retry-options` | JUSX-DM-000030 |
| `jn idle timeout` | Login class without idle timeout | WARN | `class {name}: idle-timeout {v}: set system login class {name} idle-timeout 10` | `system login class`: `idle-timeout`. Finding when no class sets one, or one is over 10 | JUSX-DM-000025 |
| `jn password length` | Password minimum under 15 | WARN | `minimum-length {n}: set system login password minimum-length 15` | `system login password minimum-length` (default 6) | JUSX-DM-000128 |
| `jn banner` | No login banner | WARN | `no login message: set system login message` | `system login message` | JUSX-DM-000032 |
| `jn snmp community` | SNMP community public or private, or read-write | FAIL | `community {name}: {problem}: rename it and set authorization read-only under snmp community` | `snmp community`: names and `authorization`. A masked name still reads `authorization`; the name part says `whether it is public or private cannot be told, the stored backup masks it (Settings > Config backups)` | JUSX-DM-000111 |
| `jn snmp clients` | SNMP community without clients | WARN | `{n} of {m} communities without clients: set snmp community {name} clients` | `snmp community`: `clients` or `client-list-name` | General practice |
| `jn snmp v2c` | SNMP version 1 or 2c in use | WARN | `{n} communities (version 1 or 2c); {m} SNMPv3 users: move to snmp v3` | `snmp community`; `snmp v3 usm` | JUSX-DM-000109, 000111 |
| `jn syslog` | No logging host | WARN | `no syslog host: set system syslog host` | `system syslog host` | JUSX-DM-000038 (seen in V1R3, not confirmed in V3R3) |
| `jn ntp` | No NTP server | WARN | `no ntp server: set system ntp server` | `system ntp server` | JUSX-DM-000094 |
| `jn ntp auth` | NTP not authenticated | WARN | `{what} not set: set system ntp authentication-key and trusted-key` | `system ntp`: `authentication-key`, `trusted-key`, when a server is set | General practice |
| `jn lo0 filter` | No filter on lo0 | WARN | `lo0 unit 0: no family inet filter input: set interfaces lo0 unit 0 family inet filter input` | `interfaces lo0 unit 0 family inet filter input` | JUSX-DM-000084 |

Left out: `root-password` strength (masked), `ssh protocol-version v1` (gone from current Junos), session limits and rollback count (minor), one local account of last resort (noisy on small sites).

## Arista (14 rules)

Reads `show running-config`, which prints non-default values only.

| Key | Label | Severity | Finding message | Reads | Source |
|---|---|---|---|---|---|
| `ar telnet` | Telnet on | FAIL | `management telnet is on: set shutdown under management telnet` | `management telnet` block with `no shutdown` (off by default) | ARST-ND-000340 |
| `ar http api` | eAPI over plain HTTP | FAIL | `eAPI over HTTP: remove protocol http under management api http-commands` | `management api http-commands` with `no shutdown` and `protocol http`. HTTPS eAPI is left alone, because automation uses it | ARST-ND-000340 (Toner checks plain HTTP only) |
| `ar snmp community` | SNMP community public, private or read-write | FAIL | `{line}: change the community and use ro (snmp-server community)` | `snmp-server community` lines. Masked: `{n} communities; whether one is public, private or read-write cannot be told, the stored backup masks it (Settings > Config backups)` | General practice, matching Cisco's rule |
| `ar snmp v2c` | SNMP version 1 or 2c in use | WARN | `{n} communities (version 1 or 2c); {m} SNMPv3 users: remove snmp-server community and use snmp-server user v3` | `snmp-server community`; `snmp-server user` with `v3` | ARST-ND-000660 |
| `ar snmp acl` | SNMP community without an access list | WARN | `{n} of {m} without an access list: add one to snmp-server community` | `snmp-server community` lines. Masked: N/A with Cisco's wording | General practice, matching Cisco's rule |
| `ar ssh acl` | SSH without an access list | WARN | `no ip access-group under management ssh: add one` | `management ssh` block, or a `vrf` block inside it: `ip access-group` | ARST-ND-000110 |
| `ar idle timeout` | No idle timeout | WARN | `management {console or ssh}: idle-timeout {v}: set idle-timeout 10` | `management console` and `management ssh`: `idle-timeout`. Missing or over 10 is a finding | ARST-ND-000490 |
| `ar lockout` | No lockout after failed logins | WARN | `aaa authentication policy lockout is not set: set aaa authentication policy lockout failure 3 duration 900` | `aaa authentication policy lockout` | ARST-ND-000120 |
| `ar password length` | Password minimum under 15 | WARN | `password minimum length {n}: set password minimum length 15 under management security` | `management security`: `password minimum length` | ARST-ND-000380 |
| `ar banner` | No login banner | WARN | `no banner login or banner motd: set one` | `banner login`, `banner motd` | ARST-ND-000130 |
| `ar logging` | No logging host | WARN | `no logging host: set logging host` | `logging host` | ARST-ND-000850 |
| `ar ntp` | No NTP server | WARN | `no ntp server: set ntp server` | `ntp server` | ARST-ND-000600 |
| `ar ntp auth` | NTP not authenticated | WARN | `ntp authenticate is not set: set ntp authenticate servers and ntp trusted-key` | `ntp authenticate`, when a server is set | ARST-ND-000600 |
| `ar accounting` | No AAA accounting | WARN | `no aaa accounting: set aaa accounting commands all default start-stop logging` | `aaa accounting` | ARST-ND-000150, 000810 |

Left out: the SSH session limit (minor), FIPS restrictions (a compliance choice), DoD PKI (not decidable from text).

## HPE (13 rules)

Reads `show running-config` on `aruba_aoscx` and `aruba_osswitch`, which have different syntax. **This section is the thinnest.** There is no STIG, the commands come from summaries of HPE's guides, and no real backup from either platform was available. Where a platform's form could not be confirmed, the rule says N/A (`Does not apply to this platform.`) on that platform rather than guess.

| Key | Label | Severity | Finding message | Reads | Source |
|---|---|---|---|---|---|
| `hp telnet` | Telnet on | FAIL | `no telnet-server is not set: set no telnet-server` | OS-Switch: `no telnet-server` (on by default). AOS-CX: N/A | ArubaOS-Switch Hardening Guide |
| `hp http` | HTTP management on | FAIL | `no web-management plaintext is not set: set web-management ssl and no web-management plaintext` | OS-Switch: `no web-management plaintext`, or `no web-management`. AOS-CX: N/A | ArubaOS-Switch Hardening Guide |
| `hp snmp community` | SNMP community public or private | FAIL | `{line}: change it (snmp-server community)` | `snmp-server community` lines on both. Masked: N/A with Cisco's wording. The line is fully masked, so operator or manager cannot be read either | Both guides |
| `hp snmp v2c` | SNMP version 1 or 2c in use | WARN | `{n} communities: remove snmp-server community and use SNMPv3 (snmpv3 only on ArubaOS-Switch)` | `snmp-server community`; OS-Switch also `snmpv3 only` | Both guides |
| `hp lockout` | No lockout after failed logins | WARN | `{setting} is not set: set {setting}` | AOS-CX: `aaa authentication limit-login-attempts {n} lockout-time {s}`, N/A when remote AAA is used (it cannot be set then). OS-Switch: `aaa authentication lockout-delay` | Both guides |
| `hp password length` | Password minimum under 15 | WARN | `{setting} {n}: set {setting} 15` | AOS-CX: `aaa authentication minimum-password-length`. OS-Switch: `password minimum-length` | Both guides. 15 matches the other vendors; the guide's example is 12 |
| `hp timeout` | Session timeout over 10 minutes | WARN | `session-timeout {v}: set session-timeout 10` | AOS-CX: `session-timeout` (default 30, 0 is never). OS-Switch: N/A, the setting's form could not be confirmed | AOS-CX Hardening Guide |
| `hp banner` | No login banner | WARN | `no banner motd or banner exec: set one` | `banner motd`, `banner exec` | Both guides |
| `hp logging` | No logging host | WARN | `no logging host: set logging {server}` | `logging` followed by an address | Both guides |
| `hp ntp` | No NTP server | WARN | `no ntp server: set ntp server` | `ntp server`; OS-Switch also `sntp server` | Both guides |
| `hp ntp auth` | NTP not authenticated | WARN | `{what} not set: set ntp authentication and ntp authentication-key` | AOS-CX: both, when a server is set. OS-Switch: N/A | AOS-CX Hardening Guide |
| `hp mgmt acl` | Management not limited by address | WARN | `no ip authorized-manager: add ip authorized-manager lines` | OS-Switch: `ip authorized-manager`. AOS-CX: N/A, the access-list form could not be confirmed | ArubaOS-Switch Hardening Guide |
| `hp accounting` | No AAA accounting | WARN | `no aaa accounting: set aaa accounting` | `aaa accounting` | Both guides |

Left out: DHCP snooping and port security (not on the requested ground), AOS-CX SSH cipher lists (could not be confirmed).

## MikroTik (14 rules)

Reads `/export`. Three points:

- Export prints non-default values only, so a service stays "on" until a line says otherwise.
- Long lines wrap with a trailing backslash, and the parser must join them.
- `/export` leaves users out, so a default-admin rule and any user-level rule cannot be decided from it. SNMP community names are not masked.

| Key | Label | Severity | Finding message | Reads | Source |
|---|---|---|---|---|---|
| `mt telnet http` | Telnet, FTP or HTTP service on | FAIL | `{services} not disabled: /ip service disable {services}` | `/ip service`: `telnet`, `ftp`, `www` | Securing your router |
| `mt api` | API service on in clear | WARN | `api not disabled: /ip service disable api` | `/ip service`: `api` | Securing your router |
| `mt service address` | Management with no source limit | WARN | `{services} without a source address: set address (available-from on RouterOS 7.25 and later) under /ip service` | `/ip service`: `ssh`, `winbox`, `api-ssl`, `www-ssl` that are on: `address=` or `available-from=`. See the doubt below | Securing your router |
| `mt mac server` | MAC access on every interface | WARN | `allowed-interface-list {v}: /tool mac-server set allowed-interface-list=none and /tool mac-server mac-winbox set allowed-interface-list=none` | `/tool mac-server` and `mac-winbox`. Missing or `all` is a finding; a named list such as LAN passes | Securing your router |
| `mt neighbor` | Neighbor discovery on every interface | WARN | `discover-interface-list {v}: /ip neighbor discovery-settings set discover-interface-list=none` | `/ip neighbor discovery-settings`. Missing or `all` is a finding | Securing your router |
| `mt bandwidth` | Bandwidth server on | WARN | `bandwidth-server is on: /tool bandwidth-server set enabled=no` | `/tool bandwidth-server`. On unless `enabled=no` | Securing your router |
| `mt proxy` | Proxy, SOCKS or UPnP on | WARN | `{services} on: set enabled=no under {paths}` | `/ip proxy`, `/ip socks`, `/ip upnp` with `enabled=yes` | Securing your router |
| `mt ssh` | SSH strong crypto off | WARN | `strong-crypto is off: /ip ssh set strong-crypto=yes` | `/ip ssh` | Securing your router |
| `mt firewall` | No input firewall drop rule | WARN | `no drop rule in chain=input: add one under /ip firewall filter` | `/ip firewall filter` with `chain=input` and `action=drop` | Securing your router |
| `mt snmp public` | SNMP community public, or write access | FAIL | `{problem}: rename the community and set write-access=no under /snmp community` | SNMP on (`/snmp set enabled=yes`): a community named public or private, `write-access=yes`, or the default community left untouched | General practice |
| `mt snmp addresses` | SNMP community open to any address | WARN | `{n} of {m} communities on 0.0.0.0/0: set addresses= under /snmp community` | `/snmp community`, when SNMP is on | General practice |
| `mt snmp v2c` | SNMP version 1 or 2c in use | WARN | `{n} communities without security=authorized or private: set security= and authentication-protocol= under /snmp community` | `/snmp community`, when SNMP is on | General practice |
| `mt syslog` | No logging host | WARN | `no remote logging action: add target=remote under /system logging action and use it in /system logging` | `/system logging action` with `target=remote` | General practice |
| `mt ntp` | NTP client off | WARN | `NTP client not enabled: /system ntp client set enabled=yes` | `/system ntp client` | General practice |

Left out: `allow-remote-requests` DNS (needed on most routers doing DNS for a LAN), the default admin and password rules (users are not in `/export`).

## Windows (18 rules)

Windows has more rows than the 8 to 14 aimed for, because the design's starting list names 15 topics. The snapshot needs two things from the collector:

- **Absent is not unreadable.** A registry value that does not exist reads as Windows' default. A value Toner could not read shows N/A, `Toner could not read this setting on this computer.` The collector must report the two differently.
- The `policy` allow-list is exactly: `MinimumPasswordLength`, `PasswordComplexity`, `PasswordHistorySize`, `ClearTextPassword`, `LockoutBadCount`, `LockoutDuration`, `ResetLockoutCount`, `EnableGuestAccount`. It holds no account names (`NewAdministratorName` and `NewGuestName` stay out) and no secrets.

Rows end `(read {date})` if approved below. `HKLM` is implied on every registry path. `Lsa` is short for `SYSTEM\CurrentControlSet\Control\Lsa`.

| Key | Label | Severity | Finding message | Reads | Source |
|---|---|---|---|---|---|
| `win smb1` | SMBv1 on | FAIL | `SMBv1 is on: remove the FS-SMB1 feature, or set LanmanServer\Parameters\SMB1 to 0 and mrxsmb10\Start to 4` | `reg`: `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1`; `SYSTEM\CurrentControlSet\Services\mrxsmb10\Start`. Passes when mrxsmb10 is absent (feature removed), or SMB1 is 0 and Start is 4 | WN22-00-000380 to 000400 |
| `win smb signing` | SMB signing not required | WARN | `RequireSecuritySignature is off on {server, client}: set Microsoft network {server, client}: Digitally sign communications (always) to Enabled` | `reg`: `...\Services\LanManServer\Parameters\RequireSecuritySignature`; `...\Services\LanmanWorkstation\Parameters\RequireSecuritySignature`. Absent reads as off, below build 26100 | WN22-SO-000190, 000160 |
| `win llmnr` | LLMNR on | WARN | `EnableMulticast is not 0: set Turn off multicast name resolution to Enabled (DNS Client policy)` | `reg`: `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast`. Absent reads as on | General practice. Not in the WN22 STIG; not confirmed in Microsoft's baseline |
| `win ntlm` | LAN Manager level below 5 | FAIL | `LmCompatibilityLevel {n}: set Network security: LAN Manager authentication level to Send NTLMv2 response only. Refuse LM & NTLM (5)` | `reg`: `Lsa\LmCompatibilityLevel`. Absent reads as 3 | WN22-SO-000310 |
| `win lsa protection` | LSA protection off | WARN | `RunAsPPL is {v}: set it to 1 under Lsa` | `reg`: `Lsa\RunAsPPL` (1 or 2 passes). Absent reads as off | Microsoft Security Baseline, MS Security Guide "LSA Protection" |
| `win wdigest` | WDigest stores credentials | FAIL | `UseLogonCredential is 1: set it to 0 (SecurityProviders\WDigest)` | `reg`: `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`. Absent reads as off | WN22-CC-000020 |
| `win credential guard` | Credential Guard off | WARN | `LsaCfgFlags is {v}: turn on Credential Guard Configuration (Device Guard policy)` | `reg`: `SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags` (1 or 2 passes); `Lsa\LsaCfgFlags` also passes. N/A on domain controllers and machines that are not domain-joined (`$o.joined`), with `Does not apply to this platform.` | WN22-MS-000140 |
| `win firewall` | Windows Firewall off | FAIL | `{profiles} off: turn on Windows Defender Firewall for those profiles` | `firewall`: each `{name, on}` | WN22-00-000280 |
| `win rdp nla` | RDP without network-level authentication | WARN | `UserAuthentication is off on RDP-Tcp: set Require user authentication for remote connections by using Network Level Authentication to Enabled` | `reg`: `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication`, else `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication`. Passes when `Control\Terminal Server\fDenyTSConnections` is 1 | General practice. Not in the WN22 STIG |
| `win uac` | UAC off | FAIL | `EnableLUA is 0: set User Account Control: Run all administrators in Admin Approval Mode to Enabled` | `reg`: `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`. Absent reads as on | WN22-SO-000440 |
| `win guest` | Guest account enabled | FAIL | `Guest is enabled: set Accounts: Guest account status to Disabled` | `policy`: `EnableGuestAccount` | WN22-SO-000010 |
| `win password` | Password policy weak | WARN | `{settings}: set Account Policies > Password Policy to length 14, complexity on and history 24` | `policy`: `MinimumPasswordLength`, `PasswordComplexity`, `PasswordHistorySize` | WN22-AC-000070, 000080, 000040 |
| `win reversible` | Reversible password encryption on | FAIL | `ClearTextPassword is 1: set Store passwords using reversible encryption to Disabled` | `policy`: `ClearTextPassword` | WN22-AC-000090 |
| `win lockout` | Account lockout weak | WARN | `{settings}: set Account Lockout Policy to 3 attempts or fewer, with duration and reset at 15 minutes or more` | `policy`: `LockoutBadCount` (0 or over 3 is a finding), `LockoutDuration`, `ResetLockoutCount` (under 15 is a finding) | WN22-AC-000020, 000010, 000030 |
| `win audit logon` | Logon auditing incomplete | WARN | `{subcategories}: set Advanced Audit Policy for Logon/Logoff and Account Logon to the needed Success or Failure` | `audit`: Credential Validation `{0CCE923F-69AE-11D9-BED3-505054503030}` S+F; Logon `{0CCE9215-69AE-11D9-BED3-505054503030}` S+F; Logoff `{0CCE9216-69AE-11D9-BED3-505054503030}` S; Special Logon `{0CCE921B-69AE-11D9-BED3-505054503030}` S; Account Lockout `{0CCE9217-69AE-11D9-BED3-505054503030}` F | WN22-AU-000070, 000080, 000190, 000200, 000180, 000210, 000160 |
| `win audit changes` | Change auditing incomplete | WARN | `{subcategories}: set Advanced Audit Policy for Account Management, Policy Change, Privilege Use, Detailed Tracking and System to the needed Success or Failure` | `audit`: User Account Management `{0CCE9235-69AE-11D9-BED3-505054503030}` S+F; Security Group Management `{0CCE9237-69AE-11D9-BED3-505054503030}` S; Audit Policy Change `{0CCE922F-69AE-11D9-BED3-505054503030}` S+F; Sensitive Privilege Use `{0CCE9228-69AE-11D9-BED3-505054503030}` S+F; Process Creation `{0CCE922B-69AE-11D9-BED3-505054503030}` S; Security State Change `{0CCE9210-69AE-11D9-BED3-505054503030}` S; Security System Extension `{0CCE9211-69AE-11D9-BED3-505054503030}` S; System Integrity `{0CCE9212-69AE-11D9-BED3-505054503030}` S+F | WN22-AU-000100 to 000120, 000140, 000260 to 000310, 000360 to 000390 |
| `win defender` | Defender real-time protection off | FAIL | `Real-time protection off: turn on Microsoft Defender real-time protection` | `defender`: `realtime`, when `mode` is Normal. Passes when another antivirus has Defender in passive mode | WN22-00-000110 |
| `win tls` | TLS 1.0 or 1.1 on | WARN | `{versions} on: set Enabled to 0 under SCHANNEL\Protocols\{version}\Server` | `reg`: `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\Enabled` and the same for `TLS 1.1`. Absent reads as on below build 26100 | Microsoft's TLS 1.0 and 1.1 deprecation article; general practice. Not in the WN22 STIG |

Left out: maximum password age (Microsoft's baseline no longer asks for it, the STIG does), Defender signature age, WinRM Basic and unencrypted traffic (Toner itself offers Basic over HTTPS), UAC consent prompt (the STIG value fires on every default machine).

## Points for your decision

1. **Thresholds.** FortiGate lockout (`fg lockout`) follows the STIG's 900 seconds. FortiOS ships at 60, so a default box warns. Windows lockout follows the STIG's 3 attempts; Microsoft's baseline is 10. Say if you prefer the looser figure for either.
2. **`win smb signing` and `win tls` below build 26100.** Windows Server 2025 changed these defaults. Toner reads the absent value by build (26100 and later as on, or off for TLS), which is the best reading from the registry and is not tested on 2025.
3. **MikroTik `mt service address`** cannot see a firewall rule that does the same job, so a router limited that way still warns. Your call to keep it.
4. **HPE**, as noted above, is the section most likely to need correcting against real backups. Several rules are one platform only.
5. **secedit needs an elevated session,** and without `/mergedpolicy` it shows local policy only, so a domain member can report weak values that domain policy overrides. This is a Windows-snapshot build point (Task 7 or 8). `auditpol`'s inclusion text may also be localised on non-English Windows.
6. **Not part of this list, but found while checking the formats:** stored backups do not mask SNMP community names for Junos when unquoted, RouterOS, FortiOS or PAN-OS (`core/backup.py`, `MASKS`). Those rules read them, and the masked view shows them too. Worth a separate fix if you want them hidden.

## Other wording to approve

| Where | Text |
|---|---|
| Windows rule rows' suffix, as backup rows end `(backup of {date})` | `(read {date})` |
| Scanning list's grouped line for a Windows device, which opens to its CVEs | `{n} CVEs, fixed in build {x}` |
| The same, for CVEs with no fix stated | `{n} CVEs, no fix stated` |
