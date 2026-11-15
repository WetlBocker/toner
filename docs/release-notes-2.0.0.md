# Toner 2.0.0

Toner now asks people to sign in, and everything it keeps is encrypted until someone does. This is a one-way upgrade: read
**Before you update** first.

## Before you update

- **There is no going back.** Versions before 2.0.0 can't open the encrypted data. Back up Toner's data folder before updating.
- **First start:** the first person to open the upgraded Toner creates the admin account and is shown a recovery key, once. Save it
  somewhere safe, like your password manager. It is the only way back in if every password is forgotten.
- **Keep `netcheck.keys` with Toner's data.** Without it the recovery key can't open anything. When you copy the data, copy both
  `netcheck.db` and `netcheck.keys`.
- **The master password is gone.** Toner moves your saved passwords into the new account. If it didn't remember the master
  password, it asks for it once.
- **The background service is off.** `cli service` is refused while sign-in is set up. Scheduled checks and backups run while
  someone is signed in to Toner's window.
- **Scheduled command-line runs stop.** The command line now asks for a username and password at the terminal. Run from Task
  Scheduler with no terminal, a command exits with code 3. On Windows, run commands with `TonerCli.exe`.
- **Database backups ask for a password.** The backup holds devices, history and settings, encrypted with the password you choose.
  Saved passwords stay in Toner's vault and aren't included.
- Every account on an upgraded copy starts as an Admin.

## Signing in

- **Accounts and the lock:** local accounts with a password. Toner locks after 15 minutes without use, or at once with
  Ctrl+Shift+L. An admin changes the time in **Settings > Accounts**.
- **Roles:** every account is an Admin, an Engineer or a Tech. An admin chooses what Engineers and Techs can do: push changes to
  devices, see passwords in config backups, use the Assistant, each tool and each Settings page.
- **Active Directory and LDAP:** people can sign in with their directory account. An admin adds the directory in
  **Settings > Accounts > External Identities** and maps its groups or OUs to roles. A Duo push or a Duo code can be required as a
  second step.
- **Single sign-on:** Entra, Okta, Google Workspace, Duo SSO or any other OpenID Connect provider, through the provider's own
  page in your browser.
- **A PIN for each computer:** directory and single sign-on accounts choose a PIN the first time they sign in on a computer. On
  Windows it is 6 digits protected by the computer's security chip; elsewhere it is at least 8 characters. The PIN unlocks
  Toner, and a full sign-in is asked for again after 12 hours (an admin can change the session length).
- **Approval:** a person's first sign-in on a computer needs an admin to approve it there. An admin can turn on
  **Let group members sign in without approval**, which installs Toner's helper service and needs administrator rights.
- **Security keys:** a local, AD or LDAP account can add FIDO2 security keys under your name > **Security keys...**. Once it has
  one, signing in needs your password or PIN, the key's own PIN and a touch; unlocking needs your password or PIN and a touch. An
  admin can require a key for every local, AD and LDAP account. Security keys are not available to AD and LDAP accounts while
  **Let group members sign in without approval** is on, and single sign-on accounts are unchanged. Update every copy that shares
  the data before adding a key.

## Your data

- Databases, logs, session logs and the files beside them are encrypted, and open only when someone signs in or uses the
  recovery key.
- Passwords in config backups are encrypted separately, so a role that isn't allowed to see them really can't.
- Config backups now mask SNMP community names for Junos, FortiOS, PAN-OS and RouterOS. Versions stored earlier are masked once,
  on upgrade.

## History and charts

- **A time range replaces the runs list.** Pick a period and History shows it.
- **Over time** draws a panel for each check, each as the kind of picture that suits it: lines, tables, heatmaps or rings.
- **Across devices** shows every device's latest reading of a check as gauges, tables and rings.
- **Failures** shows when FAIL and ERROR rows happen, by date. Click a square or a bar to list the rows it counts.
- **A device's page** has dials for its latest readings, its uptime, its vulnerabilities and every check on Trends.
- BGP, OSPF and EIGRP history is shown as tables. TrueNAS gets pools, datasets and drive temperatures.
- Moving a device to another organization keeps its history.

## Monitoring

- **WAN usage:** mark a device's WAN interfaces and Toner tracks how much each link carries, graded at 80% and 95%. It works on
  every network device, with native readers for Palo Alto and Juniper.
- **UniFi:** each device a console reports is listed under it in the Inventory and in Results, with its own page. Topology uses
  UniFi consoles as a source of neighbours.
- **Windows:** pending updates by severity and every certificate with its date, from the agent too.
- Drivers keep detail per disk, per certificate, per component and per interface.

## Scanning and hardening

- **More vulnerability sources:** Cisco falls back to NIST's NVD when PSIRT is not available, Fortinet adds its own advisory
  feed, and Windows computers are looked up in NVD by their exact patched build.
- Fixed versions are read from NVD's ranges, a CVE with no score is no longer treated as low, and Toner says so when it could
  not confirm a version is clean.
- **Check CVEs**, next to Scan, asks whether the devices shown are affected by CVEs you enter or paste. The vulnerability rings
  show counts.
- **More hardening rules:** Juniper, Arista, HPE, MikroTik and Windows, and more for FortiGate and Palo Alto.

## Tools and the rest

- **IP lookup** works with any provider's API URL and key.
- **Subnet calculator** shows the broadcast address and masks, and joins the subnets you pick.
- **Password manager:** a clearer collection editor, and collections no longer need the "Toner - " prefix.
- **External Identities:** a five-step Add flow, **Test login**, and a server's untrusted certificate can be shown and trusted.
- **Sign-in window:** **Remember me**, and **Sign out** returns to the sign-in page.
- Tables fit their columns to their text and can always be dragged wider. The Assistant panel and the sidebar open and fold
  smoothly.

## Security fixes

- A security review of the code confirmed 27 findings, and all 27 are fixed. One of them: the SSH tunnel's local port now needs
  a password, so only Toner can use it.
- A proxy no longer loses what the target sends together with the proxy's answer.

## Under the hood

- The Gemini library moves to google-genai 3.3.0. Also updated: openai 3.46.0, PyJWT 2.15.1 and pysnmp 7.1.32.
- The Windows installer and the Linux AppImage no longer carry the Qt modules that are licensed under the GPL alone, which
  Toner never used.

**Full changelog:** https://github.com/WetlBocker/toner/compare/v1.14.1...v2.0.0
