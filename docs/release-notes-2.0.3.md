# Toner 2.0.3

Scheduled scans and reports, Microsoft 365 and Google sign-in for email, and checks filled in via SNMP or SSH when a device's main
method can't answer. If you are updating from 1.14.1 or earlier, read the
[2.0.0 notes](https://github.com/WetlBocker/toner/releases/tag/v2.0.0) first: that upgrade can't be undone.

## After you update

- **Devices with SNMP set up gain rows.** A device reached by SSH or by its own API, with "This device also answers SNMP" ticked,
  now gets Storage and Interface errors via SNMP, and any of CPU, memory, uptime and interface status its main method doesn't
  report. Interface errors can raise warnings you haven't seen before. To stop a check, untick it in Settings > Checks.
- A device with its own list of checks, or under a monitoring profile, doesn't gain them: they appear there unticked.

## Checks by any available method

- **A check the main method lacks is filled via SNMP.** CPU, memory, storage, uptime, interface status and interface errors are
  read via SNMP when the device's SSH or API checks don't give them. The row's message says "via SNMP". Devices monitored through
  a vendor's cloud (Meraki, Mist, UniFi Site Manager), Windows computers and status pages are not filled.
- **A check that fails is filled too.** When the main method's check fails, or its sign-in is refused, the value comes via SNMP
  and the message says why, for example "via SNMP; the API check failed: HTTP 403". A refused sign-in keeps its own ERROR row. A
  device that doesn't answer at all is not filled.
- **Fortinet and Palo Alto: CPU, memory and uptime via SSH.** With an SSH login stored on the device (Edit device > Access),
  what the API and SNMP don't give is read over SSH, and on Palo Alto the version too. These checks never change a FortiGate's
  configuration. A FortiGate with VDOMs is not read over SSH yet.
- **Uptime on more vendors.** Fortinet and UniFi Site Manager gain an Uptime check. On Proxmox and Mist, uptime has its own tick
  box in Settings > Checks.
- **Choose interfaces works via SNMP.** A device whose interfaces are read via SNMP lists them in the picker. This also repairs
  the picker on Cisco ISE, FMC, SD-WAN Manager and vCenter, where it was offered and failed.
- **Interface errors via SNMP, "since last run".** The counters were not kept between runs, so this mode never reported an
  increase. It does now.
- Settings > Checks says "via SNMP" where it said "by SNMP".
- **Not yet run against real devices.** The FortiGate and Palo Alto commands were confirmed on real firewalls, but a whole run of
  the fill-in was not. If a row reads wrong on your device, please open an issue with the device's output.

## Scanning

- **Scans can run on a schedule.** Settings > Scanning has two new rows: **Scan automatically** (Off, Daily, Weekly, Bi-Weekly,
  Monthly) and **Devices**. The scan runs while Toner or its background service is running, and the results are on the Scanning
  page. The schedule is a Global setting and covers every organization.
- **Fixed in.** A device's Vulnerabilities tab has a new column with the releases that fix each advisory, when the source names
  them. The table now fits its width.

## Reports

- **Vulnerability and hardening reports.** Settings > Reports lists three reports: **Trend report**, **Vulnerability report**
  and **Hardening report**. Each has its own schedule (Off, Weekly, Bi-Weekly, Monthly, Quarterly), its own **Email it to** box
  and a **Send now** button.
- Each report is saved to the default folder and emailed through the first Email channel in Settings > Notifications. The
  vulnerability and hardening reports use the latest scan; when a scheduled scan is due, they wait for it.
- The trend report covers the period it is sent for: 7, 14, 30 or 90 days.

## Email

- **Sign in with Microsoft 365 or Google.** An Email channel has a new choice, **Sign in with**: Password (as before),
  Microsoft 365 account, Microsoft 365 app (no person) or Google account. These use OAuth 2.0 with an app you register in your
  own tenant; the help under the form says what to set up.
- **The sign-in stays in Toner's vault.** It is never sent to a password manager and never leaves in an export. Toner renews it
  as it sends; if the provider stops accepting it, the audit log says so and your other channels are told once.
- A channel that signs in this way connects directly and ignores Toner's proxy settings. Password channels are unchanged.
- **Send test no longer holds the window** while the mail server answers.
- **Removing an organization also removes its channels' saved passwords and sign-ins**, except those Global or another
  organization still uses.
- **Not yet run against a real Microsoft 365 or Google tenant.** If the sign-in fails on yours, please open an issue with the
  message Toner shows.

## Smaller changes

- **Trends:** each chart on a device's Trends tab has a title saying what it measures.
- **Playbooks:** right-click a playbook for Run playbook and Edit.
- **Command Runner:** **Create...** opens a window to name and type a new snippet.
- **API Tester:** Params and Headers have Add and Remove buttons, and the Variables table fills its width.
- **Checks limits:** the WARN and FAIL boxes in Edit device > Checks and in a monitoring profile line up with their rows. The
  reset button there is now **Use Global Settings**.

## Fixes

- **TLS check:** a certificate whose serial number is zero or negative is read like any other. A certificate that can't be read
  at all is an ERROR row and no longer ends the sweep.
- **Sign out:** after signing out without closing Toner, a schedule or a run on start could still fire and show an error. They
  now stop with the window, and closing it waits for a health check or a scan that is still running.

**Full changelog:** https://github.com/WetlBocker/toner/compare/v2.0.2...v2.0.3
