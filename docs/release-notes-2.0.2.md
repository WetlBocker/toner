# Toner 2.0.2

Monitoring profiles, BGP and OSPF checks for six more vendors, and the trend report by email. If you are updating from 1.14.1 or
earlier, read the [2.0.0 notes](https://github.com/WetlBocker/toner/releases/tag/v2.0.0) first: that upgrade can't be undone.

## Monitoring profiles

- **A group of devices can have its own checks and limits.** **Settings > Monitoring profiles** is a new page. A profile is made
  for one vendor: choose the vendor, tick the checks that run, set the limits that differ, then assign it to All devices, a
  location, a folder, a tag or single devices.
- **A profile overrides the global settings for its devices.** They run the profile's checks instead of the list in
  Settings > Checks, and use its limits. A limit the profile leaves alone stays as Settings > Thresholds has it. Devices with no
  profile behave as before.
- **A device's own settings still win.** What is set in Edit device > Checks beats the profile, and that tab now says which
  profile the device follows. When two profiles apply to one device, the more specific assignment wins: a single device, then a
  folder, then a tag or location, then All devices.
- **Roles:** Monitoring profiles is a Settings page an admin can open or lock for each role. It starts open for Engineers and
  locked for Techs.

## Routing checks

- **BGP and OSPF on more vendors.** Fortinet, Palo Alto, HPE Aruba (AOS-CX and AOS-S), Extreme Networks (Switch Engine and Fabric
  Engine) and OPNsense (with the FRR plugin) gain BGP peer and OSPF adjacency checks. MikroTik gains BGP peers, on RouterOS 7
  and 6.
- **They appear on devices you already monitor.** A device that doesn't run the protocol shows N/A, "not configured". To stop a
  check, untick it in Settings > Checks or leave it out of a monitoring profile.
- **Not yet run against real devices.** These checks are written from each vendor's documentation. If a row reads wrong on your
  device, please open an issue with the device's output.

## Reports

- **The scheduled trend report can be emailed.** Settings > Reports has a new box, **Email it to**. The weekly or monthly report
  is still saved to the default folder, and is also sent as an attachment to the addresses you list. It goes through the first
  Email channel in Settings > Notifications; that channel's own recipients don't receive it.
- If the mail server refuses, the report is still saved and the audit log says why. Toner doesn't send it again.

## Settings and Tools

- **Number boxes list their common values.** The timing, retention and limit boxes in Settings and Tools, and History's
  "Last n hours", have a drop-down arrow that lists the usual values, such as 7, 30, 60 or 90 days for Keep run history. Any
  other number can still be typed, and the arrow keys still step by one. Ports and the WARN and FAIL thresholds are unchanged.
- **The page lists match the sidebar.** The lists of pages in Settings, Tools and Automation use the sidebar's group names,
  spacing and highlight.

**Full changelog:** https://github.com/WetlBocker/toner/compare/v2.0.1...v2.0.2
