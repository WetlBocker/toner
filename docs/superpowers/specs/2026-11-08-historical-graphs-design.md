# Historical graphs and the device page: design

Status: approved by the owner, 2026-11-08.
Source: the owner's Adjustments.md (Device Details Page, History Page) and the answers given in conversation on 2026-11-08.

## Why

Toner draws every check's history the same way. It looks at the data: a number becomes a line or a bar, and a status word
becomes stacked status bars. That rule gets things wrong. Disk health stores a count of unhealthy disks, so it is drawn as
bars of "ok" over time, which means nothing to someone reading it. Several checks store a number that only grades the result
and is not a measurement.

The owner's rule:

- **Measurements over time** (CPU, memory, response time, interface errors) stay **line graphs**.
- **Health and up/down checks** become **heatmaps**, like the Failures tab. Selecting a square shows underneath what happened
  in that slot.
- **Lists and facts** (licences, certificates, HA state) become **tables**.
- A few checks get their own picture: gauges for disks, a wheel for pending patches, and a ring for interfaces.

Each check's chart is chosen on purpose, not guessed from its data. The device page gains what the owner looks for first:
the dials that matter, uptime, vulnerabilities and WAN usage.

## Goals

1. Every check named below gets the chart the owner chose, on the History page (Over time and Across devices) and on the device
   page, which shares the Over time drawing.
2. Every heatmap square, ring segment, wheel segment and pie slice can be selected. Selecting it shows the rows behind it.
3. Across devices shows each device's latest reading, or its 7, 30 or 90-day average, without choosing a run.
4. Heatmaps over 30 and 90 days read by date, not by weekday.
5. The device page has these:
   - CPU, memory, disk and WAN dials
   - an Uptime line under Status
   - a Vulnerabilities tab
   - every check picked by default on Trends
6. Toner records the per-item detail these charts need, starting from the update:
   - each disk
   - each certificate
   - each environmental component
   - each interface's state and errors
   - each pending update's severity
   - WAN traffic

## Non-goals

- No change to how checks are graded (OK, WARN, FAIL), except that certificate and certificates merge into one check.
- No change to the Trend report, the columns of the exports, or the Dashboard. The exports take their rows from the new time
  range instead of a run.
- No change to alerts, except that the new **wan usage** check is graded and alerts like any other check (the owner's
  decision).
- No back-filling of old history. Runs from before the update show what was saved then: for example, only the fullest disk.
- No new charting library. ECharts (through `ui/webchart.ChartView` and `ui/chartspec`) and pyqtgraph (`ui/history.py`) are
  enough.

## Anti-goals (a failure even if it works)

- A count of problems drawn as if it were a measurement, or given a unit taken from its text (the current Disk health bars).
- A coloured square, slice or segment that can't be selected to see what it stands for.
- A 30 or 90-day view labelled by weekday, so two Mondays land in one square.
- Breaking older agents. A Windows computer whose agent hasn't been updated must still report everything it reports today, and
  the new charts should say "not reported by this computer's agent yet" rather than show an error.

## Constraints

- **Wording:** every new user-facing string (tab names, titles, column heads, empty-state text, toggle labels) needs the owner's
  approval before it is built. The names in this document are working names.
- **Versions:** Windows, Linux and macOS share one version number. Changes to the agent (agent/, Go) ship in the same release.
- **The "Choose Interfaces" dialog** (`ui/interfacepicker.InterfacePicker`) is where WAN interfaces are marked. There is no
  separate WAN settings page.
- **The device page's History tab and Trends tab share one check picker** (`DeviceView.pick`), and the History page's Over time
  tab and the device page share `draw_over_time`. They must still share it after this change.
- **Motion:** any animation follows the Motion setting (`ui/motion`), and is instant when Motion is off.
- **Passwords and secrets** never appear in any chart, table or detail list.

## The chart rules

Each check has an assigned chart type for Over time and one for Across devices: a single table, keyed by stored check name.
A check missing from the table falls back to a default by kind:

| Kind of check | Over time | Across devices |
|---|---|---|
| A measurement (percent, ms, seconds, a count that is the thing measured) | line | a gauge per device |
| A health or up/down check | heatmap, details underneath | table: device, status, value, message *(my call)* |
| Text or a list | table | table |

`chart_kind()` in `ui/history.py` stays only as the last fallback for checks that aren't in the table and have no known kind.

### Heatmaps (Over time and Failures)

- **Up to 30 days:** one row per date, newest at the top, and one column per hour (00 to 23). Rows are labelled with the date,
  for example "Sat 8 Nov". The default 8 hours is one or two rows.
- **More than 30 days:** one row per week, labelled with the week's Monday, and one column per day (Mon to Sun). Each square is
  one date. *(My call, refining the recommendation the owner accepted: 90 rows of hours would be unreadable.)*
- The Failures tab keeps its own Period choice (7, 30, 90 days).
- **Over time** heatmaps colour each square by the worst status in that slot:
  - OK is green.
  - WARN is amber.
  - FAIL and ERROR are red.
  - No reading is left blank.
- **The Failures tab** keeps colouring by how many FAIL and ERROR rows fall in a square. It only changes its rows and columns
  to the scheme above.
- **Selecting a square** lists the readings in that slot underneath: time, device, status, value, message. The message is where
  the detail lives: which disk, which services, which tasks.
- Over time heatmaps and lines cover the page's **time range** (see "The time range on the History page").

### Tables

- Every table in this design can be sorted by any column. Column sizing follows "Every table in Toner" below. The owner
  confirmed that the certificates table's columns couldn't be resized on their copy.
- An Over time table lists one row each time the value changed, newest first, with the columns Checked, Status, Value and
  Message. The exceptions are listed in the tables below.

### Every table in Toner

This is the owner's rule for **every** table in the app, not only the charts here: about 42 tables in 30 files under `ui/`.

- **Sized to fit:** whenever the table is wide enough, each column is as wide as its longest text, header included. Nothing
  is cut off, and nobody has to drag a column to read it.
- **Not enough room:** the columns share the width. None goes narrower than its header, the widest give way first, and text
  that is cut off shows in full on hover. *(My call.)*
- **Always resizable:** any column can be dragged wider or narrower. A column the user has dragged keeps that width until the
  page or window is closed, so a refresh doesn't undo it. Other columns are re-fitted when the data changes. *(My call.)*
- **Why columns can't be resized today:** headers set to `ResizeToContents` or `Stretch` can't be dragged in Qt. That is the
  likely cause of the locked certificates table. Header sections stay `Interactive`, and fitting is done in code.
- **One shared helper** applies this to every table, so the rule can't drift from page to page.

### Gauges

- Gauges use the existing `chartspec.gauge`, with the warn and fail marks from the device's thresholds.
- A disk-type gauge shows the percentage, with used and total size under it, for example "412 GB of 500 GB". If only the
  percentage is known, it shows the percentage alone.

## The checks, one by one

### Over time (History page, and the device page's History tab)

**Several checks ticked:** one panel per ticked check, stacked in the picker's order, and the panel area scrolls. Line checks
that share a scale still share a panel, as `ChartStack` does today. Panels are drawn as they scroll into view, so opening a
device with every check ticked stays quick. *(My call.)*

**Trends** draws only the ticked checks that are measurements. Heatmap, table, gauge and wheel checks are left off its area
chart. *(My call: CPU percent, response time in ms and a count of changes don't belong on one axis.)*

| Check (stored name) | Chart | Notes |
|---|---|---|
| certificates (merged, see below) | table | Every certificate: name, expires, days left, where found. The latest reading only, not its history. |
| changes | line | The number of kinds of change at each check. |
| clock | line | Seconds the computer's clock is off from Toner's. This is not NTP itself: it is the computer's clock compared with the Toner machine's. |
| config backup | table + config | One row per saved version. Selecting a row shows that version underneath, with the same "Changes from the previous version / Full configuration" switch as the device page's Configuration tab. |
| disk health | heatmap | Details underneath name the disk and its state, from the message. |
| disks, disk, storage | a gauge per disk | The latest reading, one gauge per drive. Most network drivers store disk space as "disk" and SNMP adds "storage". All three names count *(my call)*. TrueNAS is the exception: its "disks" check is SMART health, with the hottest disk's temperature as its number, so on TrueNAS it is a heatmap. The chart table can therefore be keyed by vendor and check name where a name means two things. |
| firewall | table | |
| patches | wheel | See "Pending updates". |
| pending reboot | heatmap | |
| reachability | line | Response time in ms, as the device page's Trends chart draws it today. Checks with no answer show as red marks on the line *(my call)*. |
| services | heatmap | Details underneath list which services were stopped. |
| tasks | heatmap | Details underneath list the failed tasks. |
| uptime | table | One row per restart: "Restarted (about)" and "Had been up for". The current uptime is the top row *(my call: a row per reading would change at every run)*. |
| environment | heatmap | Details underneath list the components that weren't OK. |
| flash | a gauge per flash device | Like disks. |
| interface errors | line, one line per interface | A picker on the chart chooses the interfaces, starting with those that have had errors. Needs per-interface counts (new). |
| interfaces | heatmap | Details underneath list the interfaces that were down or err-disabled. |
| last commit | table | |
| licenses | table | |
| panorama | table | |
| resources | not shown | It only ever appears as an error row when CPU or memory couldn't be read. CPU and memory have their own lines. Leave it out of the check lists. |
| fortiaps, fortiswitches | table | |
| ha and ha sync | one combined table | One row each time either changed: Checked, HA, HA sync. |
| log disk | gauge | Like disks. Fortinet gives only a percentage. |
| vpn, ipsec tunnels | heatmap | Details underneath list the tunnels that were down. |

### Across devices (History page)

| Check | Chart |
|---|---|
| Any measurement (CPU, memory, disks, response time, temperature...) | A gauge per device, worst first, wrapping into a grid. A switch above: **Latest / 7-day average / 30-day average / 90-day average**. |
| antivirus | table |
| certificates | table: device, certificate, expires, days left, where found. Every certificate. |
| environment | table: device, component, state. Every component that was tested. |
| firmware | table: device, version. It includes every device whose software version Toner knows (`db.software_of`), so Cisco ASA and other Cisco devices appear, even though they record their version without a "firmware" check row. |
| interfaces | A ring per device *(my call: matches "a gauge per device")*: green for up, yellow for err-disabled, red for down, and the total number of interfaces in the middle. Interfaces turned off by an administrator are left out, as they are today. Selecting a segment lists those interfaces underneath. |

### The time range on the History page

The "Run time" table (the list of runs with OK, WARN, FAIL and ERROR counts) goes. A **time range** replaces the run choice
(the owner's decision):

- The default is the **last 8 hours**.
- It can be changed to a relative range, **Last X hours**, or to a **date range** picked from a calendar.
- **The checks table** lists every check result in the range, newest first. This is the table that today shows every check
  from one run. Clicking a row still puts that device and check on the Over time chart.
- **The CSV, HTML and PDF exports** contain the rows the checks table shows: the range, the devices shown, and any search.
- **Over time** charts cover the same range *(my reading: one range for the whole page, so the table and the chart always
  agree)*. Gauges and the certificates table still show the latest reading.
- **The device page** gets the same range control on its History and Trends tabs, with the same default *(my call)*.
- **The Assistant's page description** names the range instead of a run.
- **Across devices** doesn't use the range. It has its own Latest / average switch.
- The table must stay quick with thousands of rows. Eight hours of 5-minute runs across a fleet is about 100 runs times
  100 checks. That means a model/view table, not one `QTableWidgetItem` per cell. How is left to the builder.

## The device page

### Overview dials

- The dials are CPU, Memory, one per disk (Disk utilization) and one per WAN interface.
- Temperature, sessions, load and the other readings that are dials today leave the Overview.
- *(My reading of "Gauges: set for CPU/Mem utilization, Disk utilization". Those readings stay on History and Trends.)*

### Uptime under Status

- The facts list gets an **Uptime** line right under **Status**, from the latest uptime reading, written like "12 days 4 hours".
- The Inventory details pane shares this list (`DeviceSummary`), so it gets the line too.
- Devices with no uptime check show no line.

### Vulnerabilities tab

- A new tab, between Trends and Configuration *(placement is my call)*.
- It shows a pie of this device's advisories by CVSS severity, using the bands the Scanning page uses today:
  - Low is 0–4.
  - Medium is 4–7.
  - High is 7–9.
  - Critical is 9–10.
- Selecting a slice lists those advisories underneath: the CVE or advisory ID, title, CVSS score, whether it is known to be
  exploited, and a link.
- The data is the device's rows in the latest scan (`db.latest_scan_results`). Hardening rules are not included
  *(my call: they have no CVSS score)*.
- With no scan yet, the tab says so and points to Scanning.

### Trends

The picker starts with **every** check ticked, instead of the first one. Unticking still works. The device page's History tab
shares this picker, so it starts with every check ticked too.

### WAN dial

- **Choose Interfaces** gets two columns:
  - **WAN**, a tick box.
  - **Available bandwidth**, which defaults to the interface's port speed and can be typed over with the circuit speed.
  - These columns appear only for devices where Toner can read interface traffic.
- Toner works out each WAN interface's use from two readings of its byte counters, the same way the SNMP bandwidth check does
  today. The rate is the busier direction (in or out) as a percentage of the available bandwidth.
- The result is a new check, **wan usage**, with one row per WAN interface:
  - It has a history (a line under Over time).
  - It appears as gauges Across devices.
  - It shows as a dial on Overview.
  - The first run only records the counters, as SNMP bandwidth does today.
  - **Graded** (the owner's decision): WARN at 80% and above, FAIL at 95% and above. It alerts like any other check. The limits
    can be changed under Settings > Thresholds like the others *(my call)*.
  - It sits beside the existing Interface utilization (bandwidth) check and shares its counter readings, so a link is never
    read twice.
- **Which drivers:** every driver that can read per-interface byte counters and speed. That covers SNMP-polled devices
  (ifHCInOctets, ifHCOutOctets, ifHighSpeed) and the API drivers whose interface data includes counters (Fortinet does). The
  builder finds the full list. A device without counters doesn't offer the WAN column.

## Pending updates (the patches wheel)

- **What it shows:** a ring (donut) with the number of pending, not yet installed, updates in the middle. Each segment is a
  Microsoft severity:
  - Critical
  - Important
  - Moderate
  - Low
  - **Unrated** *(my call)*: Microsoft gives many non-security updates no severity, and they still count as pending.
- Selecting a segment lists those updates: title and KB number *(my call: as with every other chart here)*.
- **Windows:** both collection paths read the pending updates and each one's severity (`MsrcSeverity`): the Go agent
  (`agent/internal/collect/windows.go`) and the WinRM PowerShell in `core/winmon.py`.
- **Cached, not live** *(my call)*: Toner reads the result of Windows' own last update search and does not start a new one.
  A live search can take minutes and contacts Microsoft or WSUS on every check. The wheel shows the date of Windows' last
  search. If the computer refuses the request (WinRM can refuse the Windows Update API), the wheel says "not reported by this
  computer" and the check's grade is unaffected.
- **Other platforms:** Linux computers and Cisco ISE keep a table for patches *(my call: they have no Microsoft severity)*.
- **Grading doesn't change:** the patches check is still graded on days since the last update was installed. The wheel is how
  its history is drawn.

## Certificates, merged

**certificate** and **certificates** are shown as one check, **certificates**. They are merged where they are shown, not where
they are stored *(my call)*. Storing them under one name would end existing acknowledgements and restart alert state across
every device, change which alerts fire, and send Demarc a check name it hasn't seen before. All of that goes against "no change
to alerts". The checks underneath keep their names and their own grading:

- **certificate** is Toner connecting to the device's web port and reading the certificate it presents (`core/custom.py`).
- **certificates** is the device's own certificate store (Windows, Fortinet).

The merged check:

- Lists every certificate, with name, expiry date, days left, and where it was found (the store, or the port).
- Shows the worst of the rows it merges as its status. Each underlying row is graded and alerted on exactly as today.
- Includes every certificate on Windows, not only those expiring within 90 days. This is a collection change on both Windows
  paths. The machine's own self-signed certificate stays left out, as today.
- Shows older history too: rows saved as "certificate", "certificate :port" and "certificates" all show under the merged name.

## New data Toner keeps

Each check result can carry a list of items: a name, a number, a status and a short text. Charts read the items instead of
parsing the message.

| Check | Items |
|---|---|
| disks, flash, log disk | each drive: percent used, used bytes, total bytes |
| certificates | each certificate: name, expires, where found |
| environment | each component tested: name, state |
| interfaces | each interface: state |
| interface errors | each interface: error count (as graded: lifetime or new since the last run) |
| patches (Windows) | each pending update: title, KB, severity |
| wan usage | each WAN interface: in and out bits per second, available bandwidth |

How they are stored (a new table keyed to the result, or a column) is the builder's decision. It has to:

- Survive the existing schema migrations.
- Keep `run_results` and `check_rows` working for code that never reads items.
- Be cleaned up when runs are pruned.

## Done separately

The Assistant pane now slides like the sidebar (no fade, no second image). This was done on 2026-11-08 outside this design.

## Left to the builder

- How items are stored, and which drivers can supply each kind.
- How the chart table is laid out in code.
- The heatmap and ring drawing in `ui/chartspec`. A ring is the existing donut with a centre label.
- How a selection's details are shown under each chart. It should be one shared component.
- Performance: Across devices averages over 90 days for many devices must stay quick. Aggregate in SQL, not in Python loops.

## My calls (please check while reading)

1. A table across devices for health checks with no assigned chart.
2. 90-day heatmaps as weeks by day.
3. One time range for the whole History page (table, exports and Over time), and the same control on the device page.
4. Sortable, resizable tables as the meaning of "cannot be adjusted".
5. The uptime table as one row per restart.
6. Red marks for unanswered checks on the reachability line.
7. A ring per device for interfaces Across devices.
8. Overview dials limited to CPU, memory, disks and WAN.
9. The Vulnerabilities tab between Trends and Configuration, without hardening rules.
10. An "Unrated" segment, and selectable segments, on the patches wheel.
11. A table for Linux and ISE patches.
12. One panel per ticked check on Over time, and only measurements on Trends.
13. "disk", "storage" and "disks" all count as disk space for gauges, with TrueNAS's SMART "disks" check as a heatmap.
14. Pending updates read from Windows' cached search, not a live one.
15. Certificates merged where they are shown, not where they are stored.
16. When a table is too narrow, the widest columns give way first, and cut-off text shows in full on hover.
17. A column the user dragged keeps that width until the page or window closes.

## Open questions

None left. The owner answered the last two on 2026-11-08: a time range replaces the runs list, and WAN usage is graded at
80% (WARN) and 95% (FAIL).

## Added after approval (owner, 2026-11-08)

- **TrueNAS disk space:** the device page's Overview Disk dials for a TrueNAS device are its **pools** only ("pool space": one dial per pool, percent used, with used and total underneath). Datasets are not shown there. Pool rows are stored under per-pool labels ("<device> / <pool>"), so the device page gathers them from those labels.
- **TrueNAS datasets:** History > Across devices shows **one dial per dataset** for the "datasets" check (percent used, used and total underneath), not one per device. Over time, "pool space" and "datasets" are gauges like disks *(my call)*.
- **TrueNAS "disks"** stays SMART health: a heatmap over time, and the health table across devices.
- **Device details facts:** long values (for example a Cisco ASA's Version: "9.12(4)67 (asa9-12-4-67-smp-k8.bin), read 8 Nov 2026 at 23:31") wrap onto as many lines as they need and are never cut off. This applies to the facts list shared by the device page and the Inventory details pane (`DeviceSummary`).
