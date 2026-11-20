# Adjustments (2026-11-19) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Work through the owner's 12 adjustments of 2026-11-19 (C:\Users\Joshua Wetlesen\Documents\Obsidian Vault\Adjustments.md, screenshots beside it).

**Architecture:** Part 1 is seven small, independent UI and driver changes. Part 2 (credential cache time, scheduled scans, scheduled reports) waits for the owner to approve its wording. OAuth 2.0 for email (item 6) gets its own design and plan.

**Tech Stack:** Python 3.13, PySide6, ECharts through `ui/chartspec.py`, `requests`. No new dependencies.

**Spec:** the owner's list (path above) and the decisions below, made in chat on 2026-11-19. Both are binding.

## Owner decisions (2026-11-19)

- **Item 1 (uptime).** Every vendor gets an Uptime check except Cloud status pages (`cloud`) and the Wi-Fi connection (`wifi`).
- **Item 2.** The limits table (WARN / FAIL boxes) in the monitoring profile window is misaligned: the boxes cross the grid lines.
- **Item 3.** Each chart on a device's Trends tab gets a title: the check's name; a chart that groups several checks lists them ("CPU, Memory").
- **Item 4.** The device's Vulnerabilities tab lists the fixed releases when the source gives them, and the table fits its width like the other tables.
- **Item 5.** Right-clicking a playbook opens a menu with the two things the buttons do.
- **Item 9.** Command Runner gets a button that opens a window to name and type a snippet.
- **Item 10.** API Tester's Params and Headers get the Add and Remove buttons Variables has; the Variables table fills its width.
- **Item 11.** The reset button in Edit device > Checks is renamed.
- **Item 12.** A drop-down replaces the "Keep a copy of each password in Toner's vault" tick box: Off, 1 Hour, 4 Hours, 8 Hours, 12 Hours, 24 Hours. Admin only. Checks may fail when the time is up and the password manager can't be reached.
- **Item 8.** Scans can be scheduled: Daily, Weekly, Bi-Weekly, Monthly.
- **Item 7.** Settings > Reports: the trend, vulnerability and hardening reports each have their own schedule (Off, Weekly, Bi-Weekly, Monthly, Quarterly), their own recipients and a Send now button. The vulnerability and hardening reports use the latest scan.

## Approved wording (owner, 2026-11-19)

- "Use Global Settings" (item 11)
- "Run playbook" (reads "Run check" while Check mode is ticked, like the button) and "Edit" (item 5)
- Button "Create...", window title "Create snippet", labels "Name" and "Commands" (item 9)
- "Add", "Remove" (item 10)
- Column "Fixed in" (item 4)
- Drop-down options "Off", "1 Hour", "4 Hours", "8 Hours", "12 Hours", "24 Hours" (item 12)
- "Daily", "Weekly", "Bi-Weekly", "Monthly" (item 8); "Off", "Weekly", "Bi-Weekly", "Monthly", "Quarterly" and "Send now" (item 7)

## Global Constraints

- Every user-facing string comes from the approved wording above, or shipped before this plan (reusing an existing string for the same meaning is fine). Anything else: stop and ask (NEEDS_CONTEXT).
- No secret in logs, the audit, exceptions or `netcheck.keys`.
- Never connect to a real device, mail server or password manager. Tests use fakes and recorded replies. Never capture the real display; screenshots are off-screen only (`QT_QPA_PLATFORM=offscreen`).
- Tests are plain scripts in the house style (`check(name, cond, extra)`), and each prints `N passed, M failed`, because `tests/run_all.py` parses that. Run one with `python tests/test_x.py 2>/dev/null | grep -a "^  FAIL\|passed, "`. Run the tests of every module you touch; the controller runs the full suite (11 minutes) itself.
- TDD: write the test first and watch it fail for the right reason.
- The working tree has CRLF line endings (`core.autocrlf=true`). Keep them: `git diff --stat` must show only the lines you meant to change.
- No new dependencies. Never stage `.postman/`, `postman/`, `.impeccable/`, `.superpowers/` or `docs/Toner-Technical-Guide.pdf`. Commits end with `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`. No pushes, no merges.
- Slow work (network, file reads of unknown size) never runs on the UI thread.
- The smallest complete change: reuse what the codebase has (`ui/tablefit.py`, `ui/settings_base.py`, `ui/widgets.py`), no new abstractions nobody asked for.

## Review Focus

1. **A limits row taller or shorter than its boxes on another platform's font.** Row heights come from the boxes' own size hints, never a fixed pixel number. Task 1 tests it.
2. **A Trends chart that groups many checks.** A long joined title must not run over the plot or off the chart. Task 2 tests a five-check group.
3. **Right-click on empty space in the playbook list, or while a run is in progress.** No menu on empty space; the run entry is disabled while the Run button is. Task 3 tests both.
4. **A snippet created with a name that already exists, or with nothing typed.** It follows what "Save..." already does for the name; Save stays disabled until both boxes have text. Task 4 tests both.
5. **An advisory whose message names no fix, or names a build.** The "Fixed in" cell is blank, or shows the build as the Scanning page words it. Task 6 tests both.

---

## Part 1

### Task 1: Limits table alignment and the reset button (items 2 and 11)

**Files:** `ui/devicechecks.py` (the `limits` table built around line 50, the reset button at line 78).
**Test:** `tests/test_checks_tabs.py` and `tests/test_monitoring_profiles_ui.py` (extend; update any check that names the old button text).

The table is used twice: Inventory > Edit device > Checks, and the monitoring profile window (`ui/settings_pages/monitoring.py`, `DeviceChecks(for_profile=True)`). The owner's screenshot (`C:\Users\Joshua Wetlesen\Documents\Obsidian Vault\Pasted image 20261119165012.png`) shows the WARN and FAIL boxes taller than their rows, so each box overlaps the grid line under it.

- [ ] **Step 1: Write the failing tests.**
  - The reset button's text is "Use Global Settings".
  - Shown at 640 x 760 (the profile window) and after `processEvents`, for every row: the row's height is at least the WARN box's `sizeHint().height()`, and each box's geometry lies inside its cell's `visualRect`.
  - The WARN and FAIL columns have the same width, the Check column takes the slack (its header section stretches), and the columns together fill the viewport's width.
- [ ] **Step 2:** Run them and see them fail.
- [ ] **Step 3: Implement.** Row heights from the boxes' size hints (the vertical header's default section size, or per row); column 1 stretches; columns 2 and 3 share one width. No fixed pixel heights.
- [ ] **Step 4: Look at it.** Take an off-screen screenshot of the profile window and of Edit device > Checks (the scratch script named in your dispatch shows how) and check that no box crosses a grid line and nothing else in the window is out of line.
- [ ] **Step 5:** Run the two test files and `tests/test_choices.py`. **Step 6:** Commit "Checks: limits table rows fit their boxes; Use Global Settings".

### Task 2: Titles on the Trends charts (item 3)

**Files:** `ui/device_view.py` (`_draw_trends`, `_draw_trend`), `ui/chartspec.py` (the chart option the trend uses; other charts there already take a title).
**Test:** the existing device-view / trends chart test (find it with `grep -ln "_draw_trend\|Trends" tests/`).

- [ ] **Step 1: Write the failing tests.**
  - A chart of one check has the title `display.check_name(check)`.
  - A chart that groups checks has their names joined with ", " in the order drawn.
  - A group of five checks with long names: the title is cut to fit (the house way of truncating chart text) and the plot area starts below it.
  - The empty-state chart has no title.
- [ ] **Step 2:** Run and see them fail. **Step 3:** Implement, using the title style the other charts in `ui/chartspec.py` use (theme text colour, both themes).
- [ ] **Step 4:** Run the chart and device-view tests. **Step 5:** Commit "Trends: each chart says what it measures".

### Task 3: Right-click menu on a playbook (item 5)

**Files:** `ui/automation.py` (`PlaybooksPage`, `self.listing`, the `go` and `edit_btn` buttons).
**Test:** the existing Ansible playbooks page test (`grep -ln "PlaybooksPage" tests/`).

- [ ] **Step 1: Write the failing tests.**
  - Right-clicking a playbook selects it and gives a menu of exactly two entries: the first has the Run button's current text ("Run check" with Check mode ticked, "Run playbook" without), the second is "Edit".
  - Triggering the first calls what the Run button calls; triggering "Edit" calls what the Edit button calls.
  - Each entry is enabled exactly when its button is.
  - Right-clicking empty space in the list opens no menu.
- [ ] **Step 2:** Run and see them fail.
- [ ] **Step 3: Implement** with `setContextMenuPolicy(CustomContextMenu)` and a method that builds the menu for a position (so the test can ask for the menu without showing it). Follow how other lists in the app build context menus (`grep -n "customContextMenuRequested" ui/*.py`).
- [ ] **Step 4:** Run the automation tests. **Step 5:** Commit "Playbooks: right-click to run or edit".

### Task 4: Create a command snippet (item 9)

**Files:** `ui/tools2.py` (Command Runner: `self.snippets`, `snip_save`, `snip_del`, `save_snippet`, around lines 539-700).
**Test:** the existing Command Runner test (`grep -ln "save_snippet\|snip_save" tests/`).

- [ ] **Step 1: Write the failing tests.**
  - A "Create..." button sits in the Snippets row before "Save...".
  - It opens a window titled "Create snippet" with a "Name" line and a "Commands" multi-line box (the command box's font), and Save / Cancel buttons as the app's other dialogs have them.
  - Save is disabled until both boxes have text.
  - Saving stores `{"name", "commands"}` in the `snippets` setting exactly as "Save..." does, including what "Save..." does when the name already exists; the drop-down then lists it.
  - The command box's own text is left as it was.
  - Cancel stores nothing.
- [ ] **Step 2:** Run and see them fail.
- [ ] **Step 3: Implement.** One shared helper stores a snippet for both "Save..." and the new window (no copy of the storing code). No new tooltip or message text.
- [ ] **Step 4:** Run the Command Runner tests and `tests/test_choices.py`. **Step 5:** Commit "Command Runner: create a snippet in its own window".

### Task 5: API Tester tables (item 10)

**Files:** `ui/apitool.py` (`KeyValueTable`, `VariablesPanel`, the Params and Headers tabs in `ApiTesterTab` around line 479).
**Test:** the existing API Tester test (`grep -ln "KeyValueTable\|VariablesPanel" tests/`).

Screenshots: `Pasted image 20261119180949.png` (Headers) and `Pasted image 20261119181005.png` (Variables: the three columns are bunched at the left of a wide table) in `C:\Users\Joshua Wetlesen\Documents\Obsidian Vault\`.

- [ ] **Step 1: Write the failing tests.**
  - Params and Headers each have an "Add" and a "Remove" button above the table, laid out as Variables' are.
  - Add puts the cursor in the Name cell of the ready empty row (the last one); it never leaves two empty rows.
  - Remove deletes the row of the current cell and emits `changed`; with only the ready empty row, it does nothing; an empty row is always left to type into.
  - `rows()` and `set_rows()` behave as before (saved requests load unchanged).
  - Variables table, shown 900 px wide: the three columns together fill the viewport, Value takes the slack, Secret stays narrow.
- [ ] **Step 2:** Run and see them fail.
- [ ] **Step 3: Implement.** For Variables, find why the columns don't fill the width (the code already asks column 1 to stretch) and fix that cause; don't paper over it with fixed widths.
- [ ] **Step 4:** Run the API Tester tests. **Step 5:** Commit "API Tester: Add and Remove for parameters and headers; Variables fills its width".

### Task 6: Fixed releases on the Vulnerabilities tab (item 4)

**Files:** `ui/vulntab.py` (`COLUMNS`, the rows built for `DetailList`), `core/advisories.py` (the message is built at line 614: `title + " Fixed in A, B, C."`; NVD builds read "build X"), `ui/scanning.py` (`FIXED_BUILD`, the existing reader of that sentence), `ui/tablefit.py`.
**Test:** the existing Vulnerabilities tab test (`grep -ln "vulntab\|VulnTab" tests/`).

Screenshot: `Pasted image 20261119173736.png` (the table stops short of its frame).

- [ ] **Step 1: Write the failing tests.**
  - `COLUMNS` is Advisory, Title, Fixed in, CVSS, Exploited, Link.
  - A row whose message names releases shows them in "Fixed in", comma separated, as the message has them; the Title cell does not repeat the "Fixed in ..." sentence.
  - A row with a fixed build shows it as the Scanning page words it.
  - A row that names no fix has a blank "Fixed in" cell.
  - The table fills its frame's width at 1200 px and at 800 px (Title takes the slack; nothing is cut off without a tooltip or elision, as the other fitted tables do).
- [ ] **Step 2:** Run and see them fail.
- [ ] **Step 3: Implement.** One reader of the "Fixed in" sentence, shared with `ui/scanning.py` if both need it (put it in `core/advisories.py` next to the code that writes the sentence). Fit the table the way the other tables were fixed (`ui/tablefit.py`).
- [ ] **Step 4:** Run the vulnerabilities, scanning and advisories tests. **Step 5:** Commit "Vulnerabilities: a Fixed in column, and the table fits its width".

### Task 7: Uptime for every vendor (item 1)

**Files:** `core/checks.py` (`CATALOG`), `drivers/fortinet.py`, `drivers/proxmox.py`, `drivers/mist.py`, and `drivers/meraki.py`, `drivers/unifi_protect.py`, `drivers/unifi_cloud.py` where the vendor's API allows.
**Test:** each driver's existing test file, plus any test that counts a vendor's catalogue entries.

Today's catalogue has no `uptime` for: `fortinet`, `meraki`, `cloud`, `wifi`, `proxmox`, `mist`, `unifi_protect`, `unifi_cloud`. `cloud` and `wifi` stay without (owner).

- [ ] **Step 1: Find the source for each vendor** in the vendor's own API documentation (reading documentation on the web is allowed; downloading files is not).
  - **Fortinet (required):** the FortiOS REST monitor API field that gives uptime or the last boot time. Say in a code comment where the field comes from, as the BGP comment at the top of `drivers/fortinet.py` does.
  - **Proxmox, Mist (required):** their drivers already produce an uptime row (`drivers/proxmox.py:63`, `drivers/mist.py:54`); it only needs its own catalogue entry and `self.enabled("uptime")`.
  - **Meraki, UniFi Protect, UniFi Site Manager:** add the check only when the API documents an uptime or boot time for the device. Otherwise leave the vendor out and say so in the report, with the page you read.
- [ ] **Step 2: Write the failing tests**, from fake replies in the shape the documentation gives:
  - each added vendor's catalogue has `uptime` with the label the other vendors use;
  - the row is graded like the others (`grade_low` against `th["uptime"]`, value `display.uptime(hours)`, "recent reboot" when it isn't OK, `numeric=hours`);
  - a reply without the field gives no uptime row and no exception;
  - unticking `uptime` removes the row (Proxmox and Mist included).
- [ ] **Step 3:** Run and see them fail. **Step 4:** Implement.
- [ ] **Step 5:** Run every changed driver's tests, `tests/test_checks_tabs.py`, `tests/test_monitoring_profiles_ui.py` and any test that counted the old catalogue. **Step 6:** Commit "Uptime check for Fortinet, Proxmox, Mist and the vendors whose API reports it".

---

## Part 2 (waits for the owner to approve the wording below)

Not approved yet; do not build until the owner says so.

**Item 12, Settings > Security:** row "Keep passwords from the password manager for" with the approved options, and the note "How long Toner's vault keeps a copy of each password it reads from the password manager. When the time is up Toner reads the password again; if the password manager can't be reached then, checks that need it fail. Off keeps passwords in memory only." Not an admin: the drop-down is disabled with the existing "Your role doesn't allow this. Ask an admin." Existing installs: copies off becomes Off, copies on becomes 24 Hours.

**Item 8, Settings > Scanning:** row "Scan automatically" (Off, Daily, Weekly, Bi-Weekly, Monthly), row "Devices" (the group picker Checks > Schedule uses), and the note "Scans the chosen devices for vulnerabilities and hardening while Toner or its background service is running. The results are on the Scanning page."

**Item 7, Settings > Reports:** rows "Trend report", "Vulnerability report" and "Hardening report", each with its drop-down, "Email it to" and "Send now"; the note "Each report is saved to the default folder and emailed to its addresses through the first Email channel in Settings > Notifications. The vulnerability and hardening reports use the latest scan."; results "Sent to {n} addresses.", "Couldn't send the report: {reason}" and "No scan yet. Scan on the Scanning page first."

### Task 8: Credential cache time (item 12) — to be detailed after approval
### Task 9: Scheduled scans (item 8) — to be detailed after approval
### Task 10: Scheduled and sent reports (item 7) — to be detailed after approval

## Part 3

### Task 11: OAuth 2.0 for email (item 6) — its own design and plan, approved by the owner before any code
