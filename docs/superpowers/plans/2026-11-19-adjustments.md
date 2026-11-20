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

## Part 2

Wording approved by the owner on 2026-11-19 (it counts as approved wording for the Global Constraints):

**Item 12, Settings > Security:** row "Keep passwords from the password manager for" with the approved options, and the note "How long Toner's vault keeps a copy of each password it reads from the password manager. When the time is up Toner reads the password again; if the password manager can't be reached then, checks that need it fail. Off keeps passwords in memory only." Not an admin: the drop-down is disabled with the existing "Your role doesn't allow this. Ask an admin." Existing installs: copies off becomes Off, copies on becomes 24 Hours.

**Item 8, Settings > Scanning:** row "Scan automatically" (Off, Daily, Weekly, Bi-Weekly, Monthly), row "Devices" (the group picker Checks > Schedule uses), and the note "Scans the chosen devices for vulnerabilities and hardening while Toner or its background service is running. The results are on the Scanning page."

**Item 7, Settings > Reports:** rows "Trend report", "Vulnerability report" and "Hardening report", each with its drop-down, "Email it to" and "Send now"; the note "Each report is saved to the default folder and emailed to its addresses through the first Email channel in Settings > Notifications. The vulnerability and hardening reports use the latest scan."; results "Sent to {n} addresses.", "Couldn't send the report: {reason}" and "No scan yet. Scan on the Scanning page first."

### Task 8: Credential cache time (item 12)

**Files:** `core/extstore.py` (`keep_copies`, `memory_only`, `set_keep_copies`, the sync round `_sync_once`, `_loop`, `start`), `core/db.py` (the setting's default beside `vault_keep_copies`, lines 139 and 1230), `ui/vaultsettings.py` (`VaultSection`: `self.copies`, `_copies`, `copies_note`), `ui/settings.py` (`KEY_LABELS`).
**Test:** `tests/test_extvault.py` and the vault settings UI test (`grep -ln "VaultSection\|set_keep_copies" tests/`).

**Interfaces (produces):**
- Setting `vault_cache_hours`: `0` (Off), `1`, `4`, `8`, `12` or `24`. It replaces `vault_keep_copies`. While it has never been set: `vault_keep_copies` False reads as `0`, anything else as `24`.
- `extstore.CACHE_CHOICES = [("Off", 0), ("1 Hour", 1), ("4 Hours", 4), ("8 Hours", 8), ("12 Hours", 12), ("24 Hours", 24)]`, `extstore.cache_hours() -> int`, `extstore.set_cache_hours(hours)` (raises `CannotSwitch` as `set_keep_copies` does).
- `keep_copies()` is `active() == "toner" or cache_hours() > 0`; `memory_only()` stays its opposite. Toner's own vault as the store is unaffected by all of this.

**Behaviour:**
- **Off** is today's "copies off": passwords are read from the manager when Toner starts and kept in memory only.
- **N hours:** Toner's vault keeps copies, as "copies on" does today. Toner remembers when it last completed a round with the manager (persisted, so it survives a restart). When a manager is the store and that was N hours ago or more (checked when Toner starts and on every pass of the 5-minute loop), the copies are removed from Toner's vault: every password name that is not internal (`~ext/`), not local (`~toner/`) and not waiting in the unsent queue. The next round that reaches the manager reads them back and restarts the clock. Until then those passwords are unavailable and checks that need them fail, as they do today when a password is missing.
- **Never lost:** a change still waiting in the queue keeps its value until it is sent (removing it would lose the person's edit). Toner's own login for the manager and the `~toner/` entries are never removed.
- Changing between two hour values only stores the number. Off to N and N to Off go through what `set_keep_copies(True/False)` does today, with its existing refusal message.
- No password, and no password name, goes into a log, exception or audit line. The audit says only that copies were removed because the manager was not reached for N hours, in the style the module's other audit lines use (if the module writes none today, write none and say so in the report).

**UI:** the drop-down "Keep passwords from the password manager for" replaces the tick box, with the approved note under it. It appears where the tick box does (only with a manager chosen). When `perms.is_admin()` is false it is disabled and its tooltip is `perms.REASON`; the handler also refuses a change from a non-admin (the UI is not the only guard). `KEY_LABELS["vault_cache_hours"]` is the row label.

- [ ] **Step 1: Write the failing tests** (a fake manager and an injected clock; no real time, no real manager):
  - never set + `vault_keep_copies` False reads 0; never set + True or unset reads 24;
  - with 4 hours: 3 h 59 min after the last round the copies are still in the vault; at 4 h they are gone, the queue and its waiting values are intact, `~toner/` entries and the manager's login are intact;
  - after the removal, a round that reaches the manager puts the passwords back and a further 3 h 59 min keeps them;
  - a restart 5 hours after the last round removes them before anything reads a password;
  - Off behaves as copies off does today (the existing copies-off tests pass when driven through `set_cache_hours(0)`);
  - 4 to 12 changes nothing in the vault; N to Off while the manager is unreachable raises `CannotSwitch` with the existing message;
  - the drop-down has the six approved options in order, shows the stored one, is disabled for a non-admin with `perms.REASON` as tooltip, and a non-admin call to the handler changes nothing;
  - the page's change tracking lists the new setting under its row label.
- [ ] **Step 2:** Run and see them fail. **Step 3:** Implement. Update every reader of `vault_keep_copies` (`grep -rn "vault_keep_copies\|keep_copies\|set_keep_copies" core ui tests`); settings export/import (`core/db.py:1230`) carries the new key instead.
- [ ] **Step 4:** Run `tests/test_extvault.py`, every test that mentions the vault settings or `passvault`, and `tests/test_perms.py`. **Step 5:** Commit "Password manager: choose how long Toner keeps its copies".

### Task 9: Scheduled scans (item 8)

**Files:** new `core/periods.py`; `core/advisories.py` (or a small new `core/scansched.py` if that file is already too long); `core/trends.py` (`due`); `ui/settings_pages/scanning.py`; the one-minute hooks that call `trends.due()` at `app.py:983` and `core/service.py:193`; `ui/scanning.py` / `ui/results.py` (`start_scheduled`); `ui/settings.py` (`KEY_LABELS`).
**Test:** new `tests/test_scan_schedule.py`; the Scanning settings page test.

**Interfaces (produces, Task 10 uses them):**
- `core/periods.py`: `DAYS = {"daily": 1, "weekly": 7, "biweekly": 14, "monthly": 28, "quarterly": 91}`, `LABELS = {"": "Off", "daily": "Daily", "weekly": "Weekly", "biweekly": "Bi-Weekly", "monthly": "Monthly", "quarterly": "Quarterly"}`, `is_due(kind, last, now=None) -> bool` (`kind` not in `DAYS`: False; `last` empty or unreadable: True; else `now - last >= DAYS[kind]` days; `last` is a string in `trends.FMT`). `trends.due` uses it (monthly stays 28 days, so nothing changes for existing users).
- Settings `scan_schedule` (`""`, `daily`, `weekly`, `biweekly`, `monthly`), `scan_groups` (group labels, as `schedule_groups`), `scan_last`.
- `scan_due(now=None) -> bool` and `run_scheduled_scan(now=None) -> list` (the rows; it saves them the way the Scanning page saves a scan, so the page's "Latest scan" shows them, and stores `scan_last`).

**Behaviour:**
- Settings > Scanning gains the row "Scan automatically" (Off, Daily, Weekly, Bi-Weekly, Monthly), the row "Devices" (the same `GroupPicker` Checks > Schedule uses, same meaning of an empty choice and of groups that no longer exist, see `core/service.py` `_groups_alive`) and the approved note.
- The schedule belongs to the same scope `trend_schedule` does and is ticked from the same two places. Only the process that owns the schedule runs it (`service.owns_schedule()`), as for the trend report.
- In the window the scan runs on the Scanning page's own worker (never the UI thread), and not while a scan is already running. In the service it runs in the service's loop like the trend report.
- `scan_last` is stored before the scan's network work ends in a way that a failing source cannot make it scan again every minute (the trend report's comment at `core/trends.py` explains the same rule).
- A scheduled scan sends no alerts (a manual scan sends none today; keep whatever the Scanning page does). It writes one audit line in the style of the "config backup" one in `core/service.py`.

- [ ] **Step 1: Write the failing tests:** `is_due` at each period's boundary (one minute short, exactly on); off never due; never run is due; the scan covers only enabled devices in the chosen groups; groups that are all gone scan nothing; the rows are saved and `scan_last` set even when one device's scan raises; a second tick a minute later does not scan again; the settings page loads, saves and change-tracks both settings with the approved labels; `trends.due` still answers as before for weekly and monthly.
- [ ] **Step 2:** Run and see them fail. **Step 3:** Implement. **Step 4:** Run the new test, the scanning, trends, service and settings tests.
- [ ] **Step 5:** Commit "Scanning: scan on a schedule".

### Task 10: Scheduled and sent reports (item 7)

**Files:** `ui/settings_pages/appearance.py` (`ReportsPage`), `core/trends.py` (`SCHEDULES`, `due`, `generate_scheduled`), a small new `core/scanreports.py` (the vulnerability and hardening reports from the latest scan), `core/reports.py` (the existing report writers; `ui/scanning.py` `export` shows how a scan report is made today), the two one-minute hooks (`app.py:983`, `core/service.py:193`), `ui/settings.py` (`KEY_LABELS`).
**Test:** the Reports settings page test and the trend report tests (`grep -ln "trend_schedule\|ReportsPage" tests/`), new `tests/test_scan_reports.py`.

**Interfaces (consumes):** `core/periods.py` from Task 9 (`DAYS`, `LABELS`, `is_due`).

**Behaviour:**
- Settings > Reports has three report rows, each followed by its own "Email it to" row with a "Send now" button: "Trend report", "Vulnerability report", "Hardening report". Each drop-down is Off, Weekly, Bi-Weekly, Monthly, Quarterly. One approved note under them replaces today's "Sent through the first Email channel..." note. "Also one report per organization" stays with the trend report.
- Settings: `trend_schedule`, `trend_email`, `trend_last` keep their names and their stored values (`weekly`, `monthly` still mean what they did); new `vuln_report_schedule`, `vuln_report_email`, `vuln_report_last`, `hardening_report_schedule`, `hardening_report_email`, `hardening_report_last`.
- The trend report covers the period it is sent for: 7, 14, 30 or 90 days (weekly and monthly as today).
- The vulnerability report holds the latest scan's vulnerability rows, the hardening report its hardening rows, per device in scope, made with the writers the Scanning page's Export uses. Titles: "Toner Vulnerability Report" (exists) and "Toner Hardening Report". File names follow the trend report's: `Toner-vulnerability-YYYY-MM-DD`, `Toner-hardening-YYYY-MM-DD` (PDF with a window, HTML from the service).
- On schedule: saved to the default folder, then mailed to that report's addresses with `notify.mail_files`, with a subject and body in the pattern the trend report's mail uses; `*_last` is stored before the mail, and a refusal is written to the audit log as the trend report's is. With no scan yet, nothing is made or sent, and `*_last` is not stored.
- Send now: makes that report now and mails it to the addresses in its box (the box's current text, validated as on save), on a worker thread, without touching `*_last`; with no default folder it is made in a temporary folder that is removed afterwards. The button is disabled while its box is empty and while a send is running. The result appears beside the button: "Sent to {n} addresses." ("Sent to 1 address." for one), "Couldn't send the report: {reason}" (the reason from `mail_files`, already scrubbed of secrets), or "No scan yet. Scan on the Scanning page first."
- Validation on save: as today for the trend report, and the same rules for the other two (a schedule needs the default folder; addresses must be valid; addresses need an Email channel), wording as the existing messages with the report's name in place of "trend report".

- [ ] **Step 1: Write the failing tests:** the drop-downs' options and stored values; old `weekly`/`monthly` settings load as Weekly/Monthly; each report's due-ness at its boundary; the trend window per period; the vulnerability report has only vulnerability rows and the hardening report only hardening rows from the latest scan; no scan means nothing made and `*_last` unset; a refusing mail server leaves the file saved, `*_last` set and an audit line with no secret; Send now's three results (with a fake `mail_files`), the singular form, the disabled states, and that it runs off the UI thread and leaves `*_last` alone; the page change-tracks all nine settings.
- [ ] **Step 2:** Run and see them fail. **Step 3:** Implement. **Step 4:** Run the new test, the reports, trends, scanning, notify and settings tests.
- [ ] **Step 5:** Commit "Reports: vulnerability and hardening reports, each on its own schedule, and Send now".

## Part 3

### Task 11: OAuth 2.0 for email (item 6) — its own design and plan, approved by the owner before any code
