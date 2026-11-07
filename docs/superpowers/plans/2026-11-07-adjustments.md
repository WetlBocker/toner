# Adjustments (before Part 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Work through the owner's 14 adjustments (C:\Users\Joshua Wetlesen\Documents\Obsidian Vault\Adjustments.md), including UniFi devices shown one by one under their gateway or site.

**Architecture:** Mostly small, independent UI and core fixes. The one larger change, UniFi, keeps a single API call per gateway or site. Each device's results come from that call and are shown as rows under the parent in Inventory, each with its own page. A Site Manager account adds one inventory entry per site the admin ticks.

**Tech Stack:** Python 3.13, PySide6, ECharts through `ui/chartspec.py`, `requests`. No new dependencies.

**Spec:** the owner's list (path above, with screenshots beside it in the same folder) and the decisions below, made in chat on 2026-11-07. Both are binding.

## Owner decisions (2026-11-07)

1. **Overview.** Remove the "Last runs" and "Recent activity" cards.
2. **Search box.** The clear "X" sits off-centre inside the search box. It must sit vertically centred and inside the box's padding.
3. **CVSS scores.** The scores become a pie (doughnut) chart. The legend uses the bars' labels: "0–4", "4–7", "7–9", "9–10". Check its spacing against the chart beside it.
4. **Subnet calculator, divide view.**
   - Add the columns "Broadcast", "Subnet mask" and "Wildcard mask".
   - Join works on the subnets the person selects (two or more) and merges them into the one network they form.
   - When they can't form one network: "These subnets can't be joined into one network."
5. **MAC OUI download.** IEEE answers 418 to Python's default User-Agent. Send a normal browser User-Agent, and keep the proxy settings.
6. **History page charts** follow the kind of data:
   - a reading over time (CPU %, temperature, latency): line chart;
   - one value per device (counts, sessions, today's CPU): bar chart;
   - checks with only OK/WARN/FAIL: stacked bar of how often each status happened;
   - text values (firmware version, model, licence): a table, no chart.
7. **Gauges.** The needle must point at the value on the arc. Today the pointer and anchor `offsetCenter [0, "-12%"]` move the pivot off the ring's centre.
8. **UniFi.**
   - **Network API.** The gateway's inventory entry gets an expand arrow that lists the controller's devices (APs, switches and so on), taken from the gateway's own check results. These are views: no extra polling, credentials, Edit or schedule. Each device row opens a page with that device's dials, history and trends.
   - **Site Manager API.** When the account is added, the Add dialog lists the account's sites with tick boxes. Each ticked site becomes its own inventory entry (the site's gateway, sharing the account's API key, scoped to that site), with that site's devices under it as views. New sites are added by hand.
   - **A device the controller no longer reports** keeps its row, greyed, with its history, until the person removes it.
   - The device page's dials show only that one device's readings. This fixes "gauges for the first 3 devices".
9. **User menu.** Move the user drop-down (name, Lock, Sign out) so it sits above Settings in the sidebar.
10. **IP lookup** becomes provider-neutral.
    - Settings take "API URL" (hint: "Use {ip} where the address goes, and {key} for the key") and "API key". The key goes to the vault, as today.
    - The lookup fills `{ip}` and `{key}` and shows the provider's JSON answer as a readable list of fields (nested keys flattened with dots).
    - The current ipstack setup carries over as the default URL, `http(s)://api.ipstack.com/{ip}?access_key={key}`, so existing users keep working.
11. **Failed status icon** pulses again, as before (for example in "Network at a glance").
12. **Constellation backdrop.** Each dot moves smoothly on its own random path across the whole background, not along the edges. Do this for every theme that uses it.
13. **Password-manager collections.**
    - The Collection cell is clearly editable: an aligned editor of the same height as the cell, a visible edit cue (the house edit style), and no text drawn twice.
    - Make sure the default collection name and the item titles no longer start with "Toner - ".
    - Existing collections named "Toner - …" keep working, and orphan detection still recognises them.
14. **Sign-in window** uses Toner's current theme. The theme name is not secret, so keep a plain copy of it outside the encrypted database, written when the theme changes. The sign-in, setup and lock windows read it before anyone signs in.

## Approved wording (owner, 2026-11-07)

- "Broadcast", "Subnet mask", "Wildcard mask"
- "These subnets can't be joined into one network."
- "API URL", "Use {ip} where the address goes, and {key} for the key", "API key"
- "0–4", "4–7", "7–9", "9–10"
- UniFi (approved 2026-11-07):
  - the Add dialog's site list heading "Sites";
  - a gone device's row: "{name} (not seen since {date})".

## Global Constraints

- Every user-facing string comes from the approved wording above, or shipped before this plan. Anything else: stop and ask (NEEDS_CONTEXT).
- No secret in logs, the audit, exceptions or `netcheck.keys`. Secret boxes are emptied with `setText("")`.
- Windows, Linux and macOS ship together. Tests run headless (`QT_QPA_PLATFORM=offscreen`) on Windows and WSL (`~/toner-venv/bin/python`). Tests are plain scripts in the house style, and each prints `N passed, M failed`, because `run_all` parses that.
- No new dependencies. Never stage `.postman/`, `postman/`, `.impeccable/` or `.superpowers/`. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No pushes.
- Slow work (network, LDAP, file downloads) never runs on the UI thread.
- Motion respects `ui.motion.enabled()` (reduced motion means still).

## Review Focus

1. **UniFi with many devices** (hundreds of APs across many sites). Expanding a gateway must stay quick, and a page must not freeze. Task 8 tests 300 devices.
2. **Subnet Join with a gap or misaligned subnets.** For example 10.0.0.0/27 + 10.0.0.64/27, or 10.0.0.32/27 + 10.0.0.64/27. These must refuse with the approved sentence, never produce a wrong supernet. Task 4 tests both.
3. **IP lookup answers that aren't JSON, are huge, or nest deeply.** Show a readable error or a truncated list, never a crash. A URL without `{ip}` must be refused before saving. Task 10 tests these.
4. **Sign-in theme before any database exists** (first start, or a missing plain copy). It must fall back to the default theme. Task 14 tests it.
5. **Existing ipstack users and existing "Toner - …" collections** keep working after the change. Tasks 10 and 13 test them.

---

### Task 1: Small fixes batch (items 1, 2, 5, 7, 9, 11)

**Files:** `ui/dashboard.py` (1); the search box with `setClearButtonEnabled` in `ui/inventory.py:1013` and the shared style in `ui/widgets.py` or the theme QSS (2); `core/oui.py:70` (5); `ui/chartspec.py` `gauge` (7); `ui/nav.py` / `app.py` user menu (9); the status icon pulse in `ui/glance.py` and `ui/orgboard.py`, plus wherever the FAIL icon used to pulse (`git log -S` for the pulse) (11).
**Test:** `tests/test_adjustments_batch.py`, plus existing tests updated.

- [ ] **Step 1: Write the failing tests.**
  - (1) The overview has no card titled "Last runs" or "Recent activity".
  - (2) The clear action's icon rect is vertically centred within 1 px of the line edit's content rect.
  - (5) `oui.download` sends a User-Agent that isn't python-requests'. Patch `requests.get`.
  - (7) The gauge option's pointer and anchor `offsetCenter` are `[0, 0]`. The needle angle for 50% of 100 is the arc's midpoint (`startAngle` 200, `endAngle` -20).
  - (9) The user menu button's sidebar index is above Settings.
  - (11) A FAIL status icon has a running pulse animation when motion is on, and none when motion is off.
- [ ] **Step 2: Run them, and see them fail.**
- [ ] **Step 3: Implement.** For (11), find the change that stopped the pulse and restore it. Don't build a new one.
- [ ] **Step 4: Run** the new test and the dashboard, glance, nav, chart and OUI tests, on Windows and WSL.
- [ ] **Step 5: Commit** "Small adjustments: overview cards, clear button, OUI download, gauge needles, user menu, failed pulse".

### Task 2: CVSS pie chart (item 3)

**Files:** the CVSS card in `ui/tools.py` (where "CVSS scores" lives); `ui/chartspec.py` (a `pie` helper if none exists).
**Test:** extend the advisories/tools chart test.

- [ ] **Step 1:** Test that the CVSS chart option is a pie/doughnut series with the four approved labels and the same colours as before. Test that the card's height matches its neighbour's, and that the legend doesn't overlap the chart beside it at 1280 px wide.
- [ ] **Step 2:** Run it and see it fail. **Step 3:** Implement. **Step 4:** Run on both platforms. **Step 5:** Commit "CVSS scores as a pie chart".

### Task 3: Subnet calculator (item 4)

**Files:** the divide view in `ui/tools.py` ("Split in two" / "Join"); the subnet maths in core (`core/nettools.py` or the module the calculator uses).
**Test:** `tests/test_subnet_divide.py`

- [ ] **Step 1: Write the failing tests.**
  - The columns include "Broadcast", "Subnet mask" and "Wildcard mask" with correct values for /24, /27 and /31 (no broadcast row text for /31 and /32 beyond what the calculator shows elsewhere).
  - Selecting 10.0.0.0/27 and 10.0.0.32/27 then Join gives 10.0.0.0/26 in the tree.
  - Selecting all four /27s of a /25 gives the /25.
  - 10.0.0.0/27 + 10.0.0.64/27, and 10.0.0.32/27 + 10.0.0.64/27, refuse with "These subnets can't be joined into one network." and leave the tree unchanged.
  - Joining one subnet does nothing.
- [ ] **Step 2:** Run it and see it fail.
- [ ] **Step 3: Implement `join(networks) -> network | None`** in core: sort, then require that they exactly cover one aligned supernet. Use `ipaddress.collapse_addresses`, and accept only when the result is a single network whose address count equals the sum. The tree selection becomes multi-select.
- [ ] **Step 4:** Run on both platforms. **Step 5:** Commit "Subnet calculator: broadcast and masks, join the subnets you pick".

### Task 4: History charts by kind of data (item 6)

**Files:** `ui/history.py`; `ui/chartspec.py`.
**Test:** extend `tests/test_history*.py`, or add `tests/test_history_charts.py`.

- [ ] **Step 1: Write the failing tests** with seeded results:
  - a CPU % check over time → line;
  - a per-device count across devices → bar;
  - an OK/WARN/FAIL-only check → stacked bar of status counts;
  - a firmware-version text check → a table on Across Devices, and no line chart. This is the owner's example.
  - Every chart tab picks its chart from the data kind, not only Over Time.
- [ ] **Step 2:** Run it and see it fail.
- [ ] **Step 3: Implement `chart_kind(rows) -> "line" | "bar" | "status" | "table"`**, decided from whether the rows carry `numeric`, their time spread and their values. Use it on every tab.
- [ ] **Step 4:** Run on both platforms. **Step 5:** Commit "History: the chart follows the kind of data".

### Task 5: UniFi devices under their gateway and sites (item 8)

**Files:**
- `drivers/unifi_network.py`, `drivers/unifi_cloud.py`, `drivers/unifiapi.py`: the result rows already carry each device's label, so add a stable device key to each row (the device id or MAC) if it's missing.
- Core: `core/unifikids.py` (new). It lists a parent's devices from its stored results, and keeps `first_seen`/`last_seen` per device key.
- `ui/inventory.py`: expand rows.
- `ui/device_view.py`: a page for one child, filtered to that child's rows.
- The Add/Edit device dialog: the Site Manager site picker.

**Test:** `tests/test_unifi_children.py`

**Interfaces (produced):**
- `unifikids.children(parent_device) -> [{"key", "name", "model", "last_seen", "gone": bool}]`, worst status first.
- `unifikids.rows_for(parent_device, key) -> latest result rows of that device`.
- The child page reuses `DeviceView` in a child mode: dials, history and trends only; no Edit, Run checks or Back up.

- [ ] **Step 1: Write the failing tests** (with fake API answers as the existing UniFi tests use).
  - **Network API**, a gateway with 3 APs and 2 switches:
    - the gateway row expands to the 5 devices;
    - each child page shows only its own CPU and memory dials, so not "the first 3 devices";
    - the gateway's page no longer shows other devices' dials.
  - **A device missing from a later run** stays listed as "{name} (not seen since {date})", greyed, with its history.
  - **Site Manager:**
    - the Add dialog lists the account's sites under "Sites" with tick boxes;
    - ticking two sites makes two inventory entries scoped to those sites, sharing one API key in the vault (one secret, not two copies);
    - each lists only its own site's devices.
  - **300 devices:** expanding takes under 200 ms, and the list is built once.
  - **No new polling:** one run of the parent makes the same API calls as before.
- [ ] **Step 2:** Run it and see it fail.
- [ ] **Step 3: Implement.** Children come only from the parent's own results; nothing new is stored beyond `first_seen`/`last_seen` per device key. A child row can be removed by hand (right-click, using the existing "Remove"). Removing it forgets its key, not its history rows.
- [ ] **Step 4:** Run the new test, the UniFi driver tests, and test_inventory*/test_device_view* on Windows and WSL.
- [ ] **Step 5: Commit** "UniFi: each device under its gateway or site, with its own page".

### Task 6: IP lookup with any provider (item 10)

**Files:** `core/iplookup.py`; its settings page (find "ipstack" in `ui/settings_pages`); the Subnet Calculator's lookup.
**Test:** extend `tests/test_iplookup*.py`.

- [ ] **Step 1: Write the failing tests.**
  - A URL without `{ip}` is refused before saving.
  - `{ip}` and `{key}` are URL-encoded into place.
  - A JSON answer becomes a flat list: nested keys joined with dots, lists shown as their items, cut at 200 rows.
  - A non-JSON answer, an HTTP error or a timeout shows a readable message using existing approved texts or the provider's own words.
  - An existing ipstack key with no URL saved carries over to the ipstack default URL and still works.
  - The key never appears in a log line or an exception: requests are logged with `{key}` masked.
- [ ] **Step 2:** Run it and see it fail.
- [ ] **Step 3: Implement.** Keep ipstack's https-then-http fallback only when the URL host is ipstack's. Otherwise use exactly the URL given.
- [ ] **Step 4:** Run on both platforms. **Step 5:** Commit "IP lookup: any provider's API URL and key".

### Task 7: Constellation backdrop motion (item 12)

**Files:** `ui/backdrop.py`; `ui/themes.py` (the themes that use it).
**Test:** `tests/test_backdrop_motion.py`

- [ ] **Step 1: Write the failing test.** Over 600 simulated frames:
  - dots visit the middle of the area (each dot's positions spread at least 40% of the width and the height);
  - no more than 20% of samples sit within 5% of an edge;
  - each dot's path differs from the others (seeded);
  - the step per frame is bounded (smooth: no jump over 2% of the width);
  - motion off means the dots don't move.
- [ ] **Step 2:** Run it and see it fail.
- [ ] **Step 3: Implement** a smooth random walk: for each dot, a slowly turning heading plus noise. Wrap softly at the edges, or turn away from them; never slide along them. Use the same per-frame budget as now.
- [ ] **Step 4:** Run on both platforms, and look at each theme that uses it once by hand if possible. **Step 5:** Commit "Backdrop: each dot drifts on its own path".

### Task 8: Password-manager collections (item 13)

**Files:** `ui/vaultsettings.py` (the "Where each organization's passwords go" table); `core/extstore.py` (`container_name`, orphan detection at ~line 319); the item title in `describe()`.
**Test:** extend `tests/test_vaultsettings*.py` / `tests/test_extstore*.py`.

- [ ] **Step 1: Write the failing tests.**
  - The Collection cell has the edit cue.
  - The editor's geometry equals the cell's rect, give or take 2 px, and the text isn't painted twice while editing.
  - The default collection for Global is "Global" and for an organization its name, with no "Toner - " prefix.
  - Item titles have no "Toner - " prefix.
  - An existing stored name "Toner - Global" is still used as-is.
  - Orphan detection still lists a "Toner - Old" collection.
- [ ] **Step 2:** Run it and see it fail. **Step 3:** Implement. **Step 4:** Run on both platforms. **Step 5:** Commit "Password manager: a clear collection editor, no 'Toner - ' prefix".

### Task 9: Sign-in in Toner's theme (item 14)

**Files:** `ui/settings_pages/appearance.py` (write the plain copy when the theme changes); `ui/signinwindow.py`, `ui/setupdlg.py`, `ui/lockscreen.py`, and the code in `app.py` that styles them before sign-in (`plain_look`).
**Test:** `tests/test_signin_theme.py`

- [ ] **Step 1: Write the failing tests.**
  - After choosing a theme, the plain copy (a tiny JSON file in the data folder, holding only the theme's name) has that name.
  - A new sign-in window uses that theme's palette.
  - With no copy, or a damaged copy, it uses the default theme.
  - The file holds nothing but the theme name.
  - Lockdown leaves it plain: add it to the plain-files list beside `toner.log`. This is a new exception, so say so in the report.
- [ ] **Step 2:** Run it and see it fail. **Step 3:** Implement. **Step 4:** Run with test_signin_ui and test_lockdown* on both platforms. **Step 5:** Commit "Sign-in uses Toner's theme".

### Task 10: Docs and the whole suite

**Files:** `README.md` (only where a changed feature is described: IP lookup, subnet join, UniFi devices); the release notes for the next version, if a draft exists. Owner-approved sentences only. Ask before adding prose.

- [ ] **Step 1:** List the README lines that describe IP lookup (ipstack), the subnet Join, and UniFi. Show the owner the proposed replacement sentences and wait.
- [ ] **Step 2:** Run the whole suite on Windows, then WSL (not at once). Run pyflakes as CI runs it. Re-run any unclean file alone.
- [ ] **Step 3: Commit** "Docs: adjustments".
