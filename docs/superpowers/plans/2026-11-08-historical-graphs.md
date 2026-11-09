# Historical Graphs and Device Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every check's history is drawn as the chart the owner chose. History gets a time range instead of a runs list.
Across devices shows gauges, tables and rings. The device page gets the right dials, uptime, vulnerabilities and WAN usage.
Every table in Toner sizes its columns to fit.

**Architecture:**
- Results can carry per-item detail, stored in a new `result_items` table. Charts read the items instead of parsing messages.
- A single chart table (`core/chartkinds.py`) decides each check's picture.
- One shared Over time widget (`ui/overtime.py`) draws a panel per check for both the History page and the device page.
- A pure grid function (`core/heatgrid.py`) lays out every heatmap.
- One table-fitting helper is installed app-wide.

**Tech Stack:** Python 3.13, PySide6, SQLite, ECharts (via `ui/webchart.ChartView` and `ui/chartspec`), pyqtgraph
(`ui/history.ChartStack`), and the Go agent (`agent/`, using go-ole, which is already a dependency).

**Spec:** `docs/superpowers/specs/2026-11-08-historical-graphs-design.md` (approved 2026-11-08). Read it before any task.

## Global Constraints

- Every new user-facing string comes from the **Strings** appendix at the end of this plan, which the owner approves before execution. Any string not in the appendix needs the owner's approval first.
- Windows, Linux and macOS share one version number. Agent changes ship in the same release. Don't bump the version in this plan.
- Older agents and older history must keep working. Missing new fields mean "not reported", never an error.
- No change to how existing checks are graded or alerted on. The only new graded check is `wan usage`.
- Never stage `.postman/`, `postman/`, `.impeccable/` or `.superpowers/`.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Commit after each task. Never push.
- Tests are scripts with a `check(name, cond, extra)` helper. Run one with `python tests/test_<name>.py`, and a group with `python tests/run_all.py <word>`. Copy the header (paths, `NETCHECK_DB`, keyring fake, offscreen Qt) from `tests/test_assistant_motion.py`. CI also runs `python -m pyflakes core drivers ui app.py cli.py`, and `go vet ./...` and `go test ./...` in `agent/`.
- Animations follow `ui/motion`. Secrets never appear in a chart, table or detail list.

## Review Focus

1. **A range with no readings** (a new device, or a check turned off): every panel shows the approved empty text, and nothing raises. Pinned in Task 9.
2. **History saved before items existed:** a disk gauge falls back to the row's `numeric` (the fullest disk), and a certificates table falls back to the row's value and message. Pinned in Tasks 2 and 9.
3. **The Global view with several organizations:** devices come back as `dkey` keys from every file, in the range queries and in the across-device queries. Pinned in Task 3.
4. **An older agent report with no `pending_updates` or cert `expires`:** the wheel says "not reported by this computer's agent yet", the patches grade doesn't change, and certificates show days left with no date. Pinned in Tasks 7 and 9.
5. **A WAN interface that has been renamed or removed:** it is kept in the picker as "Not on the device now", the wan usage row skips it, and the dial disappears. Pinned in Task 8.

---

### Task 1: Every table sizes its columns to fit

**Files:**
- Create: `ui/tablefit.py`
- Modify: `app.py` (install it once, right after the `QApplication` exists, before `Main()`)
- Test: `tests/test_tablefit.py`

**Interfaces:**
- Produces:
  - `fit_widths(content: list[int], header: list[int], available: int) -> list[int]`
  - `fit(view: QAbstractItemView) -> None`
  - `install_everywhere(app: QApplication) -> None`

- [ ] **Step 1: Write the failing test** (`tests/test_tablefit.py`)

```python
from ui.tablefit import fit_widths, fit
check("room for everything: each column is its content width", fit_widths([80, 200, 50], [40, 60, 40], 1000) == [80, 200, 50])
w = fit_widths([80, 600, 300], [40, 60, 40], 500)
check("too narrow: they share the width exactly", sum(w) == 500, w)
check("...the widest gives way first, the small one is untouched", w[0] == 80 and w[1] < 600, w)
check("...none goes under its header", all(a >= h for a, h in zip(fit_widths([80, 600, 300], [70, 300, 200], 400), [70, 300, 200])))
t = QTableWidget(3, 2); t.setHorizontalHeaderLabels(["Name", "Message"])
t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
t.setItem(0, 1, QTableWidgetItem("x" * 120)); t.resize(2000, 300); t.show(); fit(t); app.processEvents()
check("a ResizeToContents header becomes Interactive, so it can be dragged", all(t.horizontalHeader().sectionResizeMode(i) == QHeaderView.ResizeMode.Interactive for i in range(2)))
check("the long column shows all its text", t.columnWidth(1) >= t.fontMetrics().horizontalAdvance("x" * 120))
t.horizontalHeader().resizeSection(0, 300)                      # the person drags it
t.setItem(1, 0, QTableWidgetItem("y")); app.processEvents()
check("a dragged column keeps its width after the data changes", t.columnWidth(0) == 300)
```

Also check that a tooltip shows the full text for a cell whose text is cut off. Call the viewport's event filter with a
`QHelpEvent`, or check the text it returns through the helper's `full_text_at(view, pos)`.

- [ ] **Step 2: Run it.** `python tests/test_tablefit.py` should fail with `ModuleNotFoundError: ui.tablefit`.
- [ ] **Step 3: Implement `ui/tablefit.py`.**
  - `fit_widths` water-fills. It finds the level L where the sum over columns of `min(content_i, max(L, header_i))` equals `available`. Every column gets at least its header width, even if the total then exceeds `available`.
  - `fit(view)` does the following:
    - Sets every section to `Interactive` and keeps `stretchLastSection`.
    - Calls `setResizeContentsPrecision(200)`, so it measures at most 200 rows.
    - Measures each column with `sizeHintForColumn`, against the header's `sectionSizeFromContents`.
    - Re-fits on `modelReset`, `rowsInserted`, `dataChanged` and resize. These are debounced through one 0 ms `QTimer`.
    - Remembers which sections the person resized, via `sectionResized` while it isn't fitting, and leaves those alone until the view is destroyed.
    - Shows the full text of a cut-off cell as a tooltip.
  - `install_everywhere(app)` installs an application event filter. On `QEvent.Type.Polish` of any `QTableView` or `QTreeView` it calls `fit` once per view, tracked with a weak set.
- [ ] **Step 4: Run it.** `python tests/test_tablefit.py` should PASS. Then run `python tests/run_all.py` and confirm nothing that measured widths broke. Fix any test that asserted a `Stretch` or `ResizeToContents` mode, since those are now meant to be `Interactive`.
- [ ] **Step 5: Commit.** `git add ui/tablefit.py app.py tests/test_tablefit.py` (plus any tests changed), with the message "Tables: columns fit their text and can always be dragged".

### Task 2: Results can carry items

**Files:**
- Modify:
  - `drivers/base.py` (`Result`, `Driver.result`)
  - `core/db.py`: the migration `_m15_result_items` added to `MIGRATIONS`, plus `_save_run_here`, `items_of` and `latest_items`
- Test: `tests/test_result_items.py`

**Interfaces:**
- Produces:
  - `Result.items: Optional[list[dict]]`. Each item is `{"name": str, "numeric": float|None, "status": str|None, "text": str, "data": dict}`, and `data` is stored as JSON.
  - `Driver.result(check, status, value="", message="", numeric=None, items=None)`.
  - `db.items_of(device, check, start=None, end=None) -> list[{"t": str, "items": list[dict]}]`, oldest first.
  - `db.latest_items(device, check) -> tuple[str|None, list[dict]]`. The string is the time.
  - The table is `result_items(result_id INTEGER NOT NULL REFERENCES results(id) ON DELETE CASCADE, pos INTEGER, name TEXT, numeric REAL, status TEXT, text TEXT, data TEXT)`, with an index on `result_id`.

- [ ] **Step 1: Write the failing test.**
  - Save a run with `Result("srv", "disks", "OK", "61%", "", 61.0, items=[{"name": "C:", "numeric": 61.0, "status": "OK", "text": "", "data": {"used": 61e9, "total": 100e9}}])`, plus a row with no items.
  - Check that `db.latest_items("srv", "disks")[1][0]["data"]["total"] == 100e9`.
  - Check that `db.items_of("srv", "disks")` has one entry.
  - Check that the row with no items gives `[]`.
  - Check that pruning runs (`retention_days` set to 0, then a new run saved) leaves no orphan rows in `result_items`.
  - Check that `db.schema_version() == 15`.
  - Check that `type(r)(**{**r.__dict__, "device": "x"})` keeps the items, since `core/notify.py` and `_save_run_here` copy results this way.
- [ ] **Step 2: Run it.** `python tests/test_result_items.py` should fail on `items`.
- [ ] **Step 3: Implement.**
  - Add `items` to `Result` as a field with `compare=False, repr=False`, default `None`.
  - In `_save_run_here`, insert the results row by row, so each `lastrowid` is known, then the items for rows that have them. Keep everything else in the function unchanged, including the kept-history cache.
  - `items_of` and `latest_items` honour `split_key` and `within`, the same way `check_rows` does.
- [ ] **Step 4: Run it.** `python tests/test_result_items.py` should PASS. Then run `python tests/run_all.py db history save` and confirm it is green.
- [ ] **Step 5: Commit** with the message "History: results can carry per-item detail".

### Task 3: Time-range and across-device queries

**Files:**
- Modify: `core/db.py` (`check_rows`, `series`, `_series_here`), plus the new `results_between`, `latest_per_device` and `average_per_device`
- Test: `tests/test_history_queries.py`

**Interfaces:**
- Consumes: Task 2's items.
- Produces:
  - `check_rows(device, check, limit=200, start=None, end=None)`. Rows now also carry `message`. When `start` is given there is no limit.
  - `series(device, check, limit=200, start=None, end=None)`, which behaves the same way.
  - `results_between(start: datetime, end: datetime) -> list[dict]`, newest first. Each row has the keys `t, device (dkey), check_name, status, value, message, numeric`. It reads every file of the view (`_each_file`), as `problems()` does.
  - `latest_per_device(checks: list[str]) -> list[dict]`. It returns each device's newest row among `checks`, with the keys `device (dkey), check_name, status, value, message, numeric, t`.
  - `average_per_device(checks: list[str], days: int) -> dict[str, float]`. It is computed in SQL with `AVG(numeric)` grouped by device, and only includes rows that have a number.

- [ ] **Step 1: Write the failing test.**
  - Seed two organizations, as `tests/test_fleet.py` does. Seed device "a" in Global and device "b" in an organization, with backdated runs. To backdate a run, update `runs.started_at` after `save_run`.
  - Check that `results_between(now - 8h, now)` holds only the rows from the last 8 hours, newest first.
  - Check that it includes b's row, keyed with `db.dkey("b", org)`.
  - Check that `check_rows("a", "cpu", start=now - 90 days)` returns more than 200 rows when more than 200 exist.
  - Check that `check_rows` rows have `message`.
  - Check that `average_per_device(["cpu"], 7)` equals a hand-computed mean.
  - Check that `latest_per_device(["certificate", "certificates"])` returns one row per device.
- [ ] **Step 2: Run it** and confirm it fails.
- [ ] **Step 3: Implement** with indexed SQL on `runs.started_at`. Migration 8 (`_m8_faster_history`) already added indexes; check that they cover these queries. Don't loop over rows in Python to compute averages.
- [ ] **Step 4: Run it** and confirm it passes. Then run `python tests/run_all.py history dashboard trend` and confirm it is green.
- [ ] **Step 5: Commit** with the message "History: queries by time range and per device".

### Task 4: The chart table

**Files:**
- Create: `core/chartkinds.py`
- Test: `tests/test_chartkinds.py`

**Interfaces:**
- Produces:
  - `over_time_kind(check: str, vendor: str | None = None, rows: list | None = None) -> str`. It returns one of `"line", "heatmap", "table", "gauges", "wheel", "config", "uptime", "ha", "certs", "hidden"`.
  - `across_kind(check: str, rows: list | None = None) -> str`. It returns one of `"gauges", "table", "certs", "environment", "firmware", "rings", "health"`.
  - `shown_name(check: str) -> str`. It maps `certificate`, `certificate :<port>` and `certificates` to `certificates`, and `ha sync` to `ha`. Everything else maps to itself.
  - `stored_names(shown: str, available: list[str]) -> list[str]`, the inverse of `shown_name`.
  - `is_measurement(check, vendor=None, rows=None) -> bool`, which is true when `over_time_kind` is `"line"` or `"gauges"`.

- [ ] **Step 1: Write the failing test.** It asserts the spec's tables row by row:
  - `over_time_kind("disk health") == "heatmap"`
  - `over_time_kind("disks") == "gauges"`
  - `over_time_kind("disks", vendor="truenas") == "heatmap"`
  - `over_time_kind("disk") == over_time_kind("storage") == over_time_kind("flash") == over_time_kind("log disk") == "gauges"`
  - `over_time_kind("patches", vendor="windows") == "wheel"`, and `over_time_kind("patches", vendor="ciscoise") == "table"`
  - `over_time_kind("config backup") == "config"`
  - `over_time_kind("uptime") == "uptime"`
  - `over_time_kind("ha") == over_time_kind("ha sync") == "ha"`
  - `over_time_kind("resources") == "hidden"`
  - `over_time_kind("certificate :8443") == "certs"`
  - `over_time_kind("vpn") == over_time_kind("ipsec tunnels") == "heatmap"`
  - `over_time_kind("tasks") == "heatmap"`
  - `over_time_kind("firewall") == over_time_kind("last commit") == "table"`
  - `over_time_kind("reachability") == over_time_kind("clock") == over_time_kind("changes") == "line"`
  - `over_time_kind("interface errors") == "line"`
  - `across_kind("cpu") == "gauges"`
  - `across_kind("antivirus") == "table"`
  - `across_kind("firmware") == "firmware"`
  - `across_kind("interfaces") == "rings"`
  - For an unknown check, the kind follows `ui/history.chart_kind`: numbers at several times give `"line"`, status words give `"heatmap"`, and text gives `"table"`.
  - `across_kind` of an unknown status check gives `"health"`.
- [ ] **Step 2: Run it** and confirm it fails.
- [ ] **Step 3: Implement.** It is two dictionaries keyed by stored check name, plus a small `(vendor, check)` override dictionary for TrueNAS `disks`. Anything not listed falls back to `chart_kind`. Move `chart_kind` from `ui/history.py` into `core/chartkinds.py` and re-export it from `ui/history.py`, so its importers keep working.
- [ ] **Step 4: Run it** and confirm it passes. Then run `python tests/run_all.py history` and confirm it is green.
- [ ] **Step 5: Commit** with the message "Charts: each check's picture chosen on purpose".

### Task 5: The heatmap grid, the status heatmap and the ring

**Files:**
- Create: `core/heatgrid.py`
- Modify: `ui/chartspec.py` (add `status_heatmap` and `ring`), and `ui/history.py` (`draw_failures` and `_fail_cell` use `heatgrid`)
- Test: `tests/test_heatgrid.py`

**Interfaces:**
- Produces:
  - `heatgrid.layout(start: datetime, end: datetime) -> Grid`. `Grid` has these attributes and methods:
    - `.rows: list[str]` and `.cols: list[str]`
    - `.cell(t: datetime) -> tuple[int, int] | None`, giving `(x, y)`
    - `.slot(x: int, y: int) -> tuple[datetime, datetime]`
  - `chartspec.status_heatmap(p, xlabels, ylabels, cells: list[tuple[int, int, str]], title="")`. A click reports `value: [x, y]`, as `heatmap` does.
  - `chartspec.ring(p, segments: list[tuple[str, int, str]], center_text: str, title="")`. The segments are `(name, value, colour)` and a click reports `name`.

- [ ] **Step 1: Write the failing test.**
  - `layout(now - 8h, now)` has `cols == ["00", ..., "23"]` and 1 or 2 date rows labelled like `"Sat 8 Nov"`, newest first.
  - `layout(now - 30 days, now)` has 31 rows or fewer.
  - `layout(now - 90 days, now)` has `cols == ["Mon", ..., "Sun"]` and about 13 to 14 week rows, labelled with each week's Monday.
  - `cell` and `slot` round-trip: the slot of a cell contains `t`.
  - `cell(t)` is `None` outside the range.
  - The option from `status_heatmap` colours an OK cell with `status_color(p, "OK")` and a FAIL cell with the FAIL colour.
  - `ring` puts `center_text` in its `graphic`.
  - `draw_failures` with period 30 has no `"Mon"` row label. Seed a FAIL row and read the drawn option's `yAxis` data back through a stub `ChartView.draw` that captures the builder's output.
- [ ] **Step 2: Run it** and confirm it fails.
- [ ] **Step 3: Implement.**
  - Up to 30 days, the grid has one row per date, newest first, and one column per hour. Beyond 30 days it has one row per week, labelled with that week's Monday, and one column per weekday.
  - Failures keeps colouring squares by count, and only switches its rows and columns to `heatgrid`.
  - `status_heatmap` has no visualMap. Each data item carries its own `itemStyle.color` from `status_color`, and blank squares are not sent.
- [ ] **Step 4: Run it** and confirm it passes. Then run `python tests/run_all.py history chartspec webchart` and confirm it is green.
- [ ] **Step 5: Commit** with the message "Heatmaps read by date; status heatmap and ring".

### Task 6: Drivers record their items

**Files:**
- Modify:
  - `drivers/base.py` (`interfaces_row`, `error_counter_rows`)
  - `drivers/windows.py` (`disks`, `certs`)
  - `drivers/fortinet.py` (`certificates`)
  - `core/custom.py` (the TLS `certificate` row)
  - The environment readers: `drivers/arista.py`, `drivers/clirows.py`, `drivers/dell.py`, `drivers/extreme.py`, `drivers/snmpextra.py`
  - The SNMP storage reader (`drivers/snmpdev.py`, `storage`)
- Test: `tests/test_driver_items.py`

**Interfaces:**
- Consumes: Task 2's `Driver.result(..., items=)`.
- Produces these item shapes, which Task 9 reads:
  - Disks, storage and flash: `name` = drive, `numeric` = percent used, `data` = `{"used": bytes, "total": bytes}` (left out when unknown).
  - Certificates: `name` = subject or CN, `numeric` = days left, `data` = `{"expires": "YYYY-MM-DD" or "", "where": "store" | "port <n>"}`.
  - Environment: `name` = component, `status`, `text` = the state as read.
  - Interfaces: `name`, `status` (`OK` up, `WARN` err-disabled, `FAIL` down), `text` = the state. Admin-off interfaces are left out.
  - Interface errors: `name`, `numeric` = the count as graded (lifetime, or new since the last run).

- [ ] **Step 1: Write the failing test.** Drive each reader with the fakes its existing test already uses: `tests/test_windows.py` reports, the clirows samples, and the SNMP walks in `tests/test_snmp*.py`. Check these:
  - Windows `disks` gives one item per drive, with used and total.
  - `interfaces_row([("Gi1", "up"), ("Gi2", "down"), ("Gi3", "off"), ("Gi4", "errdisabled")])` gives 3 items with statuses OK, FAIL and WARN.
  - `error_counter_rows` gives one item per wanted interface.
  - Each environment reader gives one item per component it tested, including the OK ones.
  - The Windows certs item for a report with `expires` has `data.expires`. Without it, the `expires` field is empty.
  - The value, status, message and numeric of every row are unchanged from before. Assert them against the current expectations in those tests.
- [ ] **Step 2: Run it** and confirm it fails.
- [ ] **Step 3: Implement.** Pass `items=` to the existing `self.result(...)` calls. Don't change grading or text.
- [ ] **Step 4: Run it** and confirm it passes. Then run `python tests/run_all.py windows snmp clirows fortinet arista dell extreme custom` and confirm it is green.
- [ ] **Step 5: Commit** with the message "Drivers keep per-disk, per-certificate, per-component and per-interface detail".

### Task 7: Windows reports pending updates and every certificate

**Files:**
- Modify:
  - `agent/internal/report/report.go`: `Cert.Expires string \`json:"expires,omitempty"\``, `PendingUpdates *[]Update \`json:"pending_updates,omitempty"\``, `UpdatesSearched string \`json:"updates_searched,omitempty"\``, and `type Update struct{ Title, KB, Severity string }` with the JSON keys `title`, `kb`, `severity`
  - `agent/internal/collect/windows_certs.go`: drop the 90-day and 30-day window, keep leaving out the self-named certificate, and fill `Expires` with `NotAfter` in RFC 3339 UTC
  - `agent/internal/collect/windows_system.go`: `winPendingUpdates`, registered beside `patched` in `windows.go`
  - `core/winmon.py`: the PowerShell `$o.certs` (whole store, with `expires`), `$o.pending_updates` and `$o.updates_searched`
  - `drivers/windows.py` (`patches`): attach the update items
- Test: `agent/internal/collect/windows_test.go` (or the existing collect test file) and `tests/test_windows.py`

**Interfaces:**
- Produces:
  - The report keys `pending_updates: [{"title", "kb", "severity"}]` and `updates_searched` (ISO). `severity` is `MsrcSeverity`, or `""` when Microsoft gives none.
  - Patches items: `name` = title, `text` = KB, `data` = `{"severity": "Critical" | "Important" | "Moderate" | "Low" | ""}`.
  - Every patches item's `data` also carries `"searched"`, the `updates_searched` date. The wheel reads it from the first item.
  - A report that has `pending_updates` with nothing pending gives `items == []`. A report without the key gives `items is None`. That is how Task 9 tells "nothing pending" from "not reported".

- [ ] **Step 1: Write the failing tests.**
  - **Go:** a unit test of the pure function `updatesFrom(rows []rawUpdate) []report.Update`. It maps an empty severity to `""` and joins several KB IDs with commas.
  - **Python:** `drivers/windows.py` with a report carrying `pending_updates` gives items with severities. A report without the key gives `items is None`, and the value and status are unchanged (graded on days since the last install, as today).
  - **Python:** a report whose certs have no `expires` still gives the certificates row it gives today.
- [ ] **Step 2: Run them** and confirm they fail. `cd agent && go test ./...`, then `python tests/test_windows.py`.
- [ ] **Step 3: Implement.**
  - The Go side reads `Microsoft.Update.Session`, then `CreateUpdateSearcher()` with `Online = false`, then `Search("IsInstalled=0 and IsHidden=0")`, through go-ole. It must never start an online search.
  - `UpdatesSearched` comes from `Microsoft.Update.AutoUpdate`'s `.Results.LastSearchSuccessDate`.
  - Any COM failure appends a note and leaves the field nil.
  - PowerShell does the same with `New-Object -ComObject`, inside `try`.
- [ ] **Step 4: Run them** and confirm they pass. Run `go vet ./...` with the three GOOS values from `.github/workflows/tests.yml`, then `python tests/run_all.py windows winmon agent`.
- [ ] **Step 5: Commit** with the message "Windows: pending updates by severity, every certificate with its date".

### Task 8: WAN usage

**Files:**
- Modify:
  - `core/db.py`: `DEFAULT_THRESHOLDS["wan_usage"] = {"warn": 80, "fail": 95}`, its label in the thresholds label map, the "Network devices" group, and `normalize_checkopts` keeping `"wan": {name: mbps|None}`
  - `core/checks.py`: `("wan usage", <approved label>)` for `snmp` and `fortinet`
  - `drivers/base.py`: `interface_counters()` and `wan_usage()`
  - `drivers/snmpdev.py` and `drivers/fortinet.py`: `interface_counters()`, with `wan usage` added to each run loop
  - `core/ifaces.py`: `listing` returns triples, plus `wan_capable(vendor)`
  - `ui/interfacepicker.py`: WAN and Available bandwidth columns
  - `ui/devicechecks.py`: Choose Interfaces always available, and the WAN choice saved
- Test: `tests/test_wan.py`

**Interfaces:**
- Produces:
  - `Driver.interface_counters() -> dict[str, tuple[int, int, float]]`, mapping a name to `(in_octets, out_octets, speed_bps)`. It raises `NotImplementedError` by default.
  - `Driver.wan_usage() -> Result | list`. The check is `"wan usage"`, graded with `self.th["wan_usage"]`, and `numeric` is the busiest WAN interface's percent. Each item has `name`, `numeric` = percent, and `data = {"in_bps", "out_bps", "available_bps"}`. The first run gives `"baseline set"`, as `bandwidth` does. It uses the delta keys `wan:t`, `wan:in:<name>` and `wan:out:<name>`, because the bandwidth check updates `bw:*` at its own time and `delta()` is per key.
  - `ifaces.listing(dev, opts=None) -> list[tuple[str, str, float | None]]`, giving name, state text, and port speed in bps when it is known.
  - `InterfacePicker(interfaces, chosen, wan=None, choose_checked=True, ...)`, with `.selected() -> list[str]` and `.wan() -> dict[str, float | None]`. `None` means "use the port speed".

- [ ] **Step 1: Write the failing test.**
  - `normalize_checkopts({"wan": {"wan1": 300, "port2": None, "": 5}})` gives `{"wan": {"wan1": 300.0, "port2": None}}`.
  - Two `wan_usage()` calls on a fake driver, with the counters moving 37.5 MB in 10 s on a 1 Gbps port, give 30% (that is 300 Mbps out of 1000) and OK.
  - With a 300 Mbps circuit typed in, the same traffic gives 100% and FAIL.
  - 250 Mbps on that circuit gives 83% and WARN.
  - A WAN name the device no longer has is skipped. When no WAN interface is left, `wan_usage()` returns `[]`.
  - The picker built with `wan={"wan1": 300}` shows the WAN tick and 300 for wan1, shows the port speed as the placeholder for the others, and `.wan()` round-trips.
- [ ] **Step 2: Run it** and confirm it fails.
- [ ] **Step 3: Implement.**
  - SNMP reads `ifHCInOctets`, `ifHCOutOctets`, `ifHighSpeed` and `ifSpeed`, as `bandwidth` does, keyed by `self._label(i)`.
  - Fortinet reads `rx_bytes`, `tx_bytes` and `speed` (in Mbps) from the `system/interface` monitor data that `_physical()` already fetches.
  - The rate is the busier direction: `max(din, dout) * 8 / elapsed`.
  - In `devicechecks.py`, the Choose button is enabled whenever the vendor is `wan_capable`. The "check only these" tick column appears only while "Choose which interfaces" is ticked. The WAN choice is saved in `checkopts["wan"]` either way.
- [ ] **Step 4: Run it** and confirm it passes. Then run `python tests/run_all.py snmp fortinet devicechecks interfacepicker thresholds` and confirm it is green.
- [ ] **Step 5: Commit** with the message "WAN usage: mark WAN interfaces, graded at 80% and 95%".

### Task 9: Over time panels (shared by History and the device page)

**Files:**
- Create:
  - `ui/detaillist.py`
  - `ui/overtime.py`
- Modify:
  - `ui/history.py`: `draw_over_time` becomes a thin wrapper around `CheckPanels`, or is removed and its callers updated
  - `core/display.py`: add `uptime_words(hours) -> str`
- Test: `tests/test_overtime.py`

**Interfaces:**
- Consumes:
  - Task 2: `items_of` and `latest_items`
  - Task 3: `check_rows(start=, end=)` and `series(start=, end=)`
  - Task 4: `over_time_kind`, `shown_name`, `stored_names` and `is_measurement`
  - Task 5: `heatgrid.layout`, `status_heatmap` and `ring`
  - `ui/tablefit.fit`
- Produces:
  - `DetailList(QTableView)` with `.show_rows(rows: list[dict], columns: list[tuple[str, str]])`, where each column is a key and its label.
  - `CheckPanels(QScrollArea)` with:
    - `.show(device: str, vendor: str, checks: list[str], start: datetime, end: datetime, th: dict) -> None`
    - `.line_series() -> list[tuple[str, list]]`, the measurement series, for Trends

- [ ] **Step 1: Write the failing test.** Seed one device with rows for cpu, `disk health` (OK, then FAIL with "disk 1: Unhealthy"), `disks` (with and without items), `patches` (items with severities), `uptime` (rising, then dropping), `ha` plus `ha sync`, `config backup`, and `resources` (ERROR). Then check:
  - With all of them ticked, there is one panel per shown check.
  - `resources` has no panel.
  - `certificate` and `certificates` share one panel.
  - Selecting the FAIL square of the disk health heatmap fills the `DetailList` with a row whose message contains "disk 1". Call the panel's click handler with the `[x, y]` that `grid.cell(t)` gives.
  - The disks panel has one gauge per item. A row with no items gives one gauge from `numeric`.
  - The patches ring's centre text is the pending count, its segments are named by Microsoft severity, and an "Unrated" segment appears for `""`.
  - The uptime table has one row per restart.
  - The ha table has the columns of the approved strings.
  - A Windows device whose latest patches row has `items is None` (an older agent) shows the wheel's "not reported by this computer's agent yet" text instead of a ring.
  - Every table panel can be sorted by clicking a header.
  - With a range holding no rows, every panel shows the approved empty text and nothing raises.
  - Panels below the scroll area's viewport are not drawn until they are scrolled into view. Count `ChartView.draw` calls.
- [ ] **Step 2: Run it** and confirm it fails.
- [ ] **Step 3: Implement `CheckPanels`.**
  - Consecutive `line` checks that share `ui/history.scale_key` share one `ChartStack` panel.
  - `config` reuses `backup.list_backups`, the diff/full switch, and `DiffHighlighter` from `ui/device_view.py`. Move the small helper both need into `ui/overtime.py` instead of duplicating it.
  - `interface errors` has its own small interface picker, built on `GroupPicker` and starting with the interfaces that have had errors, and draws one line per interface from `items_of`.
  - `reachability` marks its FAIL rows as red points.
- [ ] **Step 4: Run it** and confirm it passes. Then run `python tests/run_all.py history device overtime` and confirm it is green.
- [ ] **Step 5: Commit** with the message "Over time: a panel per check, drawn as its own kind".

### Task 10: The History page gets a time range

**Files:**
- Create: `ui/timerange.py`
- Modify: `ui/history.py` (`HistoryTab`). Remove `self.runs`, `show_run`, `run_ids` and the runs splitter. Add a `TimeRange`, and turn the checks table into a model/view over `results_between`. Exports use the shown rows. `screen_context` names the range.
- Test: `tests/test_timerange.py`, plus updates to the existing History tests (`python tests/run_all.py history` lists them)

**Interfaces:**
- Consumes: Task 3's `results_between`, and Task 9's `CheckPanels`.
- Produces:
  - `TimeRange(QWidget)` with:
    - the signal `changed()`
    - `.span() -> tuple[datetime, datetime]`, which defaults to the last 8 hours
    - `.describe() -> str`, for exports and the Assistant
    - `.set_hours(n: int)`
    - `.set_dates(d1: date, d2: date)`
  - Dates mode covers d1 00:00 to the end of d2. The end is never before the start.

- [ ] **Step 1: Write the failing test.**
  - A new `TimeRange` spans about 8 hours, ending now.
  - `set_hours(24)` emits `changed` once and spans 24 hours.
  - `set_dates(d2, d1)` with the dates swapped is normalised.
  - On the History page, `HistoryTab().runs` no longer exists.
  - The checks table holds exactly the rows `results_between` returns for the range, after the search box and funnel are applied.
  - Clicking a row ticks that check on Over time.
  - `report_rows()` equals the table's rows.
  - `screen_context()` mentions the range and no run.
  - 10,000 seeded rows fill the table in under 2 s offscreen.
- [ ] **Step 2: Run it** and confirm it fails.
- [ ] **Step 3: Implement.**
  - The table is a `QAbstractTableModel` behind a `QSortFilterProxyModel`.
  - Status colours come from the existing `StatusDelegate`.
  - Over time uses the same range.
  - `report_date()` returns `describe()`.
- [ ] **Step 4: Run it** and confirm it passes. Then run `python tests/run_all.py history reports assistant` and confirm it is green.
- [ ] **Step 5: Commit** with the message "History: a time range replaces the runs list".

### Task 11: Across devices

**Files:**
- Modify: `ui/history.py` (`draw_compare` and `_fill_compare`; the check list now comes from the checks that `latest_per_device` knows, not from a run)
- Test: `tests/test_across.py`

**Interfaces:**
- Consumes:
  - Task 3: `latest_per_device` and `average_per_device`
  - Task 4: `across_kind` and `shown_name`
  - Task 5: `ring`
  - Task 2: `latest_items`
  - `db.software_of(dev)`
  - Task 9: `DetailList`

- [ ] **Step 1: Write the failing test.**
  - `cpu` shows one gauge per device, worst first.
  - Switching to "7-day average" shows the averages that `average_per_device` gives.
  - `antivirus` shows a table.
  - `certificates` shows one row per certificate item, across both `certificate` and `certificates`.
  - `environment` shows one row per component item.
  - `firmware` includes a Cisco ASA device that has `software_of` set but no firmware row.
  - `interfaces` shows one ring per device, with the up, err-disabled and down counts and the total in the middle.
  - Selecting a segment lists those interfaces in the `DetailList`.
  - An unlisted status check shows the health table.
- [ ] **Step 2: Run it** and confirm it fails.
- [ ] **Step 3: Implement.** Gauges and rings sit in a wrapping grid (`ui/widgets.FlowLayout`) inside a scroll area. The switch is a `QComboBox` with the approved labels.
- [ ] **Step 4: Run it** and confirm it passes. Then run `python tests/run_all.py history` and confirm it is green.
- [ ] **Step 5: Commit** with the message "Across devices: gauges, tables and rings from each device's latest reading".

### Task 12: The device page

**Files:**
- Create: `ui/vulntab.py`
- Modify:
  - `ui/device_view.py`: `_fill_gauges`, `_fill_history`, `draw` and `_draw_trend`, plus the time range and the new tab
  - `ui/device_view.DeviceSummary._fill_info`: the Uptime row
  - `core/advisories.py`: `cvss_of`
  - `ui/scanning.py`: use `cvss_of` and the band names
- Test: `tests/test_device_page.py`

**Interfaces:**
- Consumes:
  - Task 9: `CheckPanels`
  - Task 10: `TimeRange`
  - Task 4: `is_measurement`
  - Task 2: `latest_items`
  - Task 8: `wan usage` items
  - Task 9: `display.uptime_words`
- Produces:
  - `advisories.cvss_of(value: str) -> float | None`
  - `advisories.SEVERITY_BANDS = (("Low", 0, 4), ("Medium", 4, 7), ("High", 7, 9), ("Critical", 9, 10.01))`, using the approved names
  - `VulnTab(QWidget)` with `.show_device(dev: dict) -> None`

- [ ] **Step 1: Write the failing test.**
  - **Overview:** shows exactly CPU, Memory, one dial per disk item, and one per wan usage item. A temperature row produces no dial.
  - **Facts:** the facts list has "Uptime" right after "Status", formatted by `uptime_words`. A device with no uptime row has no Uptime line. The Inventory details pane (`DeviceSummary`) shows it too.
  - **Picker:** the check picker starts with every check ticked, and unticking one redraws.
  - **Trends:** draws only `is_measurement` checks.
  - **Time range:** the History and Trends tabs follow their `TimeRange`.
  - **Vulnerabilities tab:** sits between Trends and Configuration. A seeded scan with CVSS 9.8, 7.5 and 5.0 rows gives slices Critical 1, High 1 and Medium 1. Clicking "High" lists the 7.5 advisory with its ID, title, CVSS, Exploited ("Yes" when its CVE appears in the KEV row's message) and link (`advisories.advisory_url`). Hardening rows are not counted.
  - **No scan:** the tab shows the approved empty text.
- [ ] **Step 2: Run it** and confirm it fails.
- [ ] **Step 3: Implement.** The Scanning page's pie uses `SEVERITY_BANDS`, so both pages agree.
- [ ] **Step 4: Run it** and confirm it passes. Then run `python tests/run_all.py device dashboard inventory scanning` and confirm it is green.
- [ ] **Step 5: Commit** with the message "Device page: the right dials, uptime, vulnerabilities, every check on Trends".

### Task 13: Whole-suite check and a look at it

- [ ] **Step 1:** Run `python tests/run_all.py`, `python -m pyflakes core drivers ui app.py cli.py`, and `cd agent && go vet ./... && go test ./...`. All of them must be green.
- [ ] **Step 2:** Seed a throwaway database (`NETCHECK_DB`) with 14 days of backdated runs:
  - devices: Windows, Fortinet, SNMP and TrueNAS
  - checks: disks with items, patches with updates, interfaces, and wan usage

  Open History (Over time, Across devices, Failures) and a device page offscreen, and save screenshots to the scratchpad. Look at every picture: no weekday rows on 30 days, no "ok" units, a gauge per disk, and readable text.
- [ ] **Step 3:** Fix whatever the pictures show. Commit with the message "Historical graphs: fixes from the visual pass".

---

## Strings (for the owner's approval before execution)

These are the working wording. The owner approves or changes them before Task 1 starts.

| Where | Text |
|---|---|
| Time range, default | Last 8 hours |
| Time range, relative mode | Last [n] hours |
| Time range, date mode | From [date] to [date] |
| Time range, mode choices | Last hours / Dates |
| Over time, no readings in range | No readings in this time range |
| Detail list columns | Time, Device, Status, Value, Message |
| Detail list hint before a selection | Select a square to see what happened then |
| Uptime table columns | Restarted (about), Had been up for |
| Uptime words | 12 days 4 hours (format: "[d] days [h] hours"; "[h] hours [m] minutes" under a day) |
| HA table columns | Checked, HA, HA sync |
| Config backup table columns | Saved, Changed |
| Change-history table columns | Checked, Status, Value, Message |
| Certificates table columns | Certificate, Expires, Days left, Found in |
| Certificates "Found in" values | Certificate store / Port [n] |
| Environment table columns (Across devices) | Device, Component, State |
| Firmware table columns | Device, Version |
| Across devices switch | Latest / 7-day average / 30-day average / 90-day average |
| Interfaces ring segments | Up / Err-disabled / Down |
| Patches wheel segments | Critical / Important / Moderate / Low / Unrated |
| Patches wheel note | Windows last searched for updates on [date] |
| Patches wheel, old agent | Not reported by this computer's agent yet |
| Patches wheel, refused | Not reported by this computer |
| Patches detail columns | Update, KB, Severity |
| Choose Interfaces columns | WAN, Available bandwidth |
| Available bandwidth placeholder | [port speed] (port speed) |
| Choose Interfaces hint (WAN) | Tick the interfaces that connect to the internet. Available bandwidth starts at the port speed; type your circuit speed in Mbps if it is lower. |
| Check list label | WAN usage |
| Threshold label | WAN usage % |
| wan usage first run | baseline set / rates are reported from the next run |
| Device page facts | Uptime |
| Device page tab | Vulnerabilities |
| Vulnerability severities | Low / Medium / High / Critical |
| Vulnerability list columns | Advisory, Title, CVSS, Exploited, Link |
| Exploited values | Yes / No |
| Vulnerabilities, no scan | No scan yet. Scan this device on the Scanning page to see its advisories. |
| Vulnerabilities, none found | No advisories for this version |
