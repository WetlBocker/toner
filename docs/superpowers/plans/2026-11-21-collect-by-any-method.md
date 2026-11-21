# Collect a check by any available method: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** when a device's main method (API or SSH) does not give CPU, memory, uptime, interfaces, interface errors or storage, or its check fails, SNMP and then SSH supply the value, and the row says where it came from.

**Architecture:** one function in `core/runner.py`, `fill_gaps`, runs after the vendor's driver. It works out which subjects are still missing, asks the existing SNMP extras driver for those, then (Fortinet and Palo Alto only) asks the device's command line over SSH for what is still missing. The five vendors that already have SNMP fill-in keep their present code path untouched.

**Tech stack:** Python, netmiko 4.8.0 (through `core/netconn.py`), the project's own SNMP client. Tests are plain scripts with `check(name, cond, extra)`; copy the header of `tests/test_newvendors.py`.

**Spec:** `docs/superpowers/specs/2026-11-21-collect-by-any-method-design.md`

## Global constraints

- Every user-facing string is in the Wording table below and nowhere else. Do not add, reword or "improve" one. A string you think is missing: stop and report.
- TDD: each behaviour gets its test first, watched failing for the right reason.
- No real device, SNMP agent or SSH server is contacted. Fake `SnmpDriver.run` the way `tests/test_newvendors.py:335` does; fake `cmdrun.run_cli` for SSH.
- No secret (SSH password, community, API token) in a row, a log, an exception text or a test fixture.
- Fixtures hold only the lines given in this plan. No serial numbers, host names, addresses or admin names from the owner's devices.
- Do not touch `core/extstore.py` or `core/passvault.py`.
- The working tree has CRLF line endings: edit with scripts that keep them (`io.open(p, newline="", encoding="utf-8")`).
- Run one test file with `python tests/test_x.py 2>/dev/null | grep -a "^  FAIL\|passed, "`.
- Do not commit files under `.postman/`, `postman/`, `.impeccable/`, `.superpowers/` or `docs/Toner-Technical-Guide.pdf`.
- Commit trailer: `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`. Never push.

## Wording (approved by the owner 2026-11-21)

| Where | Text |
|---|---|
| Filled row, no message of its own | `via SNMP` / `via SSH` |
| Filled row with a message | `{message}, via SNMP` (e.g. `recent reboot, via SNMP`) |
| Filled because the main check failed, API vendor | `via SNMP; the API check failed: {reason}` (same with `via SSH`) |
| Filled because the main check failed, SSH vendor | `via SNMP; the SSH check failed: {reason}` |
| SSH fill-in could not sign in or run | row `ssh`, ERROR, `SSH: {reason}` (mirrors today's `SNMP: {reason}`) |
| Settings > Checks labels | `CPU (via SNMP, when set up)`, `Memory (via SNMP)`, `Disk and storage (via SNMP)`, `Uptime and recent reboots (via SNMP)`, `Interface status (via SNMP)`, `Interface errors (via SNMP)` |

## Rulings made while planning (each is in the spec, section 8)

- **Who gains fill-in:** vendors of kind `ssh` or `api`, except the five in `vendors.SNMP_EXTRAS` (unchanged) and the three whose address is the vendor's cloud: `meraki`, `mist`, `unifi_cloud`. Windows, status pages and SNMP-only vendors are not touched.
- **A port that does not answer is not filled.** The early return at `core/runner.py:120-127` stays as it is: a device that is down would otherwise cost an SNMP time-out and gain an `snmp` ERROR row. A sign-in that is refused, or any other failed run, is filled.
- **The FortiGate login used for checks changes nothing on the firewall.** netmiko's `fortinet` login runs `config system console` / `set output standard` / `end`, and puts it back on exit: two configuration changes per run. Checks use a subclass that skips both, and commands short enough never to page.
- **A FortiGate with VDOMs is not filled over SSH** (no row, no error) until one is available to test against.
- **Fortinet's firmware version over SSH is left out:** there is no real `get system status` sample to build it from. Palo Alto's is in (real sample).

## Review focus

1. `resources` fails and SNMP has CPU but not memory: the CPU row is filled and tagged, and the `resources` ERROR row stays (Task 3).
2. The main check failed and SNMP's own read of that subject fails too: one ERROR row (the main one), not two (Task 3).
3. The SSH login is refused: one `ssh` ERROR row, one attempt, the API's rows intact (Task 5).
4. No SSH login is stored: SSH is not attempted and nothing is added (Task 5).
5. A PAN-OS that prints `top` in the older layout (`Cpu(s):  1.0%us`, `Mem:  4057112k total`): CPU and memory are simply not filled; uptime still is; no crash (Task 4 and 5).

---

### Task 1: SNMP error counters are remembered between runs

`runner.snmp_extras` never calls `flush_baselines()` on its driver, so with the counter mode "since last run" the row `interface errors` says "baseline set" on every run and never reports a change. `db.set_baselines` is an upsert, so flushing cannot disturb the main driver's keys.

**Files:** Modify `core/runner.py:87-105`. Test: `tests/test_newvendors.py` (after line 344).

- [ ] **Step 1: failing test.** With `OPTS` in delta mode and a faked client or `SnmpDriver.run` replaced by one that calls `self.error_counter_rows("interface errors", {"Gi1": n})` (first 3, then 5): call `runner.snmp_extras(ise, TH, {**OPTS, "counter_mode": "delta"}, [])` twice. Assert the second call's row has value `1` and message `Gi1 (+2)`.
- [ ] **Step 2:** run it; expect FAIL with the second row still "baseline set".
- [ ] **Step 3:** in `snmp_extras`, call `drv.flush_baselines()` after a `drv.run()` that did not raise.
- [ ] **Step 4:** run `tests/test_newvendors.py`; all pass.
- [ ] **Step 5:** commit `SNMP fill-in: error counters are remembered between runs`.

### Task 2: the catalogue knows which tick box governs a subject

**Files:** Modify `core/vendors.py` (after line 154), `core/checks.py`. Test: create `tests/test_fill_gaps.py`; modify `tests/test_newvendors.py:333`.

**Interfaces (produces):**
- `vendors.CLOUD_ONLY = {"meraki", "mist", "unifi_cloud"}`
- `vendors.fills(vendor) -> bool`: kind is `ssh` or `api`, and the vendor is in neither `SNMP_EXTRAS` nor `CLOUD_ONLY`.
- `checks.SUBJECTS = ("cpu", "memory", "storage", "uptime", "interfaces", "interface errors")`
- `checks.ERRORS_IN_INTERFACES = {"cisco", "fortinet"}` (their `interfaces` check reads error counters)
- `checks.governs(vendor, subject) -> str`: the catalogue key whose tick box switches that subject for the vendor. In order: the subject itself when the vendor's own list (before any addition) has that key; `"resources"` for `cpu` and `memory` when it has `resources`; `"interfaces"` for `interface errors` when the vendor is in `ERRORS_IN_INTERFACES`; otherwise the subject itself. `"firmware"` governs `firmware`.
- For every vendor where `vendors.fills` is true, `CATALOG[vendor]` gains the `SNMP_EXTRA` entry of each subject that `governs` returns unchanged and that the vendor's own list lacks.
- The six `SNMP_EXTRA` labels read as in the Wording table.

- [ ] **Step 1: failing tests** in `tests/test_fill_gaps.py`:
  - `checks.governs("fortinet", "cpu") == "resources"`, `("fortinet", "memory") == "resources"`, `("fortinet", "interface errors") == "interfaces"`, `("fortinet", "storage") == "storage"`, `("paloalto", "interface errors") == "interface errors"`, `("cisco", "cpu") == "cpu"`, `("juniper", "storage") == "storage"`.
  - `("storage", "Disk and storage (via SNMP)") in checks.CATALOG["fortinet"]`; `"interface errors"` is not a key of Fortinet's list; `("interface errors", "Interface errors (via SNMP)") in checks.CATALOG["paloalto"]`; Juniper's `storage` label is still `"Storage space"` and appears once; no key appears twice in any vendor's list.
  - `vendors.fills` is true for `fortinet`, `paloalto`, `cisco`, `proxmox`; false for `sonicwall`, `ciscoise`, `meraki`, `mist`, `unifi_cloud`, `windows`, `snmp`, `esxi`, `cloud`, `wifi`, `""`.
  - The lists of the five `SNMP_EXTRAS` vendors, of `meraki` and of `windows` have the same keys as before (write the expected key lists out).
  - Update `tests/test_newvendors.py:333` to the label `"CPU (via SNMP, when set up)"`.
- [ ] **Step 2:** run; expect FAIL on `governs` not defined.
- [ ] **Step 3:** implement. The additions loop goes after the `wan usage` loop at `core/checks.py:106`.
- [ ] **Step 4:** run `tests/test_fill_gaps.py`, `tests/test_newvendors.py` and every test file that mentions `CATALOG` (`grep -l "CATALOG" tests/*.py`); all pass.
- [ ] **Step 5:** commit `Checks catalogue: which tick box governs CPU, memory, uptime, interfaces and storage; labels say "via SNMP"`.

### Task 3: SNMP fills what the main method lacks or failed at

**Files:** Modify `core/runner.py`. Test: `tests/test_fill_gaps.py`.

**Interfaces:**
- Consumes: `checks.governs`, `checks.SUBJECTS`, `vendors.fills` (Task 2).
- Produces:
  - `snmp_extras(dev, thresholds, opts, have, on_check=None, only=None)`: with `only` (a collection of subjects) the driver runs exactly those checks, whatever `have` holds, and does not consult its own tick boxes for them (the caller has). Without `only`, behaviour is byte-for-byte today's.
  - `fill_gaps(dev, thresholds, opts, res, on_check=None, signed_in=True) -> list`: the new row list. Returns `res` unchanged when `vendors.fills(dev["vendor"])` is false.
  - `tagged(row, source, failed="", main="API") -> Result`: a copy of `row` with the message built from the Wording table. `source` is `"SNMP"` or `"SSH"`; `main` is `"API"` or `"SSH"` from the vendor's kind.

**Rules `fill_gaps` implements** (rows are looked at for `dev["name"]` only):
1. A subject is **switched off** when `checks.key(vendor, governs(vendor, subject))` is in `opts["disabled"]`: never filled.
2. A subject is **covered** when `res` has a row whose check is the subject or its governing key and whose status is not ERROR. (Fortinet's `resources` check makes rows named `cpu` and `memory`; Cisco's `interfaces` row covers `interface errors`.)
3. A subject **failed** when `res` has an ERROR row whose check is the subject or its governing key; its `message` is the reason.
4. Everything else in `checks.SUBJECTS` is **absent**.
5. When `profiles.snmp_configured(dev)` and any subject is failed or absent: one `snmp_extras(..., only=those)` call. A returned row whose check is a wanted subject and whose status is not ERROR fills it: `tagged(row, "SNMP", reason)`.
6. A main ERROR row is dropped once every subject it governs (among those not switched off) is filled. Until then it stays.
7. An ERROR row from SNMP for one subject is kept only when the main method had no row at all for that subject. The whole-run `snmp` ERROR row is always kept.
8. `signed_in=False` (the run raised): every subject not switched off is absent, and filled rows are tagged without a reason (the `connection` row already gives it).
9. Order: the main rows (minus dropped ones) in their order, then filled rows in `SUBJECTS` order, then SNMP's error rows.

**Call sites in `run_one`:**
- Line 141-142 becomes: the five vendors keep their `snmp_extras` call exactly; `elif vendors.fills(dev["vendor"]): res = fill_gaps(dev, thresholds, opts, res, on_check)`.
- In the `except` branch, inside the existing `try` beside `_no_login` (line 163): `rows += fill_gaps(dev, thresholds, opts, [], on_check, signed_in=False)` for the final attempt only.
- The early return for a dead port is not changed.

- [ ] **Step 1: failing tests** (fake `SD.SnmpDriver.run` to return one OK row per `check_list()` entry, plus `reachability`; patch `profiles.snmp_configured`; `fw = {"name": "fw", "vendor": "fortinet", "host": "h"}`):
  - API gave `cpu`, `memory`, `uptime`, `interfaces` OK: result adds only `storage`, message `via SNMP`.
  - API gave no `uptime` row: `uptime` added, message `via SNMP`; a filled row whose own message is `recent reboot` reads `recent reboot, via SNMP`.
  - API `uptime` is ERROR `HTTP 403`: one `uptime` row, status OK, message `via SNMP; the API check failed: HTTP 403`; no ERROR row named `uptime`.
  - API `resources` is ERROR `HTTP 500`: `cpu` and `memory` filled with that reason, no `resources` row left.
  - Review focus 1: SNMP returns `cpu` but no `memory`: `cpu` filled and tagged, the `resources` ERROR row still present.
  - Review focus 2: API `uptime` ERROR and SNMP's `uptime` row is ERROR: exactly one ERROR row named `uptime`, the API's.
  - `fortinet:resources` in `disabled`: no `cpu` or `memory` row from any method. `fortinet:storage` in `disabled`: no `storage` row.
  - A Cisco device whose `cpu` is ERROR `unexpected output`: `via SNMP; the SSH check failed: unexpected output`. With its `interfaces` row OK, no `interface errors` row is added.
  - SNMP not configured: `res` returned as it came, and `SnmpDriver.run` not called.
  - Nothing wanted (all covered, storage and errors switched off): `SnmpDriver.run` not called.
  - `SnmpDriver.run` raises `OSError`: the main rows are intact (the `uptime` ERROR row too) plus one `snmp` ERROR row.
  - `signed_in=False` with `res=[]`: six rows tagged `via SNMP` exactly.
  - `run_one` on a SonicWall with the same fakes returns the same checks, in the same order, as before this task (record them before implementing), and none of its messages contains `via`.
  - `run_one` when the driver raises `AuthRejected("x")`: the `connection` ERROR row is there, followed by the filled rows.
- [ ] **Step 2:** run; expect FAIL on `fill_gaps` not defined.
- [ ] **Step 3:** implement. `tagged` uses `dataclasses.replace`. Update the docstring of `snmp_extras` and the two comments at lines 140-142.
- [ ] **Step 4:** run `tests/test_fill_gaps.py`, `tests/test_newvendors.py`, `tests/test_engine.py`, `tests/test_reach.py`; all pass.
- [ ] **Step 5:** commit `A check the main method lacks or fails at is filled via SNMP, on every vendor with a login`.

### Task 4: parsers for the two command lines, from real output

**Files:** Modify `drivers/base.py`, `drivers/sshbase.py:125-128`, `drivers/paloalto.py:108-128`, `drivers/fortinet.py`. Test: create `tests/test_cli_fill.py`.

**Interfaces (produces):**
- `Driver.uptime_row(self, hours, text="") -> Result` in `drivers/base.py`: moved unchanged from `SshDriver`, which then inherits it. The inline copies in other drivers are left alone.
- `drivers.paloalto.cpu_memory(text) -> (float, float)`: CPU percent (100 minus idle) and memory percent (`(total - free - buff/cache) / total`), from `show system resources`. Raises `ValueError("could not read CPU and memory from 'show system resources'")` (the existing text) when either line is missing. `PaloAltoDriver.resources` calls it.
- `drivers.paloalto.uptime_hours(text) -> float`: from `31 days, 5:55:14` or `5:55:14`. Raises the existing `ValueError`. `PaloAltoDriver.uptime` calls it.
- `drivers.paloalto.cli_field(text, name) -> str`: the value of a `name: value` line of `show system info`, `""` when absent.
- `drivers.fortinet.cli_cpu(text) -> float | None`: 100 minus the idle figure of the `CPU states:` line.
- `drivers.fortinet.cli_memory(text) -> float | None`: the percent in brackets after `used` on the `Memory:` line.
- FortiGate uptime uses `sshbase.uptime_hours` on the `Uptime:` line; no new function.

**Fixtures** (real output, 2026-11-21, trimmed to the lines the parsers read):

```
PA_INFO = """hostname: fw
time: Sat Nov 21 00:29:45 2026
uptime: 31 days, 5:55:14
family: vm
model: PA-VM
sw-version: 11.1.4
"""
PA_TOP = """top - 00:29:54 up 31 days,  5:55,  1 user,  load average: 1.90, 2.04, 1.89
Tasks: 250 total,   1 running, 248 sleeping,   0 stopped,   1 zombie
%Cpu(s): 18.2 us, 12.1 sy,  0.0 ni, 63.6 id,  0.0 wa,  6.1 hi,  0.0 si,  0.0 st
MiB Mem :   5447.1 total,    127.0 free,   2532.7 used,   2787.4 buff/cache
MiB Swap:   4000.0 total,   3560.0 free,    440.0 used.    635.2 avail Mem
"""
FG_CPU = "CPU states: 0% user 0% system 0% nice 100% idle 0% iowait 0% irq 0% softirq"
FG_MEM = "Memory: 2042628k total, 1187340k used (58.1%), 589720k free (28.9%), 265568k freeable (13.0%)"
FG_UP = "Uptime: 31 days,  4 hours,  0 minutes"
```

- [ ] **Step 1: failing tests:**
  - `cpu_memory(PA_TOP)` is `(36.4, 46.5)` to one decimal.
  - `paloalto.uptime_hours("31 days, 5:55:14")` is `749.92` to two decimals; `"5:55:14"` is `5.92`.
  - `cli_field(PA_INFO, "sw-version") == "11.1.4"`, `cli_field(PA_INFO, "model") == "PA-VM"`, `cli_field(PA_INFO, "uptime") == "31 days, 5:55:14"`, `cli_field(PA_INFO, "serial") == ""`.
  - Review focus 5: `cpu_memory("Cpu(s):  1.0%us,  0.5%sy\nMem:   4057112k total,  3876544k used")` raises `ValueError`.
  - `fortinet.cli_cpu(FG_CPU) == 0.0`, `cli_memory(FG_MEM) == 58.1`, `sshbase.uptime_hours(FG_UP) == 748`; `cli_cpu("")` and `cli_memory("")` are `None`; `cli_cpu` on a `CPU0 states:` line is `None`.
  - A plain `Driver` subclass instance has `uptime_row`, and `uptime_row(748)` gives status OK and numeric 748 with default limits.
- [ ] **Step 2:** run; expect FAIL on the missing names.
- [ ] **Step 3:** implement; the API methods keep their behaviour.
- [ ] **Step 4:** run `tests/test_cli_fill.py` and every test file that mentions `paloalto`, `fortinet` or `uptime_row` (`grep -l`); all pass.
- [ ] **Step 5:** commit `Palo Alto and FortiGate: CPU, memory and uptime read from their command-line output`.

### Task 5: SSH fills what is still missing on Fortinet and Palo Alto

**Files:** Modify `core/netconn.py`, `core/cmdrun.py:265-290`, `core/runner.py`. Test: `tests/test_cli_fill.py`.

**Interfaces:**
- Consumes: Task 3's `fill_gaps` and `tagged`; Task 4's parsers and `Driver.uptime_row`.
- Produces:
  - `netconn.FortinetReadOnly(FortinetSSH)`: `disable_paging(...)` returns `""` and writes nothing; `cleanup(command="exit")` calls `BaseConnection.cleanup` only (never `set output more`). Registered as `SPECIAL["fortinet_readonly"]`.
  - `cmdrun.run_cli(dev, commands, opts=None, read_timeout=30, device_type=None, before=None) -> [(command, output)]`: the body of `_run_cli`, which becomes a call to it. `device_type` overrides `vendors.CLI_TYPES[...]`. Raises as today when no SSH login is stored.
  - `runner.SSH_FILL = {"fortinet": ("cpu", "memory", "uptime"), "paloalto": ("cpu", "memory", "uptime", "firmware")}`
  - `runner.ssh_extras(dev, thresholds, opts, wanted, on_check=None) -> list`: rows for the wanted subjects it could read; `[]` when it read none; one `Result(name, "ssh", ERROR, "", "SSH: " + Driver.explain(e))` when the session failed.

**Commands:**
- Fortinet, device type `fortinet_readonly`, one command per wanted subject, each one line of output so the pager never starts: `get system performance status | grep "CPU states"`, `get system performance status | grep Memory`, `get system performance status | grep Uptime`. Before them, when the connection's `_vdoms` is true: close and return `[]` (code comment: `shortcut: FortiGates with VDOMs are not filled over SSH, upgrade when one is available to test against`). Reaching `_vdoms` needs the connection object, so `run_cli` takes an optional `before=None` callable given the connection; it returns False to stop.
- Palo Alto, device type from `vendors.CLI_TYPES`: `show system info` when `uptime` or `firmware` is wanted; `show system resources` when `cpu` or `memory` is.

**Rows** are made with an instance of the vendor's own driver that is constructed and never run (`DRIVERS[vendor](dev, thresholds, opts)`, `on_check` set): `level_check("cpu", v)`, `level_check("memory", v)`, `uptime_row(hours)`, and for Palo Alto `result("firmware", OK, sw_version, model)`. A subject whose parser returns `None` or raises `ValueError` gets no row.

**In `fill_gaps`,** after the SNMP step: `firmware` joins the subjects for vendors in `SSH_FILL` (failed when the main `firmware` row is ERROR; absent only when `signed_in` is false). When the vendor is in `SSH_FILL`, any of its subjects is still failed or absent, and the device has `(dev.get("username") or "").strip()` and `profiles.ssh_secret(dev)`: one `ssh_extras` call. Its rows fill as SNMP's do, tagged `"SSH"`. Rules 6 and 7 of Task 3 apply to SSH the same way; an SNMP ERROR row for a subject SSH then fills is dropped. The `ssh` ERROR row is kept.

- [ ] **Step 1: failing tests** (patch `cmdrun.run_cli` to return canned `(command, output)` pairs built from Task 4's fixtures and to record its calls; `fw` has `username` and a stored `ssh` secret via `db.set_secret(db.secret_name("fw", "ssh"), "x")`):
  - Fortinet, API `uptime` absent, SNMP not configured: one `run_cli` call with device type `fortinet_readonly` and exactly the Uptime command; row `uptime`, numeric 748, message `via SSH`.
  - Fortinet, `resources` ERROR `HTTP 500`: commands for CPU and Memory only; rows `cpu` `0%` and `memory` `58%`, each `via SSH; the API check failed: HTTP 500`; no `resources` row.
  - Palo Alto, `signed_in=False`: both commands; rows `cpu` `36%`, `memory` `46%`, `uptime`, and `firmware` `11.1.4` with message `PA-VM, via SSH`.
  - SNMP configured and it fills `uptime`: `run_cli` not called when nothing else is missing.
  - Nothing missing: `run_cli` not called.
  - Review focus 3: `run_cli` raises `AuthRejected("refused")`: one `ssh` ERROR row whose message starts `SSH: `, `run_cli` called once, main rows intact including the ERROR row that was to be replaced.
  - Review focus 4: no stored SSH secret: `run_cli` not called, no `ssh` row.
  - Review focus 5: Palo Alto with the older `top` text: `uptime` and `firmware` rows, no `cpu` or `memory`, no `ssh` ERROR row.
  - A Cisco device is never passed to `ssh_extras`.
  - `netconn.FortinetReadOnly`: on an instance made with `__new__` whose `write_channel` and `send_multiline` raise if called, `disable_paging()` returns `""`; with `_original_output_mode = "more"`, `cleanup()` writes no `config system console` (patch `BaseConnection.cleanup` to a no-op and assert `send_multiline` was not called).
  - `cmdrun._run_cli` still fills `out["outputs"]` as before (the existing Command Runner tests pass).
- [ ] **Step 2:** run; expect FAIL on `ssh_extras` not defined.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run `tests/test_cli_fill.py`, `tests/test_fill_gaps.py` and every test file that mentions `cmdrun` or `netconn` (`grep -l`); all pass.
- [ ] **Step 5:** commit `Fortinet and Palo Alto: CPU, memory and uptime are filled via SSH when the API and SNMP do not give them`.

### After the last task

- [ ] Full suite: `python tests/run_all.py` (about 11 minutes; do not edit the tree while it runs), and the same under WSL with `QT_QPA_PLATFORM=offscreen ~/toner-venv/bin/python tests/run_all.py`. `tests/test_history_charts.py` can fail when the run crosses an hour boundary; re-run it alone before reporting it.
- [ ] Owed by the owner on the real FortiGate before release (not runnable here): the three `get system performance status | grep ...` commands in the Command Runner, to confirm each prints its one line.
