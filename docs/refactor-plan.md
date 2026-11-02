# Refactor plan, and what (if anything) to rebuild in another language

Written after a review of Toner 1.13.2 (65,000 lines of Python, 28,600 lines of tests). The small findings were fixed on the
`review-fixes-and-web-charts` branch; this is the plan for the three large ones, and a component-by-component answer to
"would any of this be better in another language?".

## The three large refactors

Each is a branch of its own, with the tests green before and after. They are independent; the order below is the order of
payoff.

### 1. Model/view for the big lists (about a week)

**Why.** The Inventory tree, Results tree, Configs table, History tables and the Overview's Needs attention are hand-built
`QTreeWidget`/`QTableWidget`s: thirty of them. Each refill creates a `QTableWidgetItem` per cell, so a 500-device
inventory with twelve checks each rebuilds 6,000+ items on every refresh, and the sorting, filtering and column choices
are re-implemented per page.

**What.** One `DeviceModel(QAbstractItemModel)` over `db.list_devices()` and `db.device_health()`, with
`QSortFilterProxyModel` for the search box and funnel; a `ResultsModel` for the Results and Scanning trees (one row per
device, children per check) so `ScanningTab` stops copying `ResultsTab` internals. The `StatusDelegate` and `ResultDelegate`
stay; they already paint from roles.

**Order.** Results first (Scanning inherits it), then Inventory's `DeviceTree`, then Configs. The Overview table is small and
can stay as it is.

**Risk.** Drag-and-drop in `DeviceTree` and `SessionTree` (folders) and the per-column chooser (`ColumnChooser`) depend on
widget-item behaviour; both need their tests (`test_inventory_*`, `test_sessions_*`, `test_columns`) run after every step.

### 2. Splitting `InventoryTab` and `SessionsTab` (three to four days)

**Why.** `InventoryTab` is 1,312 lines and 85 methods; `SessionsTab` 1,035 and 73. `inventory._build` alone is 260 lines.
Everything works, but a change to the details pane means reading the import dialog's code too.

**What.** Pull out, in this order, each into its own module with its own tests: the details pane (`ui/inventory_pane.py`),
the import/export menu and dialogs (`ui/inventory_io.py`), bulk edit (already `core/bulk.py`; move its dialog), the device
context menu (`ui/device_menu.py`, which Results, Topology and the Overview also build today, each by hand). For Sessions:
the split-view grid and "Type in all" (`ui/session_grid.py`), the SFTP files panel is already `ui/filebrowser.py`, and the
import of PuTTY / MobaXterm / SecureCRT sessions (`ui/session_import.py`).

### 3. Type hints and a type checker in CI (ongoing; a day to start)

**Why.** 9 of about 2,450 functions are annotated. The tests catch most mistakes, but only at runtime and only on the paths
they cover; the drivers' parsers and the database layer are exactly where a wrong type goes unnoticed until a real device
answers.

**What.** Add `pyright` (basic mode) to `tests.yml` beside pyflakes, reporting but not failing at first. Annotate from the
bottom up: `drivers/base.py` (`Result`, `Driver`), `core/db.py`'s public functions, `core/runner.py`, then each driver's
`checks()` and parsers as they are touched. Flip pyright to failing once `core/` and `drivers/` are clean; `ui/` can stay
advisory.

## Smaller follow-ups found on the way

- The History page still draws its "Over time" chart with pyqtgraph (as do Live ping and iperf3). Moving those three to the
  ECharts widget would remove pyqtgraph and numpy from the build: about 27 MB of the installer, and one fewer charting look.
- 195 broad `except Exception:` remain; the 48 that silently did `pass` now log through `quiet.ignored()`. The rest each
  deserve a look at whether a narrower exception fits.
- Only 23 widgets carry an accessible name (was 3). Dialog fields and the per-row buttons on Needs attention are next.
- `ScanningTab` inherits `ResultsTab` and reaches into it (`self.bar`, `self.table`, `self.explain`); the model/view work
  above is the moment to give it a proper base class.

## Rebuilding components in another language: the verdict, part by part

The question was whether rewriting Toner, or parts of it, in C#/.NET or Go would pay. Component by component:

| Component | Rebuild? | Why |
|---|---|---|
| **Check engine and the 29 drivers** (`core/runner.py`, `drivers/`) | **No** | 5,300 lines of regex parsers and API readers that would be retyped line for line in any language; I/O-bound (a 10-thread pool, the devices are the wait). .NET has no netmiko: prompt and paging handling would be rewritten on SSH.NET's `ShellStream`. |
| **The UI** (84 modules, PySide6) | **No** | 31,000 lines of hand-tuned Qt: 23 themes, a custom terminal, the topology scene, RDP embedding. A port would be a second application with fewer tests. |
| **Terminal** (`ui/terminal.py` on pyte) | **No** | No .NET VT emulator of pyte's quality short of xterm.js in a WebView; the existing one is 405 lines and tested. |
| **File servers, SSH tunnel, SOCKS, Telnet, SCP** (`core/fileserver.py`, `tunnel.py`, `proxy.py`, `scp.py`, `telnet.py`) | **No** | Protocol code written by hand from the RFCs; it would be the same code in Go or C#. SSH.NET has no server side, so the SFTP server and the tunnel would need another library or a rewrite. |
| **Headless service and Prometheus** (`cli.py service`, `core/service.py`) | **No** | It shares every driver with the window; a Go daemon would have to re-implement them or shell out to Python, which is worse than today. |
| **Windows agent** (`core/agents.py`: a 900-line PowerShell script) | **Yes, worth a prototype** | The one place a compiled binary wins. The agent is a scheduled task running `powershell -ExecutionPolicy Bypass`, which EDR products and group policy increasingly block or flag. A small Go binary (one signed `toner-agent.exe`, no scripting host, same `/report` JSON over HTTPS) removes the execution-policy bypass, runs as a service, could report from Linux and macOS hosts too, and is far cheaper to sign and whitelist. Toner's receiver and the agent protocol stay as they are. About two weeks for a parity version; roll out beside the PowerShell agent and retire that later. |
| **Vault and secret stores** (`core/passvault.py`, `extvault.py`) | **No** | scrypt + AES-GCM in `cryptography`, DPAPI/SecretService escrow; correct and tested. |
| **AI assistant** (`core/assistant/`) | **No** | Thin, provider-neutral tool loop on the official SDKs; all three vendors have equivalent .NET SDKs but nothing would be gained. |
| **Demarc sync** (`core/demarc.py`) | **No** | Demarc is already a separate server; the client is a queue and an allowlist. |
| **Charts** | **Done differently, not in another language** | ECharts in Qt WebEngine (this branch): web-class charts without leaving Python. |

So the honest answer is: one component, the Windows agent, and only because it is a script running on other people's
computers rather than because of Python. Everything else is better served by the three refactors above.

## Cost of the chart change

Qt WebEngine adds roughly 200 MB to the program folder (Chromium), on top of the 231 MB installed today. Removing the Qt
pieces Toner never used (virtual keyboard, QtTest, QtPdf, translations) takes back 10 to 15 MB; moving the last three
pyqtgraph charts to ECharts would take back 27 MB more. A copy built without WebEngine still runs: each chart shows a note
instead.
