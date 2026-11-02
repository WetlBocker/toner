# The Toner agent, rewritten as one binary

Toner's Windows agent is today a 900-line PowerShell script (`core/agents.py`, with the collector from `core/winmon.py`)
run by a scheduled task as SYSTEM under `-ExecutionPolicy Bypass`. It works, but a script running with that flag is what
EDR products and group policies increasingly block or flag, every report pays for a PowerShell start, and there is no way to
run it on anything but Windows. This document is the design for its replacement, `toner-agent`: one small Go binary with no
runtime, the same protocol, the same report, and room for everything on the roadmap at the end.

## What does not change

The posture is the product. Every version of the agent keeps:

- **Outbound only.** The agent opens no port and runs no listener. Toner never connects to it.
- **No commands.** The agent collects and sends. The one thing it accepts back is the reply to its own report: a new token,
  a new interval, and "a newer agent is available".
- **Toner is pinned, not trusted.** The agent is given the SHA-256 fingerprint of Toner's receiver certificate and refuses
  any server without exactly that certificate. No certificate authority, no trust on first use.
- **One token per computer**, issued at enrollment with the package's sign-up key (used once, then forgotten); only its
  hash is kept in Toner; rotated from Toner with a grace period.
- **The receiver and the report evaluator** (`core/agents.py` `_Handler`, `drivers/windows.py`) keep working for the
  PowerShell agent while any are left. The two agents coexist; nothing has to be migrated on a flag day.

## The binary

`toner-agent` (`toner-agent.exe` on Windows), written in Go 1.24, statically linked, built for `windows/amd64`,
`windows/arm64`, `linux/amd64`, `linux/arm64` and `darwin/arm64`. Dependencies are kept to three: `go-ole` and
`yusufpapurcu/wmi` for WMI on Windows, `golang.org/x/sys` for the Windows service, registry and the few Win32 calls.
Linux and macOS collectors use the standard library and the system's own tools (`systemctl`, `journalctl`, `dpkg`/`rpm`).

Subcommands:

| Command | What it does |
|---|---|
| `toner-agent install` | Installs as a service (Windows service "Toner Agent" as LocalSystem; a systemd unit on Linux; a launchd daemon on macOS), copies itself and `agent.json` to the agent folder, sends the first report. |
| `toner-agent uninstall` | Removes the service and the agent folder. |
| `toner-agent run` | What the service runs: enroll if needed, then report every `minutes`, forever. |
| `toner-agent once` | One enrollment-if-needed and one report, then exit (for a test, or a cron job). |
| `toner-agent collect` | Print the report as JSON and exit, no network: for looking at what would be sent, and for support. |
| `toner-agent version` | The version (always Toner's version, as today). |

The agent folder is `C:\ProgramData\Toner Agent` (SYSTEM and Administrators only, as today), `/var/lib/toner-agent`
on Linux and `/Library/Application Support/Toner Agent` on macOS.

### Configuration

`agent.json`, **the same file the PowerShell package uses today**, so an existing package's `agent.json` works unchanged:

```json
{"server": "https://toner.example.com:8750/report", "enroll": "https://toner.example.com:8750/enroll",
 "pin": "<sha256 hex of Toner's certificate>", "key": "<sign-up key, removed after enrollment>",
 "minutes": 5, "token": ""}
```

New, all optional: `"queue_max": 288` (store-and-forward, see below), `"proxy": "http://..."` (an explicit HTTP proxy;
by default the agent connects directly, as the script does), `"collectors": {"software": false}` to turn a collector
off.

## The protocol

### Report (v1, unchanged)

`POST /report` with `Authorization: Bearer <token>`, `X-Toner-Agent: <version>` and the JSON document the collector in
`core/winmon.py` produces today, field for field (`computer`, `os`, `build`, `boot`, `uptime_h`, `mem_*`, `ips`, `cpu`,
`disks`, `reboot`, `service_states`, `auto_stopped`, `events`, `certs`, `patched`, `software`, `admins`, `ports`,
`physical`, `volumes`, `bitlocker`, `defender`, `av_products`, `firewall`, `activation`, `sessions`, `logons`, `ad`,
`hyperv`, `backup`, `task_failures`, `now`). Where the script used PowerShell cmdlets, the agent reads the same WMI
classes, registry keys and Win32 APIs those cmdlets read, and maps codes to the words the evaluator compares against
(`Healthy`, `On`, `FullyEncrypted`...). A collector that cannot run on a computer leaves its key out, as the script's
`try {} catch {}` blocks do, and the evaluator says N/A.

One addition, ignored by today's receiver: `"agent": {"name": "toner-agent", "version": "1.14.0", "os": "windows",
"arch": "amd64"}`.

The reply is read as today: `token` (save it), `minutes` (change the interval, now without a scheduled task), `update`.

### Update

`update: true` in the reply means Toner is newer. The script fetched `/agent.ps1`; the binary fetches
`GET /agent/<os>-<arch>` with its bearer token and reads the `X-Toner-Agent-Sha256` header, writes the download beside
itself as `.new`, checks the hash, renames itself to `.old` and `.new` into place, exits with code 3, and the service
manager restarts it (recovery actions set at install; `Restart=always` in the systemd unit). The pin is what makes the
download trustworthy; the hash is for integrity. Toner serves a binary only when one is in its program folder
(`agent/toner-agent-<os>-<arch>[.exe]`, put there by the installer build), and only to a known token.

### Store-and-forward (new, in the first version)

A laptop at home, a branch whose VPN is down: today those reports are lost. The agent keeps reports it could not send in
`queue/` in the agent folder (newest `queue_max`, 288 = a day at five minutes) and sends them oldest first when Toner
answers again. Each report carries its own `at`, so History can be filled in: **the receiver should take `at` as the
metric's time when it is within the retention window** (one line in `agents.store()`); until it does, replayed reports
land at the time they arrive, which is still better than a hole.

### Reserved for later (schema version 2)

Nothing below is implemented in the first version; the names are fixed now so the first agents never have to change shape.

- `heartbeat: true` with only `computer`, `at`, `uptime_h`: a cheap minute-by-minute "still here", so a silent computer is
  noticed in minutes.
- `early: "<reason>"`: a report sent before its time because something changed (a service died, a disk crossed a limit, a
  probe failed).
- `probes: [{target, kind: icmp|tcp|dns|tls|http, ms, ok, hops?}]`: the endpoint's view of the network.
- `wifi: {ssid, bssid, band, channel, signal_dbm, rate_mbps, driver}`.
- `inventory: {hardware: {...}, software: [{name, version, publisher}]}` replacing the flat `software` map when Scanning
  learns to look software up.
- `config: {firewall_rules, scheduled_tasks, local_admins, sshd}`: snapshots for Configs and hardening.
- The reply gains `policy: {minutes, probes: [...], collectors: {...}, events: [...]}` so groups of agents are configured
  from Toner, and `jobs: [...]` for the opt-in two-way mode (signed, allow-listed, approved in Toner).

## Toner's side

- **Serving the binary:** `core/agents.py` learns `agent_binary(os, arch)` (the file in the program folder) and
  `GET /agent/<os>-<arch>`; the `/agent.ps1` route stays for PowerShell agents.
- **The package:** `package_bytes()` puts `toner-agent.exe` into the zip when Toner has it, and `Install-TonerAgent.cmd`
  runs `toner-agent.exe install`; without the binary the package is the PowerShell one, exactly as today. `agent.json` is
  the same file either way.
- **Settings > Agents** says which kind each computer runs (the `agent` field, or "PowerShell" when it is absent), and the
  package download says which it holds.
- **Builds:** a GitHub Actions job cross-compiles the agent for every platform, signs the Windows binary when the signing
  secrets exist, attaches the binaries to the release, and `build.ps1` / `build_linux.sh` copy them into the program
  folder so a Toner release always carries agents of its own version.

## Rollout

1. The binary ships inside Toner; Settings > Agents offers it. New computers get the binary; existing PowerShell agents keep
   reporting.
2. An existing computer moves over by running the new package's installer once: it reads the same `agent.json` (the token
   is already there, so no enrollment), installs the service, and removes the old scheduled task when it finds one.
3. When no PowerShell agent has reported for a release or two, `/agent.ps1` and the script go.

## Roadmap after parity, in the agreed order

1. **Faster signal, no port** (section 4 of the ideas): heartbeat, early reports, event forwarding to the syslog receiver.
   Store-and-forward is already in the first version.
2. **Fleet operations** (section 5): MSI and winget, Debian/RPM, Intune/GPO notes, provisioning token, DNS SRV discovery,
   mTLS with per-agent certificates replacing bearer tokens, signed update manifests, report compression and deltas,
   policy per folder or tag from Toner.
3. **The endpoint as a vantage point** (section 2): probes to the gateway, DNS, the DC and named services; Wi-Fi on laptops;
   path on degradation; VPN, DHCP and proxy state.
4. **Inventory for Scanning and Configs** (section 3): software with versions into NVD lookups, hardware facts,
   configuration snapshots with a Windows/Linux hardening rule set, certificate inventory.
5. **Opt-in two-way** (section 6): the signed job queue in the report's reply, and the branch probe mode of the Linux build.

## Testing

- Every collector that reads a file or a command output has a unit test with a captured sample (as the drivers do), so the
  Linux collectors are tested here and the Windows ones against saved WMI/registry fixtures where the reading is in Go
  code rather than in the API call itself.
- `tests/test_agent_go.py` builds the agent (when a Go toolchain is present), starts Toner's receiver with a throw-away
  database, enrolls with the package key, sends a report with `toner-agent once`, and runs the report through
  `drivers/windows.py`: the same path a real computer takes.
- What this cannot do is run the Windows collectors on Windows; that is the first thing to try on a real machine, with
  `toner-agent collect` showing exactly what would be sent.
