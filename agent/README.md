# toner-agent

The agent as one binary: sends reports about the computer it runs on to Toner over HTTPS, as a service on Windows,
Linux and macOS. It only sends: it opens no port and accepts no commands. Design and protocol: `docs/agent-design.md`.

    toner-agent install [agent.json]    install as a service and send the first report (administrator / root)
    toner-agent uninstall
    toner-agent run                     what the service runs
    toner-agent once                    sign up if needed, send one report, exit
    toner-agent collect                 print the report as JSON, send nothing
    toner-agent version

`agent.json` is the file Toner's agent package makes (Settings > Agents > Download agent package); the same file serves
the PowerShell agent, so an existing computer keeps its token when it moves to the binary.

## Building

Go 1.24 or newer. On a fresh checkout run `go mod tidy` once (it writes `go.sum`), then:

    bash agent/build.sh                  every platform, into agent/dist, stamped with core/version.py's version
    go build ./cmd/toner-agent           just this one, unversioned

`packaging/build.ps1` and `packaging/build_linux.sh` copy `agent/dist` into Toner's program folder, so a Toner built
after `agent/build.sh` hands the binary to computers and updates the agents it already has. CI does both on every tag.

## Testing

    go test ./...                        the unit tests (configuration, the pinned transport)
    python tests/test_agent_go.py        the binary against Toner's own receiver: enrollment, a report, the Windows
                                         driver reading it, store-and-forward, the update route (needs `go` on PATH)

The Windows collectors cannot run here; `toner-agent collect` on a Windows computer shows exactly what they produce.
