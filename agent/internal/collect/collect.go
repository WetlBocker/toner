// Package collect builds the report for the computer the agent runs on. The shape is report.Report everywhere; what
// fills it is per operating system (windows_*.go, linux.go, darwin.go). Each collector is independent: one that fails
// leaves its part out (the evaluator says N/A) and adds a note, and the rest of the report is still sent, exactly as the
// PowerShell collector's try/catch blocks behaved.
package collect

import (
	"context"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/WetlBocker/toner/agent/internal/report"
)

// Options says which collectors to skip and how the agent identifies itself.
type Options struct {
	Version string
	Enabled func(collector string) bool // nil: everything
}

func (o Options) on(name string) bool { return o.Enabled == nil || o.Enabled(name) }

// Run collects everything this computer can tell.
func Run(ctx context.Context, opts Options) *report.Report {
	started := time.Now().UTC()
	r := &report.Report{
		V:             1,
		At:            started.Format(time.RFC3339),
		IPs:           []string{},
		Disks:         []report.Disk{},
		Reboot:        []string{},
		ServiceStates: map[string]string{},
		AutoStopped:   []report.StoppedService{},
		Software:      map[string]string{},
		Agent:         report.Agent{Name: "toner-agent", Version: opts.Version, OS: runtime.GOOS, Arch: runtime.GOARCH},
	}
	if name, err := os.Hostname(); err == nil {
		r.Computer = strings.ToUpper(strings.SplitN(name, ".", 2)[0]) // what $env:COMPUTERNAME gives on Windows
	}
	r.IPs = ipv4Addresses()
	collectPlatform(ctx, r, opts) // the operating system's collectors
	r.Now = time.Now().UTC().Format(time.RFC3339)
	return r
}

// ipv4Addresses lists the computer's IPv4 addresses on interfaces that are up, loopback left out (what the script's
// Win32_NetworkAdapterConfiguration IPEnabled query gave).
func ipv4Addresses() []string {
	out := []string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLinkLocalUnicast() {
				out = append(out, v4.String())
			}
		}
	}
	sort.Strings(out)
	return out
}

// note records why a part is missing.
func note(r *report.Report, what string, err error) {
	if err == nil {
		return
	}
	r.Notes = append(r.Notes, what+": "+err.Error())
}

// topCounts returns the n most frequent keys of counts, most frequent first, ties by name.
func topCounts(counts map[string]int, n int) []report.EventSource {
	out := make([]report.EventSource, 0, len(counts))
	for k, v := range counts {
		out = append(out, report.EventSource{Source: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Source < out[j].Source
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
