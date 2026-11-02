//go:build darwin

package collect

import (
	"context"
	"fmt"
	"math"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/WetlBocker/toner/agent/internal/report"
)

// collectPlatform fills what a Mac can tell without any extra tool: the system, memory, uptime, CPU, disks, launchd
// services, installed applications, administrators, listening ports and who is signed in.
func collectPlatform(ctx context.Context, r *report.Report, opts Options) {
	part := func(name string, fn func() error) {
		if !opts.on(name) || ctx.Err() != nil {
			return
		}
		defer func() {
			if p := recover(); p != nil {
				note(r, name, fmt.Errorf("%v", p))
			}
		}()
		note(r, name, fn())
	}
	part("system", func() error { return macSystem(ctx, r) })
	part("cpu", func() error { return macCPU(ctx, r) })
	part("disks", func() error { return macDisks(r) })
	part("services", func() error { return macServices(ctx, r) })
	part("software", func() error { return macSoftware(ctx, r) })
	part("admins", func() error { return macAdmins(ctx, r) })
	part("ports", func() error { return macPorts(ctx, r) })
	part("sessions", func() error { return macSessions(ctx, r) })
}

func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func iso(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func macSystem(ctx context.Context, r *report.Report) error {
	if out, err := run(ctx, 10*time.Second, "sw_vers"); err == nil {
		name, version, build := "macOS", "", ""
		for _, line := range strings.Split(out, "\n") {
			k, v, _ := strings.Cut(line, ":")
			switch strings.TrimSpace(k) {
			case "ProductName":
				name = strings.TrimSpace(v)
			case "ProductVersion":
				version = strings.TrimSpace(v)
			case "BuildVersion":
				build = strings.TrimSpace(v)
			}
		}
		r.OS = strings.TrimSpace(name + " " + version)
		r.Build = build
	}
	if out, err := run(ctx, 10*time.Second, "sysctl", "-n", "hw.memsize", "kern.boottime"); err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) >= 1 {
			if b, err := strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64); err == nil {
				r.MemTotal = report.Ptr(int64(math.Round(float64(b) / 1048576)))
			}
		}
		if len(lines) >= 2 {
			if i := strings.Index(lines[1], "sec = "); i >= 0 {
				rest := lines[1][i+6:]
				if j := strings.IndexAny(rest, ",}"); j > 0 {
					if secs, err := strconv.ParseInt(strings.TrimSpace(rest[:j]), 10, 64); err == nil {
						boot := time.Unix(secs, 0)
						r.Boot = iso(boot)
						r.UptimeH = report.Ptr(math.Round(time.Since(boot).Hours()*100000) / 100000)
					}
				}
			}
		}
	}
	if out, err := run(ctx, 10*time.Second, "vm_stat"); err == nil {
		var pageSize int64 = 4096
		var free, inactive, speculative int64
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "page size of") {
				f := strings.Fields(line)
				for i, w := range f {
					if w == "of" && i+1 < len(f) {
						pageSize, _ = strconv.ParseInt(f[i+1], 10, 64)
					}
				}
			}
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			n, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), "."), 10, 64)
			switch strings.TrimSpace(k) {
			case "Pages free":
				free = n
			case "Pages inactive":
				inactive = n
			case "Pages speculative":
				speculative = n
			}
		}
		r.MemFree = report.Ptr(int64(math.Round(float64((free+inactive+speculative)*pageSize) / 1048576)))
	}
	return nil
}

func macCPU(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, 15*time.Second, "top", "-l", "2", "-n", "0", "-s", "1")
	if err != nil {
		return err
	}
	var idle float64 = -1
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "CPU usage:") {
			for _, part := range strings.Split(strings.TrimPrefix(line, "CPU usage:"), ",") {
				f := strings.Fields(part)
				if len(f) == 2 && f[1] == "idle" {
					idle, _ = strconv.ParseFloat(strings.TrimSuffix(f[0], "%"), 64)
				}
			}
		}
	}
	if idle < 0 {
		return fmt.Errorf("top gave no CPU line")
	}
	r.CPU = report.Ptr(math.Round((100-idle)*10) / 10)
	return nil
}

func macDisks(r *report.Report) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return err
	}
	r.Disks = append(r.Disks, report.Disk{Drive: "/", Size: int64(st.Blocks) * int64(st.Bsize), Free: int64(st.Bavail) * int64(st.Bsize)})
	return nil
}

func macServices(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, 30*time.Second, "launchctl", "list")
	if err != nil {
		return err
	}
	for i, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 {
			continue
		}
		state := "S"
		if f[0] != "-" {
			state = "R"
		}
		r.ServiceStates[f[2]] = state
	}
	return nil
}

func macSoftware(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, 60*time.Second, "mdls", "-name", "kMDItemVersion", "-name", "kMDItemDisplayName", "-raw", "/Applications")
	_ = out
	_ = err
	entries, gerr := run(ctx, 10*time.Second, "ls", "/Applications")
	if gerr != nil {
		return gerr
	}
	for _, name := range strings.Split(entries, "\n") {
		if strings.HasSuffix(name, ".app") {
			v, _ := run(ctx, 5*time.Second, "defaults", "read", "/Applications/"+name+"/Contents/Info", "CFBundleShortVersionString")
			r.Software[strings.TrimSuffix(name, ".app")] = strings.TrimSpace(v)
		}
	}
	return nil
}

func macAdmins(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, 10*time.Second, "dscl", ".", "-read", "/Groups/admin", "GroupMembership")
	if err != nil {
		return err
	}
	_, list, _ := strings.Cut(out, ":")
	names := strings.Fields(list)
	sort.Strings(names)
	r.Admins = &names
	return nil
}

func macPorts(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, 30*time.Second, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	if err != nil && out == "" {
		return err
	}
	byPort := map[int]string{}
	for i, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 9 {
			continue
		}
		addr := f[8]
		p, err := strconv.Atoi(addr[strings.LastIndex(addr, ":")+1:])
		if err != nil {
			continue
		}
		if _, ok := byPort[p]; !ok {
			byPort[p] = f[0]
		}
	}
	ports := make([]int, 0, len(byPort))
	for p := range byPort {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	list := make([]string, 0, len(ports))
	for _, p := range ports {
		list = append(list, fmt.Sprintf("%d/%s", p, byPort[p]))
	}
	r.Ports = &list
	return nil
}

func macSessions(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, 10*time.Second, "who")
	if err != nil {
		return err
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	r.Sessions = &report.Sessions{Active: n}
	return nil
}
