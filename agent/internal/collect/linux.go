//go:build linux

package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/WetlBocker/toner/agent/internal/report"
)

// collectPlatform fills the report from /proc, systemd and the package manager. The names are the Windows report's,
// so Toner's evaluator applies the same checks: a stopped enabled unit is a stopped automatic service, journald's
// errors of the last day are the event log's, dpkg or rpm is the installed software.
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
	part("system", func() error { return linuxSystem(r) })
	part("cpu", func() error { return linuxCPU(ctx, r) })
	part("disks", func() error { return linuxDisks(r) })
	part("reboot", func() error { return linuxReboot(r) })
	part("services", func() error { return linuxServices(ctx, r) })
	part("events", func() error { return linuxEvents(ctx, r) })
	part("patched", func() error { return linuxPatched(r) })
	part("software", func() error { return linuxSoftware(ctx, r) })
	part("admins", func() error { return linuxAdmins(r) })
	part("ports", func() error { return linuxPorts(r) })
	part("sessions", func() error { return linuxSessions(ctx, r) })
	part("logons", func() error { return linuxLogons(ctx, r) })
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

// ---- the system: /etc/os-release, /proc/meminfo, /proc/uptime
func linuxSystem(r *report.Report) error {
	name := ""
	for _, line := range strings.Split(readFile("/etc/os-release"), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err == nil {
		r.Build = cstr(uts.Release[:])
		if name == "" {
			name = cstr(uts.Sysname[:])
		}
	}
	r.OS = name
	for _, line := range strings.Split(readFile("/proc/meminfo"), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		kb, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			r.MemTotal = report.Ptr(int64(math.Round(float64(kb) / 1024)))
		case "MemAvailable:":
			r.MemFree = report.Ptr(int64(math.Round(float64(kb) / 1024)))
		}
	}
	if f := strings.Fields(readFile("/proc/uptime")); len(f) > 0 {
		if secs, err := strconv.ParseFloat(f[0], 64); err == nil {
			r.UptimeH = report.Ptr(math.Round(secs/3600*100000) / 100000)
			r.Boot = iso(time.Now().Add(-time.Duration(secs * float64(time.Second))))
		}
	}
	if r.OS == "" {
		return fmt.Errorf("neither /etc/os-release nor uname said what this is")
	}
	return nil
}

func cstr(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

func iso(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// ---- CPU: two readings of /proc/stat's first line, 600 ms apart (the script's three WMI samples cover 1.2 s too)
func linuxCPU(ctx context.Context, r *report.Report) error {
	read := func() (idle, total float64, err error) {
		line := strings.SplitN(readFile("/proc/stat"), "\n", 2)[0]
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "cpu" {
			return 0, 0, fmt.Errorf("/proc/stat has no cpu line")
		}
		for i, v := range f[1:] {
			n, _ := strconv.ParseFloat(v, 64)
			total += n
			if i == 3 || i == 4 { // idle, iowait
				idle += n
			}
		}
		return idle, total, nil
	}
	i1, t1, err := read()
	if err != nil {
		return err
	}
	select {
	case <-time.After(1200 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}
	i2, t2, err := read()
	if err != nil {
		return err
	}
	if t2 <= t1 {
		return nil
	}
	busy := 100 * (1 - (i2-i1)/(t2-t1))
	r.CPU = report.Ptr(math.Round(busy*10) / 10)
	return nil
}

// ---- disks: every real file system in /proc/mounts
var pseudoFS = map[string]bool{"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true, "cgroup": true, "cgroup2": true,
	"pstore": true, "securityfs": true, "debugfs": true, "tracefs": true, "configfs": true, "fusectl": true, "mqueue": true, "hugetlbfs": true,
	"bpf": true, "autofs": true, "binfmt_misc": true, "squashfs": true, "overlay": false, "nsfs": true, "ramfs": true, "rpc_pipefs": true, "efivarfs": true}

func linuxDisks(r *report.Report) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(readFile("/proc/mounts"), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || pseudoFS[f[2]] || strings.HasPrefix(f[1], "/snap/") || strings.HasPrefix(f[1], "/proc") || strings.HasPrefix(f[1], "/sys") || strings.HasPrefix(f[1], "/dev") || strings.HasPrefix(f[1], "/run") {
			continue
		}
		mount := strings.ReplaceAll(f[1], `\040`, " ")
		var st syscall.Statfs_t
		if err := syscall.Statfs(mount, &st); err != nil || st.Blocks == 0 || seen[fmt.Sprint(st.Fsid)] {
			continue
		}
		seen[fmt.Sprint(st.Fsid)] = true
		size := int64(st.Blocks) * int64(st.Bsize)
		free := int64(st.Bavail) * int64(st.Bsize)
		r.Disks = append(r.Disks, report.Disk{Drive: mount, Size: size, Free: free})
	}
	return nil
}

// ---- pending reboot: what package managers leave behind
func linuxReboot(r *report.Report) error {
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		r.Reboot = append(r.Reboot, "packages updated")
	}
	if out, err := exec.Command("needs-restarting", "-r").CombinedOutput(); err != nil && len(out) > 0 && strings.Contains(string(out), "Reboot is required") {
		r.Reboot = append(r.Reboot, "packages updated")
	}
	return nil
}

// ---- services: systemd units. Enabled but not active is "automatic but stopped"; failed is reported with its exit code.
func linuxServices(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, 30*time.Second, "systemctl", "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager")
	if err != nil && out == "" {
		return fmt.Errorf("systemctl: %w", err)
	}
	enabled := map[string]bool{}
	if files, ferr := run(ctx, 30*time.Second, "systemctl", "list-unit-files", "--type=service", "--plain", "--no-legend", "--no-pager"); ferr == nil {
		for _, line := range strings.Split(files, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[1] == "enabled" {
				enabled[strings.TrimSuffix(f[0], ".service")] = true
			}
		}
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		name := strings.TrimSuffix(f[0], ".service")
		active := f[2] // active / inactive / failed
		state := "S"
		if active == "active" {
			state = "R"
		}
		r.ServiceStates[name] = state
		if enabled[name] && active != "active" && !strings.Contains(name, "@") {
			exit := 0
			if active == "failed" {
				exit = 1
			}
			r.AutoStopped = append(r.AutoStopped, report.StoppedService{Name: name, Display: strings.Join(f[4:], " "), Exit: exit})
		}
	}
	return nil
}

// ---- events: journald, priorities emerg..err, last 24 hours, by unit or identifier
func linuxEvents(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, 60*time.Second, "journalctl", "-p", "0..3", "--since", "-24h", "-o", "json", "--no-pager", "-n", "1000")
	if err != nil && out == "" {
		return fmt.Errorf("journalctl: %w", err)
	}
	counts := map[string]int{}
	total := 0
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		var e map[string]any
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		src, _ := e["_SYSTEMD_UNIT"].(string)
		if src == "" {
			src, _ = e["SYSLOG_IDENTIFIER"].(string)
		}
		if src == "" {
			src = "kernel"
		}
		counts[src]++
		total++
	}
	r.Events = &report.Events{Count: total, Capped: total >= 1000, Top: topCounts(counts, 5)}
	return nil
}

// ---- last update: apt's history, dnf/yum's log, or pacman's
func linuxPatched(r *report.Report) error {
	for _, path := range []string{"/var/log/apt/history.log", "/var/log/dnf.rpm.log", "/var/log/dnf.log", "/var/log/yum.log", "/var/log/pacman.log"} {
		st, err := os.Stat(path)
		if err == nil {
			r.Patched = iso(st.ModTime())
			return nil
		}
	}
	return nil
}

// ---- software: dpkg, rpm, or pacman
func linuxSoftware(ctx context.Context, r *report.Report) error {
	if out, err := run(ctx, 60*time.Second, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Split(line, "\t")
			if len(f) >= 3 && strings.HasSuffix(f[2], "installed") {
				r.Software[f[0]] = f[1]
			}
		}
		return nil
	}
	if out, err := run(ctx, 60*time.Second, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Split(line, "\t"); len(f) == 2 {
				r.Software[f[0]] = f[1]
			}
		}
		return nil
	}
	if out, err := run(ctx, 60*time.Second, "pacman", "-Q"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) == 2 {
				r.Software[f[0]] = f[1]
			}
		}
		return nil
	}
	return fmt.Errorf("no dpkg, rpm or pacman")
}

// ---- administrators: uid 0 accounts and the members of sudo, wheel and admin
func linuxAdmins(r *report.Report) error {
	set := map[string]bool{}
	for _, line := range strings.Split(readFile("/etc/passwd"), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 && f[2] == "0" {
			set[f[0]] = true
		}
	}
	for _, line := range strings.Split(readFile("/etc/group"), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 4 && (f[0] == "sudo" || f[0] == "wheel" || f[0] == "admin") {
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					set[m] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	r.Admins = &out
	return nil
}

// ---- listening TCP ports with the owning process, from /proc/net/tcp{,6} and /proc/*/fd
func linuxPorts(r *report.Report) error {
	inodeToPort := map[string]int{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		for i, line := range strings.Split(readFile(path), "\n") {
			f := strings.Fields(line)
			if i == 0 || len(f) < 10 || f[3] != "0A" { // 0A = LISTEN
				continue
			}
			hexPort := f[1][strings.LastIndex(f[1], ":")+1:]
			port, err := strconv.ParseInt(hexPort, 16, 32)
			if err != nil {
				continue
			}
			inodeToPort[f[9]] = int(port)
		}
	}
	if len(inodeToPort) == 0 {
		r.Ports = &[]string{}
		return nil
	}
	byPort := map[int]string{}
	for inode, port := range inodeToPort {
		if _, ok := byPort[port]; !ok {
			byPort[port] = ""
		}
		_ = inode
	}
	procs, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fd := range procs {
		target, err := os.Readlink(fd)
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		port, ok := inodeToPort[inode]
		if !ok || byPort[port] != "" {
			continue
		}
		pid := strings.Split(strings.TrimPrefix(fd, "/proc/"), "/")[0]
		byPort[port] = strings.TrimSpace(readFile("/proc/" + pid + "/comm"))
	}
	ports := make([]int, 0, len(byPort))
	for p := range byPort {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, fmt.Sprintf("%d/%s", p, byPort[p]))
	}
	r.Ports = &out
	return nil
}

// ---- sessions: `who` counts people signed in (all active; there is no "disconnected" on a terminal)
func linuxSessions(ctx context.Context, r *report.Report) error {
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

var sshFailed = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from`)

// ---- failed sign-ins: sshd's "Failed password" lines of the last day in the journal
func linuxLogons(ctx context.Context, r *report.Report) error {
	out, err := run(ctx, 60*time.Second, "journalctl", "--since", "-24h", "-o", "cat", "--no-pager", "-g", "Failed password", "-n", "2000")
	if err != nil && out == "" {
		return fmt.Errorf("journalctl: %w", err)
	}
	users := map[string]int{}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if m := sshFailed.FindStringSubmatch(line); m != nil {
			users[m[1]]++
			n++
		}
	}
	top := topCounts(users, 3)
	lg := &report.Logons{Failed: n, Capped: n >= 2000, Top: make([]report.LogonUser, 0, len(top))}
	for _, t := range top {
		lg.Top = append(lg.Top, report.LogonUser{User: t.Source, Count: t.Count})
	}
	r.Logons = lg
	return nil
}
