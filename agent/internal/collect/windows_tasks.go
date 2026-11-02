//go:build windows

package collect

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"github.com/WetlBocker/toner/agent/internal/report"
)

// Task Scheduler results that are not failures: still running, has not run yet, ready, disabled, terminated by the user.
var benignTaskResults = map[uint32]bool{0: true, 267009: true, 267011: true, 267008: true, 267010: true, 267014: true}

// winTasks lists scheduled tasks outside Microsoft's folder that ran in the last 7 days and ended badly, through the
// Task Scheduler COM interface Get-ScheduledTask uses.
func winTasks(r *report.Report) error {
	unknown, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return fmt.Errorf("Schedule.Service: %w", err)
	}
	defer unknown.Release()
	svc, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer svc.Release()
	if _, err := oleutil.CallMethod(svc, "Connect"); err != nil {
		return fmt.Errorf("Task Scheduler Connect: %w", err)
	}
	rootV, err := oleutil.CallMethod(svc, "GetFolder", `\`)
	if err != nil {
		return err
	}
	root := rootV.ToIDispatch()
	defer root.Release()
	since := time.Now().AddDate(0, 0, -7)
	out := []report.TaskFailure{}
	var walk func(folder *ole.IDispatch, path string)
	walk = func(folder *ole.IDispatch, path string) {
		if strings.HasPrefix(strings.ToLower(path), `\microsoft`) {
			return
		}
		if tasksV, err := oleutil.CallMethod(folder, "GetTasks", 0); err == nil {
			tasks := tasksV.ToIDispatch()
			count := int(oleutil.MustGetProperty(tasks, "Count").Val)
			for i := 1; i <= count; i++ {
				itemV, err := oleutil.CallMethod(tasks, "Item", i)
				if err != nil {
					continue
				}
				task := itemV.ToIDispatch()
				state := oleutil.MustGetProperty(task, "State").Val
				name := oleutil.MustGetProperty(task, "Name").ToString()
				lastRun, _ := oleutil.MustGetProperty(task, "LastRunTime").Value().(time.Time)
				result := uint32(oleutil.MustGetProperty(task, "LastTaskResult").Val)
				task.Release()
				if state == 1 || lastRun.IsZero() || !lastRun.After(since) || benignTaskResults[result] {
					continue // 1 = disabled
				}
				out = append(out, report.TaskFailure{Name: name, Result: fmt.Sprintf("0x%X", result)})
			}
			tasks.Release()
		}
		if subsV, err := oleutil.CallMethod(folder, "GetFolders", 0); err == nil {
			subs := subsV.ToIDispatch()
			count := int(oleutil.MustGetProperty(subs, "Count").Val)
			for i := 1; i <= count; i++ {
				itemV, err := oleutil.CallMethod(subs, "Item", i)
				if err != nil {
					continue
				}
				sub := itemV.ToIDispatch()
				walk(sub, oleutil.MustGetProperty(sub, "Path").ToString())
				sub.Release()
			}
			subs.Release()
		}
	}
	walk(root, `\`)
	r.Tasks = &out
	return nil
}

var replLine = regexp.MustCompile(`(\d+)\s*/\s*(\d+)\s+(\d+)\s*`)

// winAD reads Active Directory replication health from `repadmin /replsummary` on a domain controller.
func winAD(ctx context.Context, r *report.Report) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "repadmin", "/replsummary").Output()
	if err != nil && len(out) == 0 {
		return fmt.Errorf("repadmin: %w", err)
	}
	fails, total, seen := 0, 0, false
	for _, line := range strings.Split(string(out), "\n") {
		if m := replLine.FindStringSubmatch(line); m != nil {
			seen = true
			f, _ := strconv.Atoi(m[1])
			t, _ := strconv.Atoi(m[2])
			fails += f
			total += t
		}
	}
	if !seen {
		return nil
	}
	r.AD = &report.AD{ReplFail: fails, ReplTotal: total}
	return nil
}

var backupTime = regexp.MustCompile(`(?i)Backup time:\s*(.+)`)

// winBackup reads the newest Windows Server Backup from `wbadmin get versions` (Get-WBSummary has no API outside its
// PowerShell module). Only the time is known this way; the result is reported as 0 (success) for the versions listed.
func winBackup(ctx context.Context, r *report.Report) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "wbadmin", "get", "versions").Output()
	if err != nil && len(out) == 0 {
		return fmt.Errorf("wbadmin: %w", err)
	}
	var newest time.Time
	for _, line := range strings.Split(string(out), "\n") {
		m := backupTime.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		text := strings.TrimSpace(m[1])
		for _, layout := range []string{"1/2/2006 3:04 PM", "1/2/2006 15:04", "2006-01-02 15:04", "02/01/2006 15:04", "2.1.2006 15:04"} {
			if t, perr := time.ParseInLocation(layout, text, time.Local); perr == nil {
				if t.After(newest) {
					newest = t
				}
				break
			}
		}
	}
	if newest.IsZero() {
		return nil
	}
	r.Backup = &report.Backup{Last: iso(newest), Result: 0}
	return nil
}
