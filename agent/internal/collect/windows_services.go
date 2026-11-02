//go:build windows

package collect

import (
	"golang.org/x/sys/windows/registry"

	"github.com/WetlBocker/toner/agent/internal/report"
)

// Win32_Service, as the script read it: every service's state, and the automatic ones that are not running with what
// Toner needs to decide whether that matters (delayed start, trigger start, the exit code).
type win32Service struct {
	Name             string
	DisplayName      string
	State            string
	StartMode        string
	ExitCode         uint32
	DelayedAutoStart bool
}

func winServices(r *report.Report) error {
	var services []win32Service
	if err := query(&services, "SELECT Name, DisplayName, State, StartMode, ExitCode, DelayedAutoStart FROM Win32_Service"); err != nil {
		return err
	}
	for _, s := range services {
		state := "S"
		if s.State == "Running" {
			state = "R"
		}
		r.ServiceStates[s.Name] = state
		if s.StartMode == "Auto" && s.State != "Running" {
			r.AutoStopped = append(r.AutoStopped, report.StoppedService{
				Name: s.Name, Display: s.DisplayName, Exit: int(s.ExitCode), Delayed: s.DelayedAutoStart,
				Trigger: regExists(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+s.Name+`\TriggerInfo`),
			})
		}
	}
	return nil
}
