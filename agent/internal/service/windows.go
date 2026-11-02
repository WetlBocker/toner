//go:build windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Dir is C:\ProgramData\Toner Agent, as the PowerShell agent used (so an existing agent.json with its token is found).
func Dir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Toner Agent")
}

// protectDir leaves the folder to SYSTEM and Administrators only: the token is in it. icacls is what the script used.
func protectDir(dir string) error {
	cmd := exec.Command("icacls.exe", dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("icacls: %v: %s", err, out)
	}
	return nil
}

// Install registers the Windows service (LocalSystem, automatic start, restarted on failure) and starts it. A scheduled
// task left by the PowerShell agent is removed, so a computer does not report twice.
func Install() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("the service manager refused (run as administrator): %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(Name); err == nil {
		s.Close()
		if err := Uninstall(); err != nil {
			return err
		}
	}
	cfg := mgr.Config{
		DisplayName:      Name,
		Description:      "Sends reports about this computer to Toner. It only sends: it opens no port and accepts no commands.",
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "", // LocalSystem
	}
	s, err := m.CreateService(Name, InstalledBinary(), cfg, "run")
	if err != nil {
		return fmt.Errorf("could not create the service: %w", err)
	}
	defer s.Close()
	// Restart five seconds after any exit, which is also how an update takes effect.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 60 * time.Second}}, 0)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
	exec.Command("schtasks.exe", "/Delete", "/TN", "Toner Agent", "/F").Run() //nolint:errcheck // the old agent's task, if any
	if err := s.Start(); err != nil {
		return fmt.Errorf("the service was created but did not start: %w", err)
	}
	return nil
}

// Uninstall stops and removes the service and the agent folder.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("the service manager refused (run as administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err == nil {
		status, _ := s.Control(svc.Stop)
		for i := 0; i < 30 && status.State != svc.Stopped; i++ {
			time.Sleep(500 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				break
			}
		}
		if err := s.Delete(); err != nil {
			s.Close()
			return fmt.Errorf("could not remove the service: %w", err)
		}
		s.Close()
	}
	exec.Command("schtasks.exe", "/Delete", "/TN", "Toner Agent", "/F").Run() //nolint:errcheck
	return nil
}

// RemoveDir deletes the agent folder after the service is gone; the running binary itself may linger until exit.
func RemoveDir() error {
	self, _ := os.Executable()
	entries, err := os.ReadDir(Dir())
	if err != nil {
		return nil
	}
	for _, e := range entries {
		p := filepath.Join(Dir(), e.Name())
		if sameFile(p, self) {
			continue
		}
		os.RemoveAll(p)
	}
	return nil
}

// RunUnderManager runs fn as the service body when started by the service manager, or directly otherwise (so `run` in a
// console works the same for testing). fn returns when ctx ends.
func RunUnderManager(fn func(ctx context.Context) error) error {
	interactive, err := svc.IsWindowsService()
	if err != nil || !interactive {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		return fn(ctx)
	}
	return svc.Run(Name, &handler{fn: fn})
}

type handler struct {
	fn func(ctx context.Context) error
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.fn(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case <-done:
			cancel()
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		case c := <-requests:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				cancel()
				status <- svc.Status{State: svc.StopPending}
				<-done
				return false, 0
			}
		}
	}
}
