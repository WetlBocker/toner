//go:build !windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// Dir is the agent folder: /var/lib/toner-agent on Linux, Application Support on macOS.
func Dir() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/Toner Agent"
	}
	return "/var/lib/toner-agent"
}

func protectDir(dir string) error { return os.Chmod(dir, 0o700) }

const systemdUnit = `[Unit]
Description=Toner agent: sends reports about this computer to Toner (outbound only)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run
Restart=always
RestartSec=5
# Exit code 3 means a newer agent was put in place: restart it like any other exit.
SuccessExitStatus=3
ProtectHome=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
`

const launchdPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.toner.agent</string>
  <key>ProgramArguments</key><array><string>%s</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
`

func unitPath() string {
	if runtime.GOOS == "darwin" {
		return "/Library/LaunchDaemons/com.toner.agent.plist"
	}
	return "/etc/systemd/system/toner-agent.service"
}

// Install writes the unit (or plist), enables it and starts it. Root is needed; the error says so.
func Install() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run this as root (sudo): it installs a system service")
	}
	bin := InstalledBinary()
	if runtime.GOOS == "darwin" {
		if err := os.WriteFile(unitPath(), []byte(fmt.Sprintf(launchdPlist, bin)), 0o644); err != nil {
			return err
		}
		exec.Command("launchctl", "bootout", "system/com.toner.agent").Run() //nolint:errcheck
		if out, err := exec.Command("launchctl", "bootstrap", "system", unitPath()).CombinedOutput(); err != nil {
			return fmt.Errorf("launchctl: %v: %s", err, out)
		}
		return nil
	}
	if err := os.WriteFile(unitPath(), []byte(fmt.Sprintf(systemdUnit, bin)), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "toner-agent.service"}, {"restart", "toner-agent.service"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

// Uninstall stops and removes the unit.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run this as root (sudo)")
	}
	if runtime.GOOS == "darwin" {
		exec.Command("launchctl", "bootout", "system/com.toner.agent").Run() //nolint:errcheck
	} else {
		exec.Command("systemctl", "disable", "--now", "toner-agent.service").Run() //nolint:errcheck
	}
	os.Remove(unitPath())
	if runtime.GOOS != "darwin" {
		exec.Command("systemctl", "daemon-reload").Run() //nolint:errcheck
	}
	return nil
}

// RemoveDir deletes the agent folder except the running binary.
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

// RunUnderManager runs fn until SIGTERM or SIGINT.
func RunUnderManager(fn func(ctx context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return fn(ctx)
}
