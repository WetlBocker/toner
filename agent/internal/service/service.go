// Package service installs the agent as what the operating system restarts and runs at boot (a Windows service, a
// systemd unit, a launchd daemon), runs it under that manager, and swaps the binary when Toner has a newer one.
package service

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Name is the service's name everywhere.
const Name = "Toner Agent"

// BinaryName is the installed file's name.
func BinaryName() string {
	if runtime.GOOS == "windows" {
		return "toner-agent.exe"
	}
	return "toner-agent"
}

// InstalledBinary is where the installed copy lives.
func InstalledBinary() string { return filepath.Join(Dir(), BinaryName()) }

// ConfigPath is the installed agent.json.
func ConfigPath() string { return filepath.Join(Dir(), "agent.json") }

// copyFile copies src to dst (0700 on Unix; Windows ACLs are set on the folder).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// Stage copies this binary and the given agent.json into the agent folder (unless they are already there).
func Stage(configSrc string) error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	if !sameFile(self, InstalledBinary()) {
		if err := copyFile(self, InstalledBinary()); err != nil {
			return fmt.Errorf("could not copy the agent into %s: %w", Dir(), err)
		}
	}
	if configSrc != "" && !sameFile(configSrc, ConfigPath()) {
		if err := copyFile(configSrc, ConfigPath()); err != nil {
			return fmt.Errorf("could not copy agent.json into %s: %w", Dir(), err)
		}
	}
	return protectDir(Dir())
}

func sameFile(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

// ApplyUpdate writes a downloaded binary beside the running one and swaps them: the running file is renamed (allowed on
// every platform, Windows included), the new one takes its name. The caller then exits with agent.ExitUpdated so the
// service manager starts the new binary. The old one is removed on the next start (CleanOld).
func ApplyUpdate(data []byte) (bool, error) {
	self, err := os.Executable()
	if err != nil {
		return false, err
	}
	self, _ = filepath.EvalSymlinks(self)
	newPath, oldPath := self+".new", self+".old"
	if err := os.WriteFile(newPath, data, 0o700); err != nil {
		return false, err
	}
	os.Remove(oldPath)
	if err := os.Rename(self, oldPath); err != nil {
		os.Remove(newPath)
		return false, fmt.Errorf("could not set the running agent aside: %w", err)
	}
	if err := os.Rename(newPath, self); err != nil {
		os.Rename(oldPath, self) // put it back
		return false, fmt.Errorf("could not put the new agent in place: %w", err)
	}
	return true, nil
}

// CleanOld removes the previous binary left by an update.
func CleanOld() {
	if self, err := os.Executable(); err == nil {
		os.Remove(self + ".old")
	}
}
