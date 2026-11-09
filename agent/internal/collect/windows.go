//go:build windows

package collect

import (
	"context"
	"fmt"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"

	"github.com/WetlBocker/toner/agent/internal/report"
)

// collectPlatform fills the report the way core/winmon.py's PowerShell collector does, part by part. The order and the
// try-each-part-alone behaviour are the script's; the sources are the WMI classes, registry keys and Win32 calls its
// cmdlets read.
func collectPlatform(ctx context.Context, r *report.Report, opts Options) {
	// One COM apartment for every WMI and Task Scheduler call on this thread.
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		if oleErr, ok := err.(*ole.OleError); !ok || (oleErr.Code() != 0x00000001 && oleErr.Code() != 0x80010106) { // S_FALSE / RPC_E_CHANGED_MODE: already initialised
			note(r, "COM", err)
		}
	} else {
		defer ole.CoUninitialize()
	}
	wmi.DefaultClient.AllowMissingFields = true

	part := func(name string, fn func() error) {
		if !opts.on(name) {
			return
		}
		if ctx.Err() != nil {
			if name == "updates" {
				updatesUnfinished(r)
			}
			return
		}
		defer func() {
			if p := recover(); p != nil {
				note(r, name, fmt.Errorf("%v", p))
				if name == "updates" {
					updatesUnfinished(r)
				}
			}
		}()
		note(r, name, fn())
	}

	domainRole := 0
	part("system", func() error { var err error; domainRole, err = winSystem(r); return err })
	part("cpu", func() error { return winCPU(ctx, r) })
	part("disks", func() error { return winDisks(r) })
	part("reboot", func() error { return winReboot(r) })
	part("services", func() error { return winServices(r) })
	part("events", func() error { return winEvents(r) })
	part("certs", func() error { return winCerts(r) })
	part("patched", func() error { return winPatched(r) })
	part("software", func() error { return winSoftware(r) })
	part("admins", func() error { return winAdmins(r) })
	part("ports", func() error { return winPorts(r) })
	part("physical", func() error { return winPhysicalDisks(r) })
	part("volumes", func() error { return winVolumes(r) })
	part("bitlocker", func() error { return winBitLocker(r) })
	part("defender", func() error { return winDefender(r) })
	part("av", func() error { return winAVProducts(r) })
	part("firewall", func() error { return winFirewall(r) })
	part("activation", func() error { return winActivation(r) })
	part("sessions", func() error { return winSessions(r) })
	part("logons", func() error { return winLogons(r) })
	if domainRole >= 4 {
		part("ad", func() error { return winAD(ctx, r) })
	}
	part("hyperv", func() error { return winHyperV(r) })
	part("backup", func() error { return winBackup(ctx, r) })
	part("tasks", func() error { return winTasks(r) })
	part("updates", func() error { return winPendingUpdates(r) }) // last: the slowest part, so it cannot hold up the others
}

// query runs one WMI query in root\CIMV2.
func query(dst any, q string) error { return wmi.Query(q, dst) }

// queryIn runs one WMI query in another namespace (root\Microsoft\Windows\Storage, ...).
func queryIn(namespace string, dst any, q string) error { return wmi.QueryNamespace(q, dst, namespace) }

// regString reads one string value, "" when the key or value is missing.
func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}

// regExists says whether a key exists.
func regExists(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// iso formats a time as the collector did: RFC 3339 in UTC.
func iso(t time.Time) string { return t.UTC().Format(time.RFC3339) }
