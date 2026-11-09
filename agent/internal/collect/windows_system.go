//go:build windows

package collect

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows/registry"

	"github.com/WetlBocker/toner/agent/internal/report"
)

// ---- Win32_OperatingSystem and Win32_ComputerSystem: what the computer is
type win32OperatingSystem struct {
	Caption                string
	BuildNumber            string
	LastBootUpTime         time.Time
	TotalVisibleMemorySize uint64 // KB
	FreePhysicalMemory     uint64 // KB
}

type win32ComputerSystem struct {
	Domain       string
	PartOfDomain bool
	DomainRole   uint16
}

func winSystem(r *report.Report) (int, error) {
	var oss []win32OperatingSystem
	if err := query(&oss, "SELECT Caption, BuildNumber, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem"); err != nil {
		return 0, err
	}
	if len(oss) == 0 {
		return 0, fmt.Errorf("Win32_OperatingSystem returned nothing")
	}
	o := oss[0]
	r.OS = strings.TrimSpace(o.Caption)
	r.Build = o.BuildNumber
	if !o.LastBootUpTime.IsZero() {
		r.Boot = iso(o.LastBootUpTime)
		up := time.Since(o.LastBootUpTime).Hours()
		r.UptimeH = report.Ptr(math.Round(up*100000) / 100000)
	}
	r.MemTotal = report.Ptr(int64(math.Round(float64(o.TotalVisibleMemorySize) / 1024)))
	r.MemFree = report.Ptr(int64(math.Round(float64(o.FreePhysicalMemory) / 1024)))
	var css []win32ComputerSystem
	if err := query(&css, "SELECT Domain, PartOfDomain, DomainRole FROM Win32_ComputerSystem"); err != nil {
		return 0, err
	}
	if len(css) > 0 {
		r.Domain = css[0].Domain
		r.Joined = css[0].PartOfDomain
		return int(css[0].DomainRole), nil
	}
	return 0, nil
}

// ---- CPU: Win32_Processor LoadPercentage, three samples 600 ms apart, averaged (the script's method)
type win32Processor struct {
	LoadPercentage *uint16
}

func winCPU(ctx context.Context, r *report.Report) error {
	var samples []float64
	for i := 0; i < 3; i++ {
		var cpus []win32Processor
		if err := query(&cpus, "SELECT LoadPercentage FROM Win32_Processor"); err != nil {
			return err
		}
		var sum, n float64
		for _, c := range cpus {
			if c.LoadPercentage != nil {
				sum += float64(*c.LoadPercentage)
				n++
			}
		}
		if n > 0 {
			samples = append(samples, sum/n)
		}
		if i < 2 {
			select {
			case <-time.After(600 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if len(samples) == 0 {
		return fmt.Errorf("no processor load reading")
	}
	var total float64
	for _, s := range samples {
		total += s
	}
	r.CPU = report.Ptr(math.Round(total/float64(len(samples))*10) / 10)
	return nil
}

// ---- disks: Win32_LogicalDisk DriveType=3 (local fixed disks)
type win32LogicalDisk struct {
	DeviceID  string
	Size      uint64
	FreeSpace uint64
}

func winDisks(r *report.Report) error {
	var disks []win32LogicalDisk
	if err := query(&disks, "SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3"); err != nil {
		return err
	}
	for _, d := range disks {
		r.Disks = append(r.Disks, report.Disk{Drive: d.DeviceID, Size: int64(d.Size), Free: int64(d.FreeSpace)})
	}
	return nil
}

// ---- pending reboot: the three places Windows notes one
func winReboot(r *report.Report) error {
	if regExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) {
		r.Reboot = append(r.Reboot, "component servicing")
	}
	if regExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) {
		r.Reboot = append(r.Reboot, "Windows Update")
	}
	a := regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName`, "ComputerName")
	b := regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`, "ComputerName")
	if a != "" && b != "" && !strings.EqualFold(a, b) {
		r.Reboot = append(r.Reboot, "computer rename")
	}
	return nil
}

// ---- last successful update install: Windows Update's own note, else the newest hotfix
type win32QuickFixEngineering struct {
	InstalledOn time.Time
}

func winPatched(r *report.Report) error {
	t := regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install`, "LastSuccessTime")
	if t != "" {
		for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339, "1/2/2006 3:04:05 PM", "2006-01-02T15:04:05"} {
			if when, err := time.ParseInLocation(layout, strings.TrimSpace(t), time.UTC); err == nil { // the value is written in UTC
				r.Patched = iso(when)
				return nil
			}
		}
	}
	var fixes []win32QuickFixEngineering
	if err := query(&fixes, "SELECT InstalledOn FROM Win32_QuickFixEngineering"); err != nil {
		return err
	}
	var newest time.Time
	for _, f := range fixes {
		if f.InstalledOn.After(newest) {
			newest = f.InstalledOn
		}
	}
	if !newest.IsZero() {
		r.Patched = iso(newest)
	}
	return nil
}

// ---- pending updates: Windows' own cached search result. Online is false, so no search is ever started: a live one can take
// minutes and contacts Microsoft or WSUS. Even the cached search is slow, so it runs again only when Windows has searched since
// the last one (LastSearchSuccessDate, cheap to read); otherwise the list kept from then is sent. An error (no cached catalog,
// the API refused) leaves the field nil and says so in updates_error.
func winPendingUpdates(r *report.Report) error {
	runtime.LockOSThread() // COM state belongs to the thread
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err == nil {
		defer ole.CoUninitialize()
	} // already initialised on this thread (S_FALSE, RPC_E_CHANGED_MODE): carry on
	searched := lastUpdateSearch()
	pendingCache.Lock()
	defer pendingCache.Unlock()
	if searchAgain(pendingCache.list, pendingCache.searched, searched, pendingCache.patched, r.Patched) {
		list, err := searchPending()
		if err != nil {
			r.UpdatesError = true
			return err
		}
		pendingCache.list, pendingCache.searched, pendingCache.patched = list, searched, r.Patched
	}
	out := append([]report.Update{}, pendingCache.list...)
	r.PendingUpdates = &out
	if !pendingCache.searched.IsZero() { // when Windows last searched successfully (the wheel shows it)
		r.UpdatesSearched = iso(pendingCache.searched)
	}
	return nil
}

// lastUpdateSearch is when Windows last searched for updates successfully; zero when that cannot be read.
func lastUpdateSearch() time.Time {
	av, err := oleutil.CreateObject("Microsoft.Update.AutoUpdate")
	if err != nil {
		return time.Time{}
	}
	defer av.Release()
	auto, err := av.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return time.Time{}
	}
	defer auto.Release()
	res, err := oleutil.GetProperty(auto, "Results")
	if err != nil {
		return time.Time{}
	}
	rd := res.ToIDispatch()
	defer rd.Release()
	if d, err := oleutil.GetProperty(rd, "LastSearchSuccessDate"); err == nil {
		if t, ok := d.Value().(time.Time); ok && t.Year() > 1900 {
			return t
		}
	}
	return time.Time{}
}

// searchPending runs Windows Update's offline search over its cached catalog: the updates not installed and not hidden.
func searchPending() ([]report.Update, error) {
	obj, err := oleutil.CreateObject("Microsoft.Update.Session")
	if err != nil {
		return nil, err
	}
	defer obj.Release()
	session, err := obj.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, err
	}
	defer session.Release()
	sv, err := oleutil.CallMethod(session, "CreateUpdateSearcher")
	if err != nil {
		return nil, err
	}
	searcher := sv.ToIDispatch()
	defer searcher.Release()
	if _, err := oleutil.PutProperty(searcher, "Online", false); err != nil {
		return nil, err // without Online = false the search could go to the network: do not run it
	}
	rv, err := oleutil.CallMethod(searcher, "Search", "IsInstalled=0 and IsHidden=0")
	if err != nil {
		return nil, err
	}
	result := rv.ToIDispatch()
	defer result.Release()
	uv, err := oleutil.GetProperty(result, "Updates")
	if err != nil {
		return nil, err
	}
	updates := uv.ToIDispatch()
	defer updates.Release()
	var rows []rawUpdate
	n, err := comCount(updates)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		iv, err := oleutil.GetProperty(updates, "Item", i)
		if err != nil {
			return nil, err
		}
		u := iv.ToIDispatch()
		row := rawUpdate{Title: comString(u, "Title"), Severity: comString(u, "MsrcSeverity")}
		if kv, err := oleutil.GetProperty(u, "KBArticleIDs"); err == nil {
			ids := kv.ToIDispatch()
			k, _ := comCount(ids)
			for j := 0; j < k; j++ {
				if idv, err := oleutil.GetProperty(ids, "Item", j); err == nil {
					row.KBs = append(row.KBs, idv.ToString())
					idv.Clear()
				}
			}
			ids.Release()
		}
		u.Release()
		rows = append(rows, row)
	}
	return updatesFrom(rows), nil
}

func comCount(d *ole.IDispatch) (int, error) {
	v, err := oleutil.GetProperty(d, "Count")
	if err != nil {
		return 0, err
	}
	return int(v.Val), nil
}

func comString(d *ole.IDispatch, prop string) string {
	v, err := oleutil.GetProperty(d, prop)
	if err != nil {
		return ""
	}
	defer v.Clear()
	if s, ok := v.Value().(string); ok {
		return s
	}
	return ""
}

// ---- installed software: the Uninstall keys, both registry views, as Programs and Features lists them
func winSoftware(r *report.Report) error {
	for _, path := range []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		names, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}
		for _, name := range names {
			sub, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+name, registry.QUERY_VALUE|registry.WOW64_64KEY)
			if err != nil {
				continue
			}
			display, _, _ := sub.GetStringValue("DisplayName")
			version, _, _ := sub.GetStringValue("DisplayVersion")
			system, _, _ := sub.GetIntegerValue("SystemComponent")
			parent, _, _ := sub.GetStringValue("ParentKeyName")
			sub.Close()
			if display == "" || system != 0 || parent != "" {
				continue
			}
			r.Software[display] = version
		}
	}
	return nil
}

// ---- storage health: the classes Get-PhysicalDisk and Get-Volume read
const storageNS = `root\Microsoft\Windows\Storage`

type msftPhysicalDisk struct {
	FriendlyName      string
	HealthStatus      uint16
	OperationalStatus []uint16
	MediaType         uint16
}

var (
	healthWords = map[uint16]string{0: "Healthy", 1: "Warning", 2: "Unhealthy", 5: "Unknown"}
	mediaWords  = map[uint16]string{0: "Unspecified", 3: "HDD", 4: "SSD", 5: "SCM"}
	// MSFT_PhysicalDisk.OperationalStatus values, as Get-PhysicalDisk shows them
	opWords = map[uint16]string{0: "Unknown", 1: "Other", 2: "OK", 3: "Degraded", 4: "Stressed", 5: "Predictive Failure", 6: "Error",
		7: "Non-Recoverable Error", 8: "Starting", 9: "Stopping", 10: "Stopped", 11: "In Service", 12: "No Contact", 13: "Lost Communication",
		14: "Aborted", 15: "Dormant", 16: "Supporting Entity in Error", 17: "Completed", 18: "Power Mode", 19: "Relocating",
		0xD003: "Lost Communication", 0xD004: "Removing From Pool", 0xD005: "In Maintenance Mode", 0xD006: "Updating Firmware",
		0xD007: "Device Hardware Error", 0xD008: "Not Usable", 0xD009: "Transient Error", 0xD00A: "Starting Maintenance Mode",
		0xD00B: "Stopping Maintenance Mode", 0xD00C: "Transitioning", 0xD010: "Split", 0xD011: "Stale Metadata", 0xD012: "IO Error",
		0xD013: "Unrecognized Metadata", 0xD014: "Failed Media"}
)

func word(m map[uint16]string, v uint16) string {
	if s, ok := m[v]; ok {
		return s
	}
	return fmt.Sprint(v)
}

func winPhysicalDisks(r *report.Report) error {
	var disks []msftPhysicalDisk
	if err := queryIn(storageNS, &disks, "SELECT FriendlyName, HealthStatus, OperationalStatus, MediaType FROM MSFT_PhysicalDisk"); err != nil {
		return err
	}
	out := make([]report.PhysicalDisk, 0, len(disks))
	for _, d := range disks {
		ops := make([]string, 0, len(d.OperationalStatus))
		for _, o := range d.OperationalStatus {
			ops = append(ops, word(opWords, o))
		}
		out = append(out, report.PhysicalDisk{Name: d.FriendlyName, Health: word(healthWords, d.HealthStatus), Op: strings.Join(ops, ","), Media: word(mediaWords, d.MediaType)})
	}
	r.Physical = &out
	return nil
}

type msftVolume struct {
	DriveLetter  string
	DriveType    uint32
	HealthStatus uint16
}

func winVolumes(r *report.Report) error {
	var vols []msftVolume
	if err := queryIn(storageNS, &vols, "SELECT DriveLetter, DriveType, HealthStatus FROM MSFT_Volume"); err != nil {
		return err
	}
	out := []report.Volume{}
	for _, v := range vols {
		letter := strings.TrimRight(v.DriveLetter, "\x00")
		if letter == "" || v.DriveType != 3 { // 3 = Fixed
			continue
		}
		out = append(out, report.Volume{Drive: letter + ":", Health: word(map[uint16]string{0: "Healthy", 1: "Scan Needed", 2: "Spot Fix Needed", 3: "Full Repair Needed", 4: "Unhealthy"}, v.HealthStatus)})
	}
	r.Volumes = &out
	return nil
}

// ---- BitLocker: Win32_EncryptableVolume, as Get-BitLockerVolume reads it
type win32EncryptableVolume struct {
	DriveLetter      string
	ProtectionStatus uint32
	ConversionStatus uint32
	VolumeType       uint32
}

func winBitLocker(r *report.Report) error {
	var vols []win32EncryptableVolume
	if err := queryIn(`root\CIMV2\Security\MicrosoftVolumeEncryption`, &vols, "SELECT DriveLetter, ProtectionStatus, ConversionStatus, VolumeType FROM Win32_EncryptableVolume"); err != nil {
		return err
	}
	status := map[uint32]string{0: "FullyDecrypted", 1: "FullyEncrypted", 2: "EncryptionInProgress", 3: "DecryptionInProgress", 4: "EncryptionPaused", 5: "DecryptionPaused"}
	protection := map[uint32]string{0: "Off", 1: "On", 2: "Unknown"}
	out := []report.BitLockerVolume{}
	for _, v := range vols {
		if v.VolumeType != 0 && v.VolumeType != 1 { // OperatingSystem and Data (fixed); removable data is left out
			continue
		}
		out = append(out, report.BitLockerVolume{Mount: v.DriveLetter, Protection: word32(protection, v.ProtectionStatus), Status: word32(status, v.ConversionStatus)})
	}
	r.BitLocker = &out
	return nil
}

func word32(m map[uint32]string, v uint32) string {
	if s, ok := m[v]; ok {
		return s
	}
	return fmt.Sprint(v)
}

// ---- Defender and other antivirus
type msftMpComputerStatus struct {
	AMServiceEnabled          bool
	RealTimeProtectionEnabled bool
	AntivirusSignatureAge     uint32
	AMRunningMode             string
}

func winDefender(r *report.Report) error {
	var st []msftMpComputerStatus
	if err := queryIn(`root\Microsoft\Windows\Defender`, &st, "SELECT AMServiceEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge, AMRunningMode FROM MSFT_MpComputerStatus"); err != nil {
		return err
	}
	if len(st) == 0 {
		return nil
	}
	r.Defender = &report.Defender{Enabled: st[0].AMServiceEnabled, Realtime: st[0].RealTimeProtectionEnabled, SigDays: int(st[0].AntivirusSignatureAge), Mode: st[0].AMRunningMode}
	return nil
}

type antiVirusProduct struct {
	DisplayName string
}

func winAVProducts(r *report.Report) error {
	var products []antiVirusProduct
	if err := queryIn(`root\SecurityCenter2`, &products, "SELECT displayName FROM AntiVirusProduct"); err != nil {
		return err // servers have no Security Center: the key is left out, as the script's catch did
	}
	out := []string{}
	for _, p := range products {
		out = append(out, p.DisplayName)
	}
	r.AV = &out
	return nil
}

// ---- firewall profiles: what Get-NetFirewallProfile reads
type msftNetFirewallProfile struct {
	Name    string
	Enabled uint16
}

func winFirewall(r *report.Report) error {
	var profiles []msftNetFirewallProfile
	if err := queryIn(`root\StandardCimv2`, &profiles, "SELECT Name, Enabled FROM MSFT_NetFirewallProfile"); err != nil {
		return err
	}
	out := []report.FirewallProfile{}
	for _, p := range profiles {
		out = append(out, report.FirewallProfile{Name: p.Name, On: p.Enabled == 1})
	}
	r.Firewall = &out
	return nil
}

// ---- activation: the Windows product with a partial key, as the script asked
type softwareLicensingProduct struct {
	LicenseStatus        uint32
	GracePeriodRemaining uint32
}

func winActivation(r *report.Report) error {
	var lic []softwareLicensingProduct
	if err := query(&lic, "SELECT LicenseStatus, GracePeriodRemaining FROM SoftwareLicensingProduct WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"); err != nil {
		return err
	}
	if len(lic) == 0 {
		return nil
	}
	r.Activation = &report.Activation{Status: int(lic[0].LicenseStatus), GraceMin: int(lic[0].GracePeriodRemaining)}
	return nil
}

// ---- Hyper-V: the virtual machines of root\virtualization\v2 (absent on a computer without the role: the key is left out)
type msvmComputerSystem struct {
	ElementName  string
	Caption      string
	EnabledState uint16
	HealthState  uint16
}

func winHyperV(r *report.Report) error {
	var vms []msvmComputerSystem
	if err := queryIn(`root\virtualization\v2`, &vms, "SELECT ElementName, Caption, EnabledState, HealthState FROM Msvm_ComputerSystem WHERE Caption='Virtual Machine'"); err != nil {
		return err
	}
	h := &report.HyperV{Bad: []string{}}
	states := map[uint16]string{2: "Running", 3: "Off", 6: "Saved", 9: "Paused", 10: "Starting", 32768: "Paused", 32769: "Saved", 32770: "Starting", 32773: "Saving", 32774: "Stopping", 32776: "Pausing", 32777: "Resuming"}
	for _, vm := range vms {
		state := word(states, vm.EnabledState)
		switch {
		case state == "Running" && vm.HealthState == 5:
			h.Running++
		case state == "Running":
			h.Running++
			h.Bad = append(h.Bad, vm.ElementName+" (Running, health "+fmt.Sprint(vm.HealthState)+")")
		case state == "Off":
			h.Off++
		case state == "Paused" || state == "Saved" || vm.HealthState >= 20:
			h.Bad = append(h.Bad, vm.ElementName+" ("+state+")")
		}
	}
	sort.Strings(h.Bad)
	r.HyperV = h
	return nil
}
