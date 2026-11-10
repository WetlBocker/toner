// Package report is the document the agent sends: the same fields, names and shapes as core/winmon.py's PowerShell
// collector, so Toner's receiver and drivers/windows.py read it unchanged. Optional parts are pointers: nil means the
// collector could not run here (the evaluator says N/A), an empty value means it ran and found nothing (OK).
package report

// Report is one report. Field order follows the PowerShell collector for easy comparison; JSON does not care.
type Report struct {
	V        int      `json:"v"`
	At       string   `json:"at"` // when collection started, RFC 3339 UTC
	Computer string   `json:"computer"`
	Domain   string   `json:"domain"`
	Joined   bool     `json:"joined"`
	OS       string   `json:"os"`
	Build    string   `json:"build"`
	Boot     string   `json:"boot,omitempty"`
	UptimeH  *float64 `json:"uptime_h,omitempty"`
	MemTotal *int64   `json:"mem_total_mb,omitempty"`
	MemFree  *int64   `json:"mem_free_mb,omitempty"`
	IPs      []string `json:"ips"`
	CPU      *float64 `json:"cpu,omitempty"`
	Disks    []Disk   `json:"disks"`
	Reboot   []string `json:"reboot"`

	ServiceStates map[string]string `json:"service_states"` // name -> "R" running / "S" anything else
	AutoStopped   []StoppedService  `json:"auto_stopped"`

	Events  *Events `json:"events,omitempty"`
	Certs   *[]Cert `json:"certs,omitempty"`
	Patched string  `json:"patched,omitempty"`
	// PendingUpdates is Windows' cached update search: nil = the search could not run, empty = nothing pending.
	PendingUpdates  *[]Update         `json:"pending_updates,omitempty"`
	UpdatesSearched string            `json:"updates_searched,omitempty"` // when Windows last searched successfully, RFC 3339 UTC
	UpdatesError    bool              `json:"updates_error,omitempty"`    // the search was refused or failed (PendingUpdates is then nil)
	Software        map[string]string `json:"software"`
	Admins          *[]string         `json:"admins,omitempty"`
	Ports           *[]string         `json:"ports,omitempty"` // "443/nginx", unique by port, sorted

	Physical   *[]PhysicalDisk    `json:"physical,omitempty"`
	Volumes    *[]Volume          `json:"volumes,omitempty"`
	BitLocker  *[]BitLockerVolume `json:"bitlocker,omitempty"`
	Defender   *Defender          `json:"defender,omitempty"`
	AV         *[]string          `json:"av_products,omitempty"`
	Firewall   *[]FirewallProfile `json:"firewall,omitempty"`
	Activation *Activation        `json:"activation,omitempty"`
	Sessions   *Sessions          `json:"sessions,omitempty"`
	Logons     *Logons            `json:"logons,omitempty"`
	AD         *AD                `json:"ad,omitempty"`
	HyperV     *HyperV            `json:"hyperv,omitempty"`
	Backup     *Backup            `json:"backup,omitempty"`
	Tasks      *[]TaskFailure     `json:"task_failures,omitempty"`
	Hardening  *Hardening         `json:"hardening,omitempty"`

	Now   string `json:"now"` // when collection finished, RFC 3339 UTC (the clock check compares it with Toner's)
	Agent Agent  `json:"agent"`

	// Notes are what could not be collected and why; sent along so support can see it, ignored by the evaluator.
	Notes []string `json:"notes,omitempty"`
}

// Agent identifies the program that made the report (new; absent from PowerShell reports).
type Agent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

type Disk struct {
	Drive string `json:"drive"` // "C:" on Windows, the mount point elsewhere
	Size  int64  `json:"size"`
	Free  int64  `json:"free"`
}

type StoppedService struct {
	Name    string `json:"name"`
	Display string `json:"display"`
	Exit    int    `json:"exit"`
	Delayed bool   `json:"delayed"`
	Trigger bool   `json:"trigger"`
}

type Events struct {
	Count  int           `json:"count"`
	Capped bool          `json:"capped"`
	Top    []EventSource `json:"top"`
}

type EventSource struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
}

type Cert struct {
	Subject string `json:"subject"`
	Days    int    `json:"days"`
	Thumb   string `json:"thumb"`
	Expires string `json:"expires,omitempty"` // NotAfter, RFC 3339 UTC
}

// Update is one pending Windows update.
type Update struct {
	Title    string `json:"title"`
	KB       string `json:"kb"`       // "KB5001,KB5002"
	Severity string `json:"severity"` // MsrcSeverity, "" when Microsoft gives none
}

type PhysicalDisk struct {
	Name   string `json:"name"`
	Health string `json:"health"` // Healthy / Warning / Unhealthy
	Op     string `json:"op"`     // OK, or a comma-joined list of operational states
	Media  string `json:"media"`  // HDD / SSD / Unspecified
}

type Volume struct {
	Drive  string `json:"drive"`
	Health string `json:"health"`
}

type BitLockerVolume struct {
	Mount      string `json:"mount"`
	Protection string `json:"protection"` // On / Off / Unknown
	Status     string `json:"status"`     // FullyEncrypted, FullyDecrypted, EncryptionInProgress, ...
}

type Defender struct {
	Enabled  bool   `json:"enabled"`
	Realtime bool   `json:"realtime"`
	SigDays  int    `json:"sig_days"`
	Mode     string `json:"mode"`
}

// Hardening is the Windows settings snapshot (core/winsettings.py). A Reg name left out could not be read; a nil value was
// read and is not set. Policy and Audit are left out when their tool failed.
type Hardening struct {
	V      int               `json:"v"`
	DC     *bool             `json:"dc,omitempty"` // a domain controller; left out when the role could not be read
	Reg    map[string]*int64 `json:"reg"`
	Policy map[string]int64  `json:"policy,omitempty"`
	Audit  map[string]string `json:"audit,omitempty"`
}

type FirewallProfile struct {
	Name string `json:"name"`
	On   bool   `json:"on"`
}

type Activation struct {
	Status   int `json:"status"`    // SoftwareLicensingProduct.LicenseStatus: 1 licensed
	GraceMin int `json:"grace_min"` // minutes of grace left
}

type Sessions struct {
	Active       int `json:"active"`
	Disconnected int `json:"disconnected"`
}

type Logons struct {
	Failed   int         `json:"failed"`
	Capped   bool        `json:"capped"`
	Top      []LogonUser `json:"top"`
	Lockouts int         `json:"lockouts"`
}

type LogonUser struct {
	User  string `json:"user"`
	Count int    `json:"count"`
}

type AD struct {
	ReplFail  int `json:"repl_fail"`
	ReplTotal int `json:"repl_total"`
}

type HyperV struct {
	Running int      `json:"running"`
	Off     int      `json:"off"`
	Bad     []string `json:"bad"`
}

type Backup struct {
	Last   string `json:"last"`
	Result int    `json:"result"`
}

type TaskFailure struct {
	Name   string `json:"name"`
	Result string `json:"result"` // "0x80070002"
}

// Ptr is a small helper for the optional fields.
func Ptr[T any](v T) *T { return &v }
