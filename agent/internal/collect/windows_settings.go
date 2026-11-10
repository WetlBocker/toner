//go:build windows

package collect

import (
	"context"
	"encoding/csv"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"

	"github.com/WetlBocker/toner/agent/internal/report"
)

// The Windows settings snapshot (report part "hardening"): the registry values, security policy keys and audit settings
// Toner's Windows hardening rules read. The lists are a hand-kept copy of core/winsettings.py (REG, POLICY, AUDIT), which
// tests/test_winsettings.py checks. A registry value that is set keeps its value, one in a readable hive that is not set is
// reported as null, and one that cannot be read is left out. Each source is read alone and left out when it fails.

type regValue struct{ name, path, value string }

var hardeningReg = []regValue{
	{"Smb1Server", `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1"},
	{"Smb1ClientStart", `SYSTEM\CurrentControlSet\Services\mrxsmb10`, "Start"},
	{"SmbServerSigning", `SYSTEM\CurrentControlSet\Services\LanManServer\Parameters`, "RequireSecuritySignature"},
	{"SmbClientSigning", `SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`, "RequireSecuritySignature"},
	{"LlmnrMulticast", `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast"},
	{"LmCompatibilityLevel", `SYSTEM\CurrentControlSet\Control\Lsa`, "LmCompatibilityLevel"},
	{"RunAsPPL", `SYSTEM\CurrentControlSet\Control\Lsa`, "RunAsPPL"},
	{"WDigestLogonCredential", `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, "UseLogonCredential"},
	{"CredGuardPolicy", `SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`, "LsaCfgFlags"},
	{"CredGuardLsa", `SYSTEM\CurrentControlSet\Control\Lsa`, "LsaCfgFlags"},
	{"RdpNlaPolicy", `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`, "UserAuthentication"},
	{"RdpNlaTcp", `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication"},
	{"RdpDenyConnections", `SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections"},
	{"EnableLUA", `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA"},
	{"Tls10Server", `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server`, "Enabled"},
	{"Tls11Server", `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server`, "Enabled"},
}

// Only these secedit keys are kept: never an account name (NewAdministratorName, NewGuestName) or anything else in the file.
var hardeningPolicy = map[string]bool{
	"MinimumPasswordLength": true, "PasswordComplexity": true, "PasswordHistorySize": true, "ClearTextPassword": true,
	"LockoutBadCount": true, "LockoutDuration": true, "ResetLockoutCount": true, "EnableGuestAccount": true,
}

// Audit subcategory GUIDs (uppercase, with braces).
var hardeningAudit = map[string]bool{
	"{0CCE923F-69AE-11D9-BED3-505054503030}": true, "{0CCE9215-69AE-11D9-BED3-505054503030}": true,
	"{0CCE9216-69AE-11D9-BED3-505054503030}": true, "{0CCE921B-69AE-11D9-BED3-505054503030}": true,
	"{0CCE9217-69AE-11D9-BED3-505054503030}": true, "{0CCE9235-69AE-11D9-BED3-505054503030}": true,
	"{0CCE9237-69AE-11D9-BED3-505054503030}": true, "{0CCE922F-69AE-11D9-BED3-505054503030}": true,
	"{0CCE9228-69AE-11D9-BED3-505054503030}": true, "{0CCE922B-69AE-11D9-BED3-505054503030}": true,
	"{0CCE9210-69AE-11D9-BED3-505054503030}": true, "{0CCE9211-69AE-11D9-BED3-505054503030}": true,
	"{0CCE9212-69AE-11D9-BED3-505054503030}": true,
}

func winHardening(ctx context.Context, r *report.Report) error {
	h := &report.Hardening{V: 1, Reg: readHardeningReg()}
	var errs []string
	if p, err := readHardeningPolicy(ctx); err != nil {
		errs = append(errs, "secedit: "+err.Error())
	} else {
		h.Policy = p
	}
	if a, err := readHardeningAudit(ctx); err != nil {
		errs = append(errs, "auditpol: "+err.Error())
	} else {
		h.Audit = a
	}
	r.Hardening = h
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// readHardeningReg: a name left out was unreadable; a nil value was read fine and is not set.
func readHardeningReg() map[string]*int64 {
	out := map[string]*int64{}
	for _, e := range hardeningReg {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, e.path, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if errors.Is(err, registry.ErrNotExist) {
			out[e.name] = nil
			continue
		}
		if err != nil {
			continue
		}
		n, _, err := k.GetIntegerValue(e.value)
		k.Close()
		switch {
		case errors.Is(err, registry.ErrNotExist):
			out[e.name] = nil
		case err == nil:
			v := int64(n)
			out[e.name] = &v
		}
	}
	return out
}

// readHardeningPolicy exports the effective policy (/mergedpolicy, so a domain member's domain policy counts) to a uniquely
// named temp file that is deleted whether or not the read worked. The file may hold more than the allowed keys, so its text is
// never logged or returned, and neither is the tool's output.
func readHardeningPolicy(ctx context.Context) (map[string]int64, error) {
	f, err := os.CreateTemp("", "toner_sp_*.inf")
	if err != nil {
		return nil, errors.New("no temp file")
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, system32("secedit.exe"), "/export", "/mergedpolicy", "/cfg", path, "/areas", "SECURITYPOLICY").Run(); err != nil {
		return nil, errors.New("could not export the policy")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("could not read the exported policy")
	}
	out := map[string]int64{}
	for _, line := range strings.Split(decodeInf(raw), "\n") {
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !hardeningPolicy[k] {
			continue
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			out[k] = n
		}
	}
	return out, nil
}

// decodeInf reads secedit's file: UTF-16 little endian with a byte order mark, or plain text.
func decodeInf(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return string(utf16.Decode(u))
	}
	return string(b)
}

// readHardeningAudit: `auditpol /get /category:* /r` is CSV with a header row; columns 3 and 4 are the subcategory GUID and
// the inclusion setting (read by position, since the headers are localised).
func readHardeningAudit(ctx context.Context) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, system32("auditpol.exe"), "/get", "/category:*", "/r").Output()
	if err != nil {
		return nil, errors.New("could not read the audit policy")
	}
	cr := csv.NewReader(strings.NewReader(string(out)))
	cr.FieldsPerRecord = -1
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, errors.New("could not parse the audit policy")
	}
	res := map[string]string{}
	for i, row := range rows {
		if i == 0 || len(row) < 5 {
			continue
		}
		if g := strings.ToUpper(strings.TrimSpace(row[3])); hardeningAudit[g] {
			res[g] = strings.TrimSpace(row[4])
		}
	}
	if len(res) == 0 {
		return nil, errors.New("no audit settings found")
	}
	return res, nil
}

func system32(exe string) string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", exe)
}
