//go:build windows

package collect

import (
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/WetlBocker/toner/agent/internal/report"
)

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")
	procNetApiBufferFree        = netapi32.NewProc("NetApiBufferFree")

	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateSessionsW       = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = wtsapi32.NewProc("WTSFreeMemory")
)

// winAdmins lists the members of the local Administrators group (found by its SID, so any language works), as
// DOMAIN\name, the way Get-LocalGroupMember shows them.
func winAdmins(r *report.Report) error {
	sid, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	group, _, _, err := sid.LookupAccount("")
	if err != nil {
		return err
	}
	groupW, _ := windows.UTF16PtrFromString(group)
	var buf *byte
	var read, total uint32
	var resume uintptr
	// level 3: LOCALGROUP_MEMBERS_INFO_3 { LPWSTR lgrmi3_domainandname }
	ret, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(groupW)), 3, uintptr(unsafe.Pointer(&buf)), 0xFFFFFFFF,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if ret != 0 {
		return fmt.Errorf("NetLocalGroupGetMembers: status %d", ret)
	}
	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buf)))
	out := []string{}
	entries := unsafe.Slice((**uint16)(unsafe.Pointer(buf)), read)
	for _, p := range entries {
		if p != nil {
			out = append(out, windows.UTF16PtrToString(p))
		}
	}
	sort.Strings(out)
	r.Admins = &out
	return nil
}

// WTS_SESSION_INFOW
type wtsSessionInfo struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32
}

const (
	wtsActive       = 0
	wtsDisconnected = 4
	wtsUserName     = 5
)

// winSessions counts interactive sessions with a user, active and disconnected, as `quser` lists them.
func winSessions(r *report.Report) error {
	var info *wtsSessionInfo
	var count uint32
	ok, _, e := procWTSEnumerateSessionsW.Call(0, 0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		return fmt.Errorf("WTSEnumerateSessions: %v", e)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(info)))
	sessions := unsafe.Slice(info, count)
	s := &report.Sessions{}
	for _, se := range sessions {
		if se.State != wtsActive && se.State != wtsDisconnected {
			continue
		}
		var user *uint16
		var n uint32
		ok, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(se.SessionID), wtsUserName, uintptr(unsafe.Pointer(&user)), uintptr(unsafe.Pointer(&n)))
		if ok == 0 || user == nil {
			continue
		}
		name := windows.UTF16PtrToString(user)
		procWTSFreeMemory.Call(uintptr(unsafe.Pointer(user)))
		if strings.TrimSpace(name) == "" {
			continue // the services session, listeners: not a person
		}
		if se.State == wtsActive {
			s.Active++
		} else {
			s.Disconnected++
		}
	}
	r.Sessions = s
	return nil
}
