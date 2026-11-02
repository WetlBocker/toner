//go:build windows

package collect

import (
	"fmt"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/WetlBocker/toner/agent/internal/report"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const tcpTableOwnerPidListener = 3

// MIB_TCPROW_OWNER_PID
type tcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32 // network byte order in the low 16 bits
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_TCP6ROW_OWNER_PID
type tcp6RowOwnerPid struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

// winPorts lists listening TCP ports with the process that owns them ("443/nginx"), unique by port, sorted by port,
// as the script's Get-NetTCPConnection -State Listen did.
func winPorts(r *report.Report) error {
	names, err := processNames()
	if err != nil {
		return err
	}
	byPort := map[uint16]string{}
	for _, af := range []uint32{syscall.AF_INET, syscall.AF_INET6} {
		var size uint32
		procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(af), tcpTableOwnerPidListener, 0)
		if size == 0 {
			continue
		}
		buf := make([]byte, size)
		ret, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), tcpTableOwnerPidListener, 0)
		if ret != 0 {
			return fmt.Errorf("GetExtendedTcpTable(af %d): %d", af, ret)
		}
		n := *(*uint32)(unsafe.Pointer(&buf[0]))
		base := unsafe.Pointer(&buf[4])
		for i := uint32(0); i < n; i++ {
			var port, pid uint32
			if af == syscall.AF_INET {
				row := (*tcpRowOwnerPid)(unsafe.Add(base, uintptr(i)*unsafe.Sizeof(tcpRowOwnerPid{})))
				port, pid = row.LocalPort, row.OwningPid
			} else {
				row := (*tcp6RowOwnerPid)(unsafe.Add(base, uintptr(i)*unsafe.Sizeof(tcp6RowOwnerPid{})))
				port, pid = row.LocalPort, row.OwningPid
			}
			p := uint16(port&0xFF)<<8 | uint16(port>>8&0xFF)
			if _, seen := byPort[p]; !seen {
				byPort[p] = names[pid]
			}
		}
	}
	ports := make([]int, 0, len(byPort))
	for p := range byPort {
		ports = append(ports, int(p))
	}
	sort.Ints(ports)
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, fmt.Sprintf("%d/%s", p, byPort[uint16(p)]))
	}
	r.Ports = &out
	return nil
}

// processNames maps pid -> process name without its extension, as Get-Process shows it.
func processNames() (map[uint32]string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	out := map[uint32]string{}
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return nil, err
	}
	for {
		name := windows.UTF16ToString(pe.ExeFile[:])
		out[pe.ProcessID] = strings.TrimSuffix(strings.TrimSuffix(name, ".exe"), ".EXE")
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return out, nil
}
