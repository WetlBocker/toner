//go:build windows

package collect

import (
	"encoding/xml"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/WetlBocker/toner/agent/internal/report"
)

// The Windows Event Log API (wevtapi.dll), the way Get-WinEvent reads it: a query per log, events rendered as XML.
var (
	wevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = wevtapi.NewProc("EvtQuery")
	procEvtNext   = wevtapi.NewProc("EvtNext")
	procEvtRender = wevtapi.NewProc("EvtRender")
	procEvtClose  = wevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1
	errNoMoreItems           = syscall.Errno(259)
)

const dayMs = "86400000"

// evtEvent is the part of an event's XML the collectors read.
type evtEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID string `xml:"EventID"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:",attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func (e *evtEvent) data(name string) string {
	for _, d := range e.EventData.Data {
		if d.Name == name {
			return d.Value
		}
	}
	return ""
}

// readEvents runs an XPath query against one log and gives back up to max events, newest first.
func readEvents(log, xpath string, max int) ([]evtEvent, error) {
	logW, err := windows.UTF16PtrFromString(log)
	if err != nil {
		return nil, err
	}
	queryW, err := windows.UTF16PtrFromString(xpath)
	if err != nil {
		return nil, err
	}
	h, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(logW)), uintptr(unsafe.Pointer(queryW)), evtQueryChannelPath|evtQueryReverseDirection)
	if h == 0 {
		return nil, fmt.Errorf("EvtQuery %s: %v", log, e)
	}
	defer procEvtClose.Call(h)
	out := make([]evtEvent, 0, 64)
	batch := make([]uintptr, 64)
	var buf []uint16
	for len(out) < max {
		var returned uint32
		ok, _, e := procEvtNext.Call(h, uintptr(len(batch)), uintptr(unsafe.Pointer(&batch[0])), 5000, 0, uintptr(unsafe.Pointer(&returned)))
		if ok == 0 {
			if errno, isErrno := e.(syscall.Errno); isErrno && (errno == errNoMoreItems || errno == windows.WAIT_TIMEOUT) {
				break
			}
			return out, fmt.Errorf("EvtNext %s: %v", log, e)
		}
		for i := uint32(0); i < returned; i++ {
			ev := batch[i]
			if len(out) < max {
				var used, props uint32
				if len(buf) == 0 {
					buf = make([]uint16, 8192)
				}
				ok, _, _ := procEvtRender.Call(0, ev, evtRenderEventXML, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
				if ok == 0 && used > uint32(len(buf)*2) {
					buf = make([]uint16, used/2+1)
					ok, _, _ = procEvtRender.Call(0, ev, evtRenderEventXML, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
				}
				if ok != 0 {
					text := windows.UTF16ToString(buf[:used/2])
					var parsed evtEvent
					if xml.Unmarshal([]byte(text), &parsed) == nil {
						out = append(out, parsed)
					}
				}
			}
			procEvtClose.Call(ev)
		}
		if returned < uint32(len(batch)) {
			break
		}
	}
	return out, nil
}

// winEvents counts Critical and Error events of the last 24 hours in System and Application, with the five noisiest
// sources (the script's one Get-WinEvent over both logs, capped at 1000).
func winEvents(r *report.Report) error {
	const cap = 1000
	xpath := "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= " + dayMs + "]]]"
	counts := map[string]int{}
	total := 0
	var firstErr error
	for _, log := range []string{"System", "Application"} {
		evs, err := readEvents(log, xpath, cap-total)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, e := range evs {
			counts[e.System.Provider.Name]++
			total++
		}
		if total >= cap {
			break
		}
	}
	if total == 0 && firstErr != nil {
		return firstErr // the logs could not be read at all: leave the part out, as the script did when Get-WinEvent threw
	}
	r.Events = &report.Events{Count: total, Capped: total >= cap, Top: topCounts(counts, 5)}
	return nil
}

// winLogons counts failed sign-ins (4625) and lockouts (4740) in the Security log over 24 hours, with the three accounts
// most tried. Reading Security needs the service account's rights (SYSTEM has them); without them the part is left out.
func winLogons(r *report.Report) error {
	failed, err := readEvents("Security", "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= "+dayMs+"]]]", 2000)
	if err != nil {
		return err
	}
	users := map[string]int{}
	for _, e := range failed {
		users[e.data("TargetUserName")]++
	}
	lockouts, err := readEvents("Security", "*[System[(EventID=4740) and TimeCreated[timediff(@SystemTime) <= "+dayMs+"]]]", 200)
	if err != nil && !errors.Is(err, errNoMoreItems) {
		lockouts = nil
	}
	top := topCounts(users, 3)
	lg := &report.Logons{Failed: len(failed), Capped: len(failed) >= 2000, Top: make([]report.LogonUser, 0, len(top)), Lockouts: len(lockouts)}
	for _, t := range top {
		lg.Top = append(lg.Top, report.LogonUser{User: t.Source, Count: t.Count})
	}
	r.Logons = lg
	return nil
}
