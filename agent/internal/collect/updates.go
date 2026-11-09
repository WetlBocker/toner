package collect

import (
	"sync"
	"time"

	"github.com/WetlBocker/toner/agent/internal/report"
)

// rawUpdate is one pending update as the Windows Update API gives it (KBs are bare numbers).
type rawUpdate struct {
	Title    string
	KBs      []string
	Severity string
}

// updatesFrom turns the API's rows into the report's; nothing pending is an empty slice, never nil.
func updatesFrom(rows []rawUpdate) []report.Update {
	out := make([]report.Update, 0, len(rows))
	for _, u := range rows {
		kb := ""
		for i, id := range u.KBs {
			if i > 0 {
				kb += ","
			}
			kb += "KB" + id
		}
		out = append(out, report.Update{Title: u.Title, KB: kb, Severity: u.Severity})
	}
	return out
}

// pendingCache is the last pending-updates list and the date of Windows' search it came from, kept for the agent's lifetime so
// the cached search runs again only when Windows has searched since.
var pendingCache struct {
	sync.Mutex
	list     []report.Update // nil: none read yet
	searched time.Time
}

// searchAgain says whether to run the cached search: when there is no list yet, when Windows' last search date is unknown, or
// when Windows searched after the list was read.
func searchAgain(have []report.Update, haveSearched, lastSearch time.Time) bool {
	return have == nil || lastSearch.IsZero() || lastSearch.After(haveSearched)
}
