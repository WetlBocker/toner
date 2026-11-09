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
	patched  string // r.Patched when the list was read: a change means an install since
}

// searchAgain says whether to run the cached search: when there is no list yet, when Windows' last search date is unknown, or
// when Windows searched after the list was read, or when the newest install date differs from the one the list was read at (an
// update installed since Windows' last search would otherwise stay listed as pending).
func searchAgain(have []report.Update, haveSearched, lastSearch time.Time, havePatched, patched string) bool {
	return have == nil || lastSearch.IsZero() || lastSearch.After(haveSearched) || patched != havePatched
}

// updatesUnfinished marks a report whose update step was skipped (out of time) or panicked: updates_error says so, and
// PendingUpdates stays nil unless the step had already set it.
func updatesUnfinished(r *report.Report) {
	if r.PendingUpdates == nil {
		r.UpdatesError = true
	}
}
