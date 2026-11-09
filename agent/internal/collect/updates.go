package collect

import "github.com/WetlBocker/toner/agent/internal/report"

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
