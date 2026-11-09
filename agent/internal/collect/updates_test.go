package collect

import (
	"reflect"
	"testing"
	"time"

	"github.com/WetlBocker/toner/agent/internal/report"
)

func TestSearchAgain(t *testing.T) {
	day := time.Date(2026, 11, 8, 3, 0, 0, 0, time.UTC)
	list := []report.Update{}
	cases := []struct {
		name               string
		have               []report.Update
		haveSearched, last time.Time
		havePatched, patch string
		want               bool
	}{
		{"no list yet", nil, time.Time{}, day, "", "", true},
		{"the same search date reuses the list", list, day, day, "p1", "p1", false},
		{"an empty list is a list too", list, day, day, "", "", false},
		{"Windows searched since", list, day, day.Add(time.Hour), "p1", "p1", true},
		{"an older date reuses the list", list, day, day.Add(-time.Hour), "p1", "p1", false},
		{"the date could not be read", list, day, time.Time{}, "p1", "p1", true},
		{"patched changed: an install since", list, day, day, "p1", "p2", true},
	}
	for _, c := range cases {
		if got := searchAgain(c.have, c.haveSearched, c.last, c.havePatched, c.patch); got != c.want {
			t.Errorf("%s: searchAgain = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestUpdatesFrom(t *testing.T) {
	got := updatesFrom([]rawUpdate{
		{Title: "Cumulative Update", KBs: []string{"5001", "5002"}, Severity: "Critical"},
		{Title: "Driver", Severity: ""},
	})
	want := []report.Update{
		{Title: "Cumulative Update", KB: "KB5001,KB5002", Severity: "Critical"},
		{Title: "Driver"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if got := updatesFrom(nil); got == nil || len(got) != 0 {
		t.Fatalf("nothing pending must be a non-nil empty slice, got %#v", got)
	}
}

func TestUpdatesUnfinished(t *testing.T) {
	r := &report.Report{}
	updatesUnfinished(r)
	if !r.UpdatesError || r.PendingUpdates != nil {
		t.Fatalf("skipped step: UpdatesError=%v PendingUpdates=%v", r.UpdatesError, r.PendingUpdates)
	}
	done := []report.Update{}
	r = &report.Report{PendingUpdates: &done}
	updatesUnfinished(r)
	if r.UpdatesError {
		t.Fatal("a finished step must not be marked")
	}
}
