package collect

import (
	"reflect"
	"testing"

	"github.com/WetlBocker/toner/agent/internal/report"
)

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
