package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPackageJSON(t *testing.T) {
	// Exactly what Toner's package writes, with the BOM PowerShell may add when it saves it back.
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	text := "\uFEFF" + `{"server": "https://toner.example.com:8750/report", "enroll": "https://toner.example.com:8750/enroll", "pin": "` +
		"AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99" + `", "key": "k", "minutes": 0, "token": ""}`
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Minutes != DefaultMinutes || c.QueueMax != DefaultQueueMax {
		t.Errorf("defaults: minutes %d queue %d", c.Minutes, c.QueueMax)
	}
	if len(c.Pin) != 64 || c.Pin != "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" {
		t.Errorf("pin not normalised: %q", c.Pin)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("a key is enough to start: %v", err)
	}
	if c.UpdateURL("windows", "amd64") != "https://toner.example.com:8750/agent/windows-amd64" {
		t.Errorf("update url: %s", c.UpdateURL("windows", "amd64"))
	}
	c.Token, c.Key = "tok", ""
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := Load(path)
	if err != nil || again.Token != "tok" || again.Key != "" {
		t.Errorf("saved token not read back: %v %+v", err, again)
	}
	if !again.Enabled("software") {
		t.Error("every collector runs by default")
	}
	again.Collectors = map[string]bool{"software": false}
	if again.Enabled("software") || !again.Enabled("cpu") {
		t.Error("a collector can be turned off by name")
	}
}

func TestValidate(t *testing.T) {
	c := &Config{}
	c.normalize()
	if err := c.Validate(); err == nil {
		t.Error("an empty configuration must not validate")
	}
	c = &Config{Server: "https://x/report", Pin: "0", Token: "t"}
	c.normalize()
	if err := c.Validate(); err == nil {
		t.Error("a short pin must not validate")
	}
	if c.Enroll != "https://x/enroll" {
		t.Errorf("the enroll URL follows the report URL: %s", c.Enroll)
	}
}
