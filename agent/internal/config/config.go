// Package config reads and writes agent.json: the same file the PowerShell package uses, so a package made by Toner
// today configures this agent unchanged. Toner's address, the fingerprint of its certificate, the sign-up key (used once)
// and this computer's token live here; the folder is readable by administrators and the service account only.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config is agent.json. Field names are the package's; new fields are optional and default to today's behaviour.
type Config struct {
	Server   string `json:"server"`              // https://host:port/report
	Enroll   string `json:"enroll"`              // https://host:port/enroll
	Pin      string `json:"pin"`                 // sha256 of Toner's receiver certificate, lower-case hex
	Key      string `json:"key"`                 // the sign-up key; emptied once the token is in hand
	Minutes  int    `json:"minutes"`             // how often to report (1..60)
	Token    string `json:"token"`               // this computer's token
	QueueMax int    `json:"queue_max,omitempty"` // reports kept while Toner is unreachable (default 288)
	Proxy    string `json:"proxy,omitempty"`     // an explicit HTTP proxy for the agent's own connections ("" = direct)
	// Collectors that are turned off by name ({"software": false}). Absent means every collector runs.
	Collectors map[string]bool `json:"collectors,omitempty"`

	path string
}

const (
	DefaultMinutes  = 5
	DefaultQueueMax = 288 // a day of five-minute reports
)

// Load reads agent.json from path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw = []byte(strings.TrimPrefix(string(raw), "\uFEFF")) // PowerShell may have written a BOM
	c := &Config{}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("agent.json is not valid JSON: %w", err)
	}
	c.path = path
	c.normalize()
	return c, nil
}

func (c *Config) normalize() {
	c.Pin = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(c.Pin), ":", ""), "-", ""))
	if c.Minutes < 1 || c.Minutes > 60 {
		c.Minutes = DefaultMinutes
	}
	if c.QueueMax <= 0 {
		c.QueueMax = DefaultQueueMax
	}
	if c.Enroll == "" && strings.HasSuffix(c.Server, "/report") {
		c.Enroll = strings.TrimSuffix(c.Server, "/report") + "/enroll"
	}
}

// Validate says what is missing for the agent to work at all.
func (c *Config) Validate() error {
	var missing []string
	if c.Server == "" {
		missing = append(missing, "server")
	}
	if len(c.Pin) != 64 {
		missing = append(missing, "pin (64 hex characters)")
	}
	if c.Token == "" && c.Key == "" {
		missing = append(missing, "token or key")
	}
	if len(missing) > 0 {
		return errors.New("agent.json lacks: " + strings.Join(missing, ", "))
	}
	return nil
}

// Path is where this configuration was read from.
func (c *Config) Path() string { return c.path }

// Dir is the agent folder: where agent.json lives, and the queue beside it.
func (c *Config) Dir() string { return filepath.Dir(c.path) }

// Save writes agent.json back (compact, no BOM, as the script wrote it), through a temporary file so a crash mid-write
// cannot lose the token.
func (c *Config) Save() error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// UpdateURL turns the report URL into the download URL of this agent's own binary.
func (c *Config) UpdateURL(goos, goarch string) string {
	base := strings.TrimSuffix(c.Server, "/report")
	return base + "/agent/" + goos + "-" + goarch
}

// Enabled says whether a collector runs.
func (c *Config) Enabled(collector string) bool {
	if c.Collectors == nil {
		return true
	}
	on, found := c.Collectors[collector]
	return !found || on
}
