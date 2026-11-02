// Package agent is the loop: enroll once, then collect and send every few minutes, keep what could not be sent and
// send it later, and do what Toner's answer asks (a new token, a new interval, a newer agent).
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/WetlBocker/toner/agent/internal/collect"
	"github.com/WetlBocker/toner/agent/internal/config"
	"github.com/WetlBocker/toner/agent/internal/report"
	"github.com/WetlBocker/toner/agent/internal/transport"
)

// Version is the agent's version: always Toner's, set at build time (-ldflags "-X ...Version=1.14.0").
var Version = "0.0.0"

const (
	requestTimeout = 30 * time.Second
	collectTimeout = 4 * time.Minute
	updateMaxBytes = 64 << 20
)

// ExitUpdated is the exit code after a self-update: the service manager restarts the new binary.
const ExitUpdated = 3

// Agent runs for one configuration.
type Agent struct {
	cfg    *config.Config
	client *transport.Client
	log    *log.Logger
	// Updater applies a downloaded binary; nil in `once` mode. It returns true when the process should exit for a restart.
	Updater func(data []byte) (bool, error)
}

// New makes an agent from a loaded configuration.
func New(cfg *config.Config, logger *log.Logger) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client, err := transport.New(cfg.Pin, Version, cfg.Proxy, requestTimeout)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	return &Agent{cfg: cfg, client: client, log: logger}, nil
}

// Collect builds a report without sending anything.
func (a *Agent) Collect(ctx context.Context) *report.Report {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	return collect.Run(ctx, collect.Options{Version: Version, Enabled: a.cfg.Enabled})
}

// Once enrolls if needed, sends the queue and one fresh report, and acts on the answer. The bool says whether the process
// should exit so a newer binary starts.
func (a *Agent) Once(ctx context.Context) (restart bool, err error) {
	if err := a.ensureToken(ctx); err != nil {
		return false, err
	}
	a.flushQueue(ctx)
	rep := a.Collect(ctx)
	body, err := json.Marshal(rep)
	if err != nil {
		return false, err
	}
	ans, err := a.client.Report(ctx, a.cfg.Server, a.cfg.Token, body)
	if err != nil {
		if errors.Is(err, transport.ErrUnknownToken) || errors.Is(err, transport.ErrPin) {
			return false, err // not worth keeping: it will never be accepted
		}
		a.enqueue(body)
		return false, err
	}
	a.log.Printf("report sent (%d bytes); Toner answered ok", len(body))
	return a.apply(ctx, ans)
}

// Run is the service: Once, then again every `minutes`, until ctx ends or an update asks for a restart.
func (a *Agent) Run(ctx context.Context) error {
	for {
		restart, err := a.Once(ctx)
		if err != nil {
			a.log.Printf("report not sent: %v", err)
		}
		if restart {
			return nil
		}
		wait := time.Duration(a.cfg.Minutes) * time.Minute
		if err != nil && (errors.Is(err, transport.ErrUnknownToken) || errors.Is(err, transport.ErrPin)) {
			wait = 30 * time.Minute // someone has to fix the configuration; no point hammering
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

func (a *Agent) ensureToken(ctx context.Context) error {
	if a.cfg.Token != "" {
		return nil
	}
	if a.cfg.Key == "" {
		return errors.New("this agent has no token and no sign-up key")
	}
	computer, _ := os.Hostname()
	computer = strings.ToUpper(strings.SplitN(computer, ".", 2)[0])
	ans, err := a.client.Enroll(ctx, a.cfg.Enroll, a.cfg.Key, computer)
	if err != nil {
		return err
	}
	a.cfg.Token = ans.Token
	a.cfg.Key = "" // used once, as the script did
	if err := a.cfg.Save(); err != nil {
		return fmt.Errorf("signed up with Toner as %s, but could not save the token: %w", ans.Name, err)
	}
	a.log.Printf("signed up with Toner as %s", ans.Name)
	return nil
}

func (a *Agent) apply(ctx context.Context, ans *transport.Answer) (bool, error) {
	if ans.Token != "" {
		a.cfg.Token = ans.Token
		if err := a.cfg.Save(); err != nil {
			return false, fmt.Errorf("Toner gave a new token but it could not be saved: %w", err)
		}
		a.log.Printf("Toner gave this computer a new token")
	}
	if ans.Minutes >= 1 && ans.Minutes <= 60 && ans.Minutes != a.cfg.Minutes {
		a.cfg.Minutes = ans.Minutes
		if err := a.cfg.Save(); err == nil {
			a.log.Printf("Toner changed this agent to report every %d minutes", ans.Minutes)
		}
	}
	if ans.Update && a.Updater != nil {
		data, sum, err := a.client.Download(ctx, a.cfg.UpdateURL(runtime.GOOS, runtime.GOARCH), a.cfg.Token, updateMaxBytes)
		if err != nil {
			a.log.Printf("update not applied: %v", err)
			return false, nil
		}
		restart, err := a.Updater(data)
		if err != nil {
			a.log.Printf("update not applied: %v", err)
			return false, nil
		}
		a.log.Printf("the agent updated itself (sha256 %s)", sum[:12])
		return restart, nil
	}
	return false, nil
}

// ---- store-and-forward
func (a *Agent) queueDir() string { return filepath.Join(a.cfg.Dir(), "queue") }

func (a *Agent) enqueue(body []byte) {
	dir := a.queueDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	name := filepath.Join(dir, time.Now().UTC().Format("20060102T150405.000000000Z")+".json")
	if err := os.WriteFile(name, body, 0o600); err != nil {
		return
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	sort.Strings(files)
	for len(files) > a.cfg.QueueMax { // the oldest go first
		os.Remove(files[0])
		files = files[1:]
	}
	a.log.Printf("report kept for later (%d waiting)", len(files))
}

func (a *Agent) flushQueue(ctx context.Context) {
	files, _ := filepath.Glob(filepath.Join(a.queueDir(), "*.json"))
	if len(files) == 0 {
		return
	}
	sort.Strings(files)
	sent := 0
	for _, f := range files {
		if ctx.Err() != nil {
			return
		}
		body, err := os.ReadFile(f)
		if err != nil {
			os.Remove(f)
			continue
		}
		if _, err := a.client.Report(ctx, a.cfg.Server, a.cfg.Token, body); err != nil {
			if sent > 0 {
				a.log.Printf("sent %d kept report(s); the rest wait", sent)
			}
			return // Toner is still away: try again next time
		}
		os.Remove(f)
		sent++
	}
	a.log.Printf("sent %d kept report(s)", sent)
}
