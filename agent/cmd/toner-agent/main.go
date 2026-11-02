// toner-agent sends reports about this computer to Toner. It only sends: it opens no port and accepts no commands.
//
//	toner-agent install [agent.json]   install as a service (the agent.json beside this program by default), send the first report
//	toner-agent uninstall              remove the service and the agent folder
//	toner-agent run                    what the service runs: report every few minutes
//	toner-agent once                   sign up if needed, send one report, exit
//	toner-agent collect                print the report as JSON; nothing is sent
//	toner-agent version
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/WetlBocker/toner/agent/internal/agent"
	"github.com/WetlBocker/toner/agent/internal/collect"
	"github.com/WetlBocker/toner/agent/internal/config"
	"github.com/WetlBocker/toner/agent/internal/service"
)

func main() {
	logger := log.New(os.Stderr, "toner-agent ", log.LstdFlags)
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "version", "--version", "-v":
		fmt.Println(agent.Version)
	case "collect":
		rep := collect.Run(context.Background(), collect.Options{Version: agent.Version})
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(rep)
	case "once":
		cfg, lerr := loadConfig(argOr(2, ""))
		if lerr != nil {
			err = lerr
			break
		}
		a, aerr := agent.New(cfg, logger)
		if aerr != nil {
			err = aerr
			break
		}
		_, err = a.Once(context.Background())
	case "run":
		service.CleanOld()
		cfg, lerr := loadConfig(argOr(2, ""))
		if lerr != nil {
			err = lerr
			break
		}
		a, aerr := agent.New(cfg, logger)
		if aerr != nil {
			err = aerr
			break
		}
		a.Updater = service.ApplyUpdate
		restarted := false
		err = service.RunUnderManager(func(ctx context.Context) error {
			rerr := a.Run(ctx)
			restarted = ctx.Err() == nil // Run returned on its own: an update wants a restart
			return rerr
		})
		if err == nil && restarted {
			os.Exit(agent.ExitUpdated)
		}
	case "install":
		err = install(argOr(2, ""), logger)
	case "uninstall":
		if err = service.Uninstall(); err == nil {
			err = service.RemoveDir()
		}
		if err == nil {
			fmt.Println("Toner agent removed. The computer stays listed in Toner until you delete it there.")
		}
	default:
		fmt.Fprintln(os.Stderr, "toner-agent install [agent.json] | uninstall | run | once | collect | version")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "toner-agent:", err)
		os.Exit(1)
	}
}

func argOr(i int, dflt string) string {
	if len(os.Args) > i {
		return os.Args[i]
	}
	return dflt
}

// loadConfig reads the named agent.json, else the installed one, else the one beside this program.
func loadConfig(path string) (*config.Config, error) {
	candidates := []string{}
	if path != "" {
		candidates = append(candidates, path)
	} else {
		candidates = append(candidates, service.ConfigPath())
		if self, err := os.Executable(); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(self), "agent.json"))
		}
	}
	var lastErr error
	for _, c := range candidates {
		cfg, err := config.Load(c)
		if err == nil {
			return cfg, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no agent.json found (%v)", lastErr)
}

func install(configPath string, logger *log.Logger) error {
	if configPath == "" {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		configPath = filepath.Join(filepath.Dir(self), "agent.json")
		if _, err := os.Stat(configPath); err != nil && service.ConfigPath() != configPath {
			if _, err2 := os.Stat(service.ConfigPath()); err2 == nil {
				configPath = "" // an installed agent.json is already there (moving from the PowerShell agent): keep it
			} else {
				return fmt.Errorf("no agent.json beside the program: put the package's agent.json next to toner-agent")
			}
		}
	}
	if configPath != "" {
		if _, err := config.Load(configPath); err != nil {
			return err
		}
	}
	if err := service.Stage(configPath); err != nil {
		return err
	}
	if err := service.Install(); err != nil {
		return err
	}
	fmt.Printf("Toner agent installed as a service, in %s. Sending the first report...\n", service.Dir())
	cfg, err := config.Load(service.ConfigPath())
	if err != nil {
		return err
	}
	a, err := agent.New(cfg, logger)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := a.Once(ctx); err != nil {
		fmt.Println("The agent is installed but could not reach Toner yet:", err)
		fmt.Println("It will keep trying every few minutes.")
		return nil
	}
	fmt.Println("Done. This computer will appear in Toner.")
	return nil
}
