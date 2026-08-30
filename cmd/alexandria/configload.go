// Resolving which configuration document to load.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/caparicio-esd/alexandria/internal/config"
)

// configEnvVar names the deployment file when no --config flag is given.
const configEnvVar = "ALEXANDRIA_CONFIG"

// searchPaths are the directories Discover falls back to when neither the flag
// nor the environment names a file.
var searchPaths = []string{".", "./config", "/etc/alexandria"}

// loadConfig resolves the deployment file: the --config flag wins, then
// $ALEXANDRIA_CONFIG, then a search for config.yaml in the usual places.
//
// Flag parsing writes to the caller's writer and reports the error rather than
// exiting, so run stays testable and its deferred cleanup still runs.
func loadConfig(args []string, out io.Writer) (*config.Config, error) {
	flags := flag.NewFlagSet("alexandria", flag.ContinueOnError)
	flags.SetOutput(out)

	path := flags.String("config", os.Getenv(configEnvVar),
		"path to the deployment YAML (defaults to $"+configEnvVar+")")

	if err := flags.Parse(args); err != nil {
		return nil, fmt.Errorf("parsing flags: %w", err)
	}

	if *path != "" {
		cfg, err := config.Load(*path)
		if err != nil {
			return nil, fmt.Errorf("loading config: %w", err)
		}

		return cfg, nil
	}

	cfg, err := config.Discover(searchPaths...)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	return cfg, nil
}
