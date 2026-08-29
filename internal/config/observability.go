package config

import (
	"fmt"
	"log/slog"
	"strings"
)

// LogFormat is how log records are rendered.
type LogFormat string

const (
	// LogFormatAuto picks text on a terminal and JSON everywhere else, which is
	// almost always what both a developer and a log aggregator want.
	LogFormatAuto LogFormat = "auto"
	// LogFormatText is the human-readable form.
	LogFormatText LogFormat = "text"
	// LogFormatJSON is one object per record, for ingestion.
	LogFormatJSON LogFormat = "json"
)

// Observability configures what the node reports about itself.
//
// Health probes ride on the main API port, because that is where a kubelet
// looks. Metrics and pprof ride on a separate one: they describe the process,
// not the dataspace, and nothing outside the cluster should reach them.
type Observability struct {
	// LogLevel is the minimum severity emitted: debug, info, warn or error.
	LogLevel string `mapstructure:"log_level"`
	// LogFormat selects the rendering.
	LogFormat LogFormat `mapstructure:"log_format"`
	// Metrics serves the Prometheus endpoint on the internal listener.
	Metrics bool `mapstructure:"metrics"`
	// Pprof serves the profiling endpoints on the internal listener. Off by
	// default: a heap dump is a lot to hand out for free.
	Pprof bool `mapstructure:"pprof"`
	// Port is the internal listener carrying metrics and pprof. Empty disables
	// it altogether.
	Port string `mapstructure:"port"`
}

// Validate implements the section contract, and canonicalises the spellings.
func (o *Observability) Validate() error {
	o.LogLevel = strings.ToLower(strings.TrimSpace(o.LogLevel))
	o.LogFormat = LogFormat(strings.ToLower(strings.TrimSpace(string(o.LogFormat))))

	if _, err := o.Level(); err != nil {
		return err
	}

	switch o.LogFormat {
	case LogFormatAuto, LogFormatText, LogFormatJSON:
	default:
		return invalid("observability.log_format",
			fmt.Sprintf("unknown format %q, want auto, text or json", o.LogFormat))
	}

	return nil
}

// Level parses the configured severity.
func (o Observability) Level() (slog.Level, error) {
	switch o.LogLevel {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, invalid("observability.log_level",
			fmt.Sprintf("unknown level %q, want debug, info, warn or error", o.LogLevel))
	}
}

// InternalAddr is the listen address for metrics and pprof, or "" when the
// internal listener is switched off.
func (o Observability) InternalAddr() string {
	if o.Port == "" || (!o.Metrics && !o.Pprof) {
		return ""
	}

	return ":" + o.Port
}
