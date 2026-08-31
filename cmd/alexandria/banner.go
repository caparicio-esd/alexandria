package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"

	"github.com/caparicio-esd/alexandria/internal/config"
)

// The startup report is styled, but it must survive being piped into a file or
// a log aggregator. Every write goes through a colorprofile.Writer, which
// detects what the destination can render and strips the escape sequences when
// the answer is "nothing" — so `docker logs` shows the same table, in plain
// text, and the tests read clean strings out of a bytes.Buffer.
var (
	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 2)

	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5"))
	labelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Width(10)
	valueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	okStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	faintStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

// report writes styled output to a destination, downsampling the colour to
// whatever that destination supports.
type report struct {
	out *colorprofile.Writer
}

// newReport wraps a writer for styled output.
func newReport(out io.Writer, environ []string) *report {
	return &report{out: colorprofile.NewWriter(out, environ)}
}

// line writes one styled line.
func (r *report) line(s string) error {
	if _, err := fmt.Fprintln(r.out, s); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	return nil
}

// row is one label-and-value pair of the summary table.
func row(label, value string) string {
	return labelStyle.Render(label) + valueStyle.Render(value)
}

// summary renders the startup table: what this node is, and what it is about to
// talk to. It is the answer to "which config did it actually pick up", which is
// the first question anybody asks when a deployment misbehaves.
func (r *report) summary(version string, cfg *config.Config) error {
	walletURL, err := cfg.Wallet.APIURL(config.HostHTTP)
	if err != nil {
		return err
	}

	rows := []string{
		titleStyle.Render("alexandria " + version),
		"",
		row("config", cfg.Source()),
		row("node", cfg.Common.Hosts.HTTP.URL()),
		row("api", cfg.Common.API.Prefix()),
		row("wallet", string(cfg.Wallet.Kind)+" · "+walletURL),
		row("database", databaseSummary(cfg.Common.DB)),
		row("did", string(cfg.Did.Method)),
		row("policy", policySummary(cfg.Verify)),
		row("mode", modeSummary(cfg.Common.Connection)),
	}

	return r.line(borderStyle.Render(strings.Join(rows, "\n")))
}

// internal reports the diagnostics listener, so nobody has to guess which port
// Prometheus should scrape.
func (r *report) internal(addr string, cfg config.Observability) error {
	served := make([]string, 0, 2)
	if cfg.Metrics {
		served = append(served, "/metrics")
	}

	if cfg.Pprof {
		served = append(served, "/debug/pprof")
	}

	return r.line(faintStyle.Render(" · internal   " + addr + " " + strings.Join(served, " ")))
}

// summaryAttrs is the startup summary as structured log attributes, for the
// deployments where the table would be noise in a log pipeline.
//
// It carries the same facts as the table on purpose: an operator reading JSON
// should not have to run the binary in a terminal to find out what it loaded.
func summaryAttrs(cfg *config.Config) []any {
	walletURL, err := cfg.Wallet.APIURL(config.HostHTTP)
	if err != nil {
		walletURL = "unresolved"
	}

	return []any{
		"config", cfg.Source(),
		"node", cfg.Common.Hosts.HTTP.URL(),
		"api", cfg.Common.API.Prefix(),
		"wallet", string(cfg.Wallet.Kind),
		"wallet_url", walletURL,
		"database", databaseSummary(cfg.Common.DB),
		"did_method", string(cfg.Did.Method),
		"policy", policySummary(cfg.Verify),
		"mode", modeSummary(cfg.Common.Connection),
	}
}

// module reports a bounded context that finished starting, with whatever it
// had to say for itself.
func (r *report) module(name, detail string) error {
	line := okStyle.Render(" ✓ "+name) + strings.Repeat(" ", max(1, 12-len(name)))

	if detail == "" {
		return r.line(line + faintStyle.Render("started"))
	}

	return r.line(line + valueStyle.Render(shortenDid(detail)))
}

// listening reports the address the server came up on.
func (r *report) listening(addr string) error {
	return r.line(okStyle.Render(" ▸ listening") + " " + valueStyle.Render(addr))
}

// shortenDid trims the middle out of an identifier too long to read.
//
// A did:jwk encodes the whole public key, so it runs to several hundred
// characters and would swamp the report. Byte slicing is safe here: the DID
// syntax is ASCII, so there is no rune to cut in half.
func shortenDid(id string) string {
	const (
		longest = 48
		head    = 26
		tail    = 12
	)

	if len(id) <= longest {
		return id
	}

	return id[:head] + "…" + id[len(id)-tail:]
}

// databaseSummary describes the store in one line.
func databaseSummary(db config.Database) string {
	if db.Driver == config.DriverMemory {
		return "memory"
	}

	return string(db.Driver) + " · " + db.Host + ":" + db.Port
}

// policySummary describes what a peer has to present.
func policySummary(verify config.Verify) string {
	certs := "cert denied"
	if verify.IsCertAllowed {
		certs = "cert allowed"

		if verify.AutoApproveCert {
			certs += " (auto)"
		}
	}

	credentials := strconv.Itoa(len(verify.VCsRequested)) + " credential"
	if len(verify.VCsRequested) != 1 {
		credentials += "s"
	}

	return certs + " · " + credentials + " required"
}

// modeSummary describes the deployment flags.
func modeSummary(connection config.Connection) string {
	parts := make([]string, 0, 3)

	switch {
	case connection.IsProd:
		parts = append(parts, "production")
	case connection.IsLocal:
		parts = append(parts, "local")
	default:
		parts = append(parts, "development")
	}

	if connection.IsVaultReal {
		parts = append(parts, "vault live")
	} else {
		parts = append(parts, "vault mocked")
	}

	if connection.HasTLSProxy {
		parts = append(parts, "tls proxied")
	} else {
		parts = append(parts, "tls direct")
	}

	return strings.Join(parts, " · ")
}
