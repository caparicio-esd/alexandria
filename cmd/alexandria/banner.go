package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"

	"github.com/caparicio-esd/alexandria/internal/config"
	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
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
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
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

// linked reports the identity the wallet handed over.
func (r *report) linked(identity wallet.Did) error {
	if err := r.line(okStyle.Render(" ✓ linked") + "   " + valueStyle.Render(shortenDid(identity.ID))); err != nil {
		return err
	}

	detail := "alias " + identity.Alias
	if identity.DefaultKey.Fragment != "" {
		detail += " · key #" + identity.DefaultKey.Fragment
	}

	return r.line(faintStyle.Render("            " + detail))
}

// waiting reports a failed handshake attempt and the pause before the next one.
func (r *report) waiting(attempt int, backoff, reason string) error {
	return r.line(warnStyle.Render(" … wallet not ready") +
		faintStyle.Render(" (attempt "+strconv.Itoa(attempt)+", retrying in "+backoff+") "+reason))
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
