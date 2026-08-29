// Package observability holds the cross-cutting instrumentation: structured
// logging, metrics and health probes.
//
// It sits beside the hexagon rather than inside it. The domain does not import
// it: a use case that had to remember to emit a metric would be a use case with
// an infrastructure concern baked in. Instrumentation is applied at the edges —
// in the adapters and at the composition root — where the request boundaries
// actually are.
package observability

import (
	"context"
	"io"
	"log/slog"
	"os"

	"github.com/caparicio-esd/alexandria/internal/config"
)

// requestIDKey is the context key carrying the per-request identifier.
//
// It is an unexported struct type, which is the standard way to keep a context
// key from colliding with one set by another package.
type requestIDKey struct{}

// WithRequestID returns a context carrying a request identifier.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFrom recovers the request identifier, or "" when there is none.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)

	return id
}

// NewLogger builds the process logger.
//
// It also installs the result as the slog default, so code reaching for the
// package-level functions — and any library that does — lands in the same
// stream with the same format, instead of writing unstructured lines beside it.
func NewLogger(out io.Writer, cfg config.Observability, attrs ...slog.Attr) (*slog.Logger, error) {
	level, err := cfg.Level()
	if err != nil {
		return nil, err
	}

	options := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if UsesJSON(out, cfg.LogFormat) {
		handler = slog.NewJSONHandler(out, options)
	} else {
		handler = slog.NewTextHandler(out, options)
	}

	logger := slog.New(&contextHandler{Handler: handler.WithAttrs(attrs)})
	slog.SetDefault(logger)

	return logger, nil
}

// UsesJSON resolves the auto format: a terminal gets text, anything else —
// a pipe, a file, a container's stdout — gets JSON.
//
// It is exported because the composition root asks the same question about its
// startup report: a human at a terminal gets the table, a log pipeline gets the
// same facts as one structured record instead.
func UsesJSON(out io.Writer, format config.LogFormat) bool {
	switch format {
	case config.LogFormatJSON:
		return true
	case config.LogFormatText:
		return false
	case config.LogFormatAuto:
		return !isTerminal(out)
	default:
		return true
	}
}

// isTerminal reports whether the writer is a character device.
func isTerminal(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok {
		return false
	}

	info, err := file.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}

// contextHandler copies request-scoped values onto every record.
//
// Putting it here rather than at each call site is what makes correlation
// reliable: a log line is only useful in an incident if it can be tied back to
// the request that produced it, and that cannot depend on every caller
// remembering to attach the id.
type contextHandler struct {
	slog.Handler
}

// Handle implements slog.Handler.
func (h *contextHandler) Handle(ctx context.Context, record slog.Record) error {
	if id := RequestIDFrom(ctx); id != "" {
		record.AddAttrs(slog.String("request_id", id))
	}

	//nolint:wrapcheck // a handler must pass its wrapped error through untouched
	return h.Handler.Handle(ctx, record)
}

// WithAttrs implements slog.Handler, preserving the wrapper.
func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

// WithGroup implements slog.Handler, preserving the wrapper.
func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{Handler: h.Handler.WithGroup(name)}
}

// Module and component names, so a log query can be scoped to a part of the
// tree without matching on free text. They mirror the package layout:
// internal/<module>/<component>.
const (
	// ModuleSSIAuth is internal/ssi-auth, the identity bounded context.
	ModuleSSIAuth = "ssi-auth"
	// ModuleConfig is internal/config, the deployment loader.
	ModuleConfig = "config"
	// ModuleCommon is internal/common, the shared helpers.
	ModuleCommon = "common"
	// ModuleObservability is internal/observability, this package.
	ModuleObservability = "observability"
	// ModuleMain is the composition root.
	ModuleMain = "main"
)

// Scoped derives a logger tagged with the part of the tree it speaks for.
//
// Every record then answers "who emitted this" without the message text having
// to say so, which is what lets an aggregator filter by component instead of by
// substring. Pass an empty component for a module with no subdivisions.
//
//	logger := observability.Scoped(root, observability.ModuleSSIAuth, "fafnir")
//	logger.ErrorContext(ctx, "wallet call failed", "status", 502)
//	// {"module":"ssi-auth","component":"fafnir","msg":"wallet call failed",...}
func Scoped(parent *slog.Logger, module, component string) *slog.Logger {
	if parent == nil {
		parent = slog.Default()
	}

	scoped := parent.With(slog.String("module", module))
	if component == "" {
		return scoped
	}

	return scoped.With(slog.String("component", component))
}
