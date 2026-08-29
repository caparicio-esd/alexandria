package rest

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/caparicio-esd/alexandria/internal/observability"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// requestIDHeader is the header a request identifier arrives on and leaves on.
const requestIDHeader = "X-Request-Id"

// quietRoutes are logged at debug whatever they answer.
//
// An orchestrator polls the probes every few seconds, so at info they are most
// of the stream, and a readiness probe reporting 503 while a dependency comes
// up would log an error every poll for something that is working as designed.
// Escalating those trains everyone to ignore errors.
var quietRoutes = map[string]bool{
	"/healthz": true,
	"/readyz":  true,
}

// RequestID attaches an identifier to every request and echoes it back.
//
// An inbound one is honoured rather than replaced: in a dataspace a call
// usually arrives from another node that already logged the id, and minting a
// fresh one would break the chain exactly where it matters.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(requestIDHeader)
		if id == "" {
			id = uuid.NewString()
		}

		c.Header(requestIDHeader, id)
		c.Request = c.Request.WithContext(observability.WithRequestID(c.Request.Context(), id))

		c.Next()
	}
}

// AccessLog emits one structured record per request.
//
// It replaces gin's own logger, which writes unstructured lines that no
// aggregator can filter on, and which cannot carry the request id.
//
// The severity follows the status class, so a failure is visible as a failure
// rather than as an INFO line that happens to carry a 404. Logging every
// outcome at the same level means an alert on "error rate" has to parse the
// message, and a human scanning the stream sees nothing wrong.
func AccessLog(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		// FullPath is the route template, "/wallet/did/:id", not the filled-in
		// path. Logging the raw path would make every id its own log series and
		// leak identifiers into the index.
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}

		attrs := []any{
			"method", c.Request.Method,
			"route", route,
			"status", c.Writer.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"bytes", c.Writer.Size(),
			"client_ip", c.ClientIP(),
		}

		// Whatever the handler recorded with c.Error, which is where
		// respondError files the domain error it answered with. Without it a
		// 412 says only that something was refused, not what.
		if err := c.Errors.Last(); err != nil {
			attrs = append(attrs, "err", err.Error())
		}

		level := levelFor(c.Writer.Status())
		if quietRoutes[route] {
			level = slog.LevelDebug
		}

		logger.LogAttrs(c.Request.Context(), level, "request", slogArgs(attrs)...)
	}
}

// levelFor maps a status class onto a severity.
//
// A 4xx is the caller's mistake and a 5xx is ours, which is why they are not
// the same level: one is worth a dashboard, the other is worth a page.
func levelFor(status int) slog.Level {
	switch {
	case status >= http.StatusInternalServerError:
		return slog.LevelError
	case status >= http.StatusBadRequest:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// slogArgs converts the key-value pairs into typed attributes, so LogAttrs can
// take a level chosen at run time.
func slogArgs(args []any) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(args)/2)
	for i := 0; i+1 < len(args); i += 2 {
		key, _ := args[i].(string)
		attrs = append(attrs, slog.Any(key, args[i+1]))
	}

	return attrs
}

// Recovery turns a panic into the API's own error shape.
//
// gin's recovery writes its own body, which would be the one response in the
// API that does not look like the others; and it logs to stdout rather than
// through the structured logger.
func Recovery(logger *slog.Logger) gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, recovered any) {
		logger.ErrorContext(c.Request.Context(), "panic recovered",
			"route", c.FullPath(),
			"panic", recovered,
		)

		c.AbortWithStatusJSON(http.StatusInternalServerError, errorBody{Error: "internal error"})
	})
}

// Metrics records the RED signals for every request: rate, errors and duration
// all fall out of one histogram sliced by route, method and status.
func Metrics(meter metric.Meter) (gin.HandlerFunc, error) {
	duration, err := meter.Float64Histogram(
		"http.server.request.duration",
		metric.WithDescription("Duration of inbound HTTP requests."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	inflight, err := meter.Int64UpDownCounter(
		"http.server.active_requests",
		metric.WithDescription("Requests currently being served."),
	)
	if err != nil {
		return nil, err
	}

	return func(c *gin.Context) {
		start := time.Now()

		inflight.Add(c.Request.Context(), 1)
		defer inflight.Add(c.Request.Context(), -1)

		c.Next()

		route := c.FullPath()
		if route == "" {
			// Unmatched paths share one label. Recording them verbatim would
			// let anyone on the internet mint unbounded metric series.
			route = "unmatched"
		}

		duration.Record(c.Request.Context(), time.Since(start).Seconds(), metric.WithAttributes(
			semconv.HTTPRequestMethodKey.String(c.Request.Method),
			semconv.HTTPRouteKey.String(route),
			attribute.Int("http.response.status_code", c.Writer.Status()),
		))
	}, nil
}
