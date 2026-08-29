package observability

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// serviceName is how this process identifies itself to a collector.
const serviceName = "alexandria"

// Metrics owns the metric pipeline: an OpenTelemetry SDK feeding a Prometheus
// exporter.
//
// One SDK rather than two libraries, because traces will hang off the same
// resource and the same context. Prometheus is the wire format, not the model.
type Metrics struct {
	provider *sdkmetric.MeterProvider
	registry *prometheus.Registry
}

// NewMetrics builds the metric pipeline and registers it as the global
// OpenTelemetry provider, so instrumentation anywhere in the process finds it.
func NewMetrics(version string) (*Metrics, error) {
	registry := prometheus.NewRegistry()

	// The Go collector is not OpenTelemetry's: registering it directly is what
	// gives goroutine counts, GC pauses and heap size, which are the first
	// things anyone looks at.
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, fmt.Errorf("building the prometheus exporter: %w", err)
	}

	// The semconv version must match the one resource.Default() carries, or
	// Merge refuses to reconcile the two schema URLs. Bump both together.
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(version),
	))
	if err != nil {
		return nil, fmt.Errorf("describing the service: %w", err)
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(provider)

	metrics := &Metrics{provider: provider, registry: registry}

	if err := metrics.registerBuildInfo(version); err != nil {
		return nil, err
	}

	// Go runtime metrics in OpenTelemetry's own naming, alongside the
	// Prometheus collector's: the two overlap, but a dashboard built on either
	// convention then works without translation.
	if err := runtime.Start(runtime.WithMeterProvider(provider)); err != nil {
		return nil, fmt.Errorf("starting runtime metrics: %w", err)
	}

	return metrics, nil
}

// registerBuildInfo publishes a constant gauge carrying the version.
//
// It reads as a useless metric until the first time a latency graph jumps and
// the only question that matters is which build is running.
func (m *Metrics) registerBuildInfo(version string) error {
	meter := m.provider.Meter(serviceName)

	gauge, err := meter.Int64ObservableGauge(
		"alexandria.build.info",
		metric.WithDescription("Always 1, labelled with the running build."),
	)
	if err != nil {
		return fmt.Errorf("building the build-info gauge: %w", err)
	}

	_, err = meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		observer.ObserveInt64(gauge, 1, metric.WithAttributes(attribute.String("version", version)))

		return nil
	}, gauge)
	if err != nil {
		return fmt.Errorf("registering the build-info callback: %w", err)
	}

	return nil
}

// Meter returns a meter for instrumenting a subsystem.
func (m *Metrics) Meter(name string) metric.Meter {
	return m.provider.Meter(name)
}

// Handler serves the Prometheus scrape endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Registry: m.registry})
}

// Shutdown flushes and stops the pipeline. It is called on the way out, so a
// scrape that never came does not lose the last measurements.
func (m *Metrics) Shutdown(ctx context.Context) error {
	if err := m.provider.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutting down metrics: %w", err)
	}

	return nil
}
