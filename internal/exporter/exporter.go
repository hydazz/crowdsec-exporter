package exporter

import (
	"fmt"
	"log/slog"

	"github.com/hydazz/crowdsec-exporter/internal/config"
	"github.com/hydazz/crowdsec-exporter/internal/crowdsec"
	"github.com/prometheus/client_golang/prometheus"
)

// Exporter represents the CrowdSec metrics exporter
type Exporter struct {
	config  *config.Config
	metrics *Metrics
}

// Metrics contains all Prometheus metrics
type Metrics struct {
	DecisionInfo *prometheus.GaugeVec
}

// New creates a new CrowdSec exporter
func New(cfg *config.Config) (*Exporter, error) {
	// Initialize CrowdSec client
	if err := initCrowdSecClient(cfg); err != nil {
		return nil, err
	}

	metrics := &Metrics{
		DecisionInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cs_lapi_decision",
				Help: "CrowdSec decisions with detailed metadata",
			},
			[]string{
				"instance",
				"country",
				"asname",
				"asnumber",
				"latitude",
				"longitude",
				"iprange",
				"scenario",
				"type",
				"duration",
				"scope",
				"ip",
			},
		),
	}

	exporter := &Exporter{
		config:  cfg,
		metrics: metrics,
	}

	// Register the exporter as a Prometheus collector
	prometheus.MustRegister(exporter)

	return exporter, nil
}

// Describe implements prometheus.Collector interface
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.metrics.DecisionInfo.Describe(ch)
}

// Collect implements prometheus.Collector interface
// This is called every time /metrics is accessed
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	if e.config.IsDebugEnabled() {
		slog.Debug("Scraping CrowdSec API for alerts and decisions")
	}

	// Clear existing metrics
	e.metrics.DecisionInfo.Reset()

	// Get alerts with decisions
	alerts, err := crowdsec.ReturnAlerts(1000)
	if err != nil {
		slog.Error("Error fetching alerts", "error", err)
		// Still collect existing metrics even if scrape failed
		e.metrics.DecisionInfo.Collect(ch)
		return
	}

	// Process alerts and update metrics
	for _, alert := range alerts {
		for _, decision := range alert.Decisions {
			e.metrics.DecisionInfo.WithLabelValues(
				e.config.Exporter.InstanceName,
				decision.Country,
				decision.AsName,
				decision.AsNumber,
				formatFloat(decision.Latitude),
				formatFloat(decision.Longitude),
				decision.IPRange,
				decision.Scenario,
				decision.Type,
				decision.Duration,
				decision.Scope,
				decision.IPAddress,
			).Set(1)
		}
	}

	if e.config.IsDebugEnabled() {
		slog.Debug("Updated metrics", "alert_count", len(alerts))
	}

	// Collect the metrics
	e.metrics.DecisionInfo.Collect(ch)
}

// initCrowdSecClient initializes the CrowdSec API client
func initCrowdSecClient(cfg *config.Config) error {
	// Initialize CrowdSec client with the modern config
	crowdsec.InitializeToken(cfg)
	return nil
}

// splitHostPort splits a host:port string
func splitHostPort(hostport string) []string {
	// Simple implementation - could use net.SplitHostPort for more robust parsing
	parts := make([]string, 0, 2)
	colonIndex := -1
	for i, c := range hostport {
		if c == ':' {
			colonIndex = i
			break
		}
	}

	if colonIndex == -1 {
		parts = append(parts, hostport)
	} else {
		parts = append(parts, hostport[:colonIndex])
		parts = append(parts, hostport[colonIndex+1:])
	}

	return parts
}

// formatFloat converts float64 to string for labels
func formatFloat(f float64) string {
	return fmt.Sprintf("%.6f", f)
}
