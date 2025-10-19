package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hydazz/crowdsec-exporter/internal/config"
	"github.com/hydazz/crowdsec-exporter/internal/exporter"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfg *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "crowdsec-exporter",
	Short: "Prometheus exporter for CrowdSec decisions",
	Long: `A Prometheus exporter that exposes CrowdSec decisions with rich geographical 
and ASN information as metrics, compatible with Grafana dashboards.`,
	RunE: runExporter,
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().String("crowdsec-url", "http://localhost:8080", "CrowdSec Local API URL")
	rootCmd.PersistentFlags().String("crowdsec-login", "", "CrowdSec machine login (required)")
	rootCmd.PersistentFlags().String("crowdsec-password", "", "CrowdSec machine password (required)")
	rootCmd.PersistentFlags().String("listen-address", ":9090", "Address to listen on for web interface and metrics")
	rootCmd.PersistentFlags().String("metrics-path", "/metrics", "Path under which to expose metrics")
	rootCmd.PersistentFlags().String("instance-name", "crowdsec", "Instance name to use in metrics labels")
	rootCmd.PersistentFlags().String("log-level", "info", "Log level (debug, info, warn, error)")

	// Bind flags to viper
	viper.BindPFlag("crowdsec.url", rootCmd.PersistentFlags().Lookup("crowdsec-url"))
	viper.BindPFlag("crowdsec.login", rootCmd.PersistentFlags().Lookup("crowdsec-login"))
	viper.BindPFlag("crowdsec.password", rootCmd.PersistentFlags().Lookup("crowdsec-password"))
	viper.BindPFlag("server.listen_address", rootCmd.PersistentFlags().Lookup("listen-address"))
	viper.BindPFlag("server.metrics_path", rootCmd.PersistentFlags().Lookup("metrics-path"))
	viper.BindPFlag("exporter.instance_name", rootCmd.PersistentFlags().Lookup("instance-name"))
	viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
}

func runExporter(cmd *cobra.Command, args []string) error {
	// Set up viper to read from environment variables and flags
	viper.SetEnvPrefix("CROWDSEC_EXPORTER")
	viper.AutomaticEnv()

	// Load config from flags and env vars
	cfg = &config.Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("unable to decode config: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Set up structured logging with slog
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.GetLogLevel(),
	}))
	slog.SetDefault(logger)

	// Create exporter
	_, err := exporter.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create exporter: %w", err)
	}

	// Set up HTTP server
	mux := http.NewServeMux()
	mux.Handle(cfg.Server.MetricsPath, promhttp.Handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html>
<head><title>CrowdSec Exporter</title></head>
<body>
<h1>CrowdSec Exporter</h1>
<p><a href="%s">Metrics</a></p>
</body>
</html>`, cfg.Server.MetricsPath)
	})

	server := &http.Server{
		Addr:    cfg.Server.ListenAddress,
		Handler: mux,
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("Starting CrowdSec exporter", "address", cfg.Server.ListenAddress)
		slog.Info("Metrics available", "path", cfg.Server.MetricsPath)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		return err
	}

	slog.Info("Server exited")
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
