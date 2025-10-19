package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hydazz/crowdsec-exporter/internal/config"
	"github.com/hydazz/crowdsec-exporter/internal/exporter"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		slog.Error("Command execution failed", "error", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crowdsec-exporter",
		Short: "Prometheus exporter for CrowdSec decisions",
		Long: `A Prometheus exporter that exposes CrowdSec decisions with rich geographical 
and ASN information as metrics, compatible with Grafana dashboards.`,

		SilenceUsage:  true, // Don't show usage on errors
		SilenceErrors: true, // We handle errors manually
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExporter()
		},
	}

	// Setup Viper for automatic env binding
	viper.SetEnvPrefix("CROWDSEC_EXPORTER")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	flags := cmd.Flags()
	flags.String("crowdsec-url", "http://localhost:8080", "CrowdSec Local API URL")
	flags.String("crowdsec-login", "", "CrowdSec machine login")
	flags.String("crowdsec-password", "", "CrowdSec machine password")
	flags.String("crowdsec-registration-token", "", "CrowdSec auto-registration token")
	flags.String("crowdsec-machine-name", "", "Machine name for auto-registration (defaults to hostname)")
	flags.String("listen-address", ":9090", "Address to listen on for web interface and metrics")
	flags.String("metrics-path", "/metrics", "Path under which to expose metrics")
	flags.String("instance-name", "crowdsec", "Instance name to use in metrics labels")
	flags.String("log-level", "info", "Log level (debug, info, warn, error)")

	// Bind flags to viper
	if err := viper.BindPFlag("crowdsec.url", flags.Lookup("crowdsec-url")); err != nil {
		panic(fmt.Sprintf("failed to bind crowdsec-url flag: %v", err))
	}
	if err := viper.BindPFlag("crowdsec.login", flags.Lookup("crowdsec-login")); err != nil {
		panic(fmt.Sprintf("failed to bind crowdsec-login flag: %v", err))
	}
	if err := viper.BindPFlag("crowdsec.password", flags.Lookup("crowdsec-password")); err != nil {
		panic(fmt.Sprintf("failed to bind crowdsec-password flag: %v", err))
	}
	if err := viper.BindPFlag("crowdsec.registration_token", flags.Lookup("crowdsec-registration-token")); err != nil {
		panic(fmt.Sprintf("failed to bind crowdsec-registration-token flag: %v", err))
	}
	if err := viper.BindPFlag("crowdsec.machine_name", flags.Lookup("crowdsec-machine-name")); err != nil {
		panic(fmt.Sprintf("failed to bind crowdsec-machine-name flag: %v", err))
	}
	if err := viper.BindPFlag("server.listen_address", flags.Lookup("listen-address")); err != nil {
		panic(fmt.Sprintf("failed to bind listen-address flag: %v", err))
	}
	if err := viper.BindPFlag("server.metrics_path", flags.Lookup("metrics-path")); err != nil {
		panic(fmt.Sprintf("failed to bind metrics-path flag: %v", err))
	}
	if err := viper.BindPFlag("exporter.instance_name", flags.Lookup("instance-name")); err != nil {
		panic(fmt.Sprintf("failed to bind instance-name flag: %v", err))
	}
	if err := viper.BindPFlag("log_level", flags.Lookup("log-level")); err != nil {
		panic(fmt.Sprintf("failed to bind log-level flag: %v", err))
	}

	cmd.AddCommand(newVersionCmd())

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("crowdsec-exporter %s\n", version)
			fmt.Printf("commit: %s\n", commit)
			fmt.Printf("built: %s\n", date)
		},
	}
}

func runExporter() error {
	// Load config from flags and env vars
	cfg := &config.Config{}
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
