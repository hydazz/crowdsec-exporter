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
	"github.com/hydazz/crowdsec-exporter/internal/crowdsec"
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
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "crowdsec-exporter",
		Short:         "Prometheus exporter for CrowdSec decisions",
		Long:          "A Prometheus exporter that exposes CrowdSec decisions with geographical and ASN info as metrics.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExporter()
		},
	}

	viper.SetEnvPrefix("CROWDSEC_EXPORTER")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	f := cmd.Flags()
	f.String("crowdsec-url", "http://localhost:8080", "CrowdSec Local API URL")
	f.String("crowdsec-login", "", "CrowdSec machine login")
	f.String("crowdsec-password", "", "CrowdSec machine password")
	f.String("crowdsec-registration-token", "", "CrowdSec auto-registration token")
	f.String("crowdsec-machine-name", "", "Machine name for auto-registration (defaults to hostname)")
	f.Bool("crowdsec-deregister-on-exit", false, "Deregister machine on application exit")
	f.String("listen-address", ":9090", "Address to listen on for web interface and metrics")
	f.String("metrics-path", "/metrics", "Path under which to expose metrics")
	f.String("instance-name", "crowdsec", "Instance name to use in metrics labels")
	f.String("log-level", "info", "Log level (debug, info, warn, error)")

	binds := map[string]string{
		"crowdsec.url":                "crowdsec-url",
		"crowdsec.login":              "crowdsec-login",
		"crowdsec.password":           "crowdsec-password",
		"crowdsec.registration_token": "crowdsec-registration-token",
		"crowdsec.machine_name":       "crowdsec-machine-name",
		"crowdsec.deregister_on_exit": "crowdsec-deregister-on-exit",
		"server.listen_address":       "listen-address",
		"server.metrics_path":         "metrics-path",
		"exporter.instance_name":      "instance-name",
		"log_level":                   "log-level",
	}
	for key, flag := range binds {
		if err := viper.BindPFlag(key, f.Lookup(flag)); err != nil {
			panic(fmt.Sprintf("bind flag %q: %v", flag, err))
		}
	}

	cmd.AddCommand(newVersionCmd())
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(*cobra.Command, []string) {
			fmt.Printf("crowdsec-exporter %s\n", version)
			fmt.Printf("commit: %s\n", commit)
			fmt.Printf("built: %s\n", date)
		},
	}
}

func runExporter() error {
	cfg := &config.Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.GetLogLevel()}))
	slog.SetDefault(logger)

	if _, err := exporter.New(cfg); err != nil {
		return fmt.Errorf("create exporter: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.Server.MetricsPath, promhttp.Handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, indexHTML, cfg.Server.MetricsPath)
	})

	server := &http.Server{
		Addr:    cfg.Server.ListenAddress,
		Handler: mux,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("starting exporter", "address", cfg.Server.ListenAddress, "metrics_path", cfg.Server.MetricsPath)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("shutdown initiated")

	if err := crowdsec.DeregisterMachine(); err != nil {
		slog.Warn("deregister failed", "error", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("forced shutdown", "error", err)
		return err
	}

	slog.Info("server exited")
	return nil
}

const indexHTML = `<!doctype html>
<html>
<head><meta charset="utf-8"><title>CrowdSec Exporter</title></head>
<body>
<h1>CrowdSec Exporter</h1>
<p><a href="%s">Metrics</a></p>
</body>
</html>`
