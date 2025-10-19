package config

import (
	"fmt"
	"log/slog"
	"strings"
)

// Config represents the application configuration
type Config struct {
	CrowdSec CrowdSecConfig `mapstructure:"crowdsec"`
	Server   ServerConfig   `mapstructure:"server"`
	Exporter ExporterConfig `mapstructure:"exporter"`
	LogLevel string         `mapstructure:"log_level"`
}

// CrowdSecConfig contains CrowdSec API configuration
type CrowdSecConfig struct {
	URL      string `mapstructure:"url"`
	Login    string `mapstructure:"login"`
	Password string `mapstructure:"password"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	ListenAddress string `mapstructure:"listen_address"`
	MetricsPath   string `mapstructure:"metrics_path"`
}

// ExporterConfig contains exporter-specific configuration
type ExporterConfig struct {
	InstanceName string `mapstructure:"instance_name"`
}

// Validate validates the configuration
func (c *Config) Validate() error {
	var errors []string

	if c.CrowdSec.URL == "" {
		errors = append(errors, "crowdsec.url is required")
	}

	if c.CrowdSec.Login == "" || c.CrowdSec.Password == "" {
		errors = append(errors, "crowdsec.login and crowdsec.password are required")
	}

	if c.Server.ListenAddress == "" {
		c.Server.ListenAddress = ":9999"
	}

	if c.Server.MetricsPath == "" {
		c.Server.MetricsPath = "/metrics"
	}

	if c.Exporter.InstanceName == "" {
		c.Exporter.InstanceName = "crowdsec"
	}

	// Set default log level if empty
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error"}
	levelValid := false
	for _, level := range validLogLevels {
		if strings.ToLower(c.LogLevel) == level {
			levelValid = true
			break
		}
	}
	if !levelValid {
		errors = append(errors, fmt.Sprintf("log_level must be one of: %s", strings.Join(validLogLevels, ", ")))
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation errors:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// GetLogLevel returns the slog.Level for the configured log level
func (c *Config) GetLogLevel() slog.Level {
	switch strings.ToLower(c.LogLevel) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// IsDebugEnabled returns true if debug logging is enabled
func (c *Config) IsDebugEnabled() bool {
	return strings.ToLower(c.LogLevel) == "debug"
}
