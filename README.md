# CrowdSec Exporter

A Prometheus exporter for CrowdSec decisions with geographical and ASN information.

## Overview

The built-in Prometheus metrics in CrowdSec only export stats and can't expose detailed information about decisions. This exporter solves that problem by querying the CrowdSec Local API and exposing decisions as Prometheus metrics with rich labels including:

- Geographical information (country, latitude, longitude)
- ASN information (AS name, AS number)
- IP range information
- Decision details (scenario, type, duration, scope)

## Features

- 🌍 **Rich Geographical Data**: Country, latitude, and longitude for each decision
- 🔢 **ASN Information**: AS name and number for network attribution
- 📊 **Prometheus Native**: Standard Prometheus metrics format
- 🔄 **Real-time Updates**: Queries CrowdSec Local API for live data
- 🐳 **Docker Ready**: Minimal container image
- ⚙️ **Simple Configuration**: YAML-based configuration

## Installation

### Binary

Build from source:

```bash
go build -o crowdsec-exporter main.go
```

### Docker

Build the Docker image:

```bash
docker build -t crowdsec-exporter .
```

## Configuration

Create a `config.yml` file with your CrowdSec Local API configuration:

```yaml
auth:
  login: "your-machine-login"
  password: "your-machine-password"
  api: "your-api-key"

server:
  protocol: "http"
  host: "localhost"
  port: "8080"
  version: "v1"
```

## Getting CrowdSec Credentials

### For Local API Authentication

```bash
# Create a machine account
cscli machines add crowdsec-exporter

# Note the login and password for config.yml
```

### For API Key

```bash
# Generate an API key (for decisions endpoint)
cscli bouncers add crowdsec-exporter

# Note the API key for config.yml
```
## Usage

Start the exporter with required credentials:

```bash
# Using API key (recommended)
./crowdsec-exporter --crowdsec-api-key YOUR_API_KEY

# Or using login/password
./crowdsec-exporter --crowdsec-login machine-name --crowdsec-password machine-password

# With custom settings
./crowdsec-exporter \
  --crowdsec-url http://crowdsec:8080 \
  --crowdsec-api-key YOUR_API_KEY \
  --listen-address :9090 \
  --instance-name my-crowdsec \
  --scrape-interval 60s \
  --log-level-debug
```

The exporter will start and provide:
- Prometheus metrics at `/metrics` (default port 9999)
- A simple status page at `/`

### Configuration

All configuration is done via command-line flags or environment variables:

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--crowdsec-url` | `CROWDSEC_EXPORTER_CROWDSEC_URL` | `http://localhost:8080` | CrowdSec Local API URL |
| `--crowdsec-api-key` | `CROWDSEC_EXPORTER_CROWDSEC_API_KEY` | - | CrowdSec API key (recommended) |
| `--crowdsec-login` | `CROWDSEC_EXPORTER_CROWDSEC_LOGIN` | - | CrowdSec machine login |
| `--crowdsec-password` | `CROWDSEC_EXPORTER_CROWDSEC_PASSWORD` | - | CrowdSec machine password |
| `--listen-address` | `CROWDSEC_EXPORTER_LISTEN_ADDRESS` | `:9999` | Address to listen on |
| `--metrics-path` | `CROWDSEC_EXPORTER_METRICS_PATH` | `/metrics` | Path for metrics endpoint |
| `--instance-name` | `CROWDSEC_EXPORTER_INSTANCE_NAME` | `crowdsec` | Instance name in metrics |
| `--scrape-interval` | `CROWDSEC_EXPORTER_SCRAPE_INTERVAL` | `30s` | How often to update metrics |
| `--log-level-debug` | `CROWDSEC_EXPORTER_LOG_LEVEL_DEBUG` | `false` | Enable debug logging |

## Grafana Dashboard

The metrics are designed to work with CrowdSec Grafana dashboards. The `cs_lapi_decision` metric includes all necessary labels for geographical and network analysis:

- **Geographical visualization**: Use `latitude`, `longitude`, and `country` labels
- **Network analysis**: Use `asname`, `asnumber`, and `iprange` labels  
- **Security analysis**: Use `scenario`, `type`, `scope`, and `ip` labels
- **Time-based analysis**: Use `duration` label and metric timestamps

## Building

### Prerequisites

- Go 1.24 or later

### Build Commands

```bash
# Build the binary
go build -o crowdsec-exporter main.go

# Build Docker image
docker build -t crowdsec-exporter .

# Run locally (requires config.yml)
./crowdsec-exporter
```

## Project Structure

```
crowdsec-exporter/
├── main.go                      # Application entry point  
├── core/
│   ├── requester.go            # CrowdSec API client
│   └── returner.go             # Data processing logic
├── models/
│   ├── alert.go                # Alert data structures
│   └── decision.go             # Decision data structures
├── utils/
│   ├── config.go               # Configuration management
│   └── authenticator.go        # Authentication logic
├── config.yml                  # Configuration file
├── Dockerfile                  # Docker build
├── Makefile                    # Build automation
├── go.mod                      # Go module definition
└── README.md                   # This file
```

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
