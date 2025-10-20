# CrowdSec Exporter

A Prometheus exporter that pulls detailed decision data from CrowdSec’s Local API.

## Overview

CrowdSec’s built-in Prometheus metrics provide basic counts but not much detail about what is being blocked.
This exporter queries the Local API and exposes rich Prometheus metrics including geographic data, ASN info, and scenario details.

## Features

-   Geographic data (country, latitude, longitude)
-   ASN information (name and number)
-   Full decision details (scenario, type, duration, etc.)
-   Real-time data from CrowdSec’s Local API
-   Works with existing Prometheus and Grafana setups
-   Lightweight Docker image

## Quick Start

### Method 1: Auto-Registration

If your CrowdSec instance supports auto-registration with a token:
**Note:** When using auto-registration with a token, the provided login/password will be used for the machine registration.

```bash
./crowdsec-exporter \
  --crowdsec-url http://localhost:8080 \
  --crowdsec-login your-machine-login \ # crowdsec-exporter
  --crowdsec-password your-machine-password \ # make 16+ characters
  --crowdsec-registration-token ${REGISTRATION_TOKEN} \
  --log-level debug
```

### Method 2: Existing Machine Account

```bash
./crowdsec-exporter \
  --crowdsec-url http://localhost:8080 \
  --crowdsec-login your-machine-login \
  --crowdsec-password your-machine-password \
  --log-level debug
```

Metrics are exposed at `http://localhost:9090/metrics`.

## Configuration Options

| Flag                            | Environment Variable                            | Default                 | Description                                 |
| ------------------------------- | ----------------------------------------------- | ----------------------- | ------------------------------------------- |
| `--crowdsec-url`                | `CROWDSEC_EXPORTER_CROWDSEC_URL`                | `http://localhost:8080` | CrowdSec Local API URL                      |
| `--crowdsec-login`              | `CROWDSEC_EXPORTER_CROWDSEC_LOGIN`              | -                       | Machine login (required)                    |
| `--crowdsec-password`           | `CROWDSEC_EXPORTER_CROWDSEC_PASSWORD`           | -                       | Machine password (required)                 |
| `--crowdsec-registration-token` | `CROWDSEC_EXPORTER_CROWDSEC_REGISTRATION_TOKEN` | -                       | Registration token (optional, for auto-reg) |
| `--crowdsec-machine-name`       | `CROWDSEC_EXPORTER_CROWDSEC_MACHINE_NAME`       | hostname                | Machine name used during registration       |
| `--crowdsec-deregister-on-exit` | `CROWDSEC_EXPORTER_CROWDSEC_DEREGISTER_ON_EXIT` | `false`                 | Deregister machine on exit                  |
| `--listen-address`              | `CROWDSEC_EXPORTER_SERVER_LISTEN_ADDRESS`       | `:9090`                 | Listen address                              |
| `--metrics-path`                | `CROWDSEC_EXPORTER_SERVER_METRICS_PATH`         | `/metrics`              | Metrics endpoint                            |
| `--instance-name`               | `CROWDSEC_EXPORTER_EXPORTER_INSTANCE_NAME`      | `crowdsec`              | Instance label                              |
| `--log-level`                   | `CROWDSEC_EXPORTER_LOG_LEVEL`                   | `info`                  | Log level (debug, info, warn, error)        |

## Installation

### Build from Source

```bash
git clone https://github.com/hydazz/crowdsec-exporter
cd crowdsec-exporter
make build
```

### Docker/Kubernetes

## Metrics

The main metric is `cs_lapi_decision` with labels:

-   `instance`
-   `country`
-   `asname`
-   `asnumber`
-   `latitude`, `longitude`
-   `iprange`
-   `scenario`
-   `type`
-   `duration`
-   `scope`
-   `ip`

## Attribution

This project continues on [lucadomene/crowdsec-LAPIexporter](https://github.com/lucadomene/crowdsec-LAPIexporter).

## TO-DO

Metrics should be streamed in real time, or give up and use vmmetrics 🤷