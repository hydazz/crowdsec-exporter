package exporter

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hydazz/crowdsec-exporter/internal/config"
	"github.com/prometheus/client_golang/prometheus"
)

type roundTripper func(req *http.Request) (*http.Response, error)

func (rt roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt(req)
}

func newResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// TestMultipleScrapes ensures exporter survives consecutive scrapes.
func TestMultipleScrapes(t *testing.T) {
	var loginCalls int32
	var alertsCalls int32

	expectedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	fakeTransport := roundTripper(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/v1/watchers/login":
			atomic.AddInt32(&loginCalls, 1)
			payload := fmt.Sprintf(`{"token":"test-token","expire":"%s"}`, time.Now().Add(time.Hour).Format(time.RFC3339))
			time.Sleep(5 * time.Millisecond)
			resp := newResponse(http.StatusOK, payload)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		case "/v1/alerts":
			atomic.AddInt32(&alertsCalls, 1)
			if got := req.Header.Get("Authorization"); got != "Bearer test-token" {
				return nil, fmt.Errorf("unexpected authorization header: %q", got)
			}
			payload := `[{"scenario":"test","created_at":"2025-01-01T00:00:00Z","source":{"ip":"1.2.3.4"},"decisions":[{"uuid":"uuid","scenario":"test","value":"1.2.3.4","type":"ban","duration":"1h","scope":"ip","until":"2025-01-02T00:00:00Z","created_at":"2025-01-01T00:00:00Z"}]}]`
			resp := newResponse(http.StatusOK, payload)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		default:
			return nil, fmt.Errorf("unexpected path: %s", req.URL.Path)
		}
	})

	originalClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: fakeTransport}
	defer func() { http.DefaultClient = originalClient }()

	originalRegisterer := prometheus.DefaultRegisterer
	originalGatherer := prometheus.DefaultGatherer
	registry := prometheus.NewRegistry()
	prometheus.DefaultRegisterer = registry
	prometheus.DefaultGatherer = registry
	t.Cleanup(func() {
		prometheus.DefaultRegisterer = originalRegisterer
		prometheus.DefaultGatherer = originalGatherer
	})

	cfg := &config.Config{
		CrowdSec: config.CrowdSecConfig{
			URL:               "http://crowdsec.local",
			Login:             "machine",
			Password:          "password",
			RegistrationToken: "token",
		},
		Server: config.ServerConfig{
			ListenAddress: ":0",
			MetricsPath:   "/metrics",
		},
		Exporter: config.ExporterConfig{
			InstanceName: "instance",
		},
		LogLevel: "debug",
	}

	exp, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create exporter: %v", err)
	}
	t.Cleanup(func() {
		prometheus.Unregister(exp)
	})

	const parallel = 5
	const iterations = 20
	for i := 0; i < iterations; i++ {
		var wg sync.WaitGroup
		for j := 0; j < parallel; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := prometheus.DefaultGatherer.Gather(); err != nil {
					t.Errorf("gather failed: %v", err)
				}
			}()
		}
		wg.Wait()
	}

	if atomic.LoadInt32(&alertsCalls) < 2 {
		t.Fatalf("expected at least two alerts calls, got %d", alertsCalls)
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather results failed: %v", err)
	}

	var found bool
	for _, mf := range mfs {
		if mf.GetName() != "cs_lapi_decision" {
			continue
		}
		for _, metric := range mf.Metric {
			ts := metric.GetTimestampMs()
			if ts == expectedTime.UnixMilli() {
				found = true
				break
			}
		}
	}

	if !found {
		t.Fatalf("expected timestamp %d not found in metrics", expectedTime.UnixMilli())
	}
}
