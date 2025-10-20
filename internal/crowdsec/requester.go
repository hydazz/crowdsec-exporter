package crowdsec

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hydazz/crowdsec-exporter/internal/models"
)

func QueryAlerts(limit int64, retry int) (models.Alerts, error) {
	if err := CheckAuth(); err != nil {
		return nil, fmt.Errorf("check auth: %w", err)
	}

	var (
		res *http.Response
		err error
	)
	url := fmt.Sprintf("%s/v1/alerts?limit=%d&origin=crowdsec", AuthToken.Config.CrowdSec.URL, limit)

	for attempts := retry; attempts >= 0; attempts-- {
		req, rerr := http.NewRequest("GET", url, nil)
		if rerr != nil {
			return nil, rerr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+GetToken())

		res, err = http.DefaultClient.Do(req)
		if err != nil {
			if attempts == 0 {
				return nil, err
			}
			continue
		}
		if res.StatusCode >= 300 {
			res.Body.Close()
			if attempts == 0 {
				return nil, fmt.Errorf("%s", res.Status)
			}
			continue
		}
		break
	}

	if res == nil {
		return nil, errors.New("no response received from CrowdSec")
	}
	defer res.Body.Close()

	var raw []map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return nil, err
	}

	var alerts models.Alerts
	for _, v := range raw {
		var a models.Alert
		a.Scenario = getString(v, "scenario")
		a.DateTime = getString(v, "created_at")
		a.CreatedAt = getString(v, "created_at")
		a.StartAt = getString(v, "start_at")
		a.StopAt = getString(v, "stop_at")

		if src, ok := v["source"].(map[string]interface{}); ok {
			a.IPAddress = getString(src, "ip")
			a.Latitude = getFloat(src, "latitude")
			a.Longitude = getFloat(src, "longitude")
			a.Country = getString(src, "cn")
			if r := getString(src, "range"); r != "" {
				a.Subnet = r
				a.IPRange = r
			}
			a.AsName = getString(src, "as_name")
			a.AsNumber = getString(src, "as_number")
		}

		if ds, ok := v["decisions"].([]interface{}); ok {
			for _, d := range ds {
				if dm, ok := d.(map[string]interface{}); ok {
					var dec models.Decision
					dec.ID = getInt(dm, "id")
					dec.UUID = getString(dm, "uuid")
					dec.Scenario = getString(dm, "scenario")
					dec.IPAddress = getString(dm, "value")
					dec.Type = getString(dm, "type")
					dec.Scope = getString(dm, "scope")

					// Calculate original duration because CrowdSec API provides duration as remainder?
					remainingDuration := getString(dm, "duration")
					dec.Duration = calculateOriginalDuration(a.CreatedAt, remainingDuration)

					dec.Country = a.Country
					dec.AsName = a.AsName
					dec.AsNumber = a.AsNumber
					dec.Latitude = a.Latitude
					dec.Longitude = a.Longitude
					dec.IPRange = a.IPRange

					a.Decisions = append(a.Decisions, dec)
				}
			}
		}

		alerts = append(alerts, a)
	}

	return alerts, nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	if v, ok := m[key].(int); ok {
		return v
	}
	return 0
}

func calculateOriginalDuration(alertCreatedAt, remainingDuration string) string {
	if alertCreatedAt == "" || remainingDuration == "" {
		return ""
	}

	remaining, err := time.ParseDuration(remainingDuration)
	if err != nil {
		return ""
	}

	alertTime, err := time.Parse(time.RFC3339, alertCreatedAt)
	if err != nil {
		return ""
	}

	now := time.Now()
	elapsed := now.Sub(alertTime)
	originalDuration := remaining + elapsed

	// Round to nearest minute to avoid duplicate metrics
	// Could be flaky, but better than nothing
	return originalDuration.Round(time.Minute).String()
}
