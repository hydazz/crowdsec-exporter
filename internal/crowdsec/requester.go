package crowdsec

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

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
					dec.UUID = getString(dm, "uuid")
					dec.Scenario = getString(dm, "scenario")
					dec.IPAddress = getString(dm, "value")
					dec.Type = getString(dm, "type")
					dec.Duration = getString(dm, "duration")
					dec.Scope = getString(dm, "scope")
					dec.Until = getString(dm, "until")
					dec.CreatedAt = getString(dm, "created_at")

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

func QueryUpdateDecisions(startup bool, retry int) (models.DecisionArray, []string, error) {
	if err := CheckAuth(); err != nil {
		return nil, nil, fmt.Errorf("check auth: %w", err)
	}

	url := fmt.Sprintf("%s/v1/decisions/stream?startup=%v", AuthToken.Config.CrowdSec.URL, startup)

	var (
		res *http.Response
		err error
	)
	for attempts := retry; attempts >= 0; attempts-- {
		req, rerr := http.NewRequest("GET", url, nil)
		if rerr != nil {
			return nil, nil, rerr
		}
		req.Header.Set("Content-Type", "application/json")

		res, err = http.DefaultClient.Do(req)
		if err != nil {
			if attempts == 0 {
				return nil, nil, err
			}
			continue
		}
		if res.StatusCode >= 300 {
			res.Body.Close()
			if attempts == 0 {
				return nil, nil, fmt.Errorf("%s", res.Status)
			}
			continue
		}
		break
	}

	if res == nil {
		return nil, nil, errors.New("no response received from CrowdSec")
	}
	defer res.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, nil, err
	}

	var newDecisions models.DecisionArray
	if newRaw, ok := result["new"].([]interface{}); ok {
		for _, v := range newRaw {
			if m, ok := v.(map[string]interface{}); ok {
				var d models.Decision
				d.UUID = getString(m, "uuid")
				d.Scenario = getString(m, "scenario")
				d.IPAddress = getString(m, "value")
				d.Type = getString(m, "type")
				d.Duration = getString(m, "duration")
				d.Scope = getString(m, "scope")
				d.Until = getString(m, "until")
				newDecisions = append(newDecisions, d)
			}
		}
	}

	var deleted []string
	if delRaw, ok := result["deleted"].([]interface{}); ok {
		for _, v := range delRaw {
			if m, ok := v.(map[string]interface{}); ok {
				if id := getString(m, "uuid"); id != "" {
					deleted = append(deleted, id)
				}
			}
		}
	}

	return newDecisions, deleted, nil
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
