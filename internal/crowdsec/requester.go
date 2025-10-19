package crowdsec

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hydazz/crowdsec-exporter/internal/models"
)

func QueryAlerts(limit int64, retry int) (models.Alerts, error) {

	CheckAuth()
	req, err := http.NewRequest("GET", fmt.Sprintf("%v/v1/alerts?limit=%v&origin=crowdsec", AuthToken.Config.CrowdSec.URL, limit), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+GetToken())

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	} else if res.StatusCode > 300 && retry > 0 {
		return QueryAlerts(limit, retry-1)
	} else if retry <= 0 {
		http_err := fmt.Errorf("%v", res.Status)
		return nil, http_err
	}
	defer res.Body.Close()

	var result = []map[string]interface{}{}
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	var alerts models.Alerts
	for _, v := range result {
		var alert models.Alert

		scenario, ok := v["scenario"].(string)
		if ok {
			alert.Scenario = scenario
		}

		source := v["source"].(map[string]interface{}) // type assertion
		ipaddr, ok := source["ip"].(string)
		if ok {
			alert.IPAddress = ipaddr
		}

		datetime, ok := v["created_at"].(string)
		if ok {
			alert.DateTime = datetime
		}

		latitude, ok := source["latitude"].(float64)
		if ok {
			alert.Latitude = latitude
		}

		longitude, ok := source["longitude"].(float64)
		if ok {
			alert.Longitude = longitude
		}

		countryiso, ok := source["cn"].(string)
		if ok {
			alert.Country = countryiso
		}

		subnet, ok := source["range"].(string)
		if ok {
			alert.Subnet = subnet
			alert.IPRange = subnet
		}

		asname, ok := source["as_name"].(string)
		if ok {
			alert.AsName = asname
		}

		asnumber, ok := source["as_number"].(string)
		if ok {
			alert.AsNumber = asnumber
		}

		// Process decisions for this alert
		if decisions_raw, ok := v["decisions"].([]interface{}); ok {
			for _, dec_raw := range decisions_raw {
				if dec := dec_raw.(map[string]interface{}); ok {
					var decision models.Decision

					if uuid, ok := dec["uuid"].(string); ok {
						decision.UUID = uuid
					}
					if scenario, ok := dec["scenario"].(string); ok {
						decision.Scenario = scenario
					}
					if value, ok := dec["value"].(string); ok {
						decision.IPAddress = value
					}
					if dtype, ok := dec["type"].(string); ok {
						decision.Type = dtype
					}
					if duration, ok := dec["duration"].(string); ok {
						decision.Duration = duration
					}
					if scope, ok := dec["scope"].(string); ok {
						decision.Scope = scope
					}
					if until, ok := dec["until"].(string); ok {
						decision.Until = until
					}

					// Copy geographic info from alert to decision
					decision.Country = alert.Country
					decision.AsName = alert.AsName
					decision.AsNumber = alert.AsNumber
					decision.Latitude = alert.Latitude
					decision.Longitude = alert.Longitude
					decision.IPRange = alert.IPRange

					alert.Decisions = append(alert.Decisions, decision)
				}
			}
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil

}

func QueryUpdateDecisions(startup bool, retry int) (models.DecisionArray, []string, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf("%v/v1/decisions/stream?startup=%v", AuthToken.Config.CrowdSec.URL, startup), nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	// Note: This endpoint might need API key - should be configurable

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	} else if res.StatusCode > 300 && retry > 0 {
		return QueryUpdateDecisions(startup, retry-1)
	} else if retry <= 0 {
		http_err := fmt.Errorf("%v", res.Status)
		return nil, nil, http_err
	}
	defer res.Body.Close()

	result := make(map[string]interface{})
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		return nil, nil, err
	}

	new_decisions_raw := result["new"].([]interface{})
	var new_decisions models.DecisionArray
	for _, v := range new_decisions_raw {
		var decision models.Decision

		v_parsed := v.(map[string]interface{})

		uuid, ok := v_parsed["uuid"].(string)
		if ok {
			decision.UUID = uuid
		}

		scenario, ok := v_parsed["scenario"].(string)
		if ok {
			decision.Scenario = scenario
		}

		ipaddr, ok := v_parsed["value"].(string)
		if ok {
			decision.IPAddress = ipaddr
		}

		dec_type, ok := v_parsed["type"].(string)
		if ok {
			decision.Type = dec_type
		}

		duration, ok := v_parsed["duration"].(string)
		if ok {
			decision.Duration = duration
		}

		scope, ok := v_parsed["scope"].(string)
		if ok {
			decision.Scope = scope
		}

		until, ok := v_parsed["until"].(string)
		if ok {
			decision.Until = until
		}

		new_decisions = append(new_decisions, decision)
	}

	deleted_decisions_raw := result["deleted"].([]interface{})
	var deleted_decisions []string
	for _, w := range deleted_decisions_raw {
		var decisionUUID string

		w_parsed := w.(map[string]interface{})

		uuid, ok := w_parsed["uuid"].(string)
		if ok {
			decisionUUID = uuid
		}

		deleted_decisions = append(deleted_decisions, decisionUUID)
	}

	return new_decisions, deleted_decisions, nil
}
