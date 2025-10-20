package crowdsec

import (
	"github.com/hydazz/crowdsec-exporter/internal/models"
)

func ReturnAlerts(limit int64) (models.Alerts, error) {
	alerts, err := QueryAlerts(limit, 5)
	if err != nil {
		return nil, err
	} else {
		return alerts, nil
	}
}
