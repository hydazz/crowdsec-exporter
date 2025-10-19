package crowdsec

import (
	// "fmt"
	// "log"
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

func ReturnDecisions(limit int64) (models.DecisionArray, error) {

	models.LockDecisions()
	defer models.UnlockDecisions()

	var startup = (models.GetDecisionsLength() == 0)

	newDecisions, deletedDecisions, err := QueryUpdateDecisions(startup, 5)
	if err != nil {
		return nil, err
	}

	models.AppendDecisions(newDecisions)

	models.DeleteDecisions(deletedDecisions)

	return models.GetDecisions(), nil
}
