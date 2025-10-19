package models

import (
	"sync"
)

type Decision struct {
	UUID      string `json:"uuid"`
	Scenario  string `json:"scenario"`
	IPAddress string `json:"ip"`
	Type      string `json:"type"`
	Until     string `json:"until"`
	Duration  string `json:"duration"`
	Scope     string `json:"scope"`
	// Geographic and ASN information
	Country   string  `json:"country"`
	AsName    string  `json:"asname"`
	AsNumber  string  `json:"asnumber"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	IPRange   string  `json:"iprange"`
}

type DecisionArray []Decision

var DecisionsMutex struct {
	Mu        sync.Mutex
	Length    int
	Decisions DecisionArray
}

func GetDecisions() DecisionArray {
	return DecisionsMutex.Decisions
}

func GetDecisionsLength() int {
	return DecisionsMutex.Length
}

func LockDecisions() {
	DecisionsMutex.Mu.Lock()
}

func UnlockDecisions() {
	DecisionsMutex.Mu.Unlock()
}

func deleteDecision(index int) {
	DecisionsMutex.Decisions[index] = DecisionsMutex.Decisions[DecisionsMutex.Length-1]
	DecisionsMutex.Length--
	DecisionsMutex.Decisions = DecisionsMutex.Decisions[:DecisionsMutex.Length-1]
}

func appendDecision(dec Decision) {
	DecisionsMutex.Decisions = append(DecisionsMutex.Decisions, dec)
}

func DeleteDecisions(decsUUID []string) {

	for _, v := range decsUUID {
		for j, w := range DecisionsMutex.Decisions {
			if v == w.UUID {
				deleteDecision(j)
			}
		}
	}
}

func AppendDecisions(decs DecisionArray) {

	for _, v := range decs {
		appendDecision(v)
	}
}
