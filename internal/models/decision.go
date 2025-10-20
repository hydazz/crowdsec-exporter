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
	CreatedAt string `json:"created_at"`
	// Geographic and ASN information
	Country   string  `json:"country"`
	AsName    string  `json:"asname"`
	AsNumber  string  `json:"asnumber"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	IPRange   string  `json:"iprange"`
}

type DecisionArray []Decision

var decisionsStore struct {
	mu        sync.Mutex
	decisions DecisionArray
}

func GetDecisions() DecisionArray {
	// return a copy to avoid callers mutating shared slice
	out := make(DecisionArray, len(decisionsStore.decisions))
	copy(out, decisionsStore.decisions)
	return out
}

func GetDecisionsLength() int {
	return len(decisionsStore.decisions)
}

func LockDecisions() {
	decisionsStore.mu.Lock()
}

func UnlockDecisions() {
	decisionsStore.mu.Unlock()
}

func deleteDecision(index int) {
	last := len(decisionsStore.decisions) - 1
	if last < 0 {
		return
	}
	decisionsStore.decisions[index] = decisionsStore.decisions[last]
	decisionsStore.decisions = decisionsStore.decisions[:last]
}

func appendDecision(dec Decision) {
	decisionsStore.decisions = append(decisionsStore.decisions, dec)
}

func DeleteDecisions(decsUUID []string) {
	for _, v := range decsUUID {
		for j, w := range decisionsStore.decisions {
			if v == w.UUID {
				deleteDecision(j)
				break
			}
		}
	}
}

func AppendDecisions(decs DecisionArray) {
	for _, v := range decs {
		appendDecision(v)
	}
}
