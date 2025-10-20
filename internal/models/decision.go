package models

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
