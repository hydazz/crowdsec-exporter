package models

type Alert struct {
	Scenario  string  `json:"scenario"`
	IPAddress string  `json:"ip"`
	Subnet    string  `json:"subnet"`
	DateTime  string  `json:"datetime"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Country   string  `json:"countryISO"`
	AsName    string  `json:"asname"`
	AsNumber  string  `json:"asnumber"`
	IPRange   string  `json:"iprange"`
	// Associated decisions
	Decisions []Decision `json:"decisions"`
}

type Alerts []Alert
