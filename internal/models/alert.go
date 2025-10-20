package models

type Event struct {
	Timestamp string     `json:"timestamp"`
	Meta      []MetaItem `json:"meta"`
}

type MetaItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Alert struct {
	Scenario  string  `json:"scenario"`
	IPAddress string  `json:"ip"`
	Subnet    string  `json:"subnet"`
	DateTime  string  `json:"datetime"`
	CreatedAt string  `json:"created_at"`
	StartAt   string  `json:"start_at"`
	StopAt    string  `json:"stop_at"`
	Events    []Event `json:"events"`
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
