package models

// HistorySnapshot is the compact per-finding row stored in scan_history.
type HistorySnapshot struct {
	Key     string   `json:"key"`
	CVEID   string   `json:"cveId"`
	Package string   `json:"package"`
	Level   Priority `json:"level"`
	Verdict Verdict  `json:"verdict"`
	EPSS    float64  `json:"epss,omitempty"`
}
