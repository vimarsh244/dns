package main

import (
	"os"
	"sync"
	"time"
	"encoding/json"
)

var analyticsFile = "analytics.log" // used in logAnalyticsEvent and getAnalyticsStats
var analyticsMu sync.Mutex // used for file locking

// EventType: "request", "error", "notfound"
type AnalyticsEvent struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
}

// Log an analytics event
func logAnalyticsEvent(eventType string) {
	analyticsMu.Lock()
	defer analyticsMu.Unlock()
	event := AnalyticsEvent{Type: eventType, Timestamp: time.Now().UTC()}
	f, err := os.OpenFile(analyticsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return // fail silently
	}
	defer f.Close()
	b, _ := json.Marshal(event)
	f.Write(append(b, '\n'))
}

// Aggregate stats for the past 24h, 7d, 30d
func getAnalyticsStats() (map[string]map[string]int, error) {
	analyticsMu.Lock()
	defer analyticsMu.Unlock()
	stats := map[string]map[string]int{
		"24h": {"request": 0, "error": 0, "notfound": 0},
		"7d":  {"request": 0, "error": 0, "notfound": 0},
		"30d": {"request": 0, "error": 0, "notfound": 0},
	}
	f, err := os.Open(analyticsFile)
	if err != nil {
		return stats, nil // empty stats if file missing
	}
	defer f.Close()
	now := time.Now().UTC()
	dec := json.NewDecoder(f)
	for {
		var e AnalyticsEvent
		if err := dec.Decode(&e); err != nil {
			break
		}
		if now.Sub(e.Timestamp) <= 24*time.Hour {
			stats["24h"][e.Type]++
		}
		if now.Sub(e.Timestamp) <= 7*24*time.Hour {
			stats["7d"][e.Type]++
		}
		if now.Sub(e.Timestamp) <= 30*24*time.Hour {
			stats["30d"][e.Type]++
		}
	}
	return stats, nil
}
