package app

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func startWebtopSync(cfg Config, store *Store) {
	interval := cfg.SyncInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	client := &http.Client{Timeout: 10 * time.Second}

	run := func() {
		req, err := http.NewRequest(http.MethodGet, cfg.SyncURL, nil)
		if err != nil {
			log.Printf("sync build request error: %v", err)
			return
		}
		if cfg.SyncSecret != "" {
			req.Header.Set("X-Admin-Secret", cfg.SyncSecret)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("sync fetch error: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("sync fetch status %d", resp.StatusCode)
			return
		}
		var webtops []Webtop
		if err := json.NewDecoder(resp.Body).Decode(&webtops); err != nil {
			log.Printf("sync decode error: %v", err)
			return
		}
		if err := store.ReplaceWebtops(webtops); err != nil {
			log.Printf("sync replace error: %v", err)
			return
		}
		log.Printf("synced %d webtops from %s", len(webtops), cfg.SyncURL)
	}

	run()
	for range ticker.C {
		run()
	}
}
