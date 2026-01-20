package main

import "time"

type User struct {
	ID          int64
	Username    string
	Password    string
	Disabled    bool
	LockedUntil *time.Time
}

type Webtop struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	TargetURL string `json:"target_url"`
	Enabled   bool   `json:"enabled"`
}
