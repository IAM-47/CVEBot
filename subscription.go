package main

import "time"

type Subscription struct {
	ID          int64
	ChatID      int64
	Product     string
	Version     *string
	MinSeverity int
	Kev         bool
	CreatedAt   time.Time
}
