package storage

import "time"

var SeverityNames = []string{"", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

type Subscription struct {
	ID          int64     `db:"id"`
	ChatID      int64     `db:"chat_id"`
	Product     string    `db:"product"`
	Version     *string   `db:"version"`
	MinSeverity int       `db:"min_severity"`
	Kev         bool      `db:"kev"`
	CreatedAt   time.Time `db:"created_at"`
}
