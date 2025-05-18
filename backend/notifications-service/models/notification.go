package models

import "time"

type Notification struct {
	ID        string    `cassandra:"id" json:"id"`
	UserID    string    `cassandra:"user_id" json:"userId"`
	Username  string    `cassandra:"username" json:"username"`
	Message   string    `cassandra:"message" json:"message"`
	CreatedAt time.Time `cassandra:"created_at" json:"createdAt"`
	IsRead    bool      `cassandra:"is_read" json:"isRead"`
}
