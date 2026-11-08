package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type SubscriptionsStorage struct {
	pool *pgxpool.Pool
}

func NewSubscriptionsStorage(pool *pgxpool.Pool) *SubscriptionsStorage {
	return &SubscriptionsStorage{pool: pool}
}

func (s *SubscriptionsStorage) AddSubscription(ctx context.Context, sub Subscription) (bool, error) {
	q := `insert into subscriptions (chat_id, product, version) values ($1, $2, $3)
          on conflict (chat_id, product, version) do update 
		  set min_severity = excluded.min_severity, kev = excluded.kev returning (xmax = 0) as inserted`
	var inserted bool
	err := s.pool.QueryRow(ctx, q, sub.ChatID, sub.Product, sub.Version).Scan(&inserted)
	if err != nil {
		return false, fmt.Errorf("add subscription: %w", err)
	}
	return inserted, nil
}
