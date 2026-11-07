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

func (s *SubscriptionsStorage) AddSubscription(ctx context.Context, sub Subscription) error {
	q := `insert into subscriptions (chat_id, product, version) values ($1, $2, $3)
          on conflict (chat_id, product, version) do update 
		  set min_severity = excluded.min_severity, kev = excluded.kev`
	_, err := s.pool.Exec(ctx, q, sub.ChatID, sub.Product, sub.Version)
	if err != nil {
		return fmt.Errorf("could not add subscription: %w", err)
	}
	return nil
}
