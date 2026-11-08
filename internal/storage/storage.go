package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
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
func (s *SubscriptionsStorage) GetSubscriptionList(ctx context.Context, chatID int64) ([]Subscription, error) {
	q := `select id, chat_id, product, version, min_severity, kev, created_at from subscriptions where chat_id = $1 order by id`
	rows, err := s.pool.Query(ctx, q, chatID)
	if err != nil {
		return nil, fmt.Errorf("get subscriptions: %w", err)
	}
	sub, err := pgx.CollectRows(rows, pgx.RowToStructByName[Subscription])
	if err != nil {
		return nil, fmt.Errorf("get subscriptions: %w", err)
	}
	return sub, nil

}
func (s *SubscriptionsStorage) DeleteSubscription(ctx context.Context, sub Subscription) (bool, error) {
	q := `delete from subscriptions where chat_id = $1 and product = $2 and version is not distinct from $3`
	tag, err := s.pool.Exec(ctx, q, sub.ChatID, sub.Product, sub.Version)
	if err != nil {
		return false, fmt.Errorf("unsubscribe: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	return true, nil
}
