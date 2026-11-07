package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var errBadFormat = errors.New("bad format")

func parseSubscription(text string) (Subscription, error) {
	p, v := splitProductVersion(text)
	if p == "" {
		return Subscription{}, errBadFormat
	}
	var sub Subscription
	sub.Product = p
	if v != "" {
		sub.Version = &v
	}
	return sub, nil
}
func doSubscription(ctx context.Context, query string, s *SubscriptionsStorage, chatID int64) (msg string, err error) {
	dbctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sub, err := parseSubscription(query)
	if err != nil {
		return HintMessage, nil
	}
	sub.ChatID = chatID
	if err := s.AddSubscription(dbctx, sub); err != nil {
		return DBError, fmt.Errorf("failed to add subscription: %w", err)
	}
	return SuccessfulSubscription, nil
}
