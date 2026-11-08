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
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sub, err := parseSubscription(query)
	if err != nil {
		return HintMessage, nil
	}
	sub.ChatID = chatID
	inserted, err := s.AddSubscription(dbCtx, sub)
	if err != nil {
		return DBError, err
	}
	if !inserted {
		msg = AlreadySubscribed
	} else {
		msg = SuccessfulSubscription
	}
	if sub.Version == nil {
		return fmt.Sprintf("%s %s", msg, sub.Product), nil
	}
	return fmt.Sprintf("%s %s %s", msg, sub.Product, *sub.Version), nil
}
