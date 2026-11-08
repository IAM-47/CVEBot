package bot

import (
	"CVEBot/internal/nvd"
	"CVEBot/internal/storage"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var errBadFormat = errors.New("bad format")

func parseSubscription(text string) (storage.Subscription, error) {
	p, v := nvd.SplitProductVersion(text)
	if p == "" {
		return storage.Subscription{}, errBadFormat
	}
	var sub storage.Subscription
	sub.Product = p
	if v != "" {
		sub.Version = &v
	}
	return sub, nil
}
func doSubscription(ctx context.Context, query string, s *storage.SubscriptionsStorage, chatID int64) (msg string, err error) {
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
func severityName(n int) string {
	if n > 0 && n < 5 {
		return storage.SeverityNames[n]
	}
	return "?"
}
func formatSubscription(sub []storage.Subscription) string {
	lines := make([]string, len(sub))
	for i, s := range sub {
		mSeverity := severityName(s.MinSeverity)
		if s.Version == nil {
			lines[i] = fmt.Sprintf("%d – %s (all versions) – from %s", i+1, s.Product, mSeverity)
			continue
		}
		lines[i] = fmt.Sprintf("%d – %s %s – from %s", i+1, s.Product, *s.Version, mSeverity)
	}
	return "Your subscriptions:\n" + strings.Join(lines, "\n")
}
func doList(ctx context.Context, s *storage.SubscriptionsStorage, chatID int64) (msg string, err error) {
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	subs, err := s.GetSubscriptionList(dbCtx, chatID)
	if err != nil {
		return DBError, err
	}
	if len(subs) == 0 {
		return EmptyList, nil
	}
	msg = formatSubscription(subs)
	return msg, nil
}
