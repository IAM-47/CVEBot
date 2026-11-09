package bot

import (
	"CVEBot/internal/storage"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

var errBadFormat = errors.New("bad format")

func splitProductVersion(query string) (product, version string) {
	query = strings.ToLower(query)
	words := strings.Fields(query)
	if len(words) == 0 {
		return "", ""
	}
	lastWord := words[len(words)-1]
	runes := []rune(lastWord)
	if unicode.IsDigit(runes[0]) && len(words) > 1 {
		product = strings.Join(words[:len(words)-1], " ")
		version = lastWord
		return product, version
	}
	return strings.Join(words, " "), ""
}
func WhichSeverityAndKev(text string) (newText string, s int, k bool) {
	s, k = 1, false
	text = strings.ToUpper(text)
	pref, ok := strings.CutSuffix(text, "KEV")
	if ok {
		k = true
	}
	pref = strings.TrimSpace(pref)
	for i, v := range storage.SeverityNames[1:] {
		pref, ok = strings.CutSuffix(pref, v)
		if ok {
			s = i + 1
		}
	}
	return pref, s, k
}
func parseSubscription(text string) (sub storage.Subscription, err error) {
	text, sub.MinSeverity, sub.Kev = WhichSeverityAndKev(text)
	p, v := splitProductVersion(text)
	if p == "" {
		return storage.Subscription{}, errBadFormat
	}
	sub.Product = p
	if v != "" {
		sub.Version = &v
	}
	return sub, nil
}
func subscribeReply(oldSev *int, oldKev *bool, sub storage.Subscription) (msg string) {
	updates := make([]string, 0, 2)
	if oldSev == nil || oldKev == nil {
		msg = SuccessfulSubscription
		return msg
	}
	if *oldSev == sub.MinSeverity && *oldKev == sub.Kev {
		msg = AlreadySubscribed
		return msg
	}
	if *oldSev != sub.MinSeverity {
		updates = append(updates, fmt.Sprintf("Updated %s to %s", severityName(*oldSev), severityName(sub.MinSeverity)))
	}
	if *oldKev != sub.Kev {
		updates = append(updates, "Updated KEV")
	}
	msg = strings.Join(updates, "\n")
	return msg
}
func doSubscription(ctx context.Context, query string, s *storage.SubscriptionsStorage, chatID int64) (msg string, err error) {
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sub, err := parseSubscription(query)
	if err != nil {
		return HintMessage, nil
	}
	sub.ChatID = chatID
	oldSev, oldKev, err := s.AddSubscription(dbCtx, sub)
	if err != nil {
		return DBError, err
	}
	msg = subscribeReply(oldSev, oldKev, sub)
	if sub.Version == nil {
		return fmt.Sprintf("%s %s", msg, sub.Product), nil
	}
	return fmt.Sprintf("%s %s %s", msg, sub.Product, *sub.Version), nil
}
func severityName(n int) string {
	if n > 0 && n < len(storage.SeverityNames) {
		return storage.SeverityNames[n]
	}
	return "?"
}
func isKEV(v bool) string {
	if v {
		return ", KEV"
	}
	return ""
}
func formatSubscription(sub []storage.Subscription) string {
	lines := make([]string, len(sub))
	for i, s := range sub {
		mSeverity := severityName(s.MinSeverity)
		if s.Version == nil {
			lines[i] = fmt.Sprintf("%d – %s (all versions) – from %s%s", i+1, s.Product, mSeverity, isKEV(s.Kev))
			continue
		}
		lines[i] = fmt.Sprintf("%d – %s %s – from %s%s", i+1, s.Product, *s.Version, mSeverity, isKEV(s.Kev))
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
func doUnsubscribe(ctx context.Context, query string, s *storage.SubscriptionsStorage, chatID int64) (msg string, err error) {
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sub, err := parseSubscription(query)
	if err != nil {
		return HintMessage, nil
	}
	sub.ChatID = chatID
	flag, err := s.DeleteSubscription(dbCtx, sub)
	if err != nil {
		return DBError, err
	}
	if flag {
		msg = DeletedSuccessfully
		return fmt.Sprintf("%s %s %s", msg, sub.Product, *sub.Version), nil
	}
	msg = NoSuchSubscription
	return fmt.Sprintf("%s %s %s", msg, sub.Product, *sub.Version), nil
}
