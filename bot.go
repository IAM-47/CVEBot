package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

type Bot struct {
	nvdKey  string
	sendURL string
	store   *SubscriptionsStorage
}

func getUpdates(uRl string, offset int64) ([]Update, error) {
	q := url.Values{}
	q.Add("offset", strconv.FormatInt(offset, 10))
	q.Add("timeout", "30")

	resp, err := pollClient.Get(uRl + "?" + q.Encode())
	if err != nil {
		err = cleanURL(err)
		return nil, fmt.Errorf("cant do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cant read: %w", err)
	}
	var res UpdatesResponse
	if err := json.Unmarshal(respBytes, &res); err != nil {
		return nil, fmt.Errorf("cant unmarshal: %w", err)
	}
	if !res.Ok {
		return nil, fmt.Errorf("status isn't OK, error_code: %d, description: %s", res.ErrCode, res.Description)
	}
	return res.Result, nil
}
func sendMessage(u string, chatID int64, msg string) error {
	q := url.Values{}
	q.Add("chat_id", strconv.FormatInt(chatID, 10))
	q.Add("text", msg)
	sendResponse, err := apiclient.Post(u, "application/x-www-form-urlencoded", strings.NewReader(q.Encode()))
	if err != nil {
		err = cleanURL(err)
		return fmt.Errorf("cant do request: %w", err)
	}
	defer func() { _ = sendResponse.Body.Close() }()
	msgByte, err := io.ReadAll(sendResponse.Body)
	if err != nil {
		return fmt.Errorf("cant read: %w", err)
	}
	var res SendMessageResponse
	if err := json.Unmarshal(msgByte, &res); err != nil {
		return fmt.Errorf("cant unmarshal: %w", err)
	}
	if !res.Ok {
		return fmt.Errorf("status isn't OK, error_code: %d, description: %s", res.ErrCode, res.Description)
	}
	return nil
}

func handleCVE(text string) (msg string, req string, flag bool) {
	words := strings.Fields(text)
	switch {
	//
	case len(words) == 0:
		return HintMessage, "", false
	//
	case len(words) == 2 && len([]rune(words[1])) < 2 && words[0] == "/cve":
		return TooShortQuery, "", false
	//
	case words[0] == "/start":
		return StartMessage, "", false
	//
	case words[0] == "/help":
		return HelpMessage, "", false
	//
	case strings.HasPrefix(words[0], "/") && words[0] != "/cve":
		return "Unknown command. " + HintMessage, "", false
	//
	case words[0] == "/cve" && len(words) > 1:
		return fmt.Sprintf("Trying to find cve for %s", strings.Join(words[1:], " ")), strings.Join(words[1:], " "), true
	//
	case len(words) == 1 && words[0] == "/cve":
		return HintMessage, "", false
	//
	default:
		return HintMessage, "", false
	}
}
func handleReq(req, apiKey string) (msg string, err error) {
	vulns := make([]string, 0, 5)
	resp, err := NVDData(req, apiKey)
	if err != nil {
		return BedNetworkMessage, fmt.Errorf("cant do request: %w", err)
	}
	if len(resp.Vulnerabilities) == 0 {
		return EmptyRespMessage, nil
	}
	for i := range resp.Vulnerabilities {
		vulns = append(vulns, formatCVE(resp.Vulnerabilities[i].Cve))

	}
	msg = strings.Join(vulns, "\n\n")
	return msg, nil
}
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
func (b *Bot) handleCommands(ctx context.Context, chatID int64, text string) {
	words := strings.Fields(text)
	if len(words) == 0 {
		if err := sendMessage(b.sendURL, chatID, StartMessage); err != nil {
			log.Printf("send message: %v", err)
			return
		}
		return
	}
	query := strings.Join(words[1:], " ")
	switch words[0] {
	//
	case "/subscribe":
		msg, err := doSubscription(ctx, query, b.store, chatID)
		if err != nil {
			log.Printf("cant do subscription: %v", err)
		}
		if err := sendMessage(b.sendURL, chatID, msg); err != nil {
			log.Printf("send message: %v", err)
			return
		}
	//
	default:
		message, req, flag := handleCVE(text)
		if err := sendMessage(b.sendURL, chatID, message); err != nil {
			log.Printf("send message: %v", err)
		}
		if !flag {
			return
		}
		msg, err := handleReq(req, b.nvdKey)
		if err != nil {
			log.Printf("cant handleReq: %v", err)
			return
		}
		if msg != "" {
			if err := sendMessage(b.sendURL, chatID, msg); err != nil {
				log.Printf("send message: %v", err)
				return
			}
		}
	}
}
