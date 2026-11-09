package bot

import (
	"CVEBot/internal/nvd"
	"CVEBot/internal/storage"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Update struct {
	ID  int64    `json:"update_id"`
	Msg *Message `json:"message"`
}
type Message struct {
	ID   int64  `json:"message_id"`
	From From   `json:"from"`
	Chat Chat   `json:"chat"`
	Date int64  `json:"date"`
	Text string `json:"text"`
}
type From struct {
	ID        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	UserName  string `json:"username"`
	LangCode  string `json:"language_code"`
}
type Chat struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	UserName  string `json:"username"`
	Type      string `json:"type"`
}
type UpdatesResponse struct {
	Ok          bool     `json:"ok"`
	Result      []Update `json:"result"`
	ErrCode     int      `json:"error_code"`
	Description string   `json:"description"`
}
type SendMessageResponse struct {
	Ok          bool   `json:"ok"`
	ErrCode     int    `json:"error_code"`
	Description string `json:"description"`
}

type Bot struct {
	NVDKey  string
	SendURL string
	Store   *storage.SubscriptionsStorage
}

var pollClient = http.Client{Timeout: time.Second * 45}

func GetUpdates(uRl string, offset int64) ([]Update, error) {
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
func SendMessage(u string, chatID int64, msg string) error {
	q := url.Values{}
	q.Add("chat_id", strconv.FormatInt(chatID, 10))
	q.Add("text", msg)
	sendResponse, err := nvd.Apiclient.Post(u, "application/x-www-form-urlencoded", strings.NewReader(q.Encode()))
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
	product, version := splitProductVersion(req)
	resp, err := nvd.Data(product, version, apiKey)
	if err != nil {
		return BadNetworkMessage, fmt.Errorf("cant do request: %w", err)
	}
	if len(resp.Vulnerabilities) == 0 {
		return EmptyRespMessage, nil
	}
	for i := range resp.Vulnerabilities {
		vulns = append(vulns, nvd.FormatCVE(resp.Vulnerabilities[i].Cve))

	}
	msg = strings.Join(vulns, "\n\n")
	return msg, nil
}

func (b *Bot) HandleCommands(ctx context.Context, chatID int64, text string) {
	words := strings.Fields(text)
	if len(words) == 0 {
		if err := SendMessage(b.SendURL, chatID, StartMessage); err != nil {
			log.Printf("send message: %v", err)
			return
		}
		return
	}
	query := strings.Join(words[1:], " ")
	switch words[0] {
	//
	case "/subscribe":
		msg, err := doSubscription(ctx, query, b.Store, chatID)
		if err != nil {
			log.Printf("cant do subscription: %v", err)
		}
		if err := SendMessage(b.SendURL, chatID, msg); err != nil {
			log.Printf("send message: %v", err)
			return
		}
	//
	case "/list":
		msg, err := doList(ctx, b.Store, chatID)
		if err != nil {
			log.Printf("cant do list: %v", err)
		}
		if err := SendMessage(b.SendURL, chatID, msg); err != nil {
			log.Printf("send message: %v", err)
			return
		}
	//
	case "/unsubscribe":
		msg, err := doUnsubscribe(ctx, query, b.Store, chatID)
		if err != nil {
			log.Printf("cant do unsubscribe: %v", err)
		}
		if err := SendMessage(b.SendURL, chatID, msg); err != nil {
			log.Printf("send message: %v", err)
			return
		}
	//
	default:
		message, req, flag := handleCVE(text)
		if err := SendMessage(b.SendURL, chatID, message); err != nil {
			log.Printf("send message: %v", err)
		}
		if !flag {
			return
		}
		msg, err := handleReq(req, b.NVDKey)
		if err != nil {
			log.Printf("cant handleReq: %v", err)
		}
		if msg != "" {
			if err := SendMessage(b.SendURL, chatID, msg); err != nil {
				log.Printf("send message: %v", err)
				return
			}
		}
	}
}
