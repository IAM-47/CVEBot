package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
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

var token = os.Getenv("TELEGRAM_TOKEN")
var baseURL = "https://api.telegram.org/bot" + token + "/getUpdates"
var sendURL = "https://api.telegram.org/bot" + token + "/sendMessage"
var client = http.Client{Timeout: time.Second * 10}

func main() {
	if token == "" {
		log.Fatal("TELEGRAM_TOKEN environment variable not set")
	}
	var offset int64 = 0
	for {
		res, err := getUpdates(baseURL, offset)
		if err != nil {
			log.Printf("cant get updates: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		for i := range res {
			fmt.Printf("Update ID: %d\n", res[i].ID)
			if res[i].Msg != nil {
				fmt.Printf("Text: %s\nChatID: %d\n", res[i].Msg.Text, res[i].Msg.Chat.ID)
				answer := handleText(res[i].Msg.Text)
				if answer != "" {
					if err := sendMessage(sendURL, res[i].Msg.Chat.ID, answer); err != nil {
						log.Printf("send message: %v", err)
					}
				}
			}

		}
		if len(res) > 0 {
			offset = res[len(res)-1].ID + 1
		}
	}

}

func getUpdates(uRl string, offset int64) ([]Update, error) {
	q := url.Values{}
	q.Add("offset", strconv.FormatInt(offset, 10))
	q.Add("timeout", "30")

	resp, err := http.Get(uRl + "?" + q.Encode())
	if err != nil {
		return nil, fmt.Errorf("cant do request: %w", err)
	}
	defer resp.Body.Close()
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
	sendResponse, err := http.Post(u, "application/x-www-form-urlencoded", strings.NewReader(q.Encode()))
	if err != nil {
		return fmt.Errorf("cant do request: %w", err)
	}
	defer sendResponse.Body.Close()
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

func handleText(text string) string {
	words := strings.Fields(text)
	switch {
	//
	case len(words) == 0:
		return ""
	//
	case len(words) == 1 && words[0] == "/start":
		return "Hey! just send me command like \"/cve <any tech> [version]\""
	//
	case strings.HasPrefix(words[0], "/") && words[0] != "/cve":
		return "Unknown command"
	//
	case words[0] == "/cve" && len(words) == 3:
		return fmt.Sprintf("Trying to find cve for %s %s", words[1], words[2])
	//
	case len(words) > 3 && words[0] == "/cve" || (len(words) == 1 && words[0] == "/cve"):
		return "Please send me command like \"/cve <any tech> [version]\""
	//
	case words[0] == "/cve" && len(words) == 2:
		return fmt.Sprintf("Trying to find cve for %s any version", words[1])
	//
	default:
		return text
	}
}
