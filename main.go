package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
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
var offset int64 = 0

func main() {
	if token == "" {
		log.Fatal("TELEGRAM_TOKEN environment variable not set")
	}

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
				message, result, err := handleUpdate(res[i].Msg.Text)
				if err != nil {
					log.Printf("cant handle update: %v", err)
				}
				if err := sendMessage(sendURL, res[i].Msg.Chat.ID, message); err != nil {
					log.Printf("send message: %v", err)
				}
				if result != "" {
					if err := sendMessage(sendURL, res[i].Msg.Chat.ID, result); err != nil {
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
