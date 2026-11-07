package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
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

var apiclient = http.Client{Timeout: time.Second * 10}
var pollClient = http.Client{Timeout: time.Second * 45}

func main() {
	ctx := context.Background()

	err := godotenv.Load(".env")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	pool, err := dbConnect(ctx, cfg.DSN)
	if err != nil {
		log.Fatal("db: ", err)
	}
	defer pool.Close()
	var baseURL = "https://api.telegram.org/bot" + cfg.TelegramToken + "/getUpdates"
	var sendURL = "https://api.telegram.org/bot" + cfg.TelegramToken + "/sendMessage"
	var offset int64 = 0
	bot := &Bot{
		sendURL: sendURL,
		nvdKey:  cfg.NVDAPIKey,
		store:   NewSubscriptionsStorage(pool),
	}
	log.Println("Connected to database")
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
				bot.handleCommands(ctx, res[i].Msg.Chat.ID, res[i].Msg.Text)
			}
		}
		if len(res) > 0 {
			offset = res[len(res)-1].ID + 1
		}
	}

}
