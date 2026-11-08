package main

import (
	"CVEBot/internal/bot"
	"CVEBot/internal/config"
	"CVEBot/internal/storage"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	ctx := context.Background()

	err := godotenv.Load(".env")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	pool, err := storage.DBConnect(ctx, cfg.DSN)
	if err != nil {
		log.Fatal("db: ", err)
	}
	defer pool.Close()
	var baseURL = "https://api.telegram.org/bot" + cfg.TelegramToken + "/getUpdates"
	var sendURL = "https://api.telegram.org/bot" + cfg.TelegramToken + "/sendMessage"
	var offset int64 = 0
	b := &bot.Bot{
		SendURL: sendURL,
		NVDKey:  cfg.NVDAPIKey,
		Store:   storage.NewSubscriptionsStorage(pool),
	}
	log.Println("Connected to database")
	for {
		res, err := bot.GetUpdates(baseURL, offset)
		if err != nil {
			log.Printf("cant get updates: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		for i := range res {
			fmt.Printf("Update ID: %d\n", res[i].ID)
			if res[i].Msg != nil {
				fmt.Printf("Text: %s\nChatID: %d\n", res[i].Msg.Text, res[i].Msg.Chat.ID)
				b.HandleCommands(ctx, res[i].Msg.Chat.ID, res[i].Msg.Text)
			}
		}
		if len(res) > 0 {
			offset = res[len(res)-1].ID + 1
		}
	}

}
