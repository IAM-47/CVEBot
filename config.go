package main

import (
	"errors"
	"os"
	"strings"
)

type Config struct {
	TelegramToken string
	NVDAPIKey     string
}

func loadConfig() (Config, error) {
	var cfg Config
	cfg.TelegramToken = strings.TrimSpace(os.Getenv("TELEGRAM_TOKEN"))
	cfg.NVDAPIKey = os.Getenv("NVD_API_KEY")
	if cfg.TelegramToken == "" {
		return Config{}, errors.New("TELEGRAM_TOKEN environment variable not set")
	}

	return cfg, nil
}
