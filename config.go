package main

import (
	"errors"
	"os"
	"strings"
)

type Config struct {
	TelegramToken string
	NVDAPIKey     string
	DSN           string
}

func loadConfig() (Config, error) {
	var cfg Config
	cfg.TelegramToken = strings.TrimSpace(os.Getenv("TELEGRAM_TOKEN"))
	cfg.NVDAPIKey = strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	cfg.DSN = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if cfg.TelegramToken == "" {
		return Config{}, errors.New("TELEGRAM_TOKEN environment variable not set")
	}
	if cfg.DSN == "" {
		return Config{}, errors.New("DATABASE_URL environment variable not set")
	}
	return cfg, nil
}
