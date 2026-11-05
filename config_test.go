package main

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		env     Config
		wantErr bool
		want    Config
	}{
		{
			name:    "empty token",
			env:     Config{"", "12345"},
			wantErr: true,
			want:    Config{},
		},
		{
			name:    "empty api key",
			env:     Config{"12345", ""},
			wantErr: false,
			want:    Config{"12345", ""},
		},
		{
			name:    "both here",
			env:     Config{"12345", "54321"},
			wantErr: false,
			want:    Config{"12345", "54321"},
		},
		{
			name:    "token with only spaces",
			env:     Config{"      ", "54321"},
			wantErr: true,
			want:    Config{},
		},
		{
			name:    "token with extra spaces",
			env:     Config{"  12345  ", "54321"},
			wantErr: false,
			want:    Config{"12345", "54321"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("NVD_API_KEY", test.env.NVDAPIKey)
			t.Setenv("TELEGRAM_TOKEN", test.env.TelegramToken)
			got, err := loadConfig()
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("got = %+v, want %+v", got, test.want)
			}
		})
	}
}
