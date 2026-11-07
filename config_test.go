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
			env:     Config{"", "12345", "122"},
			wantErr: true,
			want:    Config{},
		},
		{
			name:    "empty api key",
			env:     Config{"12345", "", "122"},
			wantErr: false,
			want:    Config{"12345", "", "122"},
		},
		{
			name:    "all here",
			env:     Config{"12345", "54321", "122"},
			wantErr: false,
			want:    Config{"12345", "54321", "122"},
		},
		{
			name:    "token with only spaces",
			env:     Config{"      ", "54321", "122"},
			wantErr: true,
			want:    Config{},
		},
		{
			name:    "token with extra spaces",
			env:     Config{"  12345  ", "54321", "122"},
			wantErr: false,
			want:    Config{"12345", "54321", "122"},
		},
		{
			name:    "dsn with no value",
			env:     Config{"12345", "54321", ""},
			wantErr: true,
			want:    Config{},
		},
		{
			name:    "dsn with only spaces",
			env:     Config{"122", "54321", "      "},
			wantErr: true,
			want:    Config{},
		},
		{
			name:    "apiKey with only spaces",
			env:     Config{"12345", "        ", "122"},
			wantErr: false,
			want:    Config{"12345", "", "122"},
		},
		{
			name:    "apiKey with extra spaces",
			env:     Config{"12345", "   54321    ", "122"},
			wantErr: false,
			want:    Config{"12345", "54321", "122"},
		},
		{
			name:    "dsn with extra spaces",
			env:     Config{"12345", "54321", "   122   "},
			wantErr: false,
			want:    Config{"12345", "54321", "122"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("NVD_API_KEY", test.env.NVDAPIKey)
			t.Setenv("TELEGRAM_TOKEN", test.env.TelegramToken)
			t.Setenv("DATABASE_URL", test.env.DSN)
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
