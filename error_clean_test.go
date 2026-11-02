package main

import (
	"errors"
	"net/url"
	"testing"
)

func Test_CleanURL(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected error
	}{
		{
			name: "URL error",
			err: &url.Error{
				Op:  "Get",
				URL: "https://x/bot123:ABC/getUpdates",
				Err: errors.New(`dial tcp: no such host`),
			},
			expected: errors.New("Get: dial tcp: no such host"),
		},
		{
			name:     "nil",
			err:      nil,
			expected: nil,
		},
		{
			name:     "not url error",
			err:      errors.New("database connection failed"),
			expected: errors.New("database connection failed"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := cleanURL(test.err)
			if got == nil && test.expected == nil {
				return
			}
			if got == nil || test.expected == nil {
				t.Fatalf("got %v; want %v", got, test.expected)
			}
			if got.Error() != test.expected.Error() {
				t.Errorf("got %v, want %v", got, test.expected)
			}
		})
	}
}
