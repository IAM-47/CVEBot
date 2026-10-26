package main

import "testing"

func TestHandleText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{{
		name:     "empty",
		input:    "",
		expected: "",
	},
		{
			name:     "/cve",
			input:    "/cve",
			expected: "Please send me command like \"/cve <any tech> [version]\"",
		},
		{
			name:     "start",
			input:    "/start",
			expected: "Hey! just send me command like \"/cve <any tech> [version]\"",
		},
		{
			name:     "full",
			input:    "/cve nginx 1.2",
			expected: "Trying to find cve for nginx 1.2",
		},
		{
			name:     "almost full",
			input:    "/cve nginx",
			expected: "Trying to find cve for nginx any version",
		},
		{
			name:     "/",
			input:    "/",
			expected: "Unknown command",
		},
		{
			name:     "/d",
			input:    "/d",
			expected: "Unknown command",
		},
		{
			name:     "with extra spaces",
			input:    "/cve    nginx    1.2",
			expected: "Trying to find cve for nginx 1.2",
		},
		{
			name:     "with only spaces",
			input:    "			",
			expected: "",
		},
		{
			name:     "too long command",
			input:    "/cve a a в ",
			expected: "Please send me command like \"/cve <any tech> [version]\"",
		},
		{
			name:     "/cve ",
			input:    "/cve ",
			expected: "Please send me command like \"/cve <any tech> [version]\"",
		},
		{
			name:     "typo",
			input:    "/cves nginx",
			expected: "Unknown command",
		},
		{
			name:     "/foo o o o",
			input:    "/foo o o o o",
			expected: "Unknown command",
		},
		{
			name:     "/start extra",
			input:    "/start extra",
			expected: "Unknown command",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := handleText(test.input)

			if got != test.expected {
				t.Errorf("got %q, want %q", got, test.expected)
			}
		})
	}
}
