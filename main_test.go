package main

import "testing"

func TestHandleText(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectedM string
		expectedR string
		expectedF bool
	}{{
		name:      "empty",
		input:     "",
		expectedM: HintMessage,
		expectedR: "",
		expectedF: false,
	},
		{
			name:      "/cve",
			input:     "/cve",
			expectedM: HintMessage,
			expectedR: "",
			expectedF: false,
		},
		{
			name:      "start",
			input:     "/start",
			expectedM: "Hey! " + HintMessage,
			expectedR: "",
			expectedF: false,
		},
		{
			name:      "full",
			input:     "/cve nginx 1.2",
			expectedM: "Trying to find cve for nginx 1.2",
			expectedR: "nginx 1.2",
			expectedF: true,
		},
		{
			name:      "almost full",
			input:     "/cve nginx",
			expectedM: "Trying to find cve for nginx",
			expectedR: "nginx",
			expectedF: true,
		},
		{
			name:      "/",
			input:     "/",
			expectedM: "Unknown command. " + HintMessage,
			expectedR: "",
			expectedF: false,
		},
		{
			name:      "/d",
			input:     "/d",
			expectedM: "Unknown command. " + HintMessage,
			expectedR: "",
			expectedF: false,
		},
		{
			name:      "with extra spaces",
			input:     "/cve    nginx    1.2",
			expectedM: "Trying to find cve for nginx 1.2",
			expectedR: "nginx 1.2",
			expectedF: true,
		},
		{
			name:      "with only spaces",
			input:     "			",
			expectedM: HintMessage,
			expectedR: "",
			expectedF: false,
		},
		{
			name:      "too long command",
			input:     "/cve a a в ",
			expectedM: "Trying to find cve for a a в",
			expectedR: "a a в",
			expectedF: true,
		},
		{
			name:      "/cve ",
			input:     "/cve ",
			expectedM: HintMessage,
			expectedR: "",
			expectedF: false,
		},
		{
			name:      "typo",
			input:     "/cves nginx",
			expectedM: "Unknown command. " + HintMessage,
			expectedR: "",
			expectedF: false,
		},
		{
			name:      "/foo o o o",
			input:     "/foo o o o o",
			expectedM: "Unknown command. " + HintMessage,
			expectedR: "",
			expectedF: false,
		},
		{
			name:      "/start extra",
			input:     "/start extra",
			expectedM: "Hey! " + HintMessage,
			expectedR: "",
			expectedF: false,
		},
		{
			name:      "/cve with only spaces",
			input:     "/cve			",
			expectedM: HintMessage,
			expectedR: "",
			expectedF: false,
		},
		{
			name:      "/cve apache http server",
			input:     "/cve apache http server ",
			expectedM: "Trying to find cve for apache http server",
			expectedR: "apache http server",
			expectedF: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotM, gotR, gotF := handleText(test.input)

			if gotM != test.expectedM {
				t.Errorf("got %q, want %q", gotM, test.expectedM)
			}
			if gotR != test.expectedR {
				t.Errorf("got %q, want %q", gotR, test.expectedR)
			}
			if gotF != test.expectedF {
				t.Errorf("got %v, want %v", gotF, test.expectedF)
			}
		})
	}
}
