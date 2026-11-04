package main

import (
	"math"
	"os"
	"testing"
)

func TestVulnerabilities_GetData(t *testing.T) {
	test, err := os.ReadFile("testdata/heartbleed.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("test", func(t *testing.T) {
		descriptionEn := "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug."
		got, err := GetData(test)
		if err != nil {
			t.Fatalf("cant get data: %v", err)
		}
		if len(got.Vulnerabilities) == 0 {
			t.Fatalf("got no vulnerabilities")
		}
		if got.TotalResults != 1 {
			t.Errorf("got %d, want 1", got.TotalResults)
		}
		if got.Vulnerabilities[0].Cve.ID != "CVE-2014-0160" {
			t.Errorf("got %s, want CVE-2014-0160", got.Vulnerabilities[0].Cve.ID)
		}
		if got.Vulnerabilities[0].Cve.Published != "2014-04-07T22:55:03.893" {
			t.Errorf("got %s want 2014-04-07T22:55:03.893", got.Vulnerabilities[0].Cve.Published)
		}
		desc, fl := got.Vulnerabilities[0].Cve.EngDescription()
		if fl == false {
			t.Errorf("got false, want true")
		}
		if desc != descriptionEn {
			t.Errorf("got %s, want in English", desc)
		}
		if _, ok := got.Vulnerabilities[0].Cve.Metrics["cvssMetricV31"]; !ok {
			t.Errorf("got false, want true")
		}
		if got.Vulnerabilities[0].Cve.Metrics["cvssMetricV31"][0].Type != "Primary" {
			t.Fatalf("got %s, want Primary", got.Vulnerabilities[0].Cve.Metrics["cvssMetricV31"][0].Type)
		}
		score := got.Vulnerabilities[0].Cve.Metrics["cvssMetricV31"][0].CData.BaseScore
		if score != nil {
			if math.Abs(*score-7.5) > 1e-7 {
				t.Errorf("got %f, want 7.5", *score)
			}
		} else {
			t.Errorf("got nil, want score")
		}

	})

}
func Test_GetDataWithInvalidData(t *testing.T) {
	test := []byte("{")
	_, err := GetData(test)
	if err == nil {
		t.Errorf("got nil, want error")
	}
}
func ptr(f float64) *float64 { return &f }
func TestCVE_BestScore(t *testing.T) {
	tests := []struct {
		name      string
		cve       CVE
		wantScore float64
		wantVer   string
		wantType  string
		wantOK    bool
	}{
		{
			name: "only V2",
			cve: CVE{Metrics: map[string][]Metric{
				"cvssMetricV2": {{Type: "Primary", CData: CvssData{BaseScore: ptr(5.0)}}},
			}},
			wantScore: 5.0, wantVer: "2", wantType: "Primary", wantOK: true,
		},
		{
			name: "V3 and V2",
			cve: CVE{Metrics: map[string][]Metric{
				"cvssMetricV31": {{Type: "Primary", CData: CvssData{BaseScore: ptr(7.5)}}},
				"cvssMetricV2":  {{Type: "Primary", CData: CvssData{BaseScore: ptr(5.0)}}},
			}},
			wantScore: 7.5, wantVer: "31", wantType: "Primary", wantOK: true,
		},
		{
			name: "only V40",
			cve: CVE{Metrics: map[string][]Metric{
				"cvssMetricV40": {{Type: "Primary", CData: CvssData{BaseScore: ptr(9.3)}}},
			}},
			wantScore: 9.3, wantVer: "40", wantType: "Primary", wantOK: true,
		},
		{
			name:      "empty",
			cve:       CVE{Metrics: nil},
			wantScore: 0.0, wantOK: false,
		},
		{
			name:      "no metrics",
			cve:       CVE{Metrics: map[string][]Metric{}},
			wantScore: 0.0, wantOK: false,
		},
		{
			name: "Score nil",
			cve: CVE{Metrics: map[string][]Metric{
				"cvssMetricV31": {{Type: "Primary", CData: CvssData{BaseScore: nil}}},
			}},
			wantScore: 0.0, wantOK: false,
		},
		{
			name: "extra version",
			cve: CVE{Metrics: map[string][]Metric{
				"ssvcV203":      {},
				"cvssMetricV31": {{Type: "Secondary", CData: CvssData{BaseScore: ptr(7.5)}}},
			}},
			wantScore: 7.5, wantVer: "31", wantType: "Secondary", wantOK: true,
		},
		{
			name: "empty the newest version",
			cve: CVE{Metrics: map[string][]Metric{
				"cvssMetricV40": {{Type: "Primary", CData: CvssData{BaseScore: nil}}},
				"cvssMetricV31": {{Type: "Secondary", CData: CvssData{BaseScore: ptr(8.0)}}},
			}},
			wantScore: 8.0, wantVer: "31", wantType: "Secondary", wantOK: true,
		},
		{
			name: "type priority",
			cve: CVE{Metrics: map[string][]Metric{
				"cvssMetricV31": {
					{Type: "Secondary", CData: CvssData{BaseScore: ptr(9.0)}},
					{Type: "Primary", CData: CvssData{BaseScore: ptr(6.0)}}},
			}},
			wantScore: 6.0, wantVer: "31", wantType: "Primary", wantOK: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score, version, type1, flag := tc.cve.BestScore()
			if score != tc.wantScore {
				t.Errorf("got %f, want %f", score, tc.wantScore)
			}
			if version != tc.wantVer {
				t.Errorf("got %s, want %s", version, tc.wantVer)
			}
			if type1 != tc.wantType {
				t.Errorf("got %s, want %s", type1, tc.wantType)
			}
			if flag != tc.wantOK {
				t.Errorf("got %v, want %v", flag, tc.wantOK)
			}
		})
	}
}
func TestBuildCPE(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// General
		{
			name:     "nginx 1.18",
			input:    "nginx 1.18",
			expected: "cpe:2.3:a:*:nginx:1.18",
		},
		{
			name:     "Caps",
			input:    "NGINX 1.18",
			expected: "cpe:2.3:a:*:nginx:1.18",
		},
		{
			name:     "extra spaces",
			input:    "  nginx             1.18      ",
			expected: "cpe:2.3:a:*:nginx:1.18",
		},
		{
			name:     "without version",
			input:    "nginx",
			expected: "cpe:2.3:a:*:nginx",
		},
		{
			name:     "double word query",
			input:    "internet explorer",
			expected: "cpe:2.3:a:*:internet_explorer",
		},
		{
			name:     "double word query + version",
			input:    "internet explorer 11",
			expected: "cpe:2.3:a:*:internet_explorer:11",
		},
		// Synonyms
		{
			name:     "apache 2.4.49",
			input:    "apache 2.4.49",
			expected: "cpe:2.3:a:*:http_server:2.4.49",
		},
		{
			name:     "apache http server 2.4.49",
			input:    "apache http server 2.4.49",
			expected: "cpe:2.3:a:*:http_server:2.4.49",
		},
		{
			name:     "httpd 2.4.49",
			input:    "httpd 2.4.49",
			expected: "cpe:2.3:a:*:http_server:2.4.49",
		},
		{
			name:     "postgres 14.2",
			input:    "postgres 14.2",
			expected: "cpe:2.3:a:*:postgresql:14.2",
		},
		{
			name:     "mongo 5.0",
			input:    "mongo 5.0",
			expected: "cpe:2.3:a:*:mongodb:5.0",
		},
		{
			name:     "nodejs 18.0.0",
			input:    "nodejs 18.0.0",
			expected: "cpe:2.3:a:*:node.js:18.0.0",
		},
		{
			name:     "golang 1.20",
			input:    "golang 1.20",
			expected: "cpe:2.3:a:*:go:1.20",
		},
		{
			name:     "spring 5.3.0",
			input:    "spring 5.3.0",
			expected: "cpe:2.3:a:*:spring_framework:5.3.0",
		},
		{
			name:     "k8s 1.27",
			input:    "k8s 1.27",
			expected: "cpe:2.3:a:*:kubernetes:1.27",
		},
		// Substring protection
		{
			name:     "mongodb 1.27",
			input:    "mongodb 1.27",
			expected: "cpe:2.3:a:*:mongodb:1.27",
		},
		{
			name:     "myapache 2.4",
			input:    "myapache 2.4",
			expected: "cpe:2.3:a:*:myapache:2.4",
		},
		// Edge cases
		{
			name:     "7zip",
			input:    "7zip",
			expected: "cpe:2.3:a:*:7zip",
		},
		{
			name:     "1.24.0",
			input:    "1.24.0",
			expected: "cpe:2.3:a:*:1.24.0",
		},
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "only spaces",
			input:    "       ",
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := buildCPE(test.input)
			if got != test.expected {
				t.Errorf("got %q, want %q", got, test.expected)
			}
		})
	}
}
