package main

import (
	"fmt"
	"strings"
	"testing"
)

func Test_Truncate(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		n     int
		wantS string
	}{
		{
			name:  "< n",
			s:     "1234",
			n:     5,
			wantS: "1234",
		},
		{
			name:  "= n",
			s:     "12345",
			n:     5,
			wantS: "12345",
		},
		{
			name:  "n + 1",
			s:     "123456",
			n:     5,
			wantS: "12345...",
		},
		{
			name:  "=n * 2",
			s:     "1234512345",
			n:     5,
			wantS: "12345...",
		},
		{
			name:  "rus",
			s:     "яблоки",
			n:     5,
			wantS: "яблок...",
		},
		{
			name:  "empty",
			s:     "",
			n:     5,
			wantS: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotS := truncate(tt.s, tt.n); gotS != tt.wantS {
				t.Errorf("got %q, want %v", gotS, tt.wantS)
			}
		})
	}
}
func TestFormat(t *testing.T) {
	tests := []struct {
		name string
		cve  CVE
		want string
	}{
		{
			name: "Full",
			cve: CVE{
				ID:        "CVE-2020-0001",
				Published: "2026-10-23T00:16:49.733",
				Descript:  []Description{{Lang: "en", Value: "12345"}},
				Metrics: map[string][]Metric{
					"cvssMetricV2": {{Type: "Primary", CData: CvssData{BaseScore: ptr(5.0)}}}},
			},
			want: "CVE-2020-0001 – 5.0 (CVSS 2.0, Primary)\nPublished: 2026-10-23\n12345",
		},
		{
			name: "Flag = False",
			cve: CVE{
				ID:        "CVE-2020-0001",
				Published: "2026-10-23T00:16:49.733",
				Descript:  []Description{{Lang: "en", Value: "12345"}},
				Metrics: map[string][]Metric{
					"cvssMetricV2": {{Type: "Primary", CData: CvssData{BaseScore: nil}}}},
			},
			want: "CVE-2020-0001 – This CVE doesn't have the base score\nPublished: 2026-10-23\n12345",
		},
		{
			name: "Without description",
			cve: CVE{
				ID:        "CVE-2020-0001",
				Published: "2026-10-23T00:16:49.733",
				Descript:  []Description{{Lang: "ru", Value: "-------"}},
				Metrics: map[string][]Metric{
					"cvssMetricV2": {{Type: "Primary", CData: CvssData{BaseScore: ptr(5.0)}}},
				},
			},
			want: "CVE-2020-0001 – 5.0 (CVSS 2.0, Primary)\nPublished: 2026-10-23\nThis CVE doesn't have the English description",
		},
		{
			name: "Empty",
			cve:  CVE{},
			want: " – This CVE doesn't have the base score\nPublished: \nThis CVE doesn't have the English description",
		},
		{
			name: "With V31 and len 400 description",
			cve: CVE{
				ID:        "CVE-2020-0001",
				Published: "2026-10-23T00:16:49.733",
				Descript:  []Description{{Lang: "en", Value: strings.Repeat("12345", 80)}},
				Metrics: map[string][]Metric{
					"cvssMetricV31": {{Type: "Primary", CData: CvssData{BaseScore: ptr(5.0)}}},
				},
			},
			want: fmt.Sprintf("CVE-2020-0001 – 5.0 (CVSS 3.1, Primary)\nPublished: 2026-10-23\n%s", strings.Repeat("12345", 60)+"..."),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotS := formatCVE(tt.cve); gotS != tt.want {
				t.Errorf("got %q, want %q", gotS, tt.want)
			}
		})
	}
}
