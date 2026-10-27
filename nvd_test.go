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
