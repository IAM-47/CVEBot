package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

type NVDResponse struct {
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
type Vulnerability struct {
	Cve CVE `json:"cve"`
}
type CVE struct {
	ID        string              `json:"id"`
	Published string              `json:"published"`
	Descript  []Description       `json:"descriptions"`
	Metrics   map[string][]Metric `json:"metrics"`
}
type Metric struct {
	Type  string   `json:"type"`
	CData CvssData `json:"cvssData"`
}

type CvssData struct {
	BaseScore *float64 `json:"baseScore"`
}
type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

func GetData(bytes []byte) (*NVDResponse, error) {
	var response NVDResponse
	if err := json.Unmarshal(bytes, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	return &response, nil
}
func (c CVE) EngDescription() (string, bool) {
	desc := ""
	fl := false
	for i := range c.Descript {
		if c.Descript[i].Lang == "en" {
			fl = true
			desc = c.Descript[i].Value
			break
		}
	}
	return desc, fl
}
func newNVDRequest(cpe, apiKey string) (*http.Request, error) {
	q := url.Values{}
	q.Set("VirtualMatchString", cpe)
	q.Set("resultsPerPage", "5")
	req, err := http.NewRequest(
		"GET",
		"https://services.nvd.nist.gov/rest/json/cves/2.0",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.URL.RawQuery = q.Encode()
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}
	return req, nil
}
func NVDData(keyword, apiKey string) (*NVDResponse, error) {
	cpe := buildCPE(keyword)
	req, err := newNVDRequest(cpe, apiKey)
	resp, err := apiclient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status code %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	data, err := GetData(body)
	if err != nil {
		return nil, fmt.Errorf("failed to get data from response body: %w", err)
	}
	return data, nil
}
func (c CVE) BestScore() (score float64, version string, type1 string, flag bool) {
	version = c.BestVersion()
	key := "cvssMetricV" + version
	score = -1.0
	for j := range c.Metrics[key] {
		if c.Metrics[key][j].CData.BaseScore == nil {
			continue
		}
		if c.Metrics[key][j].Type == "Primary" {
			score, type1, flag = *c.Metrics[key][j].CData.BaseScore, c.Metrics[key][j].Type, true
			break
		}
		if *c.Metrics[key][j].CData.BaseScore > score {
			score, type1, flag = *c.Metrics[key][j].CData.BaseScore, c.Metrics[key][j].Type, true
		}
	}
	if !flag {
		score = 0.0
	}
	return score, version, type1, flag
}
func (c CVE) BestVersion() string {
	mx := 0
	for i := range c.Metrics {
		if suf, ok := strings.CutPrefix(i, "cvssMetricV"); ok {
			ver, err := strconv.Atoi(suf)
			if err != nil {
				continue
			}
			for j := range c.Metrics[i] {
				if c.Metrics[i][j].CData.BaseScore == nil {
					continue
				}
				if ver > mx {
					mx = ver
					break
				}
			}

		}
	}
	if mx == 0 {
		return ""
	}
	res := strconv.Itoa(mx)
	return res
}

// Not empty query is guaranteed by handleText
func buildCPE(query string) string {
	synonyms := map[string]string{
		"apache":             "http_server",
		"apache http server": "http_server",
		"httpd":              "http_server",
		"postgres":           "postgresql",
		"mongo":              "mongodb",
		"nodejs":             "node.js",
		"golang":             "go",
		"spring":             "spring_framework",
		"k8s":                "kubernetes",
	}

	query = strings.ToLower(query)
	words := strings.Fields(query)
	if len(words) == 0 {
		return ""
	}
	lastWord := words[len(words)-1]
	runes := []rune(lastWord)
	if unicode.IsDigit(runes[0]) && len(words) > 1 {
		param := strings.Join(words[:len(words)-1], "_")
		if v, ok := synonyms[strings.Join(words[:len(words)-1], " ")]; ok {
			param = v
		}
		return fmt.Sprintf("cpe:2.3:a:*:%s:%s", param, lastWord)
	}
	param := strings.Join(words, "_")
	if v, ok := synonyms[strings.Join(words, " ")]; ok {
		param = v
	}
	return fmt.Sprintf("cpe:2.3:a:*:%s", param)
}
