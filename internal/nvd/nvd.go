package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Response struct {
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

var Apiclient = http.Client{Timeout: time.Second * 10}

func GetData(bytes []byte) (*Response, error) {
	var response Response
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
func Data(keyword, apiKey string) (*Response, error) {
	cpe := buildCPE(keyword)
	req, err := newNVDRequest(cpe, apiKey)
	resp, err := Apiclient.Do(req)
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
func SplitProductVersion(query string) (product, version string) {
	query = strings.ToLower(query)
	words := strings.Fields(query)
	if len(words) == 0 {
		return "", ""
	}
	lastWord := words[len(words)-1]
	runes := []rune(lastWord)
	if unicode.IsDigit(runes[0]) && len(words) > 1 {
		product = strings.Join(words[:len(words)-1], " ")
		version = lastWord
		return product, version
	}
	return strings.Join(words, " "), ""
}
func buildCPE(query string) string {
	var synonyms = map[string]string{
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
	product, version := SplitProductVersion(query)
	if product == "" {
		return ""
	}
	if version != "" {
		version = ":" + version
	}
	param := product
	if v, ok := synonyms[product]; ok {
		param = v
	}
	param = strings.Replace(param, " ", "_", -1)
	return fmt.Sprintf("cpe:2.3:a:*:%s%s", param, version)
}
