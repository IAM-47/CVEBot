package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
func NVDData(keyword string) (*NVDResponse, error) {
	q := url.Values{}
	q.Set("keywordSearch", keyword)
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
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()
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
func (c CVE) BestScore() (score float64, version string, type1 string, flag bool, err error) {
	suf, err := c.BestVersion()
	if err != nil {
		return score, "", "", false, fmt.Errorf("failed to determine NVD version: %w", err)
	}
	version = "cvssMetricV" + suf
	score = -1.0
	for j := range c.Metrics[version] {
		if c.Metrics[version][j].CData.BaseScore == nil {
			continue
		}
		if c.Metrics[version][j].Type == "Primary" {
			score, type1, flag, err = *c.Metrics[version][j].CData.BaseScore, c.Metrics[version][j].Type, true, nil
			break
		}
		if *c.Metrics[version][j].CData.BaseScore > score {
			score, type1, flag, err = *c.Metrics[version][j].CData.BaseScore, c.Metrics[version][j].Type, true, nil
		}
	}
	if flag == false {
		score = 0.0
	}
	return score, suf, type1, flag, nil
}
func (c CVE) BestVersion() (string, error) {
	mx := 0
	for i := range c.Metrics {
		if suf, ok := strings.CutPrefix(i, "cvssMetricV"); ok {
			ver, err := strconv.Atoi(suf)
			if err != nil {
				return "", fmt.Errorf("failed to parse cvss metric version: %w", err)
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
		return "", fmt.Errorf("cant find NVD metric version")
	}
	res := strconv.Itoa(mx)
	return res, nil
}
