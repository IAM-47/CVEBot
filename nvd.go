package main

import (
	"encoding/json"
	"fmt"
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
