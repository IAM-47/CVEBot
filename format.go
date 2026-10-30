package main

import (
	"fmt"
	"strconv"
	"strings"
)

func formatCVE(c CVE) string {
	score, version, type1, flag := c.BestScore()
	description, ok := c.EngDescription()
	if !ok {
		description = "This CVE doesn't have the English description"
	}
	dateFormat := strings.Split(c.Published, "T")
	publishedDate := dateFormat[0]
	description = truncate(description, 300)
	if !flag {
		return fmt.Sprintf("%s – This CVE doesn't have the base score\nPublished: %s\n%s", c.ID, publishedDate, description)
	}
	versionFloat, _ := strconv.ParseFloat(version, 64)
	if 10-versionFloat < 1e-7 {
		versionFloat = versionFloat / 10
	}
	return fmt.Sprintf(
		"%s – %.1f (CVSS %.1f, %s)\nPublished: %s\n%s", c.ID, score, versionFloat, type1, publishedDate, description)

}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		runes = runes[:n]
		return string(runes) + "..."
	}
	return string(runes)
}
