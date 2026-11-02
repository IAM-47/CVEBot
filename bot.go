package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func getUpdates(uRl string, offset int64) ([]Update, error) {
	q := url.Values{}
	q.Add("offset", strconv.FormatInt(offset, 10))
	q.Add("timeout", "30")

	var urlErr *url.Error
	resp, err := http.Get(uRl + "?" + q.Encode())
	if err != nil {
		if errors.As(err, &urlErr) {
			return nil, fmt.Errorf("cant do request: %s %w", urlErr.Op, urlErr.Err)
		}
		return nil, fmt.Errorf("cant do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cant read: %w", err)
	}
	var res UpdatesResponse
	if err := json.Unmarshal(respBytes, &res); err != nil {
		return nil, fmt.Errorf("cant unmarshal: %w", err)
	}
	if !res.Ok {
		return nil, fmt.Errorf("status isn't OK, error_code: %d, description: %s", res.ErrCode, res.Description)
	}
	return res.Result, nil
}
func sendMessage(u string, chatID int64, msg string) error {
	q := url.Values{}
	q.Add("chat_id", strconv.FormatInt(chatID, 10))
	q.Add("text", msg)
	sendResponse, err := http.Post(u, "application/x-www-form-urlencoded", strings.NewReader(q.Encode()))
	var urlErr *url.Error
	if err != nil {
		if errors.As(err, &urlErr) {
			return fmt.Errorf("cant do request: %s %w", urlErr.Op, urlErr.Err)
		}
		return fmt.Errorf("cant do request: %w", err)
	}
	defer func() { _ = sendResponse.Body.Close() }()
	msgByte, err := io.ReadAll(sendResponse.Body)
	if err != nil {
		return fmt.Errorf("cant read: %w", err)
	}
	var res SendMessageResponse
	if err := json.Unmarshal(msgByte, &res); err != nil {
		return fmt.Errorf("cant unmarshal: %w", err)
	}
	if !res.Ok {
		return fmt.Errorf("status isn't OK, error_code: %d, description: %s", res.ErrCode, res.Description)
	}
	return nil
}

func handleText(text string) (msg string, req string, flag bool) {
	words := strings.Fields(text)
	switch {
	//
	case len(words) == 0:
		return HintMessage, "", false
	//
	case len(words) == 2 && len([]rune(words[1])) < 2 && words[0] == "/cve":
		return TooShortQuery, "", false
	//
	case words[0] == "/start":
		return "Hey! " + HintMessage, "", false
	//
	case strings.HasPrefix(words[0], "/") && words[0] != "/cve":
		return "Unknown command. " + HintMessage, "", false
	//
	case words[0] == "/cve" && len(words) > 1:
		return fmt.Sprintf("Trying to find cve for %s", strings.Join(words[1:], " ")), strings.Join(words[1:], " "), true
	//
	case len(words) == 1 && words[0] == "/cve":
		return HintMessage, "", false
	//
	default:
		return HintMessage, "", false
	}
}
func handleReq(req string) (msg string, err error) {
	vulns := make([]string, 0, 5)
	resp, err := NVDData(req)
	if err != nil {
		return BedNetworkMessage, fmt.Errorf("cant do request: %w", err)
	}
	if len(resp.Vulnerabilities) == 0 {
		return EmptyRespMessage, nil
	}
	for i := range resp.Vulnerabilities {
		vulns = append(vulns, formatCVE(resp.Vulnerabilities[i].Cve))

	}
	msg = strings.Join(vulns, "\n\n")
	return msg, nil
}
