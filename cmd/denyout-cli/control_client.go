package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func askViaControl(base, host string) string {
	u := strings.TrimRight(base, "/") + "/ask?host=" + url.QueryEscape(host)
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(u)
	if err != nil {
		return "deny"
	}
	defer resp.Body.Close()
	var out struct {
		Action string `json:"action"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return "deny"
	}
	switch out.Action {
	case "once", "always", "deny":
		return out.Action
	default:
		return "deny"
	}
}

func postControlAlways(base, host string) {
	u := strings.TrimRight(base, "/") + "/always"
	body, _ := json.Marshal(map[string]string{"host": host})
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(u, "application/json", bytes.NewReader(body))
	if err == nil {
		resp.Body.Close()
	}
}

func postControlDenyEvent(base, host string, reasons []string, redactedURL string, doNotify bool) {
	u := strings.TrimRight(base, "/") + "/deny-event"
	body, _ := json.Marshal(map[string]any{
		"host":    host,
		"reasons": reasons,
		"url":     redactedURL,
		"notify":  doNotify,
	})
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(u, "application/json", bytes.NewReader(body))
	if err == nil {
		resp.Body.Close()
	}
}
