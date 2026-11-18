package webhook

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestInvalidSourceWarning(t *testing.T) {
	for _, source := range []string{"", "invalid-ip", "192.168.0.1", "2001:4860:4860::8888", testSecret} {
		t.Run(source, func(t *testing.T) {
			var logs bytes.Buffer
			dns := &fakeDNS{}
			h := New(&logs, Config{Secret: testSecret, HostedZoneID: "ZONE", RecordName: "vpn.example.com", LogLevel: "warn"}, dns)
			messages := []string{"IP-Address=" + testIP, "IP-Address=8.8.8.8 IP-Address=" + testIP}
			res, err := h.Handle(context.Background(), event(payload(messages), source, testSecret, "POST", false))
			if err != nil || res.StatusCode != 200 || dns.reads != 0 || dns.writes != 0 {
				t.Fatal("invalid source changed request handling")
			}
			entries := logEntries(t, logs.Bytes())
			if len(entries) != 1 {
				t.Fatal("expected one warning")
			}
			entry := entries[0]
			if entry["level"] != "WARN" || entry["type"] != "ddns_skipped" || entry["reason"] != "invalid_source_ip" {
				t.Fatal("missing invalid-source warning")
			}
			expectedSource := source
			if source == testSecret {
				expectedSource = redactedValue
			}
			if entry["source_ip"] != expectedSource || !reflect.DeepEqual(entry["event_ips"], []any{testIP, "8.8.8.8"}) {
				t.Fatal("warning does not contain source and deduplicated event IPs")
			}
			if strings.Contains(logs.String(), testSecret) {
				t.Fatal("secret leaked")
			}
		})
	}
}

func TestEventIPsWithoutAddresses(t *testing.T) {
	if got := eventIPs([]string{"no address", "IP-Address=invalid"}); got == nil || len(got) != 0 {
		t.Fatal("expected an empty array for messages without parsed addresses")
	}
}

func logEntries(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var entries []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	for decoder.More() {
		var entry map[string]any
		if err := decoder.Decode(&entry); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func TestDebugLogsEveryRequest(t *testing.T) {
	for _, tc := range []struct {
		name, method, token, body string
		encoded                   bool
		status                    int
	}{
		{"accepted", "POST", testSecret, payload("IP-Address=" + testIP), false, 200},
		{"unauthorized", "POST", "disposable-wrong", payload("IP-Address=" + testIP), false, 401},
		{"missing token", "POST", "", `{}`, false, 401},
		{"GET", "GET", testSecret, `{}`, false, 405},
		{"malformed", "POST", testSecret, `{"password":"never-print-this"`, false, 400},
		{"invalid base64", "POST", testSecret, "!never-print-this", true, 400},
		{"oversized", "POST", testSecret, strings.Repeat("x", MaxBodyBytes) + "never-print-this", false, 413},
		{"encoded", "POST", testSecret, base64.StdEncoding.EncodeToString([]byte(payload("IP-Address=" + testIP))), true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			h := New(&logs, Config{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE", DryRun: true, LogLevel: "debug"}, &fakeDNS{})
			res, _ := h.Handle(context.Background(), event(tc.body, testIP, tc.token, tc.method, tc.encoded))
			if res.StatusCode != tc.status {
				t.Fatalf("unexpected status %d", res.StatusCode)
			}
			entries := logEntries(t, logs.Bytes())
			if len(entries) == 0 || entries[0]["type"] != "webhook_request" || entries[0]["level"] != "DEBUG" {
				t.Fatal("missing debug request entry")
			}
			for _, secret := range []string{testSecret, "disposable-wrong", "disposable-auth", "disposable-cookie", "disposable-query", "ignored-disposable", "never-print-this"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatal("secret leaked")
				}
			}
			request := entries[0]["request"].(map[string]any)
			if request["rawPath"] != "/diagnostic" || request["requestContext"].(map[string]any)["http"].(map[string]any)["method"] != tc.method {
				t.Fatal("ordinary metadata lost")
			}
		})
	}
	var logs bytes.Buffer
	_, _ = New(&logs, Config{RecordName: "vpn.example.com", LogLevel: "debug"}, &fakeDNS{}).Handle(context.Background(), []byte(`{"password":"never-print-this"`))
	entries := logEntries(t, logs.Bytes())
	request := entries[0]["request"].(map[string]any)
	if request["parse_error"] != "invalid_event" || strings.Contains(logs.String(), "never-print-this") {
		t.Fatal("invalid event was logged unsafely")
	}
}

func TestLogLevelFiltering(t *testing.T) {
	for _, tc := range []struct {
		level string
		want  int
	}{{"", 1}, {"debug", 2}, {"info", 1}, {"warn", 1}, {"error", 0}} {
		t.Run(tc.level, func(t *testing.T) {
			var logs bytes.Buffer
			h := New(&logs, Config{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE", LogLevel: tc.level}, &fakeDNS{})
			_, _ = h.Handle(context.Background(), event(`{}`, testIP, "wrong", "POST", false))
			entries := logEntries(t, logs.Bytes())
			if len(entries) != tc.want {
				t.Fatalf("got %d logs, want %d", len(entries), tc.want)
			}
			if tc.want > 0 && entries[len(entries)-1]["level"] != "WARN" {
				t.Fatal("auth failure must be WARN")
			}
		})
	}
	var logs bytes.Buffer
	res, _ := New(&logs, Config{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE", LogLevel: "invalid"}, &fakeDNS{}).Handle(context.Background(), event(`{}`, testIP, testSecret, "POST", false))
	entries := logEntries(t, logs.Bytes())
	if res.StatusCode != 500 || entries[0]["level"] != "ERROR" {
		t.Fatal("invalid level must fail closed")
	}
}

func TestRequestPreservationAndSecretScrubbing(t *testing.T) {
	raw := event(`{"text":"WAN IP-Address=9.9.9.9 password=embedded-password","shardSecret":"body-secret","copy":"body-secret","nested":[{"api_key":"nested-secret","label":"visible"}],"unknown":"visible"}`, testIP, testSecret, "POST", false)
	var envelope map[string]any
	_ = json.Unmarshal(raw, &envelope)
	envelope["rawQueryString"] = "token=query-secret&view=full&view=compact"
	envelope["queryStringParameters"] = map[string]any{"token": "query-secret", "view": "full,compact"}
	envelope["headers"].(map[string]any)["content-type"] = "application/json"
	envelope["headers"].(map[string]any)["x-api-key"] = "header-secret"
	envelope["apiId"] = "visible-api-id"
	envelope["routeKey"] = "$default"
	raw, _ = json.Marshal(envelope)
	h := New(&bytes.Buffer{}, Config{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE", LogLevel: "debug"}, &fakeDNS{})
	clean := h.sanitizedRequest(raw)
	data, _ := json.Marshal(clean)
	for _, secret := range []string{testSecret, "body-secret", "nested-secret", "query-secret", "header-secret", "embedded-password", "disposable-auth", "disposable-cookie"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("secret leaked")
		}
	}
	headers := clean["headers"].(map[string]any)
	if headers["content-type"] != "application/json" || clean["apiId"] != "visible-api-id" || clean["routeKey"] != "$default" {
		t.Fatal("non-secret fields redacted")
	}
	query := clean["query"].(map[string]any)
	if len(query["view"].([]any)) != 2 || query["token"] != redactedValue {
		t.Fatal("query sanitization failed")
	}
	body := clean["body"].(map[string]any)
	if body["unknown"] != "visible" || body["copy"] != redactedValue || !strings.Contains(body["text"].(string), "IP-Address=9.9.9.9") {
		t.Fatal("body sanitization failed")
	}
}
