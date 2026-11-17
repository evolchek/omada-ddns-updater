package webhook

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

const testIP = "9.9.9.9"
const testSecret = "disposable-test-secret"

type fakeDNS struct {
	records           []string
	reads, writes     int
	readErr, writeErr error
}

func (f *fakeDNS) Read(context.Context, string) ([]string, error) {
	f.reads++
	return f.records, f.readErr
}
func (f *fakeDNS) Upsert(_ context.Context, _ string, ip string) (string, error) {
	f.writes++
	if f.writeErr != nil {
		return "", f.writeErr
	}
	f.records = []string{ip}
	return "/change/fixture", nil
}
func event(body, source, token, method string, encoded bool) []byte {
	raw, _ := json.Marshal(map[string]any{"body": body, "isBase64Encoded": encoded, "headers": map[string]string{"AcCeSs_ToKeN": token, "authorization": "disposable-auth"}, "rawPath": "/diagnostic", "rawQueryString": "password=disposable-query", "cookies": []string{"disposable-cookie"}, "requestContext": map[string]any{"http": map[string]string{"method": method, "sourceIp": source}}})
	return raw
}
func payload(text any) string {
	b, _ := json.Marshal(map[string]any{"text": text, "shardSecret": "ignored-disposable", "unknown": true})
	return string(b)
}
func TestRequestDecisions(t *testing.T) {
	cases := []struct {
		name, body, source, token, method string
		encoded                           bool
		code, reads                       int
	}{
		{"single", payload("IP-Address=" + testIP), testIP, testSecret, "POST", false, 200, 1},
		{"batch dedup", payload([]string{"release IP-Address=" + testIP, "acquire IP-Address=" + testIP}), testIP, testSecret, "POST", false, 200, 1},
		{"different IPs", payload([]string{"IP-Address=8.8.8.8", "IP-Address=" + testIP}), testIP, testSecret, "POST", false, 200, 1},
		{"multiple markers", payload("IP-Address=8.8.8.8 IP-Address=" + testIP), testIP, testSecret, "POST", false, 200, 1},
		{"missing token", payload("IP-Address=" + testIP), testIP, "", "POST", false, 401, 0},
		{"wrong token", payload("IP-Address=" + testIP), testIP, "disposable-wrong", "POST", false, 401, 0},
		{"GET", `{}`, testIP, testSecret, "GET", false, 405, 0},
		{"missing text", `{"unknown":{"a":true}}`, testIP, testSecret, "POST", false, 200, 0},
		{"null text", payload(nil), testIP, testSecret, "POST", false, 200, 0},
		{"empty text", payload(""), testIP, testSecret, "POST", false, 200, 0},
		{"empty array", payload([]string{}), testIP, testSecret, "POST", false, 200, 0},
		{"unexpected type", payload(3), testIP, testSecret, "POST", false, 200, 0},
		{"mixed array", payload([]any{"IP-Address=" + testIP, 42}), testIP, testSecret, "POST", false, 200, 0},
		{"null array entry", payload([]any{nil}), testIP, testSecret, "POST", false, 200, 0},
		{"non IP", payload("ordinary message"), testIP, testSecret, "POST", false, 200, 0},
		{"missing address", payload("IP-Address="), testIP, testSecret, "POST", false, 200, 0},
		{"bad candidate", payload("IP-Address=999.1.2.3"), testIP, testSecret, "POST", false, 200, 0},
		{"private candidate", payload("IP-Address=192.168.1.1"), testIP, testSecret, "POST", false, 200, 0},
		{"mismatch", payload("IP-Address=8.8.8.8"), testIP, testSecret, "POST", false, 200, 0},
		{"missing source", payload("IP-Address=" + testIP), "", testSecret, "POST", false, 200, 0},
		{"bad source", payload("IP-Address=" + testIP), "bad", testSecret, "POST", false, 200, 0},
		{"IPv6 source", payload("IP-Address=" + testIP), "2001:4860:4860::8888", testSecret, "POST", false, 200, 0},
		{"private source", payload("IP-Address=10.0.0.1"), "10.0.0.1", testSecret, "POST", false, 200, 0},
		{"malformed", `{"secret":"disposable-malformed"`, testIP, testSecret, "POST", false, 400, 0},
		{"array payload", `[]`, testIP, testSecret, "POST", false, 400, 0},
		{"null payload", `null`, testIP, testSecret, "POST", false, 400, 0},
		{"base64", base64.StdEncoding.EncodeToString([]byte(payload("IP-Address=" + testIP))), testIP, testSecret, "POST", true, 200, 1},
		{"bad base64", "!", testIP, testSecret, "POST", true, 400, 0},
		{"oversized", strings.Repeat("x", MaxBodyBytes+1), testIP, testSecret, "POST", false, 413, 0},
		{"oversized encoded", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, MaxBodyBytes+1)), testIP, testSecret, "POST", true, 413, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			dns := &fakeDNS{}
			h := New(&logs, Config{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE", DryRun: true}, dns)
			res, err := h.Handle(context.Background(), event(tc.body, tc.source, tc.token, tc.method, tc.encoded))
			if err != nil || res.StatusCode != tc.code {
				t.Fatalf("got code %d err %v, want %d", res.StatusCode, err, tc.code)
			}
			if dns.reads != tc.reads || dns.writes != 0 {
				t.Fatalf("unexpected AWS calls: %d reads %d writes", dns.reads, dns.writes)
			}
			if !json.Valid([]byte(res.Body)) {
				t.Fatal("response is not JSON")
			}
			for _, secret := range []string{testSecret, "ignored-disposable", "disposable-auth", "disposable-cookie", "disposable-query", "disposable-malformed", "disposable-wrong"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatal("secret leaked")
				}
			}
		})
	}
}
func TestDNSDecisions(t *testing.T) {
	for _, tc := range []struct {
		name              string
		records           []string
		dry               bool
		readErr, writeErr error
		code, writes      int
		kind              string
	}{
		{"matches", []string{testIP}, false, nil, nil, 200, 0, "ip_unchanged"},
		{"differs", []string{"8.8.8.8"}, false, nil, nil, 200, 1, "ddns_updated"},
		{"missing", nil, false, nil, nil, 200, 1, "ddns_updated"},
		{"multiple", []string{testIP, "8.8.8.8"}, false, nil, nil, 200, 1, "ddns_updated"},
		{"dry run", nil, true, nil, nil, 200, 0, "ddns_dry_run"},
		{"read failure", nil, false, errors.New("disposable-error-secret"), nil, 500, 0, "read_failed"},
		{"write failure", nil, false, nil, errors.New("disposable-error-secret"), 500, 1, "write_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			dns := &fakeDNS{records: tc.records, readErr: tc.readErr, writeErr: tc.writeErr}
			h := New(&logs, Config{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE", DryRun: tc.dry}, dns)
			res, _ := h.Handle(context.Background(), event(payload("IP-Address="+testIP), testIP, testSecret, "POST", false))
			if res.StatusCode != tc.code || dns.writes != tc.writes || !strings.Contains(logs.String(), tc.kind) {
				t.Fatalf("wrong decision: status=%d writes=%d", res.StatusCode, dns.writes)
			}
			if strings.Contains(logs.String(), "disposable-error-secret") {
				t.Fatal("SDK error leaked")
			}
		})
	}
}
func TestDuplicateAndConfiguration(t *testing.T) {
	dns := &fakeDNS{}
	h := New(&bytes.Buffer{}, Config{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE"}, dns)
	raw := event(payload("IP-Address="+testIP), testIP, testSecret, "POST", false)
	for i := 0; i < 2; i++ {
		res, _ := h.Handle(context.Background(), raw)
		if res.StatusCode != 200 {
			t.Fatal("delivery failed")
		}
	}
	if dns.writes != 1 {
		t.Fatal("duplicate delivery caused extra write")
	}
	for _, cfg := range []Config{
		{RecordName: "vpn.example.com", HostedZoneID: "ZONE"},
		{RecordName: "vpn.example.com", Secret: testSecret},
		{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE", Invalid: true},
		{Secret: testSecret, HostedZoneID: "ZONE"},
	} {
		res, _ := New(&bytes.Buffer{}, cfg, dns).Handle(context.Background(), raw)
		if res.StatusCode != 500 {
			t.Fatal("configuration did not fail closed")
		}
	}
}
func TestPublicIPv4(t *testing.T) {
	for _, s := range []string{testIP, "8.8.8.8", "1.1.1.1"} {
		if !PublicIPv4(netip.MustParseAddr(s)) {
			t.Fatal("public rejected")
		}
	}
	for _, s := range []string{"0.0.0.0", "10.0.0.1", "100.64.1.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.168.0.1", "192.0.0.9", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.175.48.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::1", "::ffff:8.8.8.8", "2001:4860::1"} {
		if PublicIPv4(netip.MustParseAddr(s)) {
			t.Fatalf("special address accepted: %s", s)
		}
	}
	for _, p := range excluded {
		if PublicIPv4(p.Addr()) {
			t.Fatalf("excluded block accepted: %s", p)
		}
	}
}
func TestExtraction(t *testing.T) {
	for _, s := range []string{"IP-Address=8.8.8.8bad", "IP-Address=8.8.8.8:80", "IP-Address=::ffff:8.8.8.8", "IP-Address=999.8.8.8", "IP-Address=", "no marker"} {
		for _, a := range Extract(s) {
			if PublicIPv4(a) {
				t.Fatal("malformed candidate accepted")
			}
		}
	}
	if len(Extract("IP-Address=8.8.8.8, IP-Address=1.1.1.1)")) != 2 {
		t.Fatal("not all markers inspected")
	}
	for _, separator := range []string{",", ")", ";", " ", "\t", "\r", "\n", "\f"} {
		addresses := Extract("IP-Address=8.8.8.8" + separator + "IP-Address=1.1.1.1")
		if len(addresses) != 2 || addresses[0].String() != "8.8.8.8" || addresses[1].String() != "1.1.1.1" {
			t.Fatalf("incorrect extraction for separator %q", separator)
		}
	}
	addresses := Extract("IP-Address=badIP-Address=1.1.1.1")
	if len(addresses) != 1 || addresses[0].String() != "1.1.1.1" {
		t.Fatal("malformed token hid subsequent marker")
	}
}
func TestRecursiveRedaction(t *testing.T) {
	body := `{"text":"non-IP disposable-message","shardSecret":"disposable-shard","unknown":{"password":"disposable-password","innocent":"disposable-hidden","arr":[{"apiKey":"disposable-api"},"disposable-array"],"safe":true},"counter":4}`
	var logs bytes.Buffer
	res, _ := New(&logs, Config{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE", DryRun: true}, &fakeDNS{}).Handle(context.Background(), event(body, testIP, testSecret, "POST", false))
	if res.StatusCode != 200 {
		t.Fatal("unexpected status")
	}
	for _, secret := range []string{testSecret, "disposable-shard", "disposable-password", "disposable-api", "disposable-auth", "disposable-cookie", "disposable-query"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("secret leaked in diagnostic")
		}
	}
	decoder := json.NewDecoder(&logs)
	found := false
	for decoder.More() {
		var entry map[string]any
		if err := decoder.Decode(&entry); err != nil {
			t.Fatal(err)
		}
		if entry["type"] == "diagnostic" {
			found = true
			request := entry["request"].(map[string]any)
			b := request["body"].(map[string]any)
			if b["text"] != "non-IP disposable-message" || b["unknown"].(map[string]any)["innocent"] != "disposable-hidden" {
				t.Fatal("non-secret strings were redacted")
			}
			if b["counter"] != float64(4) {
				t.Fatal("safe data lost")
			}
			if b["unknown"].(map[string]any)["safe"] != true {
				t.Fatal("unknown structure lost")
			}
		}
	}
	if !found {
		t.Fatal("no diagnostic log")
	}
}

func TestBoundaryBodies(t *testing.T) {
	prefix := `{"text":"IP-Address=` + testIP + `","padding":"`
	body := prefix + strings.Repeat("x", MaxBodyBytes-len(prefix)-2) + `"}`
	if len(body) != MaxBodyBytes {
		t.Fatal("bad boundary fixture")
	}
	for _, encoded := range []bool{false, true} {
		input := body
		if encoded {
			input = base64.StdEncoding.EncodeToString([]byte(body))
		}
		dns := &fakeDNS{}
		res, _ := New(&bytes.Buffer{}, Config{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE", DryRun: true}, dns).Handle(context.Background(), event(input, testIP, testSecret, "POST", encoded))
		if res.StatusCode != 200 || dns.reads != 1 || dns.writes != 0 {
			t.Fatal("exact-limit body rejected")
		}
	}
}

func TestIgnoredTrustInputs(t *testing.T) {
	for _, shard := range []any{nil, "unrelated-disposable", map[string]any{"unexpected": true}, 42} {
		body, _ := json.Marshal(map[string]any{"text": "IP-Address=" + testIP, "shardSecret": shard})
		dns := &fakeDNS{}
		h := New(&bytes.Buffer{}, Config{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE", DryRun: true}, dns)
		res, _ := h.Handle(context.Background(), event(string(body), testIP, testSecret, "POST", false))
		if res.StatusCode != 200 || dns.reads != 1 {
			t.Fatal("shardSecret influenced processing")
		}
	}
	raw := event(payload("IP-Address="+testIP), "8.8.8.8", testSecret, "POST", false)
	var envelope map[string]any
	_ = json.Unmarshal(raw, &envelope)
	envelope["headers"].(map[string]any)["x-forwarded-for"] = testIP
	raw, _ = json.Marshal(envelope)
	dns := &fakeDNS{}
	res, _ := New(&bytes.Buffer{}, Config{RecordName: "vpn.example.com", Secret: testSecret, HostedZoneID: "ZONE", DryRun: true}, dns).Handle(context.Background(), raw)
	if res.StatusCode != 200 || dns.reads != 0 || dns.writes != 0 {
		t.Fatal("forwarded header trusted")
	}
}
