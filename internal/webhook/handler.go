package webhook

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

const MaxBodyBytes = 64 * 1024

type Config struct {
	Secret, HostedZoneID string
	RecordName           string
	DryRun               bool
	Invalid              bool
	LogLevel             string
}
type DNS interface {
	Read(context.Context, string) ([]string, error)
	Upsert(context.Context, string, string) (string, error)
}
type Response struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}
type Handler struct {
	cfg    Config
	dns    DNS
	logger *slog.Logger
}

func New(output io.Writer, cfg Config, dns DNS) *Handler {
	name, err := NormalizeRecordName(cfg.RecordName)
	if err != nil {
		cfg.Invalid = true
	}
	cfg.RecordName = name
	level := slog.LevelInfo
	if cfg.LogLevel != "" && level.UnmarshalText([]byte(cfg.LogLevel)) != nil {
		cfg.Invalid = true
		level = slog.LevelInfo
	}
	return &Handler{cfg: cfg, dns: dns, logger: slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: level}))}
}
func (h *Handler) log(kind, reason string, fields map[string]any) {
	level := slog.LevelInfo
	switch kind {
	case "configuration_error", "route53_error":
		level = slog.LevelError
	case "authentication_failed", "request_rejected":
		level = slog.LevelWarn
	}
	if reason == "invalid_source_ip" {
		level = slog.LevelWarn
	}
	h.logAt(level, kind, reason, fields)
}

func (h *Handler) logAt(level slog.Level, kind, reason string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["type"] = kind
	if reason != "" {
		fields["reason"] = reason
	}
	args := make([]any, 0, len(fields)*2)
	for key, value := range fields {
		args = append(args, key, value)
	}
	h.logger.Log(context.Background(), level, kind, args...)
}
func reply(code int, status string) (Response, error) {
	return Response{code, map[string]string{"content-type": "application/json"}, `{"status":"` + status + `"}`}, nil
}

type functionURLEvent struct {
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Base64  bool              `json:"isBase64Encoded"`
	Context struct {
		HTTP struct {
			Method string `json:"method"`
			Source string `json:"sourceIp"`
		} `json:"http"`
	} `json:"requestContext"`
}

func (h *Handler) Handle(ctx context.Context, raw json.RawMessage) (Response, error) {
	h.debugRequest(raw)
	var event functionURLEvent
	if json.Unmarshal(raw, &event) != nil {
		h.log("request_rejected", "invalid_event", nil)
		return reply(400, "invalid_event")
	}
	if code, status := h.validateEvent(event); code != 0 {
		return reply(code, status)
	}
	body, code, status := h.decodeBody(event)
	if code != 0 {
		return reply(code, status)
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil || payload == nil {
		h.log("request_rejected", "malformed_json", map[string]any{"body_bytes": len(body)})
		return reply(400, "invalid_json")
	}
	messages, valid := parseMessages(payload["text"])
	if !valid {
		h.diagnostic(raw, body, "unexpected_text")
		return reply(200, "ignored")
	}
	ip, accepted := h.selectCandidate(raw, body, messages, event.Context.HTTP.Source)
	if !accepted {
		return reply(200, "ignored")
	}
	return h.updateDNS(ctx, ip.String())
}

// validateEvent preserves the request checks' order: method, configuration,
// then authentication. A zero status code means processing can continue.
func (h *Handler) validateEvent(event functionURLEvent) (int, string) {
	if event.Context.HTTP.Method != "POST" {
		h.log("request_rejected", "method", nil)
		return 405, "method_not_allowed"
	}
	if h.cfg.Secret == "" || h.cfg.HostedZoneID == "" || h.cfg.Invalid || h.dns == nil {
		h.log("configuration_error", "invalid_configuration", nil)
		return 500, "configuration_error"
	}
	if !h.authenticated(event.Headers) {
		h.log("authentication_failed", "invalid_token", nil)
		return 401, "unauthorized"
	}
	return 0, ""
}

func (h *Handler) authenticated(headers map[string]string) bool {
	token := ""
	count := 0
	for k, v := range headers {
		if strings.EqualFold(k, "access_token") {
			token = v
			count++
		}
	}
	expected, received := sha256.Sum256([]byte(h.cfg.Secret)), sha256.Sum256([]byte(token))
	return count == 1 && token != "" && subtle.ConstantTimeCompare(expected[:], received[:]) == 1
}

func (h *Handler) decodeBody(event functionURLEvent) ([]byte, int, string) {
	body := []byte(event.Body)
	if event.Base64 {
		if len(body) > base64.StdEncoding.EncodedLen(MaxBodyBytes) {
			return nil, 413, "body_too_large"
		}
		var err error
		body, err = base64.StdEncoding.DecodeString(event.Body)
		if err != nil {
			h.log("request_rejected", "invalid_base64", nil)
			return nil, 400, "invalid_body"
		}
	}
	if len(body) > MaxBodyBytes {
		h.log("request_rejected", "body_too_large", nil)
		return nil, 413, "body_too_large"
	}
	return body, 0, ""
}

// parseMessages rejects the entire array if any entry is not a string.
func parseMessages(text json.RawMessage) ([]string, bool) {
	if len(text) == 0 || string(text) == "null" {
		return nil, true
	}
	var single string
	if json.Unmarshal(text, &single) == nil {
		return []string{single}, true
	}
	var elements []json.RawMessage
	if json.Unmarshal(text, &elements) != nil {
		return nil, false
	}
	var messages []string
	for _, element := range elements {
		var message string
		if string(element) == "null" || json.Unmarshal(element, &message) != nil {
			return nil, false
		}
		messages = append(messages, message)
	}
	return messages, true
}

func hasNonIPMessages(messages []string) bool {
	if len(messages) == 0 {
		return true
	}
	for _, m := range messages {
		if !strings.Contains(m, "IP-Address=") {
			return true
		}
	}
	return false
}

func (h *Handler) selectCandidate(raw, body []byte, messages []string, sourceIP string) (netip.Addr, bool) {
	diagnostic := hasNonIPMessages(messages)
	if diagnostic {
		h.diagnostic(raw, body, "non_ip_message")
	}
	source, err := netip.ParseAddr(sourceIP)
	if err != nil || !PublicIPv4(source) {
		if !diagnostic {
			h.diagnostic(raw, body, "invalid_source_ip")
		}
		h.log("ddns_skipped", "invalid_source_ip", map[string]any{
			"source_ip": scrub(sourceIP, []string{h.cfg.Secret}),
			"event_ips": eventIPs(messages),
		})
		return netip.Addr{}, false
	}
	if len(h.matchingCandidates(messages, source)) != 1 {
		if !diagnostic {
			h.diagnostic(raw, body, "no_actionable_ip")
		}
		h.log("ddns_skipped", "no_unique_candidate", nil)
		return netip.Addr{}, false
	}
	return source, true
}

func eventIPs(messages []string) []string {
	ips := []string{}
	seen := map[netip.Addr]bool{}
	for _, message := range messages {
		for _, ip := range Extract(message) {
			if !seen[ip] {
				ips = append(ips, ip.String())
				seen[ip] = true
			}
		}
	}
	return ips
}

func (h *Handler) matchingCandidates(messages []string, source netip.Addr) map[netip.Addr]bool {
	candidates := map[netip.Addr]bool{}
	for _, m := range messages {
		for _, ip := range Extract(m) {
			if !PublicIPv4(ip) {
				h.log("ddns_skipped", "non_public_candidate", nil)
				continue
			}
			if ip != source {
				h.log("ddns_skipped", "source_ip_mismatch", map[string]any{"candidate": ip.String(), "source_ip": source.String()})
				continue
			}
			candidates[ip] = true
		}
	}
	return candidates
}

func (h *Handler) updateDNS(ctx context.Context, ip string) (Response, error) {
	h.log("candidate_accepted", "", map[string]any{"ip": ip})
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	old, err := h.dns.Read(ctx, h.cfg.HostedZoneID)
	if err != nil {
		h.log("route53_error", "read_failed", nil)
		return reply(500, "dns_error")
	}
	if len(old) == 1 && old[0] == ip {
		h.log("ddns_skipped", "ip_unchanged", map[string]any{"ip": ip})
		return reply(200, "unchanged")
	}
	fields := map[string]any{"old_ips": old, "new_ip": ip, "record": h.cfg.RecordName}
	if h.cfg.DryRun {
		h.log("ddns_dry_run", "update_required", fields)
		return reply(200, "dry_run")
	}
	change, err := h.dns.Upsert(ctx, h.cfg.HostedZoneID, ip)
	if err != nil {
		h.log("route53_error", "write_failed", nil)
		return reply(500, "dns_error")
	}
	fields["change_id"] = change
	h.log("ddns_updated", "", fields)
	return reply(200, "updated")
}

var (
	ipMarkerPattern = regexp.MustCompile(`IP-Address=`)
	ipTokenPattern  = regexp.MustCompile(`^[^,);\s]+`)
)

func Extract(message string) []netip.Addr {
	var result []netip.Addr
	// Locate markers independently so a malformed token cannot consume a
	// subsequent marker. Validate whole tokens rather than IPv4 prefixes.
	for _, marker := range ipMarkerPattern.FindAllStringIndex(message, -1) {
		token := ipTokenPattern.FindString(message[marker[1]:])
		if ip, err := netip.ParseAddr(token); err == nil {
			result = append(result, ip)
		}
	}
	return result
}
