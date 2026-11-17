package webhook

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
)

const redactedValue = "[REDACTED]"

func sensitive(key string) bool {
	key = strings.ToLower(key)
	key = strings.NewReplacer("-", "", "_", "", ".", "").Replace(key)
	for _, part := range []string{"secret", "token", "password", "passwd", "credential", "authorization", "cookie", "signature"} {
		if strings.Contains(key, part) {
			return true
		}
	}
	for _, suffix := range []string{"apikey", "privatekey", "accesskey", "accesskeyid", "sessionid"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	switch key {
	case "auth", "apikey", "key", "privatekey", "publickey", "accesskey", "accesskeyid", "session", "sessionid":
		return true
	default:
		return false
	}
}

var inlineSecret = regexp.MustCompile(`(?i)\b(access[_-]?token|shardsecret|api[_-]?key|password|passwd|client[_-]?secret|authorization)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;&]+)`)
var authCredential = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9+/=_\-.]+`)

func scrub(value string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, redactedValue)
		}
	}
	value = authCredential.ReplaceAllString(value, "$1 "+redactedValue)
	return inlineSecret.ReplaceAllString(value, "$1="+redactedValue)
}

// Collect sensitive values before redacting so copies in ordinary fields are
// also removed. Unknown non-sensitive fields otherwise remain intact.
func secretValues(value any) []string {
	var result []string
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if sensitive(key) {
				result = append(result, stringValues(item)...)
			} else {
				result = append(result, secretValues(item)...)
			}
		}
	case []any:
		for _, item := range v {
			result = append(result, secretValues(item)...)
		}
	}
	return result
}
func stringValues(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case map[string]any:
		var result []string
		for _, item := range v {
			result = append(result, stringValues(item)...)
		}
		return result
	case []any:
		var result []string
		for _, item := range v {
			result = append(result, stringValues(item)...)
		}
		return result
	default:
		return nil
	}
}
func sanitize(value any, secrets []string) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, item := range v {
			if sensitive(key) {
				out[key] = redactedValue
			} else {
				out[key] = sanitize(item, secrets)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = sanitize(item, secrets)
		}
		return out
	case string:
		return scrub(v, secrets)
	default:
		return v
	}
}

func decodeObject(raw []byte) (map[string]any, bool) {
	var value map[string]any
	if !json.Valid(raw) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil || value == nil {
		return nil, false
	}
	return value, true
}

func requestBody(event map[string]any) ([]byte, string) {
	body, ok := event["body"].(string)
	if !ok {
		return nil, "invalid_body"
	}
	encoded, _ := event["isBase64Encoded"].(bool)
	if !encoded {
		if len(body) > MaxBodyBytes {
			return nil, "body_too_large"
		}
		return []byte(body), ""
	}
	if len(body) > base64.StdEncoding.EncodedLen(MaxBodyBytes) {
		return nil, "body_too_large"
	}
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, "invalid_base64"
	}
	if len(decoded) > MaxBodyBytes {
		return nil, "body_too_large"
	}
	return decoded, ""
}

func (h *Handler) sanitizedRequest(raw []byte) map[string]any {
	event, ok := decodeObject(raw)
	if !ok {
		return map[string]any{"parse_error": "invalid_event", "event_bytes": len(raw)}
	}
	body, bodyError := requestBody(event)
	delete(event, "body")
	query, ok := event["rawQueryString"].(string)
	delete(event, "rawQueryString")
	if ok {
		addQuery(event, query)
	}
	if bodyError == "" {
		if payload, valid := decodeObject(body); valid {
			event["body"] = payload
		} else {
			bodyError = "malformed_json"
		}
	}
	if bodyError != "" {
		event["body_error"] = bodyError
	}
	secrets := append([]string{h.cfg.Secret}, secretValues(event)...)
	return sanitize(event, secrets).(map[string]any)
}

func addQuery(event map[string]any, query string) {
	values, err := url.ParseQuery(query)
	if err != nil {
		event["query_error"] = "invalid_query"
		return
	}
	parsed := map[string]any{}
	for key, items := range values {
		list := make([]any, len(items))
		for i, item := range items {
			list[i] = item
		}
		parsed[key] = list
	}
	event["query"] = parsed
}

func (h *Handler) debugRequest(raw []byte) {
	if h.logger.Enabled(context.Background(), slog.LevelDebug) {
		h.logAt(slog.LevelDebug, "webhook_request", "", map[string]any{"request": h.sanitizedRequest(raw)})
	}
}

func (h *Handler) diagnostic(raw, _ []byte, reason string) {
	if h.logger.Enabled(context.Background(), slog.LevelInfo) {
		h.log("diagnostic", reason, map[string]any{"request": h.sanitizedRequest(raw)})
	}
}
