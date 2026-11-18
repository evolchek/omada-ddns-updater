// Package digest selects application records and sends a daily CloudWatch digest.
package digest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

type Config struct {
	Sender, Recipient, LogGroup string
	Location                    *time.Location
}

func LoadConfig() (Config, error) {
	sender := os.Getenv("DIGEST_SENDER")
	if strings.TrimSpace(sender) == "" {
		return Config{}, fmt.Errorf("DIGEST_SENDER is required")
	}
	recipient := os.Getenv("DIGEST_RECIPIENT")
	if strings.TrimSpace(recipient) == "" {
		return Config{}, fmt.Errorf("DIGEST_RECIPIENT is required")
	}
	env := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return fallback
	}
	loc, err := time.LoadLocation(env("DIGEST_TIMEZONE", "America/Toronto"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid DIGEST_TIMEZONE: %w", err)
	}
	return Config{sender, recipient, env("DIGEST_LOG_GROUP", "/aws/lambda/omada-ddns-updater"), loc}, nil
}

type LogsAPI interface {
	FilterLogEvents(context.Context, *cloudwatchlogs.FilterLogEventsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error)
}
type SESAPI interface {
	SendEmail(context.Context, *sesv2.SendEmailInput, ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
}
type Handler struct {
	Config Config
	Logs   LogsAPI
	SES    SESAPI
	Now    func() time.Time
}

// Interval uses calendar arithmetic rather than subtracting 24 hours.
func Interval(now time.Time, loc *time.Location) (time.Time, time.Time) {
	local := now.In(loc)
	end := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	return end.AddDate(0, 0, -1), end
}

func Matches(message string) bool {
	var record struct {
		LevelNum *int   `json:"level_num"`
		Type     string `json:"type"`
		ChangeID string `json:"change_id"`
	}
	if json.Unmarshal([]byte(message), &record) != nil {
		return false
	}
	if record.Type == "ddns_updated" && record.ChangeID != "" {
		return true
	}
	return record.LevelNum != nil && *record.LevelNum > int(slog.LevelInfo)
}

// A conservative bound on MIME base64 expansion, wrapping, and headers keeps
// the entire SES v2 message below 40 MB without ever truncating records.
const maxMessageBytes = 40_000_000

func messageFits(bodyBytes int) bool { return ((bodyBytes+2)/3*4)*78/76+16*1024 <= maxMessageBytes }

func (h Handler) Handle(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 110*time.Second)
	defer cancel()
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	start, end := Interval(now, h.Config.Location)
	records, err := h.collectRecords(ctx, start, end)
	if err != nil {
		return err
	}
	if len(records.events) == 0 && now.In(h.Config.Location).Weekday() != time.Monday {
		return nil
	}
	_, err = h.SES.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(h.Config.Sender), Destination: &types.Destination{ToAddresses: []string{h.Config.Recipient}},
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String("Omada DDNS Digest — " + start.Format("2006-01-02")), Charset: aws.String("UTF-8")},
			Body:    &types.Body{Text: &types.Content{Data: aws.String(records.body()), Charset: aws.String("UTF-8")}},
		}},
	})
	if err != nil {
		return fmt.Errorf("send SES digest: %w", err)
	}
	return nil
}

// logRecords retains every selected event and tracks the formatted body size.
type logRecords struct {
	events    []logtypes.FilteredLogEvent
	bodyBytes int
}

func (h Handler) collectRecords(ctx context.Context, start, end time.Time) (logRecords, error) {
	input := &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String(h.Config.LogGroup), StartTime: aws.Int64(start.UnixMilli()), EndTime: aws.Int64(end.UnixMilli())}
	var result logRecords
	seenTokens := map[string]bool{}
	for {
		page, err := h.Logs.FilterLogEvents(ctx, input)
		if err != nil {
			return logRecords{}, fmt.Errorf("read CloudWatch digest interval: %w", err)
		}
		if page == nil {
			return logRecords{}, fmt.Errorf("CloudWatch returned nil page")
		}
		if err := result.addPage(page.Events, start.UnixMilli(), end.UnixMilli()); err != nil {
			return logRecords{}, err
		}
		token := aws.ToString(page.NextToken)
		if token == "" {
			break
		}
		if seenTokens[token] {
			return logRecords{}, fmt.Errorf("CloudWatch pagination token repeated")
		}
		seenTokens[token] = true
		input.NextToken = aws.String(token)
	}
	return result, nil
}

func (r *logRecords) addPage(events []logtypes.FilteredLogEvent, start, end int64) error {
	for _, event := range events {
		if event.Timestamp == nil || *event.Timestamp < start || *event.Timestamp >= end {
			continue
		}
		if !Matches(aws.ToString(event.Message)) {
			continue
		}
		r.bodyBytes += len(time.UnixMilli(*event.Timestamp).UTC().Format(time.RFC3339Nano)) + 1 + len(aws.ToString(event.Message)) + 1
		if !messageFits(r.bodyBytes) {
			return fmt.Errorf("digest exceeds SES v2 40 MB message limit (including encoding allowance)")
		}
		r.events = append(r.events, event)
	}
	return nil
}

func (r logRecords) body() string {
	sort.SliceStable(r.events, func(i, j int) bool { return *r.events[i].Timestamp < *r.events[j].Timestamp })
	var body strings.Builder
	body.Grow(r.bodyBytes)
	if len(r.events) == 0 {
		body.WriteString("Weekly heartbeat: no matching log records to report.\n")
	}
	for _, record := range r.events {
		body.WriteString(time.UnixMilli(*record.Timestamp).UTC().Format(time.RFC3339Nano))
		body.WriteByte(' ')
		body.WriteString(aws.ToString(record.Message))
		body.WriteByte('\n')
	}
	return body.String()
}
