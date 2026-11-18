package digest

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

func TestMatches(t *testing.T) {
	for _, tc := range []struct {
		message string
		want    bool
	}{
		{`{"level":"WARN","level_num":4}`, true}, {`{"level":"ERROR","level_num":8}`, true}, {`{"level":"FATAL","level_num":12}`, true}, {`{"level":"ERROR+4","level_num":12}`, true}, {`{"level":"INFO+1","level_num":1}`, true},
		{`{"level":"INFO","level_num":0}`, false}, {`{"level":"DEBUG","level_num":-4}`, false},
		{`{"level":"INFO","level_num":0,"type":"ddns_updated","change_id":"/change/123"}`, true},
		{`{"level":"INFO","level_num":0,"msg":"ddns_updated"}`, false}, {`{"level":"INFO","level_num":0,"type":"ddns_updated"}`, false},
		{`{"level":"INFO","level_num":0,"type":"ddns_dry_run"}`, false}, {`{"level":"INFO","level_num":0,"type":"ddns_skipped"}`, false},
		{`{"level":"INFO","level_num":0,"type":"route53_error"}`, false},
		{`START RequestId: abc`, false}, {`END RequestId: abc`, false}, {`REPORT RequestId: abc`, false}, {`{broken`, false}, {`null`, false}, {`[]`, false}, {`{"level":4}`, false},
		{`{"level":"ERROR"}`, false},
		{`{"level_num":1}`, true},
		{`{"level":"DEBUG","level_num":8}`, true},
		{`{"level":"ERROR","level_num":0}`, false},
		{`{"level_num":null}`, false},
		{`{"level_num":"8"}`, false},
		{`{"level_num":4.5}`, false},
		{`{"level_num":{}}`, false},
		{`{"level_num":999999999999999999999999}`, false},
		{`{"type":"ddns_updated","change_id":"legacy-success"}`, true},
	} {
		if got := Matches(tc.message); got != tc.want {
			t.Errorf("Matches(%s)=%v want %v", tc.message, got, tc.want)
		}
	}
}
func TestInterval(t *testing.T) {
	loc, err := time.LoadLocation("America/Toronto")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		now, date string
		hours     int
	}{{"2026-03-09T09:00:00-04:00", "2026-03-08", 23}, {"2026-11-02T09:00:00-05:00", "2026-11-01", 25}, {"2026-01-01T09:00:00-05:00", "2025-12-31", 24}} {
		now, _ := time.Parse(time.RFC3339, tc.now)
		start, end := Interval(now, loc)
		if start.Format("2006-01-02") != tc.date || end.Sub(start) != time.Duration(tc.hours)*time.Hour || start.Hour() != 0 || end.Hour() != 0 {
			t.Fatalf("bad interval %v %v", start, end)
		}
	}
}

type fakeLogs struct {
	pages  []*cloudwatchlogs.FilterLogEventsOutput
	inputs []cloudwatchlogs.FilterLogEventsInput
	err    error
}

func (f *fakeLogs) FilterLogEvents(_ context.Context, in *cloudwatchlogs.FilterLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error) {
	f.inputs = append(f.inputs, *in)
	if f.err != nil {
		return nil, f.err
	}
	if len(f.pages) == 0 {
		return nil, errors.New("unexpected page")
	}
	p := f.pages[0]
	f.pages = f.pages[1:]
	return p, nil
}

type fakeSES struct {
	calls int
	input *sesv2.SendEmailInput
	err   error
}

func (f *fakeSES) SendEmail(_ context.Context, in *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	f.calls++
	f.input = in
	return &sesv2.SendEmailOutput{}, f.err
}
func fixture(t *testing.T) (Handler, *fakeLogs, *fakeSES) {
	t.Helper()
	loc, e := time.LoadLocation("America/Toronto")
	if e != nil {
		t.Fatal(e)
	}
	logs := &fakeLogs{}
	ses := &fakeSES{}
	return Handler{Config: Config{"sender", "recipient", "group", loc}, Logs: logs, SES: ses, Now: func() time.Time { return time.Date(2026, 11, 18, 14, 0, 0, 0, time.UTC) }}, logs, ses
}
func event(at int64, msg string) logtypes.FilteredLogEvent {
	return logtypes.FilteredLogEvent{Timestamp: aws.Int64(at), Message: aws.String(msg)}
}
func TestPaginationOrderingAndDuplicates(t *testing.T) {
	h, logs, ses := fixture(t)
	start, end := Interval(h.Now(), h.Config.Location)
	at := start.UnixMilli()
	early := ` {"level":"WARN","level_num":4,"msg":"early"} `
	late := `{"level":"INFO","level_num":0,"type":"ddns_updated","change_id":"id"}`
	logs.pages = []*cloudwatchlogs.FilterLogEventsOutput{
		{Events: []logtypes.FilteredLogEvent{event(at+20, late)}, NextToken: aws.String("page2")},
		{NextToken: aws.String("page3")},
		{Events: []logtypes.FilteredLogEvent{event(at, early), event(at, early), event(end.UnixMilli(), early), event(at-1, early), event(at, `{"level":"INFO","level_num":0}`)}},
	}
	if err := h.Handle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(logs.inputs) != 3 || aws.ToString(logs.inputs[2].NextToken) != "page3" || *logs.inputs[0].StartTime != at || *logs.inputs[0].EndTime != end.UnixMilli() {
		t.Fatal("wrong pagination or bounds")
	}
	want := start.UTC().Format(time.RFC3339Nano) + " " + early + "\n"
	want += want
	want += start.Add(20*time.Millisecond).UTC().Format(time.RFC3339Nano) + " " + late + "\n"
	if ses.calls != 1 || *ses.input.Content.Simple.Body.Text.Data != want || *ses.input.Content.Simple.Subject.Data != "Omada DDNS Digest — 2026-11-17" {
		t.Fatalf("unexpected email: %+v", ses.input)
	}
}
func TestNoMatches(t *testing.T) {
	h, l, s := fixture(t)
	start, _ := Interval(h.Now(), h.Config.Location)
	l.pages = []*cloudwatchlogs.FilterLogEventsOutput{{Events: []logtypes.FilteredLogEvent{event(start.UnixMilli(), `{"level":"INFO","level_num":0}`)}}}
	if err := h.Handle(context.Background()); err != nil || s.calls != 0 {
		t.Fatalf("err %v calls %d", err, s.calls)
	}
}
func TestFailures(t *testing.T) {
	for _, kind := range []string{"logs", "ses", "token", "nil", "size"} {
		t.Run(kind, func(t *testing.T) {
			h, l, s := fixture(t)
			start, _ := Interval(h.Now(), h.Config.Location)
			msg := `{"level":"ERROR","level_num":8}`
			l.pages = []*cloudwatchlogs.FilterLogEventsOutput{{Events: []logtypes.FilteredLogEvent{event(start.UnixMilli(), msg)}}}
			switch kind {
			case "logs":
				l.err = errors.New("logs failure")
			case "ses":
				s.err = errors.New("SES failure")
			case "token":
				l.pages = []*cloudwatchlogs.FilterLogEventsOutput{{NextToken: aws.String("same")}, {NextToken: aws.String("same")}}
			case "nil":
				l.pages = []*cloudwatchlogs.FilterLogEventsOutput{nil}
			case "size":
				msg = `{"level":"ERROR","level_num":8,"msg":"` + strings.Repeat("x", 30_000_000) + `"}`
				l.pages[0].Events = []logtypes.FilteredLogEvent{event(start.UnixMilli(), msg)}
			}
			if err := h.Handle(context.Background()); err == nil {
				t.Fatal("expected failure")
			}
			if kind != "ses" && s.calls != 0 {
				t.Fatal("sent partial digest")
			}
		})
	}
}
func TestLoadConfig(t *testing.T) {
	for _, key := range []string{"DIGEST_SENDER", "DIGEST_RECIPIENT", "DIGEST_LOG_GROUP", "DIGEST_TIMEZONE"} {
		t.Setenv(key, "")
	}
	t.Setenv("DIGEST_SENDER", "sender@example.com")
	t.Setenv("DIGEST_RECIPIENT", "recipient@example.com")
	cfg, err := LoadConfig()
	if err != nil || cfg.Sender != "sender@example.com" || cfg.Recipient != "recipient@example.com" || cfg.LogGroup != "/aws/lambda/omada-ddns-updater" || cfg.Location.String() != "America/Toronto" {
		t.Fatalf("%+v %v", cfg, err)
	}
	t.Setenv("DIGEST_TIMEZONE", "bad/zone")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected invalid timezone error")
	}
}

func TestRequiredEmailConfig(t *testing.T) {
	for _, key := range []string{"DIGEST_SENDER", "DIGEST_RECIPIENT"} {
		for _, value := range []string{"", " \t\n"} {
			t.Run(key+"="+value, func(t *testing.T) {
				t.Setenv("DIGEST_SENDER", "sender@example.com")
				t.Setenv("DIGEST_RECIPIENT", "recipient@example.com")
				t.Setenv(key, value)
				if value == "" {
					if err := os.Unsetenv(key); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := LoadConfig(); err == nil || err.Error() != key+" is required" {
					t.Fatalf("expected missing %s error, got %v", key, err)
				}
			})
		}
	}
}

func TestMondayHeartbeat(t *testing.T) {
	for _, tc := range []struct {
		name, now      string
		match, failSES bool
		wantCalls      int
	}{
		{name: "Monday empty", now: "2026-11-23T14:00:00Z", wantCalls: 1},
		{name: "Monday nonmatching", now: "2026-11-23T14:00:00Z", wantCalls: 1},
		{name: "Monday with records", now: "2026-11-23T14:00:00Z", match: true, wantCalls: 1},
		{name: "Monday SES failure", now: "2026-11-23T14:00:00Z", failSES: true, wantCalls: 1},
		{name: "UTC Monday local Sunday", now: "2026-11-23T02:00:00Z"},
		{name: "UTC Tuesday local Monday", now: "2026-11-24T02:00:00Z", wantCalls: 1},
		{name: "Tuesday empty", now: "2026-11-24T14:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, logs, ses := fixture(t)
			now, err := time.Parse(time.RFC3339, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			h.Now = func() time.Time { return now }
			start, _ := Interval(now, h.Config.Location)
			page := &cloudwatchlogs.FilterLogEventsOutput{}
			if tc.name == "Monday nonmatching" {
				page.Events = []logtypes.FilteredLogEvent{event(start.UnixMilli(), `{"level":"INFO","level_num":0}`)}
			}
			if tc.match {
				page.Events = []logtypes.FilteredLogEvent{event(start.UnixMilli(), `{"level":"WARN","level_num":4}`)}
			}
			logs.pages = []*cloudwatchlogs.FilterLogEventsOutput{page}
			if tc.failSES {
				ses.err = errors.New("heartbeat delivery failed")
			}
			err = h.Handle(context.Background())
			if (err != nil) != tc.failSES {
				t.Fatalf("unexpected error: %v", err)
			}
			if ses.calls != tc.wantCalls {
				t.Fatalf("got %d sends, want %d", ses.calls, tc.wantCalls)
			}
			if ses.calls == 0 {
				return
			}
			if got := *ses.input.Content.Simple.Subject.Data; got != "Omada DDNS Digest — "+start.Format("2006-01-02") {
				t.Fatalf("wrong subject: %s", got)
			}
			body := *ses.input.Content.Simple.Body.Text.Data
			if tc.match {
				want := start.UTC().Format(time.RFC3339Nano) + " " + `{"level":"WARN","level_num":4}` + "\n"
				if body != want {
					t.Fatalf("unexpected records body: %q", body)
				}
			} else if body != "Weekly heartbeat: no matching log records to report.\n" {
				t.Fatalf("unexpected heartbeat: %q", body)
			}
		})
	}
}
