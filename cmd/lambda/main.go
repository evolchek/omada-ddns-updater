package main

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"omada-ddns-updater/internal/dns"
	"omada-ddns-updater/internal/webhook"
)

func main() {
	settings := webhook.Config{Secret: os.Getenv("OMADA_WEBHOOK_SECRET"), HostedZoneID: os.Getenv("ROUTE53_HOSTED_ZONE_ID"), DryRun: true}
	settings.LogLevel = os.Getenv("LOG_LEVEL")
	settings.RecordName = os.Getenv("ROUTE53_RECORD_NAME")
	if value := os.Getenv("DDNS_DRY_RUN"); value != "" {
		parsed, err := strconv.ParseBool(value)
		settings.Invalid = err != nil
		settings.DryRun = parsed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithHTTPClient(&http.Client{Timeout: 4 * time.Second}), config.WithRetryMaxAttempts(2), config.WithRegion("ca-central-1"))
	cancel()
	if err != nil {
		settings.Invalid = true
	}
	client := dns.Client{API: route53.NewFromConfig(cfg, func(o *route53.Options) { o.RetryMaxAttempts = 2; o.RetryMode = aws.RetryModeStandard }), RecordName: settings.RecordName}
	lambda.Start(webhook.New(os.Stdout, settings, client).Handle)
}
