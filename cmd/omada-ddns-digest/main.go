package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"omada-ddns-updater/internal/digest"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	settings, initErr := digest.LoadConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "ca-central-1"
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithHTTPClient(&http.Client{Timeout: 15 * time.Second}), config.WithRetryMaxAttempts(3))
	cancel()
	if initErr == nil {
		initErr = err
	}
	handler := digest.Handler{Config: settings, Logs: cloudwatchlogs.NewFromConfig(cfg), SES: sesv2.NewFromConfig(cfg)}
	lambda.Start(func(ctx context.Context) error {
		err := initErr
		if err == nil {
			err = handler.Handle(ctx)
		}
		if err != nil {
			logger.Error("digest_failed", "error", err.Error())
		}
		return err
	})
}
