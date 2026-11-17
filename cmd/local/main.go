// Command local processes one simulated Lambda event from stdin.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"omada-ddns-updater/internal/webhook"
)

func main() {
	event, err := io.ReadAll(io.LimitReader(os.Stdin, 8*1024*1024+1))
	if err == nil && len(event) > 8*1024*1024 {
		err = fmt.Errorf("local event exceeds 8 MiB")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	response, err := webhook.New(os.Stdout, webhook.Config{Secret: "disposable-local-token", HostedZoneID: "LOCAL-ONLY", RecordName: "vpn.example.com", DryRun: true}, localDNS{}).Handle(context.Background(), event)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Keep the response separate from the diagnostic log on stdout.
	if err := json.NewEncoder(os.Stderr).Encode(response); err != nil {
		os.Exit(1)
	}
}

// The local command never loads AWS credentials or accesses the network.
type localDNS struct{}

func (localDNS) Read(context.Context, string) ([]string, error) { return []string{"1.1.1.1"}, nil }
func (localDNS) Upsert(context.Context, string, string) (string, error) {
	return "", fmt.Errorf("local updates disabled")
}
