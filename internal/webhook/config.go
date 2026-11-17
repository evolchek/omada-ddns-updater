package webhook

import (
	"errors"
	"regexp"
	"strings"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// NormalizeRecordName returns the same lowercase, non-trailing-dot form used
// in Route 53 IAM conditions. Wildcards and non-hostname labels are rejected.
func NormalizeRecordName(value string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(value, "."))
	labels := strings.Split(name, ".")
	if len(name) > 253 || len(labels) < 2 {
		return "", errors.New("invalid DNS record name")
	}
	for _, label := range labels {
		if len(label) > 63 || !dnsLabel.MatchString(label) {
			return "", errors.New("invalid DNS record name")
		}
	}
	return name, nil
}
