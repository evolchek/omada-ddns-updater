package dns

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"omada-ddns-updater/internal/webhook"
)

type API interface {
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(context.Context, *route53.ChangeResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
}
type Client struct {
	API        API
	RecordName string
}

var ErrUnsafeRecord = errors.New("unsupported DNS record configuration")

func ordinary(record types.ResourceRecordSet) bool {
	// An allowlist fails closed if the SDK adds new routing/configuration fields.
	value := reflect.ValueOf(record)
	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		switch field.Name {
		case "Name", "Type", "TTL", "ResourceRecords":
			continue
		}
		if !value.Field(i).IsZero() {
			return false
		}
	}
	return record.TTL != nil && len(record.ResourceRecords) > 0
}
func (c Client) Read(ctx context.Context, zone string) ([]string, error) {
	recordName, err := webhook.NormalizeRecordName(c.RecordName)
	if err != nil {
		return nil, err
	}
	out, err := c.API.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zone), StartRecordName: aws.String(recordName + "."), StartRecordType: types.RRTypeA, MaxItems: aws.Int32(2),
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, ErrUnsafeRecord
	}
	var result []string
	found := false
	for _, r := range out.ResourceRecordSets {
		if !strings.EqualFold(strings.TrimSuffix(aws.ToString(r.Name), "."), recordName) {
			continue
		}
		if r.Type == types.RRTypeCname {
			return nil, ErrUnsafeRecord
		}
		if r.Type != types.RRTypeA {
			continue
		}
		if found || !ordinary(r) {
			return nil, ErrUnsafeRecord
		}
		found = true
		result, err = ipv4Values(r.ResourceRecords)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func ipv4Values(records []types.ResourceRecord) ([]string, error) {
	var result []string
	for _, record := range records {
		ip, err := netip.ParseAddr(aws.ToString(record.Value))
		if err != nil || !ip.Is4() {
			return nil, ErrUnsafeRecord
		}
		result = append(result, ip.String())
	}
	return result, nil
}

func (c Client) Upsert(ctx context.Context, zone, ip string) (string, error) {
	recordName, err := webhook.NormalizeRecordName(c.RecordName)
	if err != nil {
		return "", err
	}
	out, err := c.API.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zone), ChangeBatch: &types.ChangeBatch{Changes: []types.Change{{Action: types.ChangeActionUpsert, ResourceRecordSet: &types.ResourceRecordSet{
			Name: aws.String(recordName + "."), Type: types.RRTypeA, TTL: aws.Int64(60), ResourceRecords: []types.ResourceRecord{{Value: aws.String(ip)}},
		}}}},
	})
	if err != nil {
		return "", err
	}
	if out == nil || out.ChangeInfo == nil || out.ChangeInfo.Id == nil {
		return "", errors.New("missing change ID")
	}
	return *out.ChangeInfo.Id, nil
}
