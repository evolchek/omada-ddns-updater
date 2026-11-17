package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"omada-ddns-updater/internal/webhook"
	"testing"
)

type mockAPI struct {
	expectedName      string
	records           []types.ResourceRecordSet
	readErr, writeErr error
	writes            int
	input             *route53.ChangeResourceRecordSetsInput
}

func (m *mockAPI) ListResourceRecordSets(_ context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	name := m.expectedName
	if name == "" {
		name = "vpn.example.com."
	}
	if aws.ToString(in.HostedZoneId) != "ZONE" || aws.ToString(in.StartRecordName) != name || in.StartRecordType != types.RRTypeA || aws.ToInt32(in.MaxItems) != 2 {
		return nil, errors.New("incorrect read input")
	}
	return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: m.records}, m.readErr
}

func TestConfiguredRecordName(t *testing.T) {
	r := record()
	r.Name = aws.String("gateway.example.net.")
	api := &mockAPI{expectedName: "gateway.example.net.", records: []types.ResourceRecordSet{r}}
	client := Client{API: api, RecordName: "Gateway.Example.NET."}
	if values, err := client.Read(context.Background(), "ZONE"); err != nil || len(values) != 1 {
		t.Fatal("configured record was not read")
	}
	if _, err := client.Upsert(context.Background(), "ZONE", "9.9.9.9"); err != nil {
		t.Fatal(err)
	}
	if aws.ToString(api.input.ChangeBatch.Changes[0].ResourceRecordSet.Name) != "gateway.example.net." {
		t.Fatal("wrong record was updated")
	}
	client.RecordName = "*.example.net"
	if _, err := client.Read(context.Background(), "ZONE"); err == nil {
		t.Fatal("invalid read target accepted")
	}
	if _, err := client.Upsert(context.Background(), "ZONE", "9.9.9.9"); err == nil || api.writes != 1 {
		t.Fatal("invalid write target accepted")
	}
}
func (m *mockAPI) ChangeResourceRecordSets(_ context.Context, in *route53.ChangeResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	m.writes++
	m.input = in
	return &route53.ChangeResourceRecordSetsOutput{ChangeInfo: &types.ChangeInfo{Id: aws.String("/change/fixture")}}, m.writeErr
}
func record() types.ResourceRecordSet {
	return types.ResourceRecordSet{Name: aws.String("vpn.example.com."), Type: types.RRTypeA, TTL: aws.Int64(300), ResourceRecords: []types.ResourceRecord{{Value: aws.String("9.9.9.9")}}}
}
func TestRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*types.ResourceRecordSet)
		unsafe bool
	}{
		{"ordinary", func(*types.ResourceRecordSet) {}, false},
		{"alias", func(r *types.ResourceRecordSet) {
			r.AliasTarget = &types.AliasTarget{DNSName: aws.String("alias.example")}
		}, true},
		{"weighted", func(r *types.ResourceRecordSet) { r.Weight = aws.Int64(0); r.SetIdentifier = aws.String("weighted") }, true},
		{"multivalue policy", func(r *types.ResourceRecordSet) { r.MultiValueAnswer = aws.Bool(false) }, true},
		{"health checked", func(r *types.ResourceRecordSet) { r.HealthCheckId = aws.String("health") }, true},
		{"failover", func(r *types.ResourceRecordSet) { r.Failover = types.ResourceRecordSetFailoverPrimary }, true},
		{"region", func(r *types.ResourceRecordSet) { r.Region = types.ResourceRecordSetRegionUsEast1 }, true},
		{"geolocation", func(r *types.ResourceRecordSet) { r.GeoLocation = &types.GeoLocation{CountryCode: aws.String("CA")} }, true},
		{"missing TTL", func(r *types.ResourceRecordSet) { r.TTL = nil }, true},
		{"empty values", func(r *types.ResourceRecordSet) { r.ResourceRecords = nil }, true},
		{"bad value", func(r *types.ResourceRecordSet) { r.ResourceRecords[0].Value = aws.String("bad") }, true},
		{"IPv6 value", func(r *types.ResourceRecordSet) { r.ResourceRecords[0].Value = aws.String("::1") }, true},
		{"CNAME", func(r *types.ResourceRecordSet) { r.Type = types.RRTypeCname }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := record()
			tc.mutate(&r)
			api := &mockAPI{records: []types.ResourceRecordSet{r}}
			got, err := (Client{RecordName: "vpn.example.com", API: api}).Read(context.Background(), "ZONE")
			if (err != nil) != tc.unsafe {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.unsafe && (len(got) != 1 || got[0] != "9.9.9.9") {
				t.Fatal("incorrect value")
			}
		})
	}
	for _, records := range [][]types.ResourceRecordSet{nil, {{Name: aws.String("other.example.com."), Type: types.RRTypeA}}, {{Name: aws.String("vpn.example.com."), Type: types.RRTypeAaaa}}} {
		got, err := (Client{RecordName: "vpn.example.com", API: &mockAPI{records: records}}).Read(context.Background(), "ZONE")
		if err != nil || len(got) != 0 {
			t.Fatal("missing record handling")
		}
	}
	r := record()
	r.ResourceRecords = append(r.ResourceRecords, types.ResourceRecord{Value: aws.String("8.8.8.8")})
	got, err := (Client{RecordName: "vpn.example.com", API: &mockAPI{records: []types.ResourceRecordSet{r}}}).Read(context.Background(), "ZONE")
	if err != nil || len(got) != 2 {
		t.Fatal("multiple values not read")
	}
	_, err = (Client{RecordName: "vpn.example.com", API: &mockAPI{records: []types.ResourceRecordSet{record(), record()}}}).Read(context.Background(), "ZONE")
	if err == nil {
		t.Fatal("multiple record sets accepted")
	}
	_, err = (Client{RecordName: "vpn.example.com", API: &mockAPI{readErr: errors.New("fixture")}}).Read(context.Background(), "ZONE")
	if err == nil {
		t.Fatal("read error lost")
	}
}
func TestUpsert(t *testing.T) {
	api := &mockAPI{}
	id, err := (Client{RecordName: "vpn.example.com", API: api}).Upsert(context.Background(), "ZONE", "9.9.9.9")
	if err != nil || id != "/change/fixture" {
		t.Fatal("update failed")
	}
	in := api.input
	if aws.ToString(in.HostedZoneId) != "ZONE" || len(in.ChangeBatch.Changes) != 1 {
		t.Fatal("incorrect scope")
	}
	change := in.ChangeBatch.Changes[0]
	r := change.ResourceRecordSet
	if change.Action != types.ChangeActionUpsert || aws.ToString(r.Name) != "vpn.example.com." || r.Type != types.RRTypeA || aws.ToInt64(r.TTL) != 60 || len(r.ResourceRecords) != 1 || aws.ToString(r.ResourceRecords[0].Value) != "9.9.9.9" {
		t.Fatal("incorrect UPSERT")
	}
	api.writeErr = errors.New("fixture")
	if _, err := (Client{RecordName: "vpn.example.com", API: api}).Upsert(context.Background(), "ZONE", "9.9.9.9"); err == nil {
		t.Fatal("write error lost")
	}
}
func TestHandlerKeepsMatchingTTL(t *testing.T) {
	for _, ttl := range []int64{60, 300} {
		r := record()
		r.TTL = aws.Int64(ttl)
		api := &mockAPI{records: []types.ResourceRecordSet{r}}
		raw, _ := json.Marshal(map[string]any{"headers": map[string]string{"access_token": "fixture"}, "body": `{"text":"IP-Address=9.9.9.9"}`, "requestContext": map[string]any{"http": map[string]string{"method": "POST", "sourceIp": "9.9.9.9"}}})
		res, _ := webhook.New(&bytes.Buffer{}, webhook.Config{RecordName: "vpn.example.com", Secret: "fixture", HostedZoneID: "ZONE"}, Client{RecordName: "vpn.example.com", API: api}).Handle(context.Background(), raw)
		if res.StatusCode != 200 || api.writes != 0 {
			t.Fatal("matching IP should not change TTL")
		}
	}
}
