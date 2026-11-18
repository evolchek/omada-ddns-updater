# Omada event-driven DDNS updater

Two Go AWS Lambda functions keep a Route 53 DNS record aligned with Omada WAN
address changes and report selected application logs by email:

- `omada-ddns-updater` receives authenticated Omada webhooks through a public
  HTTPS Function URL and updates a configured Route 53 A record.
- `omada-ddns-digest` reads the updater's CloudWatch logs and sends a conditional
  daily SES email, with a Monday heartbeat when no records match.

The functions use separate deployment stacks and IAM roles. The updater's
`DryRun` template parameter defaults to `true`; saved deployment configuration
can override it. Local tests and builds do not deploy resources or change DNS.

All hostnames and addresses in examples are generic fixtures. Set your deployment
target through the required `RecordName` parameter; no personal hostname is
hardcoded. Tests use `9.9.9.9` as a synthetic public IPv4 fixture and never contact
that address.

## Request processing

1. Only POST is accepted (405 otherwise).
2. The `access_token` header is compared with `OMADA_WEBHOOK_SECRET` using SHA-256
   and constant-time comparison of equal-length digests. Missing/incorrect tokens
   return 401. Missing/invalid application configuration fails closed with 500.
   `shardSecret` is ignored, regardless of presence, value, or type.
3. Decode Base64 if necessary; enforce a 64 KiB decoded body limit (413).
   Parse a JSON object (400 for malformed JSON, arrays, or null).
4. Accept `text` as a string or array of strings. Missing/null/empty/unexpected
   `text` is acknowledged with 200 and sanitized diagnostic logs. Mixed arrays
   are treated as unexpected, rather than partially processed.
5. Inspect every literal `IP-Address=` marker, including multiple markers within
   a message. Parse the complete following token with `net/netip`; no event
   description, interface name, site, controller, or timestamp matching occurs.
6. Exclude special-use/non-public IPv4 addresses. Require exact equality with
   `requestContext.http.sourceIp`; never use `x-forwarded-for` or a public-IP
   lookup service. Deduplicate candidates; proceed only for one accepted IP.
7. Read the configured A record (for example `vpn.example.com`). If it contains exactly the accepted
   IP, make no change, even if its TTL differs from 60. Missing records or ordinary
   multi-value/different-IP records require an UPSERT with one address and TTL 60.
8. In dry-run, log the proposed change and do not call the write API. In live mode,
   log the returned Route 53 change ID. Acceptance by Route 53 is not a claim that
   the change has propagated; no polling is introduced.

Aliases, CNAME collisions, health checks, routing policies, duplicate A record
sets, and unexpected record properties fail safely with 500. The adapter uses an
allowlist of ordinary record fields, including rejection of newly introduced SDK
fields if set. AWS failures return 500 for Omada to retry; no particular retry
schedule is assumed. The SDK makes at most two attempts, with a four-second HTTP
timeout and a twelve-second overall DNS-operation context. Lambda timeout is 20 s.
No raw SDK error messages are logged because they may contain request data.

## Public address policy and ordering limitations

`internal/webhook/ip.go` explicitly excludes IANA special-purpose blocks, even
special assignments marked globally reachable, and multicast/reserved space.
This conservative policy rejects documentation, benchmark, CGNAT, private,
loopback, link-local, IPv6, and IPv4-mapped IPv6 addresses. It is testable and
requires review if IANA assignments change. It does not prove current Internet
routability of an otherwise ordinary address.

The source check assumes the controller exits through the WAN being reported.
Multiple WANs, outbound proxies, VPN egress, or routing changes can violate this
assumption. It supplements authentication. It reduces stale-update risk but
does not prove the WAN address is still current when a delayed request is handled.
Reserved concurrency 1 serializes this Lambda's invocations, but provides no
durable event ordering or atomic read/write transaction. External DNS writers and
Route 53 visibility delays remain possible races. No persistent storage is added.

## Logging and secrets

Operational logs contain fixed decision
reasons, validated addresses, old/new records, and change IDs. Non-IP messages
produce a sanitized request containing the request/event structure, body,
headers, query parameters, context, and unknown fields where safe.

Redaction targets secrets: token, secret, authorization, cookie, password,
credential, signature, API-key and session fields are redacted recursively.
Ordinary strings, message text, paths, request context, non-sensitive headers,
and unknown fields remain visible. Known secret values are also scrubbed from
other strings, along with recognizable inline credentials. Arbitrary unlabeled
secrets cannot be reliably detected; use credential field names for credentials.
Raw query strings are replaced by parsed, sanitized parameters; Base64 bodies
are decoded and logged as sanitized JSON. Malformed or oversized bodies produce
metadata and a fixed error reason, never raw body contents. Logs remain subject
to service limits and seven-day retention.

`LOG_LEVEL` supports `debug`, `info` (default), `warn`, and `error`. JSON entries
include `time`, `level`, `level_num`, `msg`, `type`, and operational fields.
`level_num` uses Go slog severity values: DEBUG = -4, INFO = 0, WARN = 4,
ERROR = 8, with custom higher levels retaining their numeric values. Normal decisions
and unexpected-payload diagnostics use info; request/authentication rejections
use warn; configuration and Route 53 errors use error. At debug level, every
invocation additionally emits a `webhook_request` entry with sanitized request
data, including requests rejected for method, authentication, or body errors.
Invalid invocation JSON produces only parsing metadata. Invalid log-level
configuration fails closed.

Set the SAM `LogLevel` parameter to `debug` to enable request logging. In
`samconfig.toml`, set `LogLevel = "debug"` in the saved parameter overrides table,
preserving the hosted zone, secret ARN, and current `DryRun` setting. Then run
`make deploy` and review the change set. Set it back to `LogLevel = "info"` to
disable debug request entries. This changes logging only; it does not change
the saved live/dry-run mode.

Store the webhook token in an AWS Secrets Manager secret in ca-central-1,
as a JSON key named `token`. Create/configure it through the AWS Console using a
strong random value; do not paste it into shell commands or this repository.
Configure Omada with the same value. Rotate the token if it is exposed.

CloudFormation resolves a Secrets Manager dynamic reference into the Lambda
environment. Only the secret ARN is a deployment parameter, not its value. No
secret is output. The deployer/CloudFormation execution identity needs
`secretsmanager:GetSecretValue` (and `kms:Decrypt` if a customer-managed KMS key
requires it). The Lambda execution role has no Secrets Manager permissions.
Anyone permitted to read Lambda environment configuration can still access the
resolved secret; limit that access. Secret changes alone do not refresh Lambda's
environment: change the reference ARN to a newly rotated secret and redeploy, or
perform a reviewed function configuration update. Changing the ARN is the
recommended reproducible rotation procedure here. Secrets Manager incurs its
own storage/API charges; this stack does not create or delete the secret.

## Project and local checks

- `cmd/lambda`: environment configuration and official AWS SDK v2 adapter wiring.
- `internal/webhook`: authentication, parsing, candidate selection, redaction.
- `internal/dns`: SDK adapter with safe Route 53 reads/UPSERTs and mocked tests.
- `cmd/omada-ddns-digest`: digest Lambda configuration and AWS client wiring.
- `internal/digest`: log filtering, pagination, reporting intervals, and email delivery.
- `template.yaml`: updater function, Function URL, log group, and IAM role.
- `digest-template.yaml`: digest function, log group, IAM roles, and schedule.
- `cmd/local`: processes stdin using a fake DNS client; no AWS credentials/network.
- `examples/function-url-event.json`: disposable authenticated local fixture.

Requirements: supported Go 1.27, make, zip/unzip, AWS CLI v2, current SAM CLI.
Production dependencies are the official AWS Lambda Go library and AWS SDK v2;
their transitive dependencies are pinned in go.mod/go.sum.

```sh
make test
go vet ./...
make package package-digest
make local
file build/bootstrap build/digest/bootstrap
unzip -l build/function.zip
unzip -l build/digest/function.zip
```

The local fixture uses fixed `disposable-local-token` and a fake current DNS value.
It logs a proposed change but cannot write DNS. Stdout carries logs, stderr carries
the response. `make package` cross-compiles a static Linux ARM64 `bootstrap`, marks
it executable, and puts it at the ZIP root. Artifacts/caches are ignored by Git.

## Infrastructure and IAM review

The updater stack creates the function, public Function URL, seven-day log group,
and execution role. The hosted zone and webhook secret are supplied separately.
Review deployment change sets before execution.

| Setting | Updater configuration |
| --- | --- |
| Function | `omada-ddns-updater`, ARM64, `provided.al2023`, 128 MB, outside VPC |
| Timeout / concurrency | 20 seconds / reserved concurrency 1 |
| Function URL | Public HTTPS URL, AWS auth NONE; application header auth |
| Logs | `/aws/lambda/omada-ddns-updater`, seven-day retention |
| Secret | `OMADA_WEBHOOK_SECRET`, resolved from external Secrets Manager secret |
| Hosted zone | `ROUTE53_HOSTED_ZONE_ID`, required `HostedZoneId` parameter |
| DNS record | `ROUTE53_RECORD_NAME`, required `RecordName` parameter |
| Dry-run | `DDNS_DRY_RUN`, parameter `DryRun`, default `true` |
| Logging | `LOG_LEVEL`, parameter `LogLevel`, default `info` |

The execution role can write to the updater log group. Route 53 permissions:

- `ListResourceRecordSets` scoped to the supplied hosted zone ARN. AWS does not
  support restricting this list permission to a single record name.
- `ChangeResourceRecordSets` scoped to the same zone, with
  `ForAllValues:StringEquals` conditions restricting normalized names to
  the configured `RecordName`, types to `A`, and actions to `UPSERT`.

`RecordName` must be a lowercase hostname without a trailing dot, for example
`vpn.example.com`. IAM and runtime configuration use the same parameter. There
is no default target; missing or invalid runtime names fail closed. Set the
required updater parameters in the local, ignored `samconfig.toml`:

```toml
[default.deploy.parameters.parameter_overrides]
RecordName = "vpn.example.com"
HostedZoneId = "YOUR_VERIFIED_ZONE_ID"
WebhookSecretArn = "YOUR_WEBHOOK_SECRET_ARN"
DryRun = "true"
LogLevel = "info"
```

Preserve the intended target and live/dry-run setting when updating a deployment.

The updater role has no wildcard Route 53 actions or zone creation/deletion
permissions. Write IAM permission exists in dry-run; code suppresses
write calls. Keep the template parameter explicitly true on every diagnostic
deployment, including updates to an existing stack.

## Deployment plan — requires explicit approval

Do not execute deployment or a live-mode change until approved. Use your existing
IAM-user AWS CLI profile, not root access keys:

```sh
export AWS_PROFILE=YOUR_EXISTING_PROFILE
export AWS_REGION=ca-central-1
aws sts get-caller-identity
```

First verify your hosted zone in Route 53 Console (for example `example.com`),
its **public hosted zone** status, intended zone ID, and target A record (for
example `vpn.example.com`). Do not guess the
ID or choose a private/duplicate zone. For the first deployment, set these
nonsecret identifiers once; SAM will save them in the project configuration:

```sh
export HOSTED_ZONE_ID=YOUR_VERIFIED_ZONE_ID
export RECORD_NAME=YOUR_TARGET_FQDN
export WEBHOOK_SECRET_ARN=YOUR_WEBHOOK_SECRET_ARN

aws route53 get-hosted-zone --id "$HOSTED_ZONE_ID" \
  --query '{Name:HostedZone.Name,Private:VPCs,Config:HostedZone.Config}'
aws route53 list-resource-record-sets --hosted-zone-id "$HOSTED_ZONE_ID" \
  --query "ResourceRecordSets[?Name == '${RECORD_NAME}.']"
```

These are read-only. Confirm the zone has `PrivateZone: false` and the target
record configuration is supported. Deployment credentials need the CloudFormation,
S3 artifact, Lambda, IAM role/policy, PassRole, logging, and secret-resolution permissions required
by the template. The deployment identity may also need Route 53
read permissions for these manual verification commands. Do not broaden the
Lambda runtime role to solve deployment-user permission errors.

Build and validate:

```sh
make test
go vet ./...
make package
sam validate --lint --template-file template.yaml --region ca-central-1
```

For the first deployment with saved configuration, run:

```sh
sam deploy --template-file template.yaml \
  --stack-name omada-ddns-updater --region ca-central-1 \
  --resolve-s3 --capabilities CAPABILITY_IAM \
  --parameter-overrides HostedZoneId="$HOSTED_ZONE_ID" \
    RecordName="$RECORD_NAME" WebhookSecretArn="$WEBHOOK_SECRET_ARN" DryRun=true \
  --confirm-changeset --no-fail-on-empty-changeset \
  --save-params
```

SAM displays a change set and asks for confirmation before executing it. For updates, inspect any proposed replacement of
`DiagnosticFunction` or `FunctionUrl`, since replacing the URL affects the
Omada webhook configuration. After review and approval, confirm deployment. `--resolve-s3` uses SAM's artifact bucket and may create its
supporting stack if absent.

`--save-params` saves the deployment settings, hosted zone ID, record name, secret ARN, and
`DryRun=true` in project-local `samconfig.toml`. It stores **only the secret ARN,
not the token value**. The configuration file is already in `.gitignore`; do not
add credentials or the token to it. Inspect its `[default.deploy.parameters]`
section after the first deployment and confirm the parameter overrides include
`DryRun=true` and change-set confirmation remains enabled.

For later deployments from this directory, you no longer need to export
`HOSTED_ZONE_ID`, `RECORD_NAME`, or `WEBHOOK_SECRET_ARN`:

```sh
make test
go vet ./...
make package
sam validate --lint --template-file template.yaml --region ca-central-1
sam deploy
```

SAM reads the saved settings and prompts for change-set confirmation. Continue
using the intended AWS CLI profile; the configuration does not replace AWS
authentication. Command-line options override saved settings. To change the
zone or secret ARN, repeat the full first-deployment command with all intended
parameter values and `--save-params`.

For a separate review without executing the change set, use the saved config:

```sh
sam deploy --no-execute-changeset
```

Review CloudFormation → stack → Change sets, then execute the approved change
set in the Console or with its exact ARN:

```sh
aws cloudformation execute-change-set --change-set-name YOUR_CHANGE_SET_ARN \
  --region ca-central-1
aws cloudformation wait stack-update-complete \
  --stack-name omada-ddns-updater --region ca-central-1
```

Do not save `--no-execute-changeset` as the normal deployment setting unless you
intend every future deployment to stop at change-set creation.

For subsequent deployments, `make deploy` runs the tests, rebuilds the package,
and invokes SAM using the saved configuration with change-set confirmation
enabled. It does not require `HOSTED_ZONE_ID`, `RECORD_NAME`, or `WEBHOOK_SECRET_ARN` environment
variables and does not override the saved `DryRun` value:

```sh
make deploy
```

## Verify the dry-run deployment

Retrieve the deployed Function URL:

```sh
FUNCTION_URL=$(aws cloudformation describe-stacks \
  --stack-name omada-ddns-updater --region ca-central-1 \
  --query 'Stacks[0].Outputs[?OutputKey==`FunctionUrl`].OutputValue' --output text)

# GET is unsupported: expect 405.
curl -i "$FUNCTION_URL"
# Missing auth: expect 401.
curl -i "$FUNCTION_URL" -H 'Content-Type: application/json' --data '{}'
# Incorrect disposable auth: expect 401.
curl -i "$FUNCTION_URL" -H 'access_token: disposable-wrong-token' \
  -H 'Content-Type: application/json' --data '{}'
make logs
```

For valid-auth testing, trigger an Omada webhook with the rotated token configured
there. Do not put the real token into curl arguments or shell history. Confirm a
valid request returns 200, then capture a real DHCP event. Check `candidate_accepted`
and either `ip_unchanged` or `ddns_dry_run`. If the IP already matches, no proposed
change is expected. Compare the candidate/source IP with the actual WAN and DNS
record; verify no write occurred. The source check means a test from a different
network will intentionally skip an Omada address.

**Stop for explicit approval before changing `DryRun` to `false`.** A later
live-mode rollout must preserve the same zone/secret parameters, review its change
set, and only then set `DryRun=false`. During diagnostics, keep `DryRun=true` in
the saved parameter overrides. After an approved mode change, deliberately save
the intended mode for future deployments; the template default does not override
a saved parameter value. `make deploy` preserves that saved mode.

## Disable or remove

To stop invocations while retaining resources/logs (creates deliberate stack
configuration drift):

```sh
aws lambda put-function-concurrency --function-name omada-ddns-updater \
  --reserved-concurrent-executions 0 --region ca-central-1
```

To remove the endpoint only (also creates drift):

```sh
aws lambda delete-function-url-config --function-name omada-ddns-updater \
  --region ca-central-1
```

For full stack teardown, including diagnostic logs:

```sh
sam delete --stack-name omada-ddns-updater --region ca-central-1
```

The external secret and existing Route 53 record are not stack resources and
remain. SAM's shared artifact bucket/supporting stack may remain. Review shared
resources separately before deleting them. Reconcile any deliberate drift before
subsequent stack updates.

## References

- [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
- [Route 53 IAM conditions](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/specifying-conditions-route53.html)
- [Secrets Manager dynamic references](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references-secretsmanager.html)
- [Lambda environment variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html)

## Daily CloudWatch email digest

The independent `cmd/omada-ddns-digest` Lambda reads the preceding calendar day
in the configured timezone (default `America/Toronto`) from
`/aws/lambda/omada-ddns-updater`. It selects JSON
application records whose integer `level_num` is greater than 0 (INFO),
including WARN = 4, ERROR = 8, and custom higher severities, plus successful updates with
`type: "ddns_updated"` and a nonempty `change_id`. The digest uses only `level_num` for severity selection, not the text `level`.
Missing, null, or malformed numeric levels do not qualify by severity. Deploy
the updated updater before the digest; older records without `level_num` will
not qualify by severity, but successful update events still qualify.
The updater emits that event only after Route 53 accepts an UPSERT; this does not assert that the
change has reached INSYNC. Dry runs, unchanged IPs, diagnostics, platform
START/END/REPORT lines, and malformed/non-JSON entries are excluded unless an
application record independently meets the severity rule.

When records match, the email body consists solely of those records, each preceded by its
CloudWatch timestamp in UTC RFC3339 format with millisecond precision when
present. Original message content and duplicate records are preserved, sorted
by CloudWatch timestamp. Equal timestamps retain retrieval order. Empty days
produce no email except on Monday runs (in the configured reporting timezone),
which send a weekly heartbeat with the body
`Weekly heartbeat: no matching log records to report.` Monday still reports
only the preceding calendar day (Sunday), not the whole week. The subject date is the reporting day's local date:
`Omada DDNS Digest — YYYY-MM-DD`.

The interval is computed from the actual invocation time, from yesterday's local
midnight inclusive to today's local midnight exclusive. Calendar arithmetic and
embedded timezone data handle 23-hour and 25-hour days. The event payload is
ignored: `{}` is sufficient for scheduled or manual invocation. There is no
persistent cursor or delivery state. Repeated invocations can send duplicate
emails; delayed invocations use the day preceding their actual invocation.
CloudWatch records arriving after a run will not be recovered automatically.

### Digest configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `AWS_REGION` | `ca-central-1` outside Lambda | SDK region; Lambda supplies this automatically. Deploy in the same region as the updater. |
| `DIGEST_SENDER` | None; required | SES From address |
| `DIGEST_RECIPIENT` | None; required | Single email recipient |
| `DIGEST_LOG_GROUP` | `/aws/lambda/omada-ddns-updater` | Source log group |
| `DIGEST_TIMEZONE` | `America/Toronto` | Reporting calendar timezone |

The template requires a `SesIdentity` parameter (with no template default) for the
verified SES domain or email identity name, not its ARN. Override it at deployment
with `--parameter-overrides SesIdentity=example.com`. The IAM identity ARN uses
the stack's account and region. This parameter changes the permitted SES identity;
the sender address must still belong to that identity.

The `DigestSender` and `DigestRecipient` parameters also have no template defaults.
Configure the `digest` environment in your local, ignored `samconfig.toml` with
your verified identity, sender, and recipient. For example:

```toml
[digest.deploy.parameters.parameter_overrides]
SesIdentity = "example.com"
DigestSender = "omada@example.com"
DigestRecipient = "admin@example.com"
```

Each address parameter sets both
the Lambda environment variable and its IAM address restriction, keeping them
in sync. For example:

```sh
--parameter-overrides SesIdentity=example.com DigestSender=omada@example.com DigestRecipient=admin@example.com
```

If the SES sender identity has a default configuration set, add
`SesConfigurationSet = "YOUR_CONFIGURATION_SET"` to the same parameter overrides
table. This optional parameter defaults to an empty string and grants
`ses:SendEmail` on that exact configuration set in addition to the identities.
It does not create or attach a configuration set: SES automatically applies the
identity's existing default. Omitting this permission when a default is attached
can cause `AccessDeniedException` naming the configuration-set ARN. The sender
and recipient address conditions still apply to all allowed SES resources.

The template explicitly sets the four `DIGEST_*` values. Use the sender and
recipient parameters to change those addresses. If overriding the source log
group, also adjust its ARN in the IAM policy. The `DigestTimezone` parameter
(default `America/Toronto`) sets both `DIGEST_TIMEZONE` and the schedule timezone,
keeping the reporting calendar and daily 9 AM invocation in sync. Override it
with, for example, `--parameter-overrides DigestTimezone=America/Vancouver`.
The `DigestScheduleExpression` parameter defaults to `cron(0 9 * * ? *)`.
To run daily at 10 AM in the configured timezone, use
`--parameter-overrides 'DigestScheduleExpression=cron(0 10 * * ? *)'`.
Quote the complete parameter assignment so the shell preserves spaces and
wildcards. Each invocation still reports only the preceding calendar day;
changing the schedule does not change that reporting interval.
No SES credentials or SMTP
configuration are needed: the SDK uses the Lambda execution role.

AWS configuration loading has a 5-second deadline, HTTP requests have a
15-second timeout, SDK calls have at most three attempts, and the complete
handler has a 110-second deadline inside a 120-second Lambda. CloudWatch or SES
errors, invalid timezone, repeated pagination tokens, and oversized digests
fail the invocation and emit `digest_failed` to its own log group. The code
checks a conservative MIME/base64 expansion allowance plus 16 KiB of headers
against the SES v2 40 MB limit; it can reject a near-limit message early and
never truncates a digest. SES acceptance does not guarantee inbox delivery.

### Build and deploy the digest separately

Local verification and packaging (no AWS changes):

```sh
go test -race ./...
make build build-digest
make package-digest
```

`build/digest/function.zip` contains the Linux arm64 `bootstrap`. The
updater build output and `template.yaml` are independent of the digest stack.
Before deploying, configure the `digest` environment in `samconfig.toml` in
addition to the required SES parameter table shown above:

```toml
[digest.global.parameters]
region = "ca-central-1" # Use the same region as the updater.

[digest.deploy.parameters]
template_file = "digest-template.yaml"
stack_name = "omada-ddns-digest"
resolve_s3 = true
capabilities = ["CAPABILITY_IAM"]
confirm_changeset = true
fail_on_empty_changeset = false
```

Optional values such as `DigestTimezone` and `DigestScheduleExpression` belong
in `[digest.deploy.parameters.parameter_overrides]` alongside the SES values.
The default schedule runs at 9 AM in the configured timezone.

After obtaining explicit approval to create AWS resources, deploy using:

```sh
make deploy-digest
```

This target runs tests, packages the digest, and invokes `sam deploy --config-env digest`
with changeset confirmation. The `digest` configuration selects `digest-template.yaml`, the separate
`omada-ddns-digest` stack, and the required SES parameter values. The updater
continues to use the `default` configuration. `digest-template.yaml` provides the complete
least-privilege execution policy: `logs:FilterLogEvents` only on the updater
log group, `ses:SendEmail` only for the configured sender identity and exact
recipient identity (needed when SES authorizes a verified sandbox recipient),
with conditions restricting the From and recipient addresses, and stream creation/writes only to the digest's
pre-created log group. It grants no Route 53 permissions and needs no
`logs:CreateLogGroup` permission because CloudFormation creates the group.

The same template creates EventBridge Scheduler schedule
`omada-ddns-digest-daily`, with the configured expression and timezone
(defaults: `cron(0 9 * * ? *)` and `America/Toronto`), flexible window OFF,
target `omada-ddns-digest`, and payload
`{}`. Its separate execution role permits `lambda:InvokeFunction` only on the
digest, with a trust policy restricted to this account's default schedule group.
This same-account role supplies invoke permission; no public Lambda resource
policy is needed. Scheduler retries are disabled to reduce duplicate sends;
Lambda's asynchronous delivery may still retry failed executions, so exactly-once
email delivery is not guaranteed. Inspect digest Lambda logs for execution
failures; a successfully accepted asynchronous invocation does not prove the
handler succeeded.

### Manual testing and SES delivery

Verify your configured SES domain or sender email identity in the deployment
region. While SES remains in the sandbox, **the recipient must also be verified
in that region**. The commands below use generic example addresses; replace
them with your configured sender and recipient.
If needed, after approval, request recipient verification and follow the link
sent to that inbox:

```sh
aws sesv2 create-email-identity --region ca-central-1 \
  --email-identity admin@example.com
```

After approval, test SES independently (this sends a real test email):

```sh
aws sesv2 send-email --region ca-central-1 \
  --from-email-address omada@example.com \
  --destination '{"ToAddresses":["admin@example.com"]}' \
  --content '{"Simple":{"Subject":{"Data":"Omada DDNS SES delivery test","Charset":"UTF-8"},"Body":{"Text":{"Data":"Manual SES delivery test.","Charset":"UTF-8"}}}}'
```

After deployment and approval, invoke the digest synchronously without waiting
for the daily schedule (this can send a real digest email):

```sh
aws lambda invoke --region ca-central-1 --function-name omada-ddns-digest \
  --invocation-type RequestResponse --cli-binary-format raw-in-base64-out \
  --payload '{}' /tmp/omada-ddns-digest-response.json
cat /tmp/omada-ddns-digest-response.json
aws logs tail /aws/lambda/omada-ddns-digest --region ca-central-1 --since 10m
```

Check the invoke command's metadata for `FunctionError` as well as the response
file: HTTP status 200 alone does not mean success. A successful Go handler
returns `null`. No matching records yesterday means no email except for the Monday heartbeat; use
the independent SES test above to verify delivery in that situation. The unit
tests use fake AWS clients and a fixed clock to verify prior dates and DST
without changing logs or sending mail. SES production access removes the
sandbox requirement to verify recipients; the sender identity remains required.
