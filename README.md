# Omada event-driven DDNS updater — Phase 2

Extends the deployed Phase 1 Lambda: Omada → public HTTPS Function URL →
authenticated Go handler → Route 53. **Dry-run is enabled by default.**
Implementation and local verification do not deploy resources or change DNS.

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

Phase 1 raw-event logging is removed. Operational logs contain fixed decision
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
include `time`, `level`, `msg`, `type`, and operational fields. Normal decisions
and unexpected-payload diagnostics use info; request/authentication rejections
use warn; configuration and Route 53 errors use error. At debug level, every
invocation additionally emits a `webhook_request` entry with sanitized request
data, including requests rejected for method, authentication, or body errors.
Invalid invocation JSON produces only parsing metadata. Invalid log-level
configuration fails closed.

Set the SAM `LogLevel` parameter to `debug` to enable request logging. In
`samconfig.toml`, add `LogLevel=\"debug\"` to the existing saved parameter overrides,
preserving the hosted zone, secret ARN, and current `DryRun` setting. Then run
`make deploy` and review the change set. Set it back to `LogLevel=\"info\"` to
disable debug request entries. This changes logging only; it does not change
the saved live/dry-run mode.

The original Phase 1 token was logged. **Rotate it before deploying this version.**
Store the rotated value in an existing AWS Secrets Manager secret in ca-central-1,
as a JSON key named `token`. Create/configure it through the AWS Console using a
new strong random value; do not paste it into shell commands or this repository.
Update Omada to use the same value only as part of the reviewed rollout.

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
- `internal/dns`: mocked SDK interface and safe Route 53 reads/UPSERTs.
- `cmd/local`: processes stdin using a fake DNS client; no AWS credentials/network.
- `examples/function-url-event.json`: disposable authenticated local fixture.

Requirements: supported Go 1.27, make, zip/unzip, AWS CLI v2, current SAM CLI.
Production dependencies are the official AWS Lambda Go library and AWS SDK v2;
their transitive dependencies are pinned in go.mod/go.sum.

```sh
make test
go vet ./...
make package
make local
file build/bootstrap
unzip -l build/function.zip
```

The local fixture uses fixed `disposable-local-token` and a fake current DNS value.
It logs a proposed change but cannot write DNS. Stdout carries logs, stderr carries
the response. `make package` cross-compiles a static Linux ARM64 `bootstrap`, marks
it executable, and puts it at the ZIP root. Artifacts/caches are ignored by Git.

## Infrastructure and IAM review

Existing logical IDs, function name, runtime, architecture, URL, and permissions
are retained. Expected changes are in-place function code/configuration and role
policy updates. No resource replacements are intended; verify the actual change
set before execution. This cannot be confirmed solely by local template linting.

| Setting | Phase 2 |
| --- | --- |
| Function | `omada-ddns-updater`, ARM64, `provided.al2023`, 128 MB, outside VPC |
| Timeout / concurrency | 20 seconds / reserved concurrency 1 |
| Function URL | Existing URL, AWS auth NONE; application header auth |
| Logs | Existing group, seven-day retention |
| Secret | `OMADA_WEBHOOK_SECRET`, resolved from external Secrets Manager secret |
| Hosted zone | `ROUTE53_HOSTED_ZONE_ID`, required `HostedZoneId` parameter |
| DNS record | `ROUTE53_RECORD_NAME`, required `RecordName` parameter |
| Dry-run | `DDNS_DRY_RUN`, parameter `DryRun`, default `true` |
| Logging | `LOG_LEVEL`, parameter `LogLevel`, default `info` |

Role permissions retain log writes to the existing group. Route 53 permissions:

- `ListResourceRecordSets` scoped to the supplied hosted zone ARN. AWS does not
  support restricting this list permission to a single record name.
- `ChangeResourceRecordSets` scoped to the same zone, with
  `ForAllValues:StringEquals` conditions restricting normalized names to
  the configured `RecordName`, types to `A`, and actions to `UPSERT`.

`RecordName` must be a lowercase hostname without a trailing dot, for example
`vpn.example.com`. IAM and runtime configuration use the same parameter. There
is no default target; missing or invalid runtime names fail closed. When updating
an earlier deployment, add `RecordName=\"YOUR_EXISTING_FQDN\"` to the saved
`parameter_overrides` in ignored `samconfig.toml` before running `make deploy`.
Preserve the deployed target and current `DryRun`/`LogLevel` settings.
If your SAM configuration uses a TOML subtable for overrides instead of a string,
add the parameter there:

```toml
[default.deploy.parameters.parameter_overrides]
RecordName = "YOUR_EXISTING_FQDN"
# Keep the other existing parameters in this table.
```

There are no wildcard Route 53 actions, zone creation/deletion permissions, or
new runtime services. Write IAM permission exists in dry-run; code suppresses
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
export WEBHOOK_SECRET_ARN=YOUR_ROTATED_SECRET_ARN

aws route53 get-hosted-zone --id "$HOSTED_ZONE_ID" \
  --query '{Name:HostedZone.Name,Private:VPCs,Config:HostedZone.Config}'
aws route53 list-resource-record-sets --hosted-zone-id "$HOSTED_ZONE_ID" \
  --query "ResourceRecordSets[?Name == '${RECORD_NAME}.']"
```

These are read-only. Confirm the zone has `PrivateZone: false` and the target
record configuration is supported. Deployment credentials need the CloudFormation,
S3 artifact, Lambda, IAM role/policy, PassRole, and logging permissions used in
Phase 1, plus secret resolution. The deployment identity may also need Route 53
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

SAM displays a change set and asks for confirmation before executing it. Expect
no replacement of `DiagnosticFunction` or `FunctionUrl`. If a replacement is
shown, decline the prompt and inspect why. Otherwise, after review and approval,
confirm deployment. `--resolve-s3` uses SAM's artifact bucket and may create its
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

Retrieve the existing URL:

```sh
FUNCTION_URL=$(aws cloudformation describe-stacks \
  --stack-name omada-ddns-updater --region ca-central-1 \
  --query 'Stacks[0].Outputs[?OutputKey==`FunctionUrl`].OutputValue' --output text)

# GET is intentionally unsupported in Phase 2: expect 405.
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
