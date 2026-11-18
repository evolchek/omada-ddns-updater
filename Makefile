REGION ?= ca-central-1
STACK ?= omada-ddns-updater

.PHONY: build test package deploy logs local clean
build:
	mkdir -p build
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -tags lambda.norpc -o build/bootstrap ./cmd/lambda
	chmod 755 build/bootstrap

test:
	go test -race ./...

package: build
	cd build && zip -j function.zip bootstrap

# Invoke only after explicit deployment approval.
# Deployment parameters, including DryRun, come from samconfig.toml.
deploy: test package
	sam deploy --confirm-changeset --no-fail-on-empty-changeset

logs:
	aws logs tail /aws/lambda/omada-ddns-updater --region $(REGION) --since 10m --follow

local:
	go run ./cmd/local < examples/function-url-event.json

clean:
	go clean
	$(RM) -r build .aws-sam

.PHONY: build-digest package-digest deploy-digest
build-digest:
	mkdir -p build/digest
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -tags lambda.norpc -o build/digest/bootstrap ./cmd/omada-ddns-digest
	chmod 755 build/digest/bootstrap

package-digest: build-digest
	cd build/digest && zip -j function.zip bootstrap

# Invoke only after explicit deployment approval.
# Digest deployment parameters come from the digest environment in samconfig.toml.
deploy-digest: test package-digest
	sam deploy --config-env digest --confirm-changeset --no-fail-on-empty-changeset
