# Location SAM will put build artifacts
ARTIFACTS_DIR ?= .aws-sam/build
BINARY = bootstrap

GOOS = linux
GOARCH = arm64
CGO_ENABLED = 0

build-AuthFn:
	@echo "Building Lambda binary..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
		go build -tags lambda.norpc -ldflags="-s -w" -o $(BINARY) .
	mkdir -p $(ARTIFACTS_DIR)
	cp $(BINARY) $(ARTIFACTS_DIR)/$(BINARY)