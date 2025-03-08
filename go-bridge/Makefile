.PHONY: build clean test install release all test-race coverage dev lint

# Variables
BINARY_NAME=pyvider-rpcplugin-bridge
BUILD_DIR=bin
VERSION ?= 0.2.0
PLATFORMS=darwin linux windows
ARCHITECTURES=amd64 arm64
LDFLAGS=-ldflags "-X main.BridgeVersion=${VERSION}"

# Default target
all: lint test build

# Build for current platform
build:
	@echo "Building ${BINARY_NAME} v${VERSION}..."
	@mkdir -p $(BUILD_DIR)
	go build ${LDFLAGS} -o $(BUILD_DIR)/$(BINARY_NAME) .

# Development build with race detection
dev:
	@echo "Building development version with race detection..."
	@mkdir -p $(BUILD_DIR)
	go build -race ${LDFLAGS} -o $(BUILD_DIR)/$(BINARY_NAME)-dev .

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf coverage

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with race detector
test-race:
	@echo "Running tests with race detector..."
	go test -race -v ./...

# Generate code coverage report
coverage:
	@echo "Generating code coverage report..."
	@mkdir -p coverage
	go test -coverprofile=coverage/coverage.out ./...
	go tool cover -html=coverage/coverage.out -o coverage/coverage.html
	@echo "Coverage report generated at coverage/coverage.html"

# Run linter
lint:
	@echo "Running linter..."
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, skipping enhanced linting"; \
	fi

# Build release binaries for all platforms
release:
	@echo "Building release binaries v${VERSION}..."
	@mkdir -p $(BUILD_DIR)/release
	@for platform in $(PLATFORMS); do \
		for arch in $(ARCHITECTURES); do \
			extension=""; \
			if [ "$$platform" = "windows" ]; then \
				extension=".exe"; \
			fi; \
			echo "Building for $$platform/$$arch..."; \
			GOOS=$$platform GOARCH=$$arch go build ${LDFLAGS} -o $(BUILD_DIR)/release/$(BINARY_NAME)_$(VERSION)_$${platform}_$${arch}$${extension} .; \
		done; \
	done
	@echo "Release binaries built in $(BUILD_DIR)/release/"

# Install in Terraform plugin directory
install: build
	@echo "Installing to Terraform plugin directory..."
	@mkdir -p ~/.terraform.d/plugins/registry.terraform.io/provide-io/pyvider/$(VERSION)/$$(go env GOOS)_$$(go env GOARCH)
	@cp $(BUILD_DIR)/$(BINARY_NAME) ~/.terraform.d/plugins/registry.terraform.io/provide-io/pyvider/$(VERSION)/$$(go env GOOS)_$$(go env GOARCH)/terraform-provider-pyvider
	@echo "Provider installed to ~/.terraform.d/plugins/registry.terraform.io/provide-io/pyvider/$(VERSION)/$$(go env GOOS)_$$(go env GOARCH)/"

# Run the bridge in debug mode
debug: dev
	@echo "Running bridge in debug mode..."
	@$(BUILD_DIR)/$(BINARY_NAME)-dev --debug
