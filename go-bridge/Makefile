.PHONY: build clean test install

# Variables
BINARY_NAME=pyvider-rpcplugin-bridge
BUILD_DIR=bin
VERSION ?= 0.1.0
PLATFORMS=darwin linux windows
ARCHITECTURES=amd64 arm64

# Default target
all: build

# Build for current platform
build:
   @mkdir -p $(BUILD_DIR)
   go build -o $(BUILD_DIR)/$(BINARY_NAME) .

# Clean build artifacts
clean:
   rm -rf $(BUILD_DIR)

# Run tests
test:
   go test -v ./...

# Build release binaries for all platforms
release:
   @mkdir -p $(BUILD_DIR)/release
   @for platform in $(PLATFORMS); do \
      for arch in $(ARCHITECTURES); do \
         if [ "$$platform" = "windows" ]; then \
            EXTENSION=".exe"; \
         else \
            EXTENSION=""; \
         fi; \
         echo "Building for $$platform/$$arch..."; \
         GOOS=$$platform GOARCH=$$arch go build -o $(BUILD_DIR)/release/$(BINARY_NAME)_$(VERSION)_$${platform}_$${arch}$${EXTENSION} ./cmd/rpcplugin-bridge; \
      done; \
   done
   @echo "Release binaries built in $(BUILD_DIR)/release/"

# Install in Terraform plugin directory
install: build
   @mkdir -p ~/.terraform.d/plugins/registry.terraform.io/provide-io/pyvider/$(VERSION)/$(go env GOOS)_$(go env GOARCH)
   @cp $(BUILD_DIR)/$(BINARY_NAME) ~/.terraform.d/plugins/registry.terraform.io/provide-io/pyvider/$(VERSION)/$(go env GOOS)_$(go env GOARCH)/terraform-provider-pyvider
   @echo "Provider installed to ~/.terraform.d/plugins/registry.terraform.io/provide-io/pyvider/$(VERSION)/$(go env GOOS)_$(go env GOARCH)/"

# Run with debugging enabled
debug: build
   $(BUILD_DIR)/$(BINARY_NAME) --debug

help:
   @echo "Available targets:"
   @echo "  build    - Build for current platform"
   @echo "  clean    - Remove build artifacts"
   @echo "  test     - Run tests"
   @echo "  release  - Build release binaries for all platforms"
   @echo "  install  - Install provider in Terraform plugin directory"
   @echo "  debug    - Run with debugging enabled"
   @echo ""
   @echo "Variables:"
   @echo "  VERSION  - Provider version (default: $(VERSION))"