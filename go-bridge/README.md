# Pyvider RPC Plugin Bridge

A lightweight bridge that allows Terraform to communicate with Python-based Terraform providers.

## Overview

This bridge enables Terraform to use providers written in Python by:

1. Acting as a native Go binary that Terraform can directly execute
2. Launching a Python process running the Pyvider module
3. Proxying all stdin/stdout communication between Terraform and Python
4. Handling signals and process lifecycle management

## Installation

You can install the bridge using one of the following methods:

### Using the provided Makefile:

```bash
# Build for your current platform
make build

# Install to your Terraform plugin directory
make install

# Build for all supported platforms
make release
```

### Manual installation:

```bash
# Build the binary
go build -o bin/terraform-provider-pyvider ./cmd/rpcplugin-bridge

# Copy to Terraform plugin directory
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/local/pyvider/0.1.0/$(go env GOOS)_$(go env GOARCH)
cp bin/terraform-provider-pyvider ~/.terraform.d/plugins/registry.terraform.io/local/pyvider/0.1.0/$(go env GOOS)_$(go env GOARCH)/
```

## Usage

Once installed, you can use it in your Terraform configuration:

```hcl
terraform {
  required_providers {
    pyvider = {
      source = "local/pyvider"
      version = "0.1.0"
    }
  }
}

provider "pyvider" {
  # Provider configuration here
}
```

## Configuration

The bridge can be configured with the following flags:

```
Usage of terraform-provider-pyvider:
  -debug
        Enable debug logging
  -install-deps
        Automatically install dependencies if missing (default true)
  -log-file string
        Log file path (default: stderr only)
  -module string
        Python module to run (default "pyvider")
  -no-proxy
        Skip proxying to Python (debugging only)
  -python string
        Path to Python executable (default: auto-detect)
  -version
        Show version information
```

## Development

### Prerequisites

- Go 1.18 or later
- Python 3.8 or later with Pyvider installed

### Building

```bash
make build
```

### Testing

```bash
make test
```

### Debugging

To run the bridge with debug logging:

```bash
make debug
```

## How It Works

1. Terraform executes the bridge binary as a provider
2. The bridge starts a Python process with the Pyvider module
3. It proxies all stdin/stdout communication between Terraform and the Python process
4. When Terraform sends a signal or closes the connection, the bridge ensures proper cleanup

## License

This project is licensed under the MIT License - see the LICENSE file for details.
