## Repository Structure

```
pyvider-rpcplugin/
├── bridge/                # Go module directory
│   ├── main.go            # Main entry point 
│   ├── launcher.go        # Python launcher
│   ├── proxy.go           # Proxy implementation
│   ├── go.mod             # Go module definition
│   ├── go.sum             # Go dependency checksums
│   └── Makefile           # Build automation
└── ... (other Python-related files)
```# pyvider-rpcplugin-bridge

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

Note: When installed, the binary is renamed to `terraform-provider-pyvider` in the Terraform plugin directory, as that's the name Terraform expects based on the provider source.

### Manual installation:

```bash
# Build the binary
go build -o bin/pyvider-rpcplugin-bridge .

# Copy to Terraform plugin directory (note the rename to what Terraform expects)
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/provide-io/pyvider/0.1.0/$(go env GOOS)_$(go env GOARCH)
cp bin/pyvider-rpcplugin-bridge ~/.terraform.d/plugins/registry.terraform.io/provide-io/pyvider/0.1.0/$(go env GOOS)_$(go env GOARCH)/terraform-provider-pyvider
```

## Usage

Once installed, you can use it in your Terraform configuration:

```hcl
terraform {
  required_providers {
    pyvider = {
      source = "provide-io/pyvider"
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
Usage of pyvider-rpcplugin-bridge:
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

