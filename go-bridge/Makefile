# Testing Guide for pyvider-rpcplugin-bridge

This document explains how to run and extend the test suite for the pyvider-rpcplugin-bridge.

## Test Structure

The test suite is organized into several categories:

1. **Unit Tests**: Test individual components in isolation
   - `main_test.go`: Tests for command-line handling and version output
   - `launcher_test.go`: Tests for Python program launching functionality
   - `proxy_test.go`: Tests for I/O proxying functionality

2. **Integration Tests**: Test components working together
   - `integration_test.go`: End-to-end tests of the bridge's functionality

3. **Mock Tests**: Tests using mock implementations
   - `mock_test.go`: Contains helper utilities for testing without real dependencies

## Running Tests

### Basic Test Commands

```bash
# Run all unit tests
make test

# Run only integration tests
make test-integration

# Run all tests (unit + integration)
make test-all

# Run tests with race detection
make test-race

# Run tests with code coverage
make test-coverage

# Run tests in short mode (skipping long-running tests)
make test-short
```

### Test Environment Variables

The test suite respects the following environment variables:

- `GOOS`: Operating system target (automatically set by Go)
- `GOARCH`: Architecture target (automatically set by Go)
- `PYTHONPATH`: Path to Python modules (used in integration tests)

## Writing New Tests

When adding new functionality or fixing bugs, please add appropriate tests:

1. For new features, add both unit tests and integration tests
2. For bug fixes, add a test that verifies the fix

### Test Naming Conventions

- Test functions should be named `Test<FunctionName>` for unit tests
- Integration test functions should be named `Test<Feature>` 
- Mock test utilities should be in `mock_test.go`

### Test Tags

Use build tags to categorize tests:

```go
// +build integration

package main

// ... integration tests ...
```

## Test Coverage

To view test coverage:

```bash
make test-coverage
```

This generates an HTML report at `coverage/coverage.html` that shows which lines of code are covered by tests.

## Troubleshooting Tests

Common issues and solutions:

1. **Tests fail to find Python**: Some tests require a Python interpreter. Make sure Python is installed and in your PATH.

2. **Permission denied errors**: Ensure the test directory has write permissions.

3. **Timing-related test failures**: Some tests involve process execution and may be sensitive to timing. If you encounter flaky tests, try running them again or with longer timeouts.

4. **Platform-specific failures**: Some tests may be designed for specific platforms (Unix/Windows). Check for platform-specific skip conditions.

## Continuous Integration

The test suite is designed to run in CI environments. The following steps are typically performed:

1. Checkout code
2. Set up Go environment
3. Run `make test-all`
4. Generate and upload coverage reports
