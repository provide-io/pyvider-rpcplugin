#!/bin/bash

set -e

# Ensure `uv` environment is activated
eval "$(uv venv)"

# Function to run tests
run_tests() {
    echo "Running Pyvider tests..."
    uv sync --all-groups --dev
    uv run pytest -n auto --cov=pyvider.rpcplugin --cov-report=term-missing
}

# Function to build the package
run_build() {
    echo "Building Pyvider package..."
    uv run hatch build
    cp dist/* /dist/
}

# Main entrypoint logic
case "$1" in
test)
    run_tests
    ;;
build)
    run_build
    ;;
*)
    exec "$@"
    ;;
esac
