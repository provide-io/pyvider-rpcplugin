#!/bin/bash

set -e

# Function to run tests
run_tests() {
    echo "Running Pyvider tests..."
    pytest -xvs
}

# Function to run specific interop tests
run_interop() {
    echo "Running interoperability tests between Python and Go..."
    cd /app/tests/interop
    python run_interop_tests.py
}

# Function to start development shell
run_dev() {
    echo "Starting development environment..."
    # Start any background services needed for development

    # Drop into a shell
    exec /bin/bash
}

# Function to build the package
run_build() {
    echo "Building Pyvider package..."
    python -m build
    cp dist/* /dist/
}

# Main entrypoint logic
case "$1" in
test)
    run_tests
    ;;
interop)
    run_interop
    ;;
dev)
    run_dev
    ;;
build)
    run_build
    ;;
*)
    exec "$@"
    ;;
esac
