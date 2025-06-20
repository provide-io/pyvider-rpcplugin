#!/bin/sh
set -e

echo "Building Go server and client..."
go build -o ./bin/kv-go-server ./plugin-go-server
go build -o ./bin/kv-go-client ./plugin-go-client
echo "Build complete."
