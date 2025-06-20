#!/bin/bash
set -e

echo "🧼 Cleaning up previous builds..."
rm -rf ./bin

echo "🚚 Ensuring Go dependencies are correct and tidy..."
go mod tidy
echo "⬆️ Updating Go dependencies to the latest versions..."
go get -u ./...

echo "🛠️ Building client and server..."
go build -o ./bin/kv-go-server ./plugin-go-server
go build -o ./bin/kv-go-client ./plugin-go-client

echo "✅ Build complete."
