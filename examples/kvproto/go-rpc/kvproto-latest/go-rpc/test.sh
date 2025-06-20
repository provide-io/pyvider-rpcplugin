#!/bin/sh
set -e

# First, build the binaries
./build.sh

echo "\n\n"
echo "======================================================================"
echo "  TEST 1: Default (ECDSA with secp521r1) and Auto mTLS"
echo "======================================================================"
./bin/kv-go-client ./bin/kv-go-server

echo "\n\n"
echo "======================================================================"
echo "  TEST 2: RSA 2048-bit key and Auto mTLS"
echo "======================================================================"
./bin/kv-go-client ./bin/kv-go-server --key-type rsa --rsa-bits 2048

echo "\n\n"
echo "======================================================================"
echo "  TEST 3: ECDSA with secp384r1 curve and Auto mTLS"
echo "======================================================================"
./bin/kv-go-client ./bin/kv-go-server --key-type ecdsa --curve secp384r1

echo "\n\n"
echo "======================================================================"
echo "  TEST 4: Insecure (No mTLS)"
echo "======================================================================"
./bin/kv-go-client ./bin/kv-go-server --auto-mtls=false

echo "\n\n"
echo "All tests completed successfully."
