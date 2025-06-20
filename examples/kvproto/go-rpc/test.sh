#!/bin/bash
set -e

echo "🚀 Running build script first..."
./build.sh
echo ""
echo ""

# Function to run a test case
run_test() {
    TITLE=$1
    shift
    CLIENT_ARGS=("$@")

    echo "======================================================================"
    echo "  TEST: $TITLE"
    echo "======================================================================"
    
    # Run client with specified args, perform a put and a get
    ./bin/kv-go-client "${CLIENT_ARGS[@]}" put mykey "hello world"
    ./bin/kv-go-client "${CLIENT_ARGS[@]}" get mykey
    echo ""
    echo ""
}

# Test Cases
run_test "Default (ECDSA with secp521r1) and Auto mTLS"
run_test "ECDSA with secp384r1 and Auto mTLS" --curve secp384r1
run_test "RSA with 2048 bits and Auto mTLS" --key-type rsa --rsa-bits 2048
run_test "Insecure (Auto mTLS disabled)" --auto-mtls=false

echo "✅ All tests completed."
