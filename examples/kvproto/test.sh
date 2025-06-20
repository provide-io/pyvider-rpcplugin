#!/bin/bash
set -e

# Use color for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🚀 Running build script first...${NC}"
./build.sh
echo ""

# Function to run a test case
run_test() {
    TITLE=$1
    shift
    CLIENT_ARGS=("$@")

    echo -e "${YELLOW}======================================================================${NC}"
    echo -e "${YELLOW}  TEST: $TITLE${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
    
    # Run client with specified args, perform a put and a get
    ./bin/kv-go-client "${CLIENT_ARGS[@]}" put mykey "hello world from test: $TITLE"
    ./bin/kv-go-client "${CLIENT_ARGS[@]}" get mykey
    echo ""
}

# Test Cases
run_test "Default (ECDSA with secp521r1) and Auto mTLS"
run_test "ECDSA with secp384r1 and Auto mTLS" --curve secp384r1
run_test "RSA with 2048 bits and Auto mTLS" --key-type rsa --rsa-bits 2048
run_test "Insecure (Auto mTLS disabled)" --auto-mtls=false

echo -e "${GREEN}✅ All tests completed successfully.${NC}"
