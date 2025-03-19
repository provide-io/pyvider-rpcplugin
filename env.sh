#!/bin/bash

# Base configuration
BASE_PATH=$(pwd)

# local DEFAULT_PLUGIN_HOST="localhost"
# local DEFAULT_PLUGIN_PORT="50051"

#local DEFAULT_PLUGIN_ALGO="ec-secp256r1"

export PLUGIN_MAGIC_COOKIE_KEY=BASIC_PLUGIN
export PLUGIN_MAGIC_COOKIE_VALUE=hello
export PLUGIN_MAGIC_COOKIE=hello
export BASIC_PLUGIN=hello

# export PLUGIN_PROTOCOL_VERSIONS=1
# export PLUGIN_TRANSPORTS=unix
export PLUGIN_AUTO_MTLS=true

# PLUGIN_HOST=${PLUGIN_HOST:-${DEFAULT_PLUGIN_HOST}}
# PLUGIN_PORT=${PLUGIN_PORT:-${DEFAULT_PLUGIN_PORT}}

# TLS algorithm configuration
#PLUGIN_ALGO=${PLUGIN_ALGO:-${DEFAULT_PLUGIN_ALGO}}
# PLUGIN_CLIENT_ALGO=${PLUGIN_CLIENT_ALGO:-"ec-secp384r1"}
# PLUGIN_SERVER_ALGO=${PLUGIN_SERVER_ALGO:-"ec-secp384r1"}

# Certificate paths
# PLUGIN_CLIENT_CERT_FILE="${BASE_PATH}/tests/certs/${PLUGIN_CLIENT_ALGO}-mtls-client.crt"
# PLUGIN_CLIENT_KEY_FILE="${BASE_PATH}/tests/certs/${PLUGIN_CLIENT_ALGO}-mtls-client.key"

# Load certificates
# if [ ! -f "${PLUGIN_CLIENT_CERT_FILE}" ]; then
#     echo "❌ Error: Client certificate not found at ${PLUGIN_CLIENT_CERT_FILE}"
#     return
# fi

# if [ ! -f "${PLUGIN_CLIENT_KEY_FILE}" ]; then
#     echo "❌ Error: Client key not found at ${PLUGIN_CLIENT_KEY_FILE}"
#     return
# fi

# PLUGIN_CLIENT_CERT="$(cat ${PLUGIN_CLIENT_CERT_FILE})"
# PLUGIN_CLIENT_KEY="$(cat ${PLUGIN_CLIENT_KEY_FILE})"
#
# PLUGIN_SERVER_CERT_FILE="${BASE_PATH}/tests/certs/${PLUGIN_SERVER_ALGO}-mtls-server.crt"
# PLUGIN_SERVER_KEY_FILE="${BASE_PATH}/tests/certs/${PLUGIN_SERVER_ALGO}-mtls-server.key"

# Load certificates
# if [ ! -f "${PLUGIN_SERVER_CERT_FILE}" ]; then
#     echo "❌ Error: Server certificate not found at ${PLUGIN_SERVER_CERT_FILE}"
#     return
# fi
#
# if [ ! -f "${PLUGIN_SERVER_KEY_FILE}" ]; then
#     echo "❌ Error: Server key not found at ${PLUGIN_SERVER_KEY_FILE}"
#     return
# fi

# PLUGIN_SERVER_CERT="$(cat ${PLUGIN_SERVER_CERT_FILE})"
# PLUGIN_SERVER_KEY="$(cat ${PLUGIN_SERVER_KEY_FILE})"

# Endpoint configuration
# PLUGIN_SERVER_ENDPOINT="tcp:${PLUGIN_HOST}:${PLUGIN_PORT}"
# PLUGIN_PYTHON_SERVER_ENDPOINT="${PLUGIN_HOST}:${PLUGIN_PORT}"
# PLUGIN_CS_SERVER_ENDPOINT="https://${PLUGIN_HOST}:${PLUGIN_PORT}"

function get_key_size() {
    openssl req -new \
        -key $1 \
        -x509 \
        -nodes \
        -days 365 \
        -subj "/CN=test.com" |
        openssl x509 -noout -text |
        grep Public-Key |
        sed -E 's/[^0-9]+//g'
}

# PLUGIN_CLIENT_KEY_SIZE=$(echo $(get_key_size "${PLUGIN_CLIENT_KEY_FILE}"))
# PLUGIN_SERVER_KEY_SIZE=$(echo $(get_key_size "${PLUGIN_SERVER_KEY_FILE}"))


# Export all necessary environment variables
# export PLUGIN_HOST \
#     PLUGIN_PORT \
#     PLUGIN_CLIENT_CERT \
#     PLUGIN_CLIENT_KEY \
#     PLUGIN_SERVER_PATH \
#     PLUGIN_SERVER_CERT \
#     PLUGIN_SERVER_KEY \
#     PLUGIN_SERVER_ENDPOINT \
#     PLUGIN_PYTHON_SERVER_ENDPOINT \
#     PLUGIN_CS_SERVER_ENDPOINT
#
# Path configuration
export PYTHONPATH="${BASE_PATH}/src:${BASE_PATH}:${PYTHONPATH}"

# OpenSSL aliases
alias ossl-client='openssl s_client -connect localhost:50051 \
   -cert <(echo "$PLUGIN_CLIENT_CERT") \
   -key <(echo "$PLUGIN_CLIENT_KEY") \
   -CAfile <(echo "$PLUGIN_SERVER_CERT") \
   -servername localhost'

alias ossl-check-server-cert='openssl crl2pkcs7 \
    -nocrl \
    -certfile <(echo "$PLUGIN_SERVER_CERT") \
    | openssl pkcs7 -print_certs -text -noout'

alias ossl-server='openssl s_server \
    -cert <(echo "$PLUGIN_SERVER_CERT") \
    -key <(echo "$PLUGIN_SERVER_KEY") \
    -accept 50051 \
    -verify_return_error \
    -Verify 2'

alias rpcenv-refresh=" \
  unset PLUGIN_CLIENT_CERT \
    PLUGIN_CLIENT_KEY \
    PLUGIN_CLIENT_ALGO \
    PLUGIN_CLIENT_KEY_SIZE \
    PLUGIN_SERVER_CERT \
    PLUGIN_SERVER_KEY \
    PLUGIN_SERVER_ALGO \
    PLUGIN_SERVER_KEY_SIZE \
    ;

    set | grep _CERT=
    pushd ~/code/tf/pyvider/src/pyvider/rpcplugin;

    source env.sh;

    popd;
"
alias show-dupdefs="grep -r 'def ' * | sed -E 's/.*def //g;s/\(.*//g' |sort -h | uniq -c | sort -d | grep test | grep -v '1 '"

alias py-kv-client="(cd ${BASE_PATH}/examples/kvproto; ./py_kv_client.py)"
alias py-kv-server="(cd ${BASE_PATH}/examples/kvproto; ./py_kv_server.py)"

alias go-kv-client="${BASE_PATH}/examples/kvproto/go-plugin/bin/kv-go-client"
alias go-kv-server="${BASE_PATH}/examples/kvproto/go-plugin/bin/kv-go-server"

PLUGIN_SERVER_PATH=${PLUGIN_SERVER_PATH:-"${BASE_PATH}/examples/kvproto/py_kv_server.py"}

export PLUGIN_SERVER_PATH

alias venv-activate="
  uv venv 2>&1 | grep 'Activate with' | sed 's/.* source //g'
"

echo ""
echo "🔐 TLS Configuration:"
echo "   • Algorithm: ${PLUGIN_ALGO}"
echo "   • Client Algorithm: ${PLUGIN_CLIENT_ALGO} (${PLUGIN_CLIENT_KEY_SIZE} bits)"
echo "   • Server Algorithm: ${PLUGIN_SERVER_ALGO} (${PLUGIN_SERVER_KEY_SIZE} bits)"
echo ""
echo "📊 Environment Status:"
echo "   • Client Cert Size: $(echo "$PLUGIN_CLIENT_CERT" | wc -c | tr -d ' ') bytes"
echo "   • Client  Key Size: $(echo "$PLUGIN_CLIENT_KEY" | wc -c | tr -d ' ') bytes"
echo "   • Server Plugin Path: ${PLUGIN_SERVER_PATH}"
echo "   • Server Cert Size: $(echo "$PLUGIN_SERVER_CERT" | wc -c | tr -d ' ') bytes"
echo "   • Server  Key Size: $(echo "$PLUGIN_SERVER_KEY" | wc -c | tr -d ' ') bytes"
echo ""
echo "🌐 Network Configuration:"
echo "   • Host: ${PLUGIN_HOST}"
echo "   • Port: ${PLUGIN_PORT}"
echo "   • gRPC Endpoint: ${PLUGIN_SERVER_ENDPOINT}"
echo ""
echo "🚀 Environment setup complete!"
echo ""
