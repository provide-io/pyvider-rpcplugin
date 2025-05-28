#!/bin/bash

ENV_SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
echo "env: ${ENV_SCRIPT_DIR}"

CWD=$(pwd)

cd ${ENV_SCRIPT_DIR}

if ! command -v uv >/dev/null 2>&1; then
  log "🚀 Installing 'uv'..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  success "✅ 'uv' installed at $(which uv)"
  uv -V
fi


uv venv
uv sync --all-groups --dev

source .venv/bin/activate

export PYTHONPATH=$(pwd)/src:$(pwd)

export PLUGIN_MAGIC_COOKIE_KEY=BASIC_PLUGIN
export PLUGIN_MAGIC_COOKIE_VALUE=hello
export PLUGIN_MAGIC_COOKIE=hello

export BASIC_PLUGIN=hello

export PLUGIN_AUTO_MTLS=true

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

alias py-kv-client="(cd ${ENV_SCRIPT_DIR}/examples/kvproto/py_rpc; ./py_kv_client.py)"
alias py-kv-server="(cd ${ENV_SCRIPT_DIR}/examples/kvproto/py_rpc; ./py_kv_server.py)"

alias go-kv-client="${ENV_SCRIPT_DIR}/examples/kvproto/go-plugin/bin/kv-go-client"
alias go-kv-server="${ENV_SCRIPT_DIR}/examples/kvproto/go-plugin/bin/kv-go-server"

export PLUGIN_SERVER_PATH=${PLUGIN_SERVER_PATH:-"${ENV_SCRIPT_DIR}/examples/kvproto/py_kv_server.py"}

cd ${CWD}
