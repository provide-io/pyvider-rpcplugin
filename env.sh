#
# env.sh
#
# Sets up the development environment for pyvider.
# Uses 'uv' for fast virtual environment and package management.
#

# Ensure the script is run from its own directory to correctly locate .venv
ENV_SCRIPT_DIR=$(dirname "${0}")
CWD=$(pwd)

echo "ENV_SCRIPT_DIR=${ENV_SCRIPT_DIR}"
echo "CWD: ${CWD}"

if ! command -v uv >/dev/null 2>&1; then
  echo "🚀 Installing 'uv'..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  source "${HOME}/.local/bin/env"
  echo "✅ 'uv' installed at $(which uv)"
  uv -V
fi

echo "🐍 Setting up Python virtual environment using uv..."

echo $(pwd)
uv venv

echo "📦 Syncing dependencies using uv..."
# Ensure all dependency groups, including 'dev', are synced.
# Explicitly use the uv installed in $HOME/.local/bin
uv sync --all-groups
echo "Attempting editable install with $HOME/.local/bin/uv..."
uv pip install -e .

echo "🔗 Activating virtual environment..."
source .venv/bin/activate

export PYTHONPATH="${PWD}/src:${PWD}"

echo "✅ Environment setup complete. PYTHONPATH set to: ${PYTHONPATH}"

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
