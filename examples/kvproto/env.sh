# Get the directory of the currently executing script.
# This is more robust than `dirname ${0}` especially when sourcing.
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

CWD=$(pwd)

# Set PYTHONPATH relative to the project root, assuming this script is two levels down
# e.g., /app/examples/kvproto -> /app
cd "${SCRIPT_DIR}/../../"
export PYTHONPATH=$(pwd)/src:$(pwd)

# Return to the original directory
cd "${CWD}"

export PLUGIN_MAGIC_COOKIE=hello
export PLUGIN_MAGIC_COOKIE_KEY=BASIC_PLUGIN
export PLUGIN_MAGIC_COOKIE_VALUE=hello

# Set the server path using the robust SCRIPT_DIR
export PLUGIN_SERVER_PATH=${SCRIPT_DIR}/py_rpc/py_kv_server.py
