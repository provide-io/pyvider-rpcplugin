# the directory of the environment script.
# we're going to assume that we're in pyvider-rpcplugin/examples/kvproto/env.sh
export ENV_SCRIPT_DIR=$(dirname ${0})

CWD=$(pwd)

cd ${ENV_SCRIPT_DIR}/../../
export PYTHONPATH=$(pwd)/src:$(pwd)

cd ${CWD}

export PLUGIN_MAGIC_COOKIE=hello
export PLUGIN_MAGIC_COOKIE_KEY=BASIC_PLUGIN
export PLUGIN_MAGIC_COOKIE_VALUE=hello

export PLUGIN_SERVER_PATH=${ENV_SCRIPT_DIR}/py_rpc/py_kv_server.py
