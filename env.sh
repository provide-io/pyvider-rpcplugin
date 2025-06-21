#
# env.sh (Version 3 - Focused Robustness)
#
# Sets up the development environment for pyvider.
# Uses 'uv' for fast virtual environment and package management.
# This script is designed to be idempotent and robust.
#

# --- Initial Setup ---
# Determine the absolute path of the script's directory
# This ensures that relative paths are handled correctly, regardless of where the script is called from.
# Using BASH_SOURCE[0] is reliable in bash. For broader sh compatibility, $0 might need more handling.
# Assuming bash for this project's dev script is acceptable.
if [ -n "$BASH_SOURCE" ]; then
    ENV_SCRIPT_DIR_ABS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    # Fallback for sh or if BASH_SOURCE is not set (e.g. direct execution, not sourcing)
    # This might be less reliable if the script is symlinked.
    ENV_SCRIPT_DIR_ABS="$(cd "$(dirname "$0")" && pwd)"
fi

# Store the original Current Working Directory, to return to it at the end if the script is executed.
# If sourced, this cd won't persist in the parent shell, which is fine.
ORIGINAL_CWD=$(pwd)

# Change to the script's directory to ensure all relative paths for venv, src, etc., are correct.
# This is crucial for consistent behavior.
cd "${ENV_SCRIPT_DIR_ABS}"

echo "Running env.sh from: ${ENV_SCRIPT_DIR_ABS}"
echo "Original CWD was: ${ORIGINAL_CWD}" # Informative, even if sourcing changes context

# --- uv Detection and Installation ---
UV_COMMAND=""

# 1. Check if uv is already in PATH and executable
if command -v uv >/dev/null 2>&1; then
  UV_COMMAND=$(command -v uv)
  echo "✅ 'uv' found in PATH: ${UV_COMMAND}."
else
  echo "uv command not found in current PATH. Checking common user installation methods..."
  # 2. Check common environment scripts that might add uv to PATH
  POTENTIAL_UV_ENV_SCRIPTS=(
    "${HOME}/.local/share/uv/env"  # Current astral.sh installer path
    "${HOME}/.cargo/env"           # Path if installed via cargo by user
  )
  for env_script in "${POTENTIAL_UV_ENV_SCRIPTS[@]}"; do
    if [ -f "${env_script}" ]; then
      echo "Sourcing potential uv environment from: ${env_script}"
      # shellcheck source=/dev/null
      source "${env_script}"
      if command -v uv >/dev/null 2>&1; then
        UV_COMMAND=$(command -v uv)
        echo "✅ 'uv' now in PATH after sourcing ${env_script}: ${UV_COMMAND}."
        break
      fi
    fi
  done

  # 3. If uv is still not found, proceed with installation
  if [ -z "${UV_COMMAND}" ]; then
    echo "uv not found after checking PATH and common env scripts. Attempting installation..."
    if curl -LsSf https://astral.sh/uv/install.sh | sh; then
      # Source the newly installed uv environment script
      if [ -f "${HOME}/.local/share/uv/env" ]; then
        # shellcheck source=/dev/null
        source "${HOME}/.local/share/uv/env"
        if command -v uv >/dev/null 2>&1; then
          UV_COMMAND=$(command -v uv)
          echo "✅ 'uv' installed and configured. Path: ${UV_COMMAND}."
        else
          echo "❌ CRITICAL: 'uv' installation seemed to succeed, but command still not found in PATH. Check installation output and PATH."
          cd "${ORIGINAL_CWD}" # Return to original directory
          return 1 # Use return for sourced scripts
        fi
      else
        echo "❌ CRITICAL: 'uv' installation script ran, but env file not found at ${HOME}/.local/share/uv/env. Check installation."
        cd "${ORIGINAL_CWD}"
        return 1
      fi
    else
      echo "❌ CRITICAL: 'uv' installation script failed."
      cd "${ORIGINAL_CWD}"
      return 1
    fi
  fi
fi

if [ -z "${UV_COMMAND}" ]; then
  echo "❌ CRITICAL: Could not find or install 'uv'. Aborting setup."
  cd "${ORIGINAL_CWD}"
  return 1
fi
echo "Using 'uv' from: ${UV_COMMAND}. Version: $(${UV_COMMAND} --version)"

# --- Virtual Environment Setup ---
VENV_DIR=".venv" # Relative to ENV_SCRIPT_DIR_ABS (current dir)
PYTHON_INTERPRETER_FOR_VENV="python3.11" # Desired Python for the venv

echo "🐍 Setting up Python virtual environment in '${VENV_DIR}' using ${UV_COMMAND}..."

# Check if .venv exists and is a valid venv (basic check for pyvenv.cfg)
CREATE_VENV=false
if [ ! -f "${VENV_DIR}/pyvenv.cfg" ]; then
    echo "Virtual environment config '${VENV_DIR}/pyvenv.cfg' not found."
    CREATE_VENV=true
else
    # Optional: could add a check here to see if the venv's Python matches PYTHON_INTERPRETER_FOR_VENV
    # For now, if pyvenv.cfg exists, assume it's usable or will be correctly synced.
    echo "Virtual environment '${VENV_DIR}' appears to exist."
fi

if [ "${CREATE_VENV}" = true ]; then
    echo "Creating new virtual environment in '${VENV_DIR}' with Python ${PYTHON_INTERPRETER_FOR_VENV}..."
    # Ensure old venv is removed if we decided to (re)create it.
    rm -rf "${VENV_DIR}"
    if "${UV_COMMAND}" venv -p "${PYTHON_INTERPRETER_FOR_VENV}" "${VENV_DIR}"; then
        echo "✅ Virtual environment created successfully."
    else
        echo "❌ Failed to create virtual environment. Ensure Python ${PYTHON_INTERPRETER_FOR_VENV} is available to uv."
        cd "${ORIGINAL_CWD}"
        return 1
    fi
fi

# --- Dependency Synchronization & Editable Install ---
UV_CACHE_DIR=".uv_cache" # Relative to ENV_SCRIPT_DIR_ABS (current dir)
mkdir -p "${UV_CACHE_DIR}"
echo "📦 Syncing dependencies and performing editable install using ${UV_COMMAND} (cache: ${UV_CACHE_DIR})..."

# Activate venv temporarily for sync and install if not already active
# This ensures uv uses the correct Python interpreter from the venv for its operations.
# Note: Sourcing within a script block like this only affects the subshell of the command.
# The final `source .venv/bin/activate` is for the user's shell.
SYNC_CMD="source \"${VENV_DIR}/bin/activate\";           echo 'Activated venv for sync/install. Python: ' \$(python -V);           \"${UV_COMMAND}\" sync --all-groups --cache-dir \"${UV_CACHE_DIR}\";           \"${UV_COMMAND}\" pip install -e . --cache-dir \"${UV_CACHE_DIR}\""

if bash -c "${SYNC_CMD}"; then
  echo "✅ Dependencies synced and editable install successful."
else
  echo "❌ Failed to sync dependencies or perform editable install."
  echo "   Attempting to remove '${VENV_DIR}' and try once more from scratch..."
  rm -rf "${VENV_DIR}"
  if "${UV_COMMAND}" venv -p "${PYTHON_INTERPRETER_FOR_VENV}" "${VENV_DIR}"; then
    if bash -c "${SYNC_CMD}"; then
        echo "✅ Dependencies synced and editable install successful on second attempt."
    else
        echo "❌ Failed again. Please check 'pyproject.toml', network access, and Python availability."
        echo "   Consider manually deleting '${VENV_DIR}' and '${UV_CACHE_DIR}' before re-running."
        cd "${ORIGINAL_CWD}"
        return 1
    fi
  else
    echo "❌ Failed to recreate virtual environment on second attempt."
    cd "${ORIGINAL_CWD}"
    return 1
  fi
fi

# --- Activate Virtual Environment for User Shell ---
echo "🔗 Activating virtual environment for your shell..."
# shellcheck source=./.venv/bin/activate
source "${VENV_DIR}/bin/activate"
if [ $? -ne 0 ]; then
    echo "⚠️ Failed to activate virtual environment. Script should be sourced: '. env.sh' or 'source env.sh'"
    # If sourcing failed, there's not much more to do in the script itself.
    cd "${ORIGINAL_CWD}"
    return 1 # Indicate error to sourcing shell if possible.
fi
echo "✅ Virtual environment activated. Python: $(python -V)"


# --- PYTHONPATH Configuration ---
# Add project's 'src' directory and project root (ENV_SCRIPT_DIR_ABS) to PYTHONPATH if not already present.
PATH_TO_ADD_SRC="${ENV_SCRIPT_DIR_ABS}/src"
PATH_TO_ADD_ROOT="${ENV_SCRIPT_DIR_ABS}" # This is the project root

# Function to add path to PYTHONPATH if not already present
add_to_pythonpath() {
  local path_to_add="$1"
  if [ -d "${path_to_add}" ]; then
    # Check if the path is already in PYTHONPATH
    # Using grep with extended regex for more precise matching of path segments
    if echo "${PYTHONPATH}" | tr ':' '\n' | grep -Fxq "${path_to_add}"; then
      echo "Path already in PYTHONPATH: ${path_to_add}"
    else
      export PYTHONPATH="${path_to_add}${PYTHONPATH:+":${PYTHONPATH}"}"
      echo "Added to PYTHONPATH: ${path_to_add}"
    fi
  else
    echo "Warning: Directory not found, not adding to PYTHONPATH: ${path_to_add}"
  fi
}

add_to_pythonpath "${PATH_TO_ADD_SRC}"
add_to_pythonpath "${PATH_TO_ADD_ROOT}" # Adding project root itself
echo "Current PYTHONPATH: ${PYTHONPATH}"


# --- Original Aliases and Exports (ensure paths use ENV_SCRIPT_DIR_ABS) ---
echo "🔧 Setting up aliases and environment variables..."

# OpenSSL aliases
alias ossl-client='openssl s_client -connect localhost:50051    -cert <(echo "$PLUGIN_CLIENT_CERT")    -key <(echo "$PLUGIN_CLIENT_KEY")    -CAfile <(echo "$PLUGIN_SERVER_CERT")    -servername localhost'

alias ossl-check-server-cert='openssl crl2pkcs7     -nocrl     -certfile <(echo "$PLUGIN_SERVER_CERT")     | openssl pkcs7 -print_certs -text -noout'

alias ossl-server='openssl s_server     -cert <(echo "$PLUGIN_SERVER_CERT")     -key <(echo "$PLUGIN_SERVER_KEY")     -accept 50051     -verify_return_error     -Verify 2'

# Example aliases using ENV_SCRIPT_DIR_ABS for robust pathing
PY_KV_EXAMPLES_DIR="${ENV_SCRIPT_DIR_ABS}/examples/kvproto/py_rpc"
alias py-kv-client="(cd '${PY_KV_EXAMPLES_DIR}' && ./py_kv_client.py)"
alias py-kv-server="(cd '${PY_KV_EXAMPLES_DIR}' && ./py_kv_server.py)"

# Path for Go examples - adjust if structure is different
# Assuming go binaries are in examples/kvproto/go-rpc/bin relative to script dir
GO_PLUGIN_BIN_DIR="${ENV_SCRIPT_DIR_ABS}/examples/kvproto/go-rpc/bin"
if [ -f "${GO_PLUGIN_BIN_DIR}/kv-go-client" ]; then
    alias go-kv-client="'${GO_PLUGIN_BIN_DIR}/kv-go-client'"
else
    echo "Info: go-kv-client not found at ${GO_PLUGIN_BIN_DIR}/kv-go-client. Alias not set."
fi

if [ -f "${GO_PLUGIN_BIN_DIR}/kv-go-server" ]; then
    alias go-kv-server="'${GO_PLUGIN_BIN_DIR}/kv-go-server'"
else
    echo "Info: go-kv-server not found at ${GO_PLUGIN_BIN_DIR}/kv-go-server. Alias not set."
fi

# Export default server path, using absolute path
export PLUGIN_SERVER_PATH=${PLUGIN_SERVER_PATH:-"${ENV_SCRIPT_DIR_ABS}/examples/kvproto/py_rpc/py_kv_server.py"}

echo "✅ Environment setup script finished."
echo "🐍 Python version in activated venv: $(python -V)"
echo "📦 uv version used: $(${UV_COMMAND} --version)"
echo "🛠️ To use this environment, ensure this script was sourced: '. env.sh' or 'source env.sh'"

# Return to the original directory from which the script was called IF THE SCRIPT WAS EXECUTED.
# If sourced, 'cd' affects the current shell, so this ensures the user is back where they started
# if they accidentally executed it. However, the primary intent is sourcing.
if [ "${ORIGINAL_CWD}" != "${ENV_SCRIPT_DIR_ABS}" ]; then
    cd "${ORIGINAL_CWD}"
    echo "Returned to original directory: ${ORIGINAL_CWD}"
fi

# Use 'return 0' if sourced, to avoid exiting the user's shell.
# If the script is executed (not sourced), this has no effect after the last command.
return 0
