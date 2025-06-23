#
# env.sh (Version 5 - Fix for 'uv' alias handling)
#
# Sets up the development environment for pyvider.
# Uses 'uv' for fast virtual environment and package management.
# This script is designed to be idempotent, robust, and clear about its actions.
# It relies on 'uv pip install -e .' for project importability, not manual PYTHONPATH settings.
#

# --- Initial Setup ---
echo_info() { echo "INFO: $1"; }
echo_warn() { echo "WARN: $1"; }
echo_err() { echo "ERROR: $1"; return 1; }

if [ -n "$BASH_SOURCE" ]; then
    ENV_SCRIPT_DIR_ABS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    ENV_SCRIPT_DIR_ABS="$(cd "$(dirname "$0")" && pwd)" # Fallback for sh
fi
echo_info "Script directory determined as: ${ENV_SCRIPT_DIR_ABS}"
ORIGINAL_CWD=$(pwd)
echo_info "Original current working directory: ${ORIGINAL_CWD}"
cd "${ENV_SCRIPT_DIR_ABS}"
echo_info "Changed to script directory: $(pwd)"

# --- uv Detection, Alias Handling, and Installation ---
echo_info "Detecting 'uv' (universal Python package manager)..."
UV_CMD="uv" # Default to 'uv', assuming it's an alias or in PATH directly.
            # This will be refined if a specific path is found and preferred.
UV_IS_ALIAS=false
UV_CMD_PATH="" # Stores actual path if not an alias and found via command -v

# 1. Check how 'uv' is available using 'command -v'.
UV_COMMAND_V_OUTPUT=$(command -v uv)
if [ $? -eq 0 ]; then
  # 'uv' is found. Check if it's an alias.
  # 'command -v' output for an alias typically starts with "alias " or "uv is aliased to "
  if echo "$UV_COMMAND_V_OUTPUT" | grep -qE "^alias | aliased to "; then
    UV_IS_ALIAS=true
    # Extract the actual command from alias if possible and simple, otherwise just use 'uv'.
    # For 'alias uv=noglob uv', `uv` is the command.
    # For 'alias myuv=uv', `uv` is the command.
    # This can get complex, so for now, if it's an alias, we stick to UV_CMD="uv".
    echo_info "'uv' is an alias: ${UV_COMMAND_V_OUTPUT}. Will use 'uv' directly."
    UV_CMD="uv" # Ensure it's just 'uv'
  else
    # Not an alias, so it should be a path.
    UV_IS_ALIAS=false
    UV_CMD_PATH_TEMP="$UV_COMMAND_V_OUTPUT" # Store path from command -v

    # Check if this path points inside this script's .venv directory (VENV_DIR_NAME is ".venv")
    # ENV_SCRIPT_DIR_ABS and VENV_DIR_NAME are defined earlier.
    IS_INSIDE_PROJECT_VENV=false
    # Ensure VENV_DIR_NAME is defined before this check if it's used here.
    # For safety, let's use literal ".venv" as VENV_DIR_NAME might not be defined *yet* in script flow.
    # Actually, VENV_DIR_NAME is defined much later. This check needs to be robust or happen after VENV_DIR_NAME is set.
    # Let's assume VENV_DIR_NAME=".venv" for this check.
    PROJECT_VENV_UV_PATH="${ENV_SCRIPT_DIR_ABS}/.venv/bin/uv"

    if [ "$UV_CMD_PATH_TEMP" = "$PROJECT_VENV_UV_PATH" ]; then
        IS_INSIDE_PROJECT_VENV=true
    fi

    if [ "$IS_INSIDE_PROJECT_VENV" = true ] && [ ! -f "${ENV_SCRIPT_DIR_ABS}/.venv/pyvenv.cfg" ]; then
        # Points to our .venv uv, but the .venv is invalid (e.g., deleted).
        echo_info "Path $UV_CMD_PATH_TEMP points to uv inside an invalid/deleted project .venv. Discarding this path."
        UV_COMMAND_V_OUTPUT="" # Critical: This forces fallback to other detection methods
        UV_CMD_PATH=""         # Clear invalid path
        UV_CMD="uv"            # Reset to default
    elif [ -x "$UV_CMD_PATH_TEMP" ]; then # Path is executable
        UV_CMD_PATH="$UV_CMD_PATH_TEMP"
        UV_CMD="$UV_CMD_PATH_TEMP"
        echo_info "'uv' found as an executable at: ${UV_CMD}"
    else
        # Path found by command -v is not executable for other reasons.
        echo_info "'uv' reported at ${UV_CMD_PATH_TEMP} by 'command -v' but it's not executable. Resetting search."
        UV_COMMAND_V_OUTPUT="" # Force fallback
        UV_CMD_PATH=""
        UV_CMD="uv"
    fi
  fi
fi

# If initial 'command -v uv' failed, or its result was discarded (e.g., non-executable or stale .venv path)
if [ -z "$UV_COMMAND_V_OUTPUT" ] && ! $UV_IS_ALIAS; then
  echo_info "'uv' not found or initial path invalid. Checking known user environment scripts and standard install locations..."
  POTENTIAL_UV_ENV_SCRIPTS=(
    "${HOME}/.local/share/uv/env"
    "${HOME}/.cargo/env"
  )
  FOUND_UV_AFTER_SOURCING=false
  for env_script in "${POTENTIAL_UV_ENV_SCRIPTS[@]}"; do
    if [ -f "${env_script}" ]; then
      echo_info "Sourcing potential uv environment from: ${env_script}"
      # shellcheck source=/dev/null
      source "${env_script}"
      # Check again - prefer direct path if available and executable
      TMP_UV_PATH=$(command -v uv)
      if [ $? -eq 0 ]; then
        if echo "$TMP_UV_PATH" | grep -qE "^alias | aliased to "; then
            # If it's an alias, command -v doesn't give a direct path to test with -x
            # We assume 'uv' as alias is fine for now, will be verified by $UV_CMD --version
            UV_IS_ALIAS=true; UV_CMD="uv"; UV_CMD_PATH=""
            echo_info "'uv' is an alias after sourcing ${env_script}: ${TMP_UV_PATH}. Will use 'uv' directly."
            FOUND_UV_AFTER_SOURCING=true; break
        elif [ -x "$TMP_UV_PATH" ]; then # Path found and is executable
            UV_IS_ALIAS=false; UV_CMD_PATH="$TMP_UV_PATH"; UV_CMD="$UV_CMD_PATH"
            echo_info "'uv' found as an executable after sourcing ${env_script}: ${UV_CMD}"
            FOUND_UV_AFTER_SOURCING=true; break
        else
            echo_info "Found '$TMP_UV_PATH' after sourcing ${env_script}, but it's not executable. Continuing search..."
        fi
      fi
    fi
  done

  # If not found after sourcing user scripts, specifically check installer path, then try install
  if [ "$FOUND_UV_AFTER_SOURCING" = false ]; then
    echo_info "uv not found after sourcing user env scripts. Checking default install path: ${HOME}/.local/bin/uv"
    if [ -x "${HOME}/.local/bin/uv" ]; then
        echo_info "Found executable uv at ${HOME}/.local/bin/uv."
        # Ensure PATH includes ${HOME}/.local/bin for this to be picked up by plain 'uv' if not already preferred.
        # Or directly use it. For safety, using it directly.
        UV_CMD="${HOME}/.local/bin/uv"; UV_CMD_PATH="${HOME}/.local/bin/uv"; UV_IS_ALIAS=false
        FOUND_UV_AFTER_SOURCING=true # Technically not after sourcing, but found before install
    fi
  fi

  # 3. If uv is still not found by any means, proceed with installation.
  if [ "$FOUND_UV_AFTER_SOURCING" = false ]; then
    echo_info "'uv' still not found by previous methods. Proceeding with installation via astral.sh script..."
    if ! command -v curl >/dev/null 2>&1; then
        echo_err "curl is required to install 'uv' but it's not installed. Aborting."
        cd "${ORIGINAL_CWD}"; return 1
    fi
    if curl -LsSf https://astral.sh/uv/install.sh | sh; then
      if [ -f "${HOME}/.local/share/uv/env" ]; then
        # shellcheck source=/dev/null
        source "${HOME}/.local/share/uv/env"
        # After install, it should be a direct command, not an alias from this install.
        if command -v uv >/dev/null 2>&1; then
            UV_CMD_PATH=$(command -v uv) # Get the path of the installed uv
            UV_CMD="$UV_CMD_PATH"
            UV_IS_ALIAS=false
            echo_info "'uv' installed and configured. Path: ${UV_CMD}"
        else
            echo_err "'uv' installation seemed successful, but command still not found. Check PATH."
            cd "${ORIGINAL_CWD}"; return 1
        fi
      else
        echo_err "'uv' install script ran, but env file not found. Check installation."
        cd "${ORIGINAL_CWD}"; return 1
      fi
    else
      echo_err "'uv' installation script failed."
      cd "${ORIGINAL_CWD}"; return 1
    fi
  elif [ -z "$UV_CMD_PATH" ] && [ "$UV_IS_ALIAS" = false ]; then
    # If command -v uv succeeded but we didn't set UV_CMD_PATH (e.g. it wasn't an alias)
    # this means uv is in path directly without being an alias, and wasn't found via the initial check's specific path assignment
    # This case implies UV_CMD="uv" is the correct approach.
    # This logic path might be redundant if initial `command -v uv` is robust.
    # The important part is that UV_CMD is set. If it's not an alias and not a path, it must be a direct command.
    echo_info "'uv' is directly available in PATH (not an alias, no specific path captured initially)."
    UV_CMD="uv" # Defaulted already, but confirm.
  fi
fi


# Final check for uv command readiness
# Ensure UV_CMD is set to a valid command or path by this point.
# If previous steps failed to identify a working uv, the install logic should have run.
# The script will then try to use UV_CMD.
echo_info "Verifying final 'uv' command '$UV_CMD'..."
# Add an explicit test for the command defined in UV_CMD
if ! $UV_CMD --version >/dev/null 2>&1; then
    # If $UV_CMD fails, and it was from a path, try plain 'uv' (in case of PATH issues or stale UV_CMD_PATH)
    if [ -n "$UV_CMD_PATH" ] && [ "$UV_CMD" = "$UV_CMD_PATH" ]; then # Was UV_CMD set to a specific path?
        echo_warn "'$UV_CMD --version' failed. Retrying with plain 'uv' assuming it might be in PATH now."
        if command -v uv >/dev/null 2>&1 && uv --version >/dev/null 2>&1; then
            UV_CMD="uv"
            echo_info "Successfully fell back to plain 'uv' command."
        else
            echo_err "Fallback to plain 'uv' also failed. 'uv' is not correctly configured. Output of 'command -v uv': $(command -v uv)"
            cd "${ORIGINAL_CWD}"; return 1
        fi
    else # $UV_CMD was already plain 'uv' or some other case
      echo_err "Failed to execute '$UV_CMD --version'. 'uv' is not correctly configured or found. Output of 'command -v uv': $(command -v uv)"
      cd "${ORIGINAL_CWD}"; return 1
    fi
fi
echo_info "Using '$UV_CMD' for uv operations. Version: $($UV_CMD --version)"


# --- Virtual Environment Setup ---
VENV_DIR_NAME=".venv"
VENV_PATH="${ENV_SCRIPT_DIR_ABS}/${VENV_DIR_NAME}"
PYTHON_FOR_VENV="python3.13" # Changed from python3.11 to python3.13
echo_info "Setting up Python virtual environment in '${VENV_PATH}' using ${PYTHON_FOR_VENV}..."
NEEDS_VENV_CREATE=false
if [ ! -f "${VENV_PATH}/pyvenv.cfg" ]; then
    echo_info "Virtual environment config '${VENV_PATH}/pyvenv.cfg' not found."
    NEEDS_VENV_CREATE=true
else
    echo_info "Virtual environment '${VENV_PATH}' appears to exist."
fi
if [ "${NEEDS_VENV_CREATE}" = true ]; then
    echo_info "(Re)creating virtual environment in '${VENV_PATH}' with Python ${PYTHON_FOR_VENV}..."
    rm -rf "${VENV_PATH}"
    if $UV_CMD venv -p "${PYTHON_FOR_VENV}" "${VENV_PATH}"; then
        echo_info "Virtual environment created successfully."
    else
        echo_err "Failed to create venv with ${PYTHON_FOR_VENV}. Ensure it's installed and accessible to '$UV_CMD'."
        cd "${ORIGINAL_CWD}"; return 1
    fi
fi

# --- Dependency Synchronization & Editable Install ---
UV_CACHE_DIR_NAME=".uv_cache"
UV_CACHE_PATH="${ENV_SCRIPT_DIR_ABS}/${UV_CACHE_DIR_NAME}"
mkdir -p "${UV_CACHE_PATH}"
echo_info "Syncing dependencies and performing editable install (cache: ${UV_CACHE_PATH})..."
run_in_venv() {
    (
        echo_info "Activating venv for UV operations: ${VENV_PATH}/bin/activate"
        # shellcheck source=./.venv/bin/activate
        source "${VENV_PATH}/bin/activate"
        echo_info "Python in activated venv: $(python -V)"
        echo_info "Running: $UV_CMD sync --all-groups --cache-dir ${UV_CACHE_PATH}"
        if ! $UV_CMD sync --all-groups --cache-dir "${UV_CACHE_PATH}"; then
            echo_err "uv sync failed."
            return 1
        fi
        echo_info "uv sync successful."
        echo_info "Running: $UV_CMD pip install -e . --cache-dir ${UV_CACHE_PATH}"
        if ! $UV_CMD pip install -e . --cache-dir "${UV_CACHE_PATH}"; then
            echo_err "uv pip install -e . failed."
            return 1
        fi
        echo_info "uv pip install -e . successful."
        return 0
    )
}
if run_in_venv; then
  echo_info "Dependencies synced and editable install successful."
else
  echo_warn "Initial attempt to sync/install failed. Trying to recreate venv and retry..."
  rm -rf "${VENV_PATH}"
  if $UV_CMD venv -p "${PYTHON_FOR_VENV}" "${VENV_PATH}"; then
    echo_info "Virtual environment recreated. Retrying sync/install..."
    if run_in_venv; then
      echo_info "Dependencies synced and editable install successful on second attempt."
    else
      echo_err "Failed again after venv recreation. Check 'pyproject.toml', network, Python setup."
      cd "${ORIGINAL_CWD}"; return 1
    fi
  else
    echo_err "Failed to recreate virtual environment on second attempt."
    cd "${ORIGINAL_CWD}"; return 1
  fi
fi

# --- Activate Virtual Environment for User Shell ---
echo_info "Activating virtual environment for your shell: ${VENV_PATH}/bin/activate"
# shellcheck source=./.venv/bin/activate
source "${VENV_PATH}/bin/activate"
if [ $? -ne 0 ]; then
    echo_warn "Failed to activate venv. Script needs to be sourced: '. env.sh'"
    cd "${ORIGINAL_CWD}"; return 1
fi
echo_info "Virtual environment activated. Current Python: $(python -V)"

# --- PYTHONPATH Configuration ---

# --- Aliases and Exports ---
echo_info "Setting up aliases and environment variables..."
alias ossl-client='openssl s_client -connect localhost:50051    -cert <(echo "$PLUGIN_CLIENT_CERT") -key <(echo "$PLUGIN_CLIENT_KEY")    -CAfile <(echo "$PLUGIN_SERVER_CERT") -servername localhost'
# ... (other aliases remain the same) ...
PY_KV_EXAMPLES_DIR="${ENV_SCRIPT_DIR_ABS}/examples/kvproto/py_rpc"
alias py-kv-client="(cd '${PY_KV_EXAMPLES_DIR}' && ./py_kv_client.py)"
alias py-kv-server="(cd '${PY_KV_EXAMPLES_DIR}' && ./py_kv_server.py)"
GO_PLUGIN_BIN_DIR="${ENV_SCRIPT_DIR_ABS}/examples/kvproto/go-rpc/bin"
if [ -f "${GO_PLUGIN_BIN_DIR}/kv-go-client" ]; then alias go-kv-client="'${GO_PLUGIN_BIN_DIR}/kv-go-client'"; else echo_info "Go client alias not set."; fi
if [ -f "${GO_PLUGIN_BIN_DIR}/kv-go-server" ]; then alias go-kv-server="'${GO_PLUGIN_BIN_DIR}/kv-go-server'"; else echo_info "Go server alias not set."; fi
export PLUGIN_SERVER_PATH=${PLUGIN_SERVER_PATH:-"${PY_KV_EXAMPLES_DIR}/py_kv_server.py"}

# Prepend project's src directory to PYTHONPATH to ensure correct namespace package handling
# This is crucial for pyvider.rpcplugin to be found correctly alongside pyvider.telemetry
export PYTHONPATH="${ENV_SCRIPT_DIR_ABS}/src${PYTHONPATH:+:$PYTHONPATH}"
echo_info "PYTHONPATH set to: $PYTHONPATH"

echo_info "Environment setup script finished successfully."
echo_info "Python in venv: $(python -V). uv: $($UV_CMD --version)."
cd "${ORIGINAL_CWD}"
echo_info "Returned to original directory: $(pwd)"
return 0
