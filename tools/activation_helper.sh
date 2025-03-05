function venv-pyvider-rpcplugin() {
    local activate_cmd
    activate_cmd=$(uv venv 2>&1 | grep 'Activate with' | cut -d':' -f2- | xargs)

    if [ -n "$activate_cmd" ]; then
        echo "Activating virtual environment..."

        # Ensure correct sourcing syntax
        local activate_path
        activate_path=$(echo "$activate_cmd" | awk '{print $2}')

        if [ -f "$activate_path" ]; then
            eval "$activate_cmd"
        else
            echo "Activation script not found: $activate_path" >&2
            return 1
        fi
    else
        echo "Failed to extract activation command." >&2
        return 1
    fi
}
