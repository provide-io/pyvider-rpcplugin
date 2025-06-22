#!/bin/bash
echo "START OF SCRIPT EXECUTION"

echo "Setting up environment and running initial checks..."

echo "Current directory: $(pwd)"
echo "Listing files in /app before cd:"
ls -la /app || echo "/app not found or ls failed"

echo "Attempting to change directory to /app and source env.sh..."
cd /app || { echo "Failed to cd to /app"; exit 1; }
echo "Current directory after cd: $(pwd)"

if [ -f "./env.sh" ]; then
    echo "env.sh found. Sourcing..."
    source ./env.sh || { echo "Failed to source env.sh"; exit 1; }
    echo "env.sh sourced successfully."
else
    echo "env.sh not found in /app. Listing /app contents:"
    ls -la
    exit 1
fi

echo "Checking tool versions..."
echo "uv version:"
uv -V || echo "uv command failed"
echo "python3 version:"
python3 -V || echo "python3 command failed"

echo "Running pytest..."
# Using timeout as pytest can hang
# Using || true to ensure script continues even if pytest fails or times out
timeout 1800 pytest --cov=pyvider.rpcplugin --cov-branch --cov-report=term-missing || true
echo "Pytest execution finished or timed out."

echo "Initial checks script finished."
echo "END OF SCRIPT EXECUTION"
