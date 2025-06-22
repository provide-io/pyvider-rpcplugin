#!/bin/bash

echo "Changing directory to /app and sourcing env.sh..."
cd /app && source env.sh

echo "Running pytest with a timeout..."
# Using 'timeout' to prevent indefinite blocking due to long-running tests.
# The '|| true' ensures that the subtask continues even if pytest fails or times out.
timeout 1800 pytest --cov=pyvider.rpcplugin --cov-branch --cov-report=term-missing || true
echo "Pytest execution finished or timed out."

echo "Checking tool versions..."
uv -V
python3 -V
echo "Environment setup and baseline test run complete."
