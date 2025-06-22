#!/bin/bash
cd /app
source env.sh
# It's important to run the tests in a way that they don't block indefinitely.
# We'll use a timeout for the pytest command.
# The issue mentioned a long-running test, so we need to handle potential timeouts.
# We'll also ignore the exit code of pytest using '|| true' as requested.
echo "Running pytest with a timeout..."
timeout 1800 pytest --cov=pyvider.rpcplugin --cov-branch --cov-report=term-missing || true
echo "Pytest execution finished or timed out."
uv -V
python3 -V
